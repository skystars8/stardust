//! AES-256-GCM-SIV file encryption / decryption CLI.
//!
//! Usage:
//!   aes E <input> <output>   # encrypt
//!   aes D <input> <output>   # decrypt
//!
//! All three files (input, output, key.key) must be plain filenames
//! located in the current working directory. No path components allowed.
//! The tool refuses to overwrite an existing output file and processes
//! the entire payload in memory for maximum reliability.

use std::fs;
use std::path::{Component, Path};
use std::process::ExitCode;

use aes_gcm_siv::{
    aead::{Aead, KeyInit, OsRng, generic_array::GenericArray},
    Aes256GcmSiv, Nonce,
};
use rand_core::RngCore;
use anyhow::{bail, Context, Result};
use clap::Parser;
use zeroize::Zeroize;

const KEY_FILE: &str = "key.key";
const KEY_LEN: usize = 32; // AES-256
const NONCE_LEN: usize = 12; // AES-GCM-SIV nonce
const TAG_LEN: usize = 16; // authentication tag (appended by the crate)
const MIN_CIPHERTEXT_LEN: usize = NONCE_LEN + TAG_LEN;

/// AES-256-GCM-SIV encrypt / decrypt tool.
///
/// Requires a 32-byte `key.key` file in the current working directory.
/// Input and output must be simple filenames (no directories).
#[derive(Parser, Debug)]
#[command(
    name = "aes",
    version,
    about = "Bulletproof AES-256-GCM-SIV file encryption/decryption (in-memory, no overwrite)",
    long_about = None
)]
struct Args {
    /// Operation: E = encrypt, D = decrypt (must be capital)
    mode: String,

    /// Input filename (must be a plain name in the current directory)
    input: String,

    /// Output filename (must be a plain name in the current directory; must not already exist)
    output: String,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Print the full error chain for maximum debuggability
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let args = Args::parse();

    // Strict mode check – only capital E or D accepted
    let encrypt = match args.mode.as_str() {
        "E" => true,
        "D" => false,
        other => bail!(
            "mode must be exactly 'E' (encrypt) or 'D' (decrypt), got '{other}'"
        ),
    };

    // Enforce plain filenames only (no path components). This guarantees
    // that input, output and key.key all live in the same directory and
    // keeps the tool's behaviour identical on every platform.
    ensure_plain_filename(&args.input, "input")?;
    ensure_plain_filename(&args.output, "output")?;

    let input_path = Path::new(&args.input);
    let output_path = Path::new(&args.output);
    let key_path = Path::new(KEY_FILE);

    // Basic existence checks
    if !input_path.is_file() {
        bail!("input file '{}' does not exist or is not a regular file", args.input);
    }
    if output_path.exists() {
        bail!(
            "output file '{}' already exists – refusing to overwrite (data-safety policy)",
            args.output
        );
    }
    if !key_path.is_file() {
        bail!(
            "key file '{}' not found in the current directory (must be exactly 32 bytes)",
            KEY_FILE
        );
    }

    // Load key (exactly 32 bytes) and zeroize the buffer when dropped
    let mut key_bytes = fs::read(key_path)
        .with_context(|| format!("failed to read key file '{}'", KEY_FILE))?;
    if key_bytes.len() != KEY_LEN {
        key_bytes.zeroize();
        bail!(
            "key file '{}' must be exactly {} bytes long (got {})",
            KEY_FILE,
            KEY_LEN,
            key_bytes.len()
        );
    }

    // Load the entire input into memory
    let plaintext_or_ciphertext = fs::read(input_path)
        .with_context(|| format!("failed to read input file '{}'", args.input))?;

    // Build the cipher
    // Aes256GcmSiv::new takes &GenericArray<u8, U32>; length already verified.
    let key = GenericArray::from_slice(&key_bytes);
    let cipher = Aes256GcmSiv::new(key);

    // Perform the cryptographic operation
    let result_bytes = if encrypt {
        encrypt_file(&cipher, &plaintext_or_ciphertext)?
    } else {
        decrypt_file(&cipher, &plaintext_or_ciphertext)?
    };

    // Zeroize key material as soon as we no longer need it
    key_bytes.zeroize();

    // Atomic write: write to a temporary file in the same directory,
    // then rename. This prevents leaving a partially-written output
    // if the process is killed or the disk fills up.
    let tmp_name = format!("{}.tmp", args.output);
    let tmp_path = Path::new(&tmp_name);

    // Extra safety: if a previous crash left a .tmp behind, refuse
    if tmp_path.exists() {
        bail!(
            "temporary file '{}' already exists – remove it manually and retry",
            tmp_name
        );
    }

    fs::write(tmp_path, &result_bytes)
        .with_context(|| format!("failed to write temporary file '{}'", tmp_name))?;

    // Rename is atomic on the same filesystem (which it is, by construction)
    fs::rename(tmp_path, output_path).with_context(|| {
        // Best-effort cleanup of the temp file on rename failure
        let _ = fs::remove_file(tmp_path);
        format!(
            "failed to rename temporary file '{}' to '{}'",
            tmp_name, args.output
        )
    })?;

    Ok(())
}

/// Encrypt: generate a fresh random nonce, encrypt, prepend nonce.
fn encrypt_file(cipher: &Aes256GcmSiv, plaintext: &[u8]) -> Result<Vec<u8>> {
    // Generate a cryptographically secure random 12-byte nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    // Output layout: nonce || ciphertext (ciphertext already contains the 16-byte tag)
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt: extract nonce, verify tag, recover plaintext.
fn decrypt_file(cipher: &Aes256GcmSiv, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < MIN_CIPHERTEXT_LEN {
        bail!(
            "ciphertext too short (need at least {} bytes, got {})",
            MIN_CIPHERTEXT_LEN,
            data.len()
        );
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed – wrong key, corrupted data, or tampered ciphertext"))
}

/// Reject any path that is not a single plain filename component.
fn ensure_plain_filename(name: &str, label: &str) -> Result<()> {
    if name.is_empty() {
        bail!("{label} filename must not be empty");
    }
    let path = Path::new(name);
    let mut components = path.components();
    match components.next() {
        Some(Component::Normal(_)) if components.next().is_none() => Ok(()),
        _ => bail!(
            "{label} must be a plain filename with no directory components \
             (got '{name}'). All files must live in the current working directory."
        ),
    }
}
