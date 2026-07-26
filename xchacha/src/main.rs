//! XChaCha20-Poly1305 file encryption / decryption CLI.
//!
//! Usage:
//!   xchacha E <input> <output>   # encrypt
//!   xchacha D <input> <output>   # decrypt
//!
//! All three files (input, output, key.key) must be plain filenames
//! located in the current working directory. No path components allowed.
//! The tool refuses to overwrite an existing output file and processes
//! the entire payload in memory for maximum reliability.

use std::fs;
use std::path::{Component, Path};
use std::process::ExitCode;

use chacha20poly1305::{
    aead::{Aead, Generate, Key, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use anyhow::{bail, Context, Result};
use clap::Parser;
use zeroize::Zeroize;

const KEY_FILE: &str = "key.key";
const KEY_LEN: usize = 32; // XChaCha20-Poly1305 key
const NONCE_LEN: usize = 24; // XChaCha extended nonce (192-bit)
const TAG_LEN: usize = 16; // Poly1305 authentication tag (appended by the crate)
const MIN_CIPHERTEXT_LEN: usize = NONCE_LEN + TAG_LEN;

/// XChaCha20-Poly1305 encrypt / decrypt tool.
///
/// Requires a 32-byte `key.key` file in the current working directory.
/// Input and output must be simple filenames (no directories).
#[derive(Parser, Debug)]
#[command(
    name = "xchacha",
    version,
    about = "Bulletproof XChaCha20-Poly1305 file encryption/decryption (in-memory, no overwrite)",
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
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let args = Args::parse();

    let encrypt = match args.mode.as_str() {
        "E" => true,
        "D" => false,
        other => bail!(
            "mode must be exactly 'E' (encrypt) or 'D' (decrypt), got '{other}'"
        ),
    };

    ensure_plain_filename(&args.input, "input")?;
    ensure_plain_filename(&args.output, "output")?;

    let input_path = Path::new(&args.input);
    let output_path = Path::new(&args.output);
    let key_path = Path::new(KEY_FILE);

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

    let plaintext_or_ciphertext = fs::read(input_path)
        .with_context(|| format!("failed to read input file '{}'", args.input))?;

    // Construct the key using TryFrom (modern hybrid_array API)
    let key = Key::<XChaCha20Poly1305>::try_from(key_bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("internal error: key length already validated"))?;
    let cipher = XChaCha20Poly1305::new(&key);

    let result_bytes = if encrypt {
        encrypt_file(&cipher, &plaintext_or_ciphertext)?
    } else {
        decrypt_file(&cipher, &plaintext_or_ciphertext)?
    };

    key_bytes.zeroize();

    let tmp_name = format!("{}.tmp", args.output);
    let tmp_path = Path::new(&tmp_name);

    if tmp_path.exists() {
        bail!(
            "temporary file '{}' already exists – remove it manually and retry",
            tmp_name
        );
    }

    fs::write(tmp_path, &result_bytes)
        .with_context(|| format!("failed to write temporary file '{}'", tmp_name))?;

    fs::rename(tmp_path, output_path).with_context(|| {
        let _ = fs::remove_file(tmp_path);
        format!(
            "failed to rename temporary file '{}' to '{}'",
            tmp_name, args.output
        )
    })?;

    Ok(())
}

/// Encrypt: generate a fresh random 24-byte nonce, encrypt, prepend nonce.
fn encrypt_file(cipher: &XChaCha20Poly1305, plaintext: &[u8]) -> Result<Vec<u8>> {
    // XNonce::generate() uses the getrandom feature (enabled by default)
    let nonce = XNonce::generate();

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    // Output layout: nonce || ciphertext (ciphertext already contains the 16-byte tag)
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt: extract nonce, verify tag, recover plaintext.
fn decrypt_file(cipher: &XChaCha20Poly1305, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < MIN_CIPHERTEXT_LEN {
        bail!(
            "ciphertext too short (need at least {} bytes, got {})",
            MIN_CIPHERTEXT_LEN,
            data.len()
        );
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = XNonce::try_from(nonce_bytes)
        .map_err(|_| anyhow::anyhow!("internal error: nonce length already validated"))?;

    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| {
            anyhow::anyhow!(
                "decryption failed – wrong key, corrupted data, or tampered ciphertext"
            )
        })
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
