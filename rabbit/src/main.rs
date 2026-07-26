use anyhow::{bail, Context, Result};
use clap::Parser;
use rabbit::cipher::{KeyIvInit, StreamCipher};
use rabbit::Rabbit;
use rand::RngCore;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"RABBITv2";
const HEADER_SIZE: usize = 32; // magic(8) + salt(16) + iv(8)
const MAC_SIZE: usize = 32;
const KEY_MATERIAL_LEN: usize = 48; // 16 bytes Rabbit key + 32 bytes BLAKE3 key
const BUFFER_SIZE: usize = 128 * 1024;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Rabbit stream cipher — secure, password-based, authenticated, atomic in-place encryption",
    long_about = "Encrypts or decrypts a file in place using the Rabbit stream cipher.\n\
                  Automatically detects mode from the file header.\n\
                  Uses Argon2id for key derivation and BLAKE3 for authentication.\n\
                  Atomic replacement via temporary file (same filesystem required)."
)]
struct Cli {
    /// File to encrypt or decrypt in place (mode is auto-detected)
    file: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if !cli.file.is_file() {
        bail!("Error: {} is not a regular file", cli.file.display());
    }

    // Peek at the start to decide encrypt or decrypt
    let is_encrypted = {
        let mut f = File::open(&cli.file).with_context(|| {
            format!("failed to open {}", cli.file.display())
        })?;
        let mut magic_buf = [0u8; 8];
        f.read_exact(&mut magic_buf).is_ok() && &magic_buf == MAGIC
    };

    if is_encrypted {
        println!("🔓 Decrypting {} in place (atomic)...", cli.file.display());
        decrypt_in_place(&cli.file)?;
        println!("✅ Decryption complete!");
    } else {
        println!("🔐 Encrypting {} in place (atomic)...", cli.file.display());
        encrypt_in_place(&cli.file)?;
        println!("✅ Encryption complete!");
    }

    Ok(())
}

fn derive_keys(password: &[u8], salt: &[u8]) -> Result<([u8; 16], [u8; 32])> {
    let params = argon2::Params::new(65536, 3, 1, Some(KEY_MATERIAL_LEN))
        .map_err(|e| anyhow::anyhow!("Argon2 parameter error: {e}"))?;

    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );

    let mut key_material = [0u8; KEY_MATERIAL_LEN];
    argon2
        .hash_password_into(password, salt, &mut key_material)
        .map_err(|e| anyhow::anyhow!("Argon2 key derivation failed: {e}"))?;

    let enc_key: [u8; 16] = key_material[0..16]
        .try_into()
        .expect("slice length is fixed");
    let mac_key: [u8; 32] = key_material[16..48]
        .try_into()
        .expect("slice length is fixed");

    key_material.zeroize();
    Ok((enc_key, mac_key))
}

fn encrypt_in_place(path: &Path) -> Result<()> {
    let password = Zeroizing::new(rpassword::prompt_password("Enter password: ")?);
    let confirm = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);

    if *password != *confirm {
        bail!("Passwords do not match");
    }

    let mut rng = rand::thread_rng();
    let mut salt = [0u8; 16];
    let mut iv = [0u8; 8];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut iv);

    let (enc_key, mac_key) = derive_keys(password.as_bytes(), &salt)?;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create temporary file in {}", parent.display()))?;

    // Write header: magic + salt + iv
    let mut header = [0u8; HEADER_SIZE];
    header[0..8].copy_from_slice(MAGIC);
    header[8..24].copy_from_slice(&salt);
    header[24..32].copy_from_slice(&iv);
    temp.write_all(&header)
        .context("failed to write header")?;

    let mut cipher = Rabbit::new_from_slices(&enc_key, &iv)
        .map_err(|_| anyhow::anyhow!("invalid key/iv length for Rabbit"))?;

    let mut mac_hasher = blake3::Hasher::new_keyed(&mac_key);
    mac_hasher.update(&iv);

    let mut reader = File::open(path)
        .with_context(|| format!("failed to open {} for reading", path.display()))?;
    let mut buffer = vec![0u8; BUFFER_SIZE];

    loop {
        let n = reader.read(&mut buffer).context("failed to read input")?;
        if n == 0 {
            break;
        }
        let chunk = &mut buffer[..n];
        cipher.apply_keystream(chunk);
        mac_hasher.update(chunk);
        temp.write_all(chunk).context("failed to write ciphertext")?;
    }

    let mac = mac_hasher.finalize();
    temp.write_all(mac.as_bytes())
        .context("failed to write MAC")?;
    temp.flush().context("failed to flush temporary file")?;

    // Atomic replace (requires same filesystem)
    temp.persist(path)
        .map_err(|e| anyhow::anyhow!("atomic replace failed: {}", e.error))?;

    // Zeroize remaining sensitive material (password already Zeroizing)
    // enc_key / mac_key are Copy arrays; they drop at end of scope
    Ok(())
}

fn decrypt_in_place(path: &Path) -> Result<()> {
    let password = Zeroizing::new(rpassword::prompt_password("Enter password: ")?);

    let mut file = File::open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    let size = file
        .metadata()
        .with_context(|| format!("failed to get metadata for {}", path.display()))?
        .len();

    if size < (HEADER_SIZE + MAC_SIZE) as u64 {
        bail!("File is too small to be a valid encrypted file");
    }

    let ciphertext_len = size - (HEADER_SIZE + MAC_SIZE) as u64;

    // Read and validate header
    let mut header = [0u8; HEADER_SIZE];
    file.read_exact(&mut header)
        .context("failed to read header")?;
    if &header[0..8] != MAGIC {
        bail!("Invalid magic header — not a Rabbit-encrypted file");
    }
    let salt = &header[8..24];
    let iv = &header[24..32];

    let (enc_key, mac_key) = derive_keys(password.as_bytes(), salt)?;

    let mut cipher = Rabbit::new_from_slices(&enc_key, iv)
        .map_err(|_| anyhow::anyhow!("invalid key/iv length for Rabbit"))?;

    let mut mac_hasher = blake3::Hasher::new_keyed(&mac_key);
    mac_hasher.update(iv);

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create temporary file in {}", parent.display()))?;

    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut bytes_remaining = ciphertext_len as usize;

    while bytes_remaining > 0 {
        let to_read = std::cmp::min(buffer.len(), bytes_remaining);
        let n = file
            .read(&mut buffer[..to_read])
            .context("failed to read ciphertext")?;
        if n == 0 {
            bail!("Unexpected end of file while reading ciphertext");
        }
        let chunk = &mut buffer[..n];
        // MAC first (encrypt-then-MAC verification)
        mac_hasher.update(chunk);
        cipher.apply_keystream(chunk);
        temp.write_all(chunk).context("failed to write plaintext")?;
        bytes_remaining -= n;
    }

    // Read and verify MAC (constant-time via blake3::Hash PartialEq)
    let mut stored_mac = [0u8; MAC_SIZE];
    file.read_exact(&mut stored_mac)
        .context("failed to read MAC")?;

    let computed_mac = mac_hasher.finalize();
    if computed_mac != blake3::Hash::from(stored_mac) {
        // Explicitly close temp so it is deleted; original file remains untouched
        let _ = temp.close();
        bail!("❌ MAC verification failed! Wrong password or file has been tampered with.");
    }

    temp.flush().context("failed to flush temporary file")?;
    temp.persist(path)
        .map_err(|e| anyhow::anyhow!("atomic replace failed: {}", e.error))?;

    Ok(())
}
