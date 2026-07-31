#![forbid(unsafe_code)]

// ============================================================
// Secure File Encryption Tool (AES-256-GCM-SIV)
// ============================================================
//
// DESIGN NOTES:
// - Linux/Unix only
// - Requires a raw 32-byte key in "key.key" next to executable
// - No password/KDF by design
//
// FILE FORMAT:
// [ MAGIC (9) | VERSION (1) | FLAGS (1) | NONCE (8) | SIZE (8) | CHUNKS (4) ]
// followed by repeated:
// [ ciphertext chunk | 16-byte authentication tag ]
//
// SECURITY:
// - Header is authenticated via AEAD (AAD)
// - Nonce = base_nonce (random per file) || counter (u32)
// - Max size ≈ 2^32 chunks (~32 TB with 8MB chunks)
//
// ============================================================

use aes_gcm_siv::{
    aead::{AeadInPlace, KeyInit},
    Aes256GcmSiv, Nonce,
};
use anyhow::{anyhow, Context, Result};
use rand::{rngs::OsRng, RngCore};
use std::{
    env,
    fs::{self, File},
    io::{BufReader, Read, Write},
    path::Path,
};
use zeroize::Zeroize;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const MAGIC: [u8; 9] = *b"SIVCRYPT1";
const VERSION: u8 = 1;
const FLAGS: u8 = 0;

const BASE_NONCE_LEN: usize = 8;
const NONCE_LEN: usize = 12;
const TAG_SIZE: usize = 16;
const CHUNK_SIZE: usize = 8 * 1024 * 1024;

// Header layout
const OFFSET_MAGIC: usize = 0;
const OFFSET_VERSION: usize = OFFSET_MAGIC + 9;
const OFFSET_FLAGS: usize = OFFSET_VERSION + 1;
const OFFSET_NONCE: usize = OFFSET_FLAGS + 1;
const OFFSET_FILE_SIZE: usize = OFFSET_NONCE + BASE_NONCE_LEN;
const OFFSET_CHUNK_COUNT: usize = OFFSET_FILE_SIZE + 8;
const HEADER_LEN: usize = OFFSET_CHUNK_COUNT + 4;

const AAD_LEN: usize = HEADER_LEN + 4 + 4;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 || args.len() > 4 {
        eprintln!("Usage:\n  {} E <input> <output>\n  {} D <input> <output>\n  {} V <input>", args[0], args[0], args[0]);
        std::process::exit(1);
    }

    let mut key = load_key()?;

    let result = match args[1].as_str() {
        "E" => encrypt_file(&args[2], &args[3], &key),
        "D" => decrypt_file(&args[2], &args[3], &key),
        "V" => verify_file(&args[2], &key),
        _ => Err(anyhow!("Invalid mode (must be E, D, or V)")),
    };

    key.zeroize();
    result
}

fn load_key() -> Result<[u8; 32]> {
    let exe = env::current_exe().context("cannot locate executable")?;
    let key_path = exe.parent().unwrap_or_else(|| Path::new(".")).join("key.key");

    #[cfg(unix)]
    {
        let meta = fs::metadata(&key_path).context("key.key not found")?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            anyhow::bail!("key.key must be exactly 0600, found {:o}", mode);
        }
    }

    let data = fs::read(&key_path)?;
    if data.len() != 32 {
        anyhow::bail!("key.key must be exactly 32 bytes");
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&data);
    Ok(key)
}

fn make_nonce(base: &[u8; BASE_NONCE_LEN], counter: u32) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..BASE_NONCE_LEN].copy_from_slice(base);
    nonce[BASE_NONCE_LEN..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn make_aad(header: &[u8; HEADER_LEN], counter: u32, chunk_len: u32) -> [u8; AAD_LEN] {
    let mut aad = [0u8; AAD_LEN];
    aad[..HEADER_LEN].copy_from_slice(header);
    aad[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&counter.to_be_bytes());
    aad[HEADER_LEN + 4..].copy_from_slice(&chunk_len.to_be_bytes());
    aad
}

fn encrypt_file(input_path: &str, output_path: &str, key: &[u8; 32]) -> Result<()> {
    let input = File::open(input_path).context("failed to open input file")?;
    let file_size = input.metadata()?.len();

    let mut base_nonce = [0u8; BASE_NONCE_LEN];
    OsRng.fill_bytes(&mut base_nonce);

    let chunk_count = ((file_size + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64) as u32;

    let cipher = Aes256GcmSiv::new_from_slice(key)
        .map_err(|_| anyhow!("invalid key material"))?;

    let mut header = [0u8; HEADER_LEN];

    header[OFFSET_MAGIC..OFFSET_MAGIC + MAGIC.len()].copy_from_slice(&MAGIC);
    header[OFFSET_VERSION] = VERSION;
    header[OFFSET_FLAGS] = FLAGS;
    header[OFFSET_NONCE..OFFSET_NONCE + BASE_NONCE_LEN].copy_from_slice(&base_nonce);
    header[OFFSET_FILE_SIZE..OFFSET_FILE_SIZE + 8].copy_from_slice(&file_size.to_le_bytes());
    header[OFFSET_CHUNK_COUNT..].copy_from_slice(&chunk_count.to_le_bytes());

    let tmp_path = format!("{}.tmp", output_path);
    let mut output = File::create(&tmp_path)?;

    #[cfg(unix)]
    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;

    output.write_all(&header)?;

    let mut reader = BufReader::new(input);
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut counter = 0u32;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }

        let nonce_bytes = make_nonce(&base_nonce, counter);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = make_aad(&header, counter, n as u32);

        let tag = cipher
            .encrypt_in_place_detached(nonce, &aad, &mut buf[..n])
            .map_err(|_| anyhow!("encryption failure (unexpected)"))?;

        output.write_all(&buf[..n])?;
        output.write_all(tag.as_slice())?;

        counter = counter.checked_add(1).ok_or_else(|| anyhow!("chunk counter overflow"))?;
    }

    if counter != chunk_count {
        anyhow::bail!("internal error: chunk count mismatch");
    }

    output.sync_all()?;
    fs::rename(tmp_path, output_path)?;

    println!("✅ Encrypted → {}", output_path);
    Ok(())
}

fn decrypt_file(input_path: &str, output_path: &str, key: &[u8; 32]) -> Result<()> {
    process_file(input_path, Some(output_path), key)
}

fn verify_file(input_path: &str, key: &[u8; 32]) -> Result<()> {
    process_file(input_path, None, key)
}

fn process_file(input_path: &str, output_path: Option<&str>, key: &[u8; 32]) -> Result<()> {
    let mut input = File::open(input_path).context("failed to open input file")?;

    let cipher = Aes256GcmSiv::new_from_slice(key)
        .map_err(|_| anyhow!("invalid key material"))?;

    let mut header = [0u8; HEADER_LEN];
    input.read_exact(&mut header)?;

    if &header[OFFSET_MAGIC..OFFSET_MAGIC + MAGIC.len()] != MAGIC {
        anyhow::bail!("invalid file format (bad magic)");
    }

    if header[OFFSET_VERSION] != VERSION {
        anyhow::bail!("unsupported file version");
    }

    let base_nonce: [u8; BASE_NONCE_LEN] = header[OFFSET_NONCE..OFFSET_NONCE + BASE_NONCE_LEN]
        .try_into()
        .map_err(|_| anyhow!("header parsing error (nonce)"))?;

    let original_size = u64::from_le_bytes(
        header[OFFSET_FILE_SIZE..OFFSET_FILE_SIZE + 8]
            .try_into()
            .map_err(|_| anyhow!("header parsing error (size)"))?,
    );

    let chunk_count = u32::from_le_bytes(
        header[OFFSET_CHUNK_COUNT..]
            .try_into()
            .map_err(|_| anyhow!("header parsing error (chunks)"))?,
    );

    let mut output = if let Some(path) = output_path {
        let tmp = format!("{}.tmp", path);
        let file = File::create(&tmp)?;

        #[cfg(unix)]
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;

        Some((tmp, file))
    } else {
        None
    };

    let mut reader = BufReader::new(input);
    let mut buf = vec![0u8; CHUNK_SIZE + TAG_SIZE];

    let mut counter = 0u32;
    let mut written = 0u64;

    while written < original_size {
        if counter >= chunk_count {
            cleanup(&mut output);
            anyhow::bail!("file corrupted: too many chunks");
        }

        let remaining = original_size - written;
        let chunk_len = std::cmp::min(remaining as usize, CHUNK_SIZE);
        let to_read = chunk_len + TAG_SIZE;

        reader
            .read_exact(&mut buf[..to_read])
            .map_err(|_| {
                cleanup(&mut output);
                anyhow!("file truncated or corrupted")
            })?;

        let data = &mut buf[..to_read];
        let (ct, tag_bytes) = data.split_at_mut(chunk_len);
        let tag = aes_gcm_siv::Tag::from_slice(tag_bytes);

        let nonce_bytes = make_nonce(&base_nonce, counter);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = make_aad(&header, counter, chunk_len as u32);

        if cipher
            .decrypt_in_place_detached(nonce, &aad, ct, tag)
            .is_err()
        {
            cleanup(&mut output);
            anyhow::bail!("authentication failed: wrong key or corrupted file");
        }

        if let Some((_, ref mut file)) = output {
            file.write_all(ct)?;
        }

        written += chunk_len as u64;
        counter = counter.checked_add(1).ok_or_else(|| anyhow!("chunk counter overflow"))?;
    }

    if counter != chunk_count {
        cleanup(&mut output);
        anyhow::bail!("file corrupted: missing chunks");
    }

    let mut probe = [0u8; 1];
    if reader.read(&mut probe)? != 0 {
        cleanup(&mut output);
        anyhow::bail!("file corrupted: trailing data detected");
    }

    if let Some((tmp, file)) = output {
        file.sync_all()?;
        fs::rename(tmp, output_path.unwrap())?;
        println!("✅ Decrypted → {}", output_path.unwrap());
    } else {
        println!("✅ File verified (OK)");
    }

    Ok(())
}

fn cleanup(output: &mut Option<(String, File)>) {
    if let Some((path, _)) = output {
        let _ = fs::remove_file(path);
    }
}
