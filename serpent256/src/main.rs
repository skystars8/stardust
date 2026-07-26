//! serpent256 — whole-file Serpent-256 + HMAC-SHA-256 (Encrypt-then-MAC)
//!
//! Usage:
//!   serpent256 <file>          encrypt → <file>.ser
//!   serpent256 <file>.ser      decrypt
//!
//! Requires ser.key (exactly 32 bytes) in the same directory as the executable.
//! Files being processed must also live next to the executable.

use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use cipher::BlockCipherEncrypt;
use cipher::KeyInit;
use console::style;
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use rand::RngCore;
use serpent::Serpent;
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const MAGIC: &[u8; 4] = b"S256";
const VERSION: u8 = 1;
const NONCE_LEN: usize = 16;
const MAC_LEN: usize = 32;
const KEY_LEN: usize = 32;
const BLOCK_SIZE: usize = 16;
const HEADER_LEN: usize = 4 + 1 + NONCE_LEN;

struct Secrets {
    key: [u8; KEY_LEN],
}

impl Drop for Secrets {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn executable_dir() -> Result<PathBuf> {
    let exe = env::current_exe().context("failed to locate current executable")?;
    let dir = exe
        .parent()
        .context("executable has no parent directory")?
        .to_path_buf();
    Ok(dir)
}

fn load_key(dir: &Path) -> Result<Secrets> {
    let key_path = dir.join("ser.key");
    let data = fs::read(&key_path)
        .with_context(|| format!("failed to read key file {}", key_path.display()))?;
    if data.len() != KEY_LEN {
        bail!(
            "ser.key must be exactly {} bytes (got {})\n\
             Generate with:  openssl rand -out ser.key 32",
            KEY_LEN,
            data.len()
        );
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&data);
    let mut data = data;
    data.zeroize();
    Ok(Secrets { key })
}

fn compute_mac(key: &[u8], data: &[u8]) -> [u8; MAC_LEN] {
    let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(key).expect("HMAC key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&result);
    out
}

fn verify_mac(key: &[u8], data: &[u8], expected: &[u8]) -> bool {
    let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(key).expect("HMAC key length");
    mac.update(data);
    mac.verify_slice(expected).is_ok()
}

fn apply_ctr(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], data: &mut [u8]) {
    // serpent 0.6 accepts 16..=32 byte keys via new_from_slice and expands them
    let cipher = Serpent::new_from_slice(key).expect("valid Serpent-256 key");
    let mut counter = [0u8; BLOCK_SIZE];
    for i in 0..NONCE_LEN {
        counter[i] ^= nonce[i];
    }

    let mut offset = 0;
    while offset < data.len() {
        let mut block = counter;
        cipher.encrypt_block((&mut block).into());
        let take = std::cmp::min(BLOCK_SIZE, data.len() - offset);
        for i in 0..take {
            data[offset + i] ^= block[i];
        }
        offset += take;

        for i in (0..BLOCK_SIZE).rev() {
            let (sum, carry) = counter[i].overflowing_add(1);
            counter[i] = sum;
            if !carry {
                break;
            }
        }
    }
}

fn encrypt_file(dir: &Path, filename: &str, secrets: &Secrets) -> Result<()> {
    let path = dir.join(filename);
    let mut plaintext =
        fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;

    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&nonce);

    apply_ctr(&secrets.key, &nonce, &mut plaintext);
    let ciphertext = plaintext;

    let mut to_mac = header.clone();
    to_mac.extend_from_slice(&ciphertext);
    let tag = compute_mac(&secrets.key, &to_mac);

    let out_path = dir.join(format!("{}.ser", filename));
    let tmp = out_path.with_extension("ser.tmp");
    {
        let mut f = File::create(&tmp)
            .with_context(|| format!("cannot create temporary file {}", tmp.display()))?;
        f.write_all(&header)?;
        f.write_all(&ciphertext)?;
        f.write_all(&tag)?;
        f.sync_all()
            .context("failed to fsync temporary output")?;
    }
    fs::rename(&tmp, &out_path).with_context(|| {
        format!(
            "failed to atomically replace {} with temporary file",
            out_path.display()
        )
    })?;

    println!(
        "{} encrypted -> {}",
        style("✓").green().bold(),
        out_path.display()
    );
    Ok(())
}

fn decrypt_file(dir: &Path, filename: &str, secrets: &Secrets) -> Result<()> {
    let path = dir.join(filename);
    let data = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;

    if data.len() < HEADER_LEN + MAC_LEN {
        bail!("file too short / truncated");
    }

    let (header, rest) = data.split_at(HEADER_LEN);
    let (ciphertext, tag) = rest.split_at(rest.len() - MAC_LEN);

    if &header[0..4] != MAGIC {
        bail!("not a Serpent-256 encrypted file (bad magic)");
    }
    if header[4] != VERSION {
        bail!(
            "unsupported version {} (this tool requires version {})",
            header[4],
            VERSION
        );
    }

    let nonce: [u8; NONCE_LEN] = header[5..HEADER_LEN]
        .try_into()
        .expect("nonce length checked by HEADER_LEN");

    let mut to_mac = header.to_vec();
    to_mac.extend_from_slice(ciphertext);
    if !verify_mac(&secrets.key, &to_mac, tag) {
        bail!("authentication failed – wrong key or corrupted file");
    }

    let mut plaintext = ciphertext.to_vec();
    apply_ctr(&secrets.key, &nonce, &mut plaintext);

    let out_name = filename.strip_suffix(".ser").unwrap_or(filename);
    let out_path = dir.join(out_name);
    let tmp = out_path.with_extension("dec.tmp");
    {
        let mut f = File::create(&tmp)
            .with_context(|| format!("cannot create temporary file {}", tmp.display()))?;
        f.write_all(&plaintext)?;
        f.sync_all()
            .context("failed to fsync temporary output")?;
    }
    fs::rename(&tmp, &out_path).with_context(|| {
        format!(
            "failed to atomically replace {} with temporary file",
            out_path.display()
        )
    })?;

    plaintext.zeroize();
    println!(
        "{} decrypted -> {}",
        style("✓").green().bold(),
        out_path.display()
    );
    Ok(())
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: serpent256 <file>");
        eprintln!("  Encrypts any file → <file>.ser");
        eprintln!("  Decrypts only *.ser files");
        eprintln!();
        eprintln!("Requires ser.key (exactly 32 bytes) in the same directory as the executable.");
        eprintln!("Generate with:  openssl rand -out ser.key 32");
        std::process::exit(1);
    }

    let filename = &args[1];
    let dir = executable_dir()?;
    let path = dir.join(filename);
    if !path.exists() {
        bail!("file not found: {}", path.display());
    }

    let secrets = load_key(&dir)?;
    let is_encrypted = filename.ends_with(".ser");

    if is_encrypted {
        decrypt_file(&dir, filename, &secrets)
    } else {
        encrypt_file(&dir, filename, &secrets)
    }
}

fn main() -> ExitCode {
    if let Err(e) = run() {
        eprintln!("{} {:#}", style("error:").red().bold(), e);
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
