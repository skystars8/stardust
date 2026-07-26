use anyhow::{bail, Context, Result};
use cipher::generic_array::GenericArray;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha512;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use threefish::cipher::BlockEncrypt;
use threefish::Threefish1024;
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

const MAGIC: &[u8; 4] = b"T3F1";
const VERSION: u8 = 2;
const NONCE_LEN: usize = 16; // used as Threefish tweak
const MAC_LEN: usize = 64;
const KEY_LEN: usize = 128; // Threefish-1024 key size
const MAC_KEY_LEN: usize = 64;
const KEY_FILE_LEN: usize = KEY_LEN + MAC_KEY_LEN; // 192
const BLOCK_SIZE: usize = 128; // Threefish-1024 block size
const HEADER_LEN: usize = 4 + 1 + NONCE_LEN; // magic + version + nonce

struct Secrets {
    key: [u8; KEY_LEN],
    mac_key: [u8; MAC_KEY_LEN],
}

impl Drop for Secrets {
    fn drop(&mut self) {
        self.key.zeroize();
        self.mac_key.zeroize();
    }
}

/// Load the fixed-size binary key file from the same directory as the target file.
/// Exactly 192 bytes required: first 128 = Threefish key, next 64 = HMAC key.
fn load_key(dir: &Path) -> Result<Secrets> {
    let key_path = dir.join("key.key");
    let data = fs::read(&key_path)
        .with_context(|| format!("cannot read key file {}", key_path.display()))?;

    if data.len() != KEY_FILE_LEN {
        bail!(
            "key.key must be exactly {} bytes of raw binary data (got {} bytes)",
            KEY_FILE_LEN,
            data.len()
        );
    }

    let mut key = [0u8; KEY_LEN];
    let mut mac_key = [0u8; MAC_KEY_LEN];
    key.copy_from_slice(&data[..KEY_LEN]);
    mac_key.copy_from_slice(&data[KEY_LEN..]);

    // Best-effort wipe of the temporary buffer that held the key material
    let mut data = data;
    data.zeroize();

    Ok(Secrets { key, mac_key })
}

fn compute_mac(mac_key: &[u8], data: &[u8]) -> [u8; MAC_LEN] {
    let mut mac = HmacSha512::new_from_slice(mac_key).expect("HMAC key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&result);
    out
}

fn verify_mac(mac_key: &[u8], data: &[u8], expected: &[u8]) -> bool {
    let mut mac = HmacSha512::new_from_slice(mac_key).expect("HMAC key length");
    mac.update(data);
    mac.verify_slice(expected).is_ok()
}

/// Correct CTR mode for Threefish-1024.
/// - 128-byte big-endian counter starting at 0
/// - 16-byte nonce used as the Threefish tweak (unique per file)
fn apply_ctr(key: &[u8; KEY_LEN], tweak: &[u8; NONCE_LEN], data: &mut [u8]) {
    let cipher = Threefish1024::new_with_tweak(key, tweak);

    let mut counter = [0u8; BLOCK_SIZE];
    let mut offset = 0;

    while offset < data.len() {
        // Turn the counter into the type required by BlockEncrypt
        let mut block = GenericArray::clone_from_slice(&counter);
        cipher.encrypt_block(&mut block);

        let take = std::cmp::min(BLOCK_SIZE, data.len() - offset);
        for i in 0..take {
            data[offset + i] ^= block[i];
        }
        offset += take;

        // Increment the 128-byte counter (big-endian)
        for i in (0..BLOCK_SIZE).rev() {
            let (sum, carry) = counter[i].overflowing_add(1);
            counter[i] = sum;
            if !carry {
                break;
            }
        }
    }
}

fn encrypt_file(path: &Path, secrets: &Secrets) -> Result<()> {
    let mut plaintext = fs::read(path).with_context(|| format!("read {}", path.display()))?;

    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

    // Header: magic + version + nonce
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&nonce);

    // Encrypt in place (CTR is symmetric)
    apply_ctr(&secrets.key, &nonce, &mut plaintext);
    let ciphertext = plaintext;

    // Authenticate header + ciphertext (Encrypt-then-MAC)
    let mut to_mac = header.clone();
    to_mac.extend_from_slice(&ciphertext);
    let tag = compute_mac(&secrets.mac_key, &to_mac);

    // Atomic write → <original>.enc
    let out_path = PathBuf::from(format!("{}.enc", path.display()));
    let tmp = out_path.with_extension("enc.tmp");

    {
        let mut f = File::create(&tmp).context("create temp file")?;
        f.write_all(&header)?;
        f.write_all(&ciphertext)?;
        f.write_all(&tag)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &out_path).context("atomic rename")?;

    println!("Encrypted → {}", out_path.display());
    Ok(())
}

fn decrypt_file(path: &Path, secrets: &Secrets) -> Result<()> {
    if path.extension().and_then(|e| e.to_str()) != Some("enc") {
        bail!("Only .enc files can be decrypted");
    }

    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if data.len() < HEADER_LEN + MAC_LEN {
        bail!("File too short / truncated");
    }

    let (header, rest) = data.split_at(HEADER_LEN);
    let (ciphertext, tag) = rest.split_at(rest.len() - MAC_LEN);

    if &header[0..4] != MAGIC {
        bail!("Not a Threefish-1024 encrypted file (bad magic)");
    }
    if header[4] != VERSION {
        bail!("Unsupported version {} (this tool requires version {})", header[4], VERSION);
    }

    let nonce: [u8; NONCE_LEN] = header[5..HEADER_LEN]
        .try_into()
        .expect("nonce length checked");

    // Verify MAC *before* any decryption – critical for reliability
    let mut to_mac = header.to_vec();
    to_mac.extend_from_slice(ciphertext);
    if !verify_mac(&secrets.mac_key, &to_mac, tag) {
        bail!("Authentication failed – wrong key or corrupted file");
    }

    // Decrypt
    let mut plaintext = ciphertext.to_vec();
    apply_ctr(&secrets.key, &nonce, &mut plaintext);

    // Strip the .enc extension
    let out_path = path.with_extension("");
    let tmp = out_path.with_extension("dec.tmp");

    {
        let mut f = File::create(&tmp).context("create temp file")?;
        f.write_all(&plaintext)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &out_path).context("atomic rename")?;

    println!("Decrypted → {}", out_path.display());
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <file>", args[0]);
        eprintln!("  Encrypts any file  → <file>.enc");
        eprintln!("  Decrypts only *.enc files");
        eprintln!();
        eprintln!("Requires a binary key file named key.key in the same directory as <file>.");
        eprintln!("key.key must be exactly 192 bytes:");
        eprintln!("  bytes 0..128  → Threefish-1024 key");
        eprintln!("  bytes 128..192 → HMAC-SHA-512 key");
        std::process::exit(1);
    }

    let path = Path::new(&args[1]);
    if !path.exists() {
        bail!("File does not exist: {}", path.display());
    }

    // key.key must live in the same directory as the target file
    let key_dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let secrets = load_key(key_dir)?;

    let is_enc = path.extension().and_then(|e| e.to_str()) == Some("enc");

    let result = if is_enc {
        decrypt_file(path, &secrets)
    } else {
        encrypt_file(path, &secrets)
    };

    // Secrets are zeroized on drop
    result
}
