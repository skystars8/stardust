#![forbid(unsafe_code)]

// Linux-only - will not compile anywhere else
#[cfg(not(target_os = "linux"))]
compile_error!("This cipher tool is designed exclusively for Linux.");

use anyhow::{Context, Result};
use argon2::{Argon2, Params};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Key, Nonce};
use clap::{Parser, Subcommand};
use rand::RngCore;
use std::fs;
use std::io::Write;
use std::path::Path;

const MAGIC: &[u8] = b"CIPHER02";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[derive(Parser)]
#[command(author, version, about = "Modern secure file encryption CLI for Linux (atomic in-place)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file (creates .cph then deletes original atomically)
    Encrypt(EncryptArgs),
    /// Decrypt a file (restores original then deletes .cph atomically)
    Decrypt(DecryptArgs),
    /// Launch interactive mode
    Interactive,
}

#[derive(Parser)]
struct EncryptArgs {
    input: String,
    #[arg(short, long)]
    output: Option<String>,
}

#[derive(Parser)]
struct DecryptArgs {
    input: String,
    #[arg(short, long)]
    output: Option<String>,
}

// Atomic write helper (temp file + rename = safe on Linux)
fn atomic_write(target: &str, data: &[u8]) -> Result<()> {
    let target_path = Path::new(target);
    let dir = target_path.parent().unwrap_or_else(|| Path::new("."));
    let name = target_path.file_name().and_then(|s| s.to_str()).unwrap_or("file");
    let temp_path = dir.join(format!(".{}.{}.tmp", name, rand::thread_rng().next_u64()));

    fs::write(&temp_path, data)
        .with_context(|| format!("Failed to write temporary file for {}", target))?;

    fs::rename(&temp_path, target_path)
        .with_context(|| format!("Failed to atomically replace {}", target))?;

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt(args) => encrypt_file(args),
        Commands::Decrypt(args) => decrypt_file(args),
        Commands::Interactive => interactive_mode(),
    }
}

fn get_password(confirm: bool) -> Result<String> {
    let pw = rpassword::prompt_password("Enter password: ")?;
    if confirm {
        let confirm_pw = rpassword::prompt_password("Confirm password: ")?;
        if pw != confirm_pw {
            anyhow::bail!("Passwords do not match!");
        }
    }
    Ok(pw)
}

fn encrypt_file(args: EncryptArgs) -> Result<()> {
    let password = get_password(true)?;
    let data = fs::read(&args.input)
        .with_context(|| format!("Failed to read {}", args.input))?;

    let (ciphertext, salt, nonce) = encrypt_data(&password, &data)?;

    let mut file = Vec::new();
    file.extend_from_slice(MAGIC);
    file.extend_from_slice(&salt);
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&ciphertext);

    let output = args.output.unwrap_or_else(|| {
        let mut p = std::path::PathBuf::from(&args.input);
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("file");
        p.set_file_name(format!("{}.cph", name));
        p.to_string_lossy().into_owned()
    });

    atomic_write(&output, &file)?;

    // Remove original after successful atomic write
    fs::remove_file(&args.input)
        .with_context(|| format!("Failed to remove original {}", args.input))?;

    println!("✅ Encrypted: {} → {} (original removed)", args.input, output);
    Ok(())
}

fn decrypt_file(args: DecryptArgs) -> Result<()> {
    let password = get_password(false)?;
    let data = fs::read(&args.input)
        .with_context(|| format!("Failed to read {}", args.input))?;

    if data.len() < MAGIC.len() + SALT_LEN + NONCE_LEN {
        anyhow::bail!("File too small or not a valid .cph file");
    }
    if &data[0..MAGIC.len()] != MAGIC {
        anyhow::bail!("Not a valid CIPHER file (wrong magic)");
    }

    let salt = &data[MAGIC.len()..MAGIC.len() + SALT_LEN];
    let nonce = &data[MAGIC.len() + SALT_LEN..MAGIC.len() + SALT_LEN + NONCE_LEN];
    let ciphertext = &data[MAGIC.len() + SALT_LEN + NONCE_LEN..];

    let plaintext = decrypt_data(&password, salt, nonce, ciphertext)?;

    let output = args.output.unwrap_or_else(|| {
        let mut p = std::path::PathBuf::from(&args.input);
        if p.extension().and_then(|e| e.to_str()) == Some("cph") {
            p.set_extension("");
        } else {
            p.set_extension("dec");
        }
        p.to_string_lossy().into_owned()
    });

    atomic_write(&output, &plaintext)?;

    // Remove encrypted file after successful atomic write
    fs::remove_file(&args.input)
        .with_context(|| format!("Failed to remove encrypted file {}", args.input))?;

    println!("✅ Decrypted: {} → {} (encrypted file removed)", args.input, output);
    Ok(())
}

fn encrypt_data(password: &str, data: &[u8]) -> Result<(Vec<u8>, [u8; SALT_LEN], [u8; NONCE_LEN])> {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = derive_key(password, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    Ok((ciphertext, salt, nonce_bytes))
}

fn decrypt_data(password: &str, salt: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let key = derive_key(password, salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed — wrong password or corrupted file"))?;

    Ok(plaintext)
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(64 * 1024, 3, 4, Some(32))
        .map_err(|e| anyhow::anyhow!("Argon2 params error: {}", e))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;

    Ok(key)
}

fn interactive_mode() -> Result<()> {
    println!("🔐 Cipher Interactive Mode (Linux - Atomic In-Place)\n");
    loop {
        println!("1. Encrypt a file");
        println!("2. Decrypt a file");
        println!("3. Exit");
        print!("> ");
        std::io::stdout().flush()?;

        let mut choice = String::new();
        std::io::stdin().read_line(&mut choice)?;

        match choice.trim() {
            "1" => {
                print!("Input file path: ");
                std::io::stdout().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                let args = EncryptArgs { input: input.trim().to_string(), output: None };
                let _ = encrypt_file(args);
            }
            "2" => {
                print!("Encrypted (.cph) file path: ");
                std::io::stdout().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                let args = DecryptArgs { input: input.trim().to_string(), output: None };
                let _ = decrypt_file(args);
            }
            "3" => break,
            _ => println!("Invalid option, try again."),
        }
    }
    Ok(())
}