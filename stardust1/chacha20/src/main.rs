use anyhow::{anyhow, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use clap::{Parser, Subcommand};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
};

const DEFAULT_KEY_FILE: &str = "key.key";
const KEY_SIZE: usize = 32;    // 32 bytes for XChaCha20 key
const NONCE_SIZE: usize = 24;  // 24 bytes for XChaCha20 nonce

#[derive(Parser)]
#[command(
    name = "XChaCha20 File Encryptor",
    version = "0.1.0",
    author = "Your Name <youremail@example.com>",
    about = "Encrypt and decrypt files using XChaCha20-Poly1305",
    help_template = "\
{before-help}{name} - {about}

Usage: {usage}

{subcommands}{after-help}"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generates a new encryption key and saves it to a file
    GenKey {
        /// Path to save the generated key
        #[arg(short, long, default_value = DEFAULT_KEY_FILE)]
        key: String,
    },
    /// Encrypts a file
    Encrypt {
        /// The input file to encrypt
        input: String,
        /// The output encrypted file
        output: String,
        /// Path to the encryption key file
        #[arg(short, long, default_value = DEFAULT_KEY_FILE)]
        key: String,
    },
    /// Decrypts a file
    Decrypt {
        /// The input file to decrypt
        input: String,
        /// The output decrypted file
        output: String,
        /// Path to the encryption key file
        #[arg(short, long, default_value = DEFAULT_KEY_FILE)]
        key: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenKey { key } => generate_key(&key),
        Commands::Encrypt { input, output, key } => encrypt_file(&input, &output, &key),
        Commands::Decrypt { input, output, key } => decrypt_file(&input, &output, &key),
    }
}

fn generate_key(key_path: &str) -> Result<()> {
    if Path::new(key_path).exists() {
        // Prompt the user for confirmation to overwrite the existing key
        println!("Key file already exists at '{}'. Overwrite? (y/N): ", key_path);
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .with_context(|| "Failed to read user input.")?;
        if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
            println!("Key generation aborted.");
            return Ok(());
        }
    }

    let mut key = [0u8; KEY_SIZE];
    OsRng.fill_bytes(&mut key);   // Use OsRng for secure random number generation

    let mut key_file = File::create(key_path)
        .with_context(|| format!("Failed to create key file at '{}'.", key_path))?;
    key_file
        .write_all(&key)
        .with_context(|| "Failed to write key to file.")?;

    // Zeroize key after writing to the file
    key.zeroize();

    set_key_file_permissions(&key_file)?;

    println!(
        "Random key successfully generated and saved as '{}'.",
        key_path
    );
    Ok(())
}

fn set_key_file_permissions(file: &File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = file.metadata()?.permissions();
        perms.set_mode(0o600); // Owner read/write permissions
        file.set_permissions(perms)?;
    }
    #[cfg(windows)]
    {
        // On Windows, set the file to read-only
        let mut perms = file.metadata()?.permissions();
        perms.set_readonly(true);
        file.set_permissions(perms)?;
    }
    Ok(())
}

fn load_key(key_path: &str) -> Result<[u8; KEY_SIZE]> {
    if !Path::new(key_path).exists() {
        return Err(anyhow!(
            "Key file '{}' not found. Please generate the key first.",
            key_path
        ));
    }

    let mut key_data = [0u8; KEY_SIZE];
    let mut key_file = File::open(key_path)
        .with_context(|| format!("Failed to open key file at '{}'.", key_path))?;
    key_file
        .read_exact(&mut key_data)
        .with_context(|| format!("Failed to read key from '{}'.", key_path))?;

    Ok(key_data)
}

fn encrypt_file(input_path: &str, output_path: &str, key_path: &str) -> Result<()> {
    let key = load_key(key_path)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| anyhow!("Invalid key length."))?;

    let input_file = File::open(input_path)
        .with_context(|| format!("Failed to open input file '{}'.", input_path))?;
    let mut reader = BufReader::new(input_file);
    let mut data = Vec::new();
    reader
        .read_to_end(&mut data)
        .with_context(|| "Failed to read input file.")?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);   // Use OsRng for secure nonce generation
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data.as_ref())
        .map_err(|_| anyhow!("Encryption failed."))?;

    // Zeroize sensitive data
    data.zeroize();

    let output_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_path)
        .with_context(|| format!("Failed to create output file '{}'.", output_path))?;
    let mut writer = BufWriter::new(output_file);

    writer
        .write_all(&nonce_bytes)
        .with_context(|| "Failed to write nonce to output file.")?;
    writer
        .write_all(&ciphertext)
        .with_context(|| "Failed to write ciphertext to output file.")?;

    // Zeroize nonce and key
    nonce_bytes.zeroize();
    drop(cipher); // Ensure cipher is dropped before zeroizing the key
    let mut key = key;
    key.zeroize();

    println!("File successfully encrypted to '{}'.", output_path);
    Ok(())
}

fn decrypt_file(input_path: &str, output_path: &str, key_path: &str) -> Result<()> {
    let key = load_key(key_path)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| anyhow!("Invalid key length."))?;

    let input_file = File::open(input_path)
        .with_context(|| format!("Failed to open input file '{}'.", input_path))?;
    let mut reader = BufReader::new(input_file);

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    reader
        .read_exact(&mut nonce_bytes)
        .with_context(|| "Failed to read nonce from input file.")?;
    let nonce = XNonce::from_slice(&nonce_bytes);

    let mut ciphertext = Vec::new();
    reader
        .read_to_end(&mut ciphertext)
        .with_context(|| "Failed to read ciphertext from input file.")?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow!("Decryption failed. Incorrect key or corrupted data."))?;

    // Zeroize sensitive data
    ciphertext.zeroize();
    nonce_bytes.zeroize();

    let output_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_path)
        .with_context(|| format!("Failed to create output file '{}'.", output_path))?;
    let mut writer = BufWriter::new(output_file);

    writer
        .write_all(&plaintext)
        .with_context(|| "Failed to write plaintext to output file.")?;

    // Zeroize plaintext and key
    drop(cipher); // Ensure cipher is dropped before zeroizing the key
    let mut key = key;
    key.zeroize();
    let mut plaintext = plaintext;
    plaintext.zeroize();

    println!("File successfully decrypted to '{}'.", output_path);
    Ok(())
}
