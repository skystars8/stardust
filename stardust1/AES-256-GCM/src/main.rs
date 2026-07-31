use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

use structopt::StructOpt;

use rand::rngs::OsRng;
use rand::RngCore;

use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;

use argon2::{Algorithm, Argon2, Params, Version};

/// A simple and secure file encryption tool.
#[derive(StructOpt)]
#[structopt(
    name = "Encryptor",
    about = "A simple file encryption tool.",
    no_version, // Disable the -V/--version flag
    setting = structopt::clap::AppSettings::DisableHelpFlags, // Disable the -h/--help flags
)]
struct Opt {
    /// The operation to perform: encrypt or decrypt.
    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(StructOpt)]
enum Command {
    /// Encrypt a file.
    Encrypt {
        /// Input file to encrypt.
        #[structopt(parse(from_os_str))]
        input: PathBuf,

        /// Output file for the encrypted data.
        #[structopt(parse(from_os_str))]
        output: PathBuf,
    },
    /// Decrypt a file.
    Decrypt {
        /// Input file to decrypt.
        #[structopt(parse(from_os_str))]
        input: PathBuf,

        /// Output file for the decrypted data.
        #[structopt(parse(from_os_str))]
        output: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    // Parse command-line arguments.
    let opt = Opt::from_args();

    match opt.cmd {
        Command::Encrypt { input, output } => {
            // Prompt for the password.
            let password = rpassword::prompt_password("Password: ")?;
            encrypt_file(&input, &output, &password)?;
        }
        Command::Decrypt { input, output } => {
            // Prompt for the password.
            let password = rpassword::prompt_password("Password: ")?;
            decrypt_file(&input, &output, &password)?;
        }
    }

    Ok(())
}

/// Encrypts a file using AES-256-GCM and Argon2 key derivation.
fn encrypt_file(input: &PathBuf, output: &PathBuf, password: &str) -> anyhow::Result<()> {
    // Read the input file.
    let mut input_file = File::open(input)?;
    let mut plaintext = Vec::new();
    input_file.read_to_end(&mut plaintext)?;

    // Generate a random salt.
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    // Derive a key from the password and salt using Argon2.
    let key_bytes = derive_key(password, &salt)?;

    // Generate a random nonce.
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Create an AES-GCM cipher instance.
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| anyhow::anyhow!("Key init error: {:?}", e))?;

    // Encrypt the plaintext.
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow::anyhow!("Encryption error: {:?}", e))?;

    // Write the salt, nonce, and ciphertext to the output file.
    let mut output_file = File::create(output)?;
    output_file.write_all(&salt)?;
    output_file.write_all(&nonce_bytes)?;
    output_file.write_all(&ciphertext)?;

    Ok(())
}

/// Decrypts a file using AES-256-GCM and Argon2 key derivation.
fn decrypt_file(input: &PathBuf, output: &PathBuf, password: &str) -> anyhow::Result<()> {
    // Read the input file.
    let mut input_file = File::open(input)?;
    let mut contents = Vec::new();
    input_file.read_to_end(&mut contents)?;

    // Ensure the file is long enough to contain the salt and nonce.
    if contents.len() < 16 + 12 {
        return Err(anyhow::anyhow!("File too short to be valid."));
    }

    // Extract the salt, nonce, and ciphertext.
    let salt = &contents[..16];
    let nonce_bytes = &contents[16..28];
    let ciphertext = &contents[28..];

    // Derive the key from the password and salt.
    let key_bytes = derive_key(password, salt)?;

    // Create an AES-GCM cipher instance.
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| anyhow::anyhow!("Key init error: {:?}", e))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt the ciphertext.
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| anyhow::anyhow!("Decryption error: {:?}", e))?;

    // Write the plaintext to the output file.
    let mut output_file = File::create(output)?;
    output_file.write_all(&plaintext)?;

    Ok(())
}

/// Derives a 256-bit key from the password and salt using Argon2.
fn derive_key(password: &str, salt: &[u8]) -> anyhow::Result<[u8; 32]> {
    let mut key = [0u8; 32];
    let params = Params::default();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Key derivation error: {:?}", e))?;
    Ok(key)
}
