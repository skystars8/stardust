use pqcrypto::kem::kyber1024::*;
use pqcrypto::traits::kem::{Ciphertext as CiphertextTrait, SharedSecret as SharedSecretTrait, PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait};
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

use std::io::stdin;

// Encrypt a random symmetric key using Kyber1024
fn encrypt_key(public_key: &PublicKey) -> (Vec<u8>, Vec<u8>) {
    let (shared_secret, ciphertext) = encapsulate(&public_key);
    println!("Generated shared secret of size: {} bytes", shared_secret.as_bytes().len());
    println!("Generated ciphertext of size: {} bytes", ciphertext.as_bytes().len());
    (ciphertext.as_bytes().to_vec(), shared_secret.as_bytes().to_vec())
}

// Decrypt symmetric key using Kyber1024
fn decrypt_key(secret_key: &SecretKey, ciphertext: &[u8]) -> Vec<u8> {
    let ciphertext = Ciphertext::from_bytes(ciphertext).expect("Failed to create ciphertext from bytes");
    let shared_secret = decapsulate(&ciphertext, &secret_key);
    shared_secret.as_bytes().to_vec()
}

// Encrypt file contents with a simple XOR-based encryption using the shared key
fn xor_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

// File encryption using Kyber1024
fn encrypt_file(input_path: &str, output_path: &str, public_key: &PublicKey) -> io::Result<()> {
    // Read input file
    let mut input_file = fs::File::open(input_path)?;
    let mut data = Vec::new();
    input_file.read_to_end(&mut data)?;

    // Encrypt key and data
    let (ciphertext_key, shared_secret) = encrypt_key(public_key);
    let encrypted_data = xor_encrypt(&data, &shared_secret);

    // Write output file
    let mut output_file = fs::File::create(output_path)?;
    println!("Writing ciphertext key of size: {} bytes", ciphertext_key.len());
    output_file.write_all(&ciphertext_key)?; // Write the fixed-size ciphertext key (1568 bytes)
    println!("Writing encrypted data of size: {} bytes", encrypted_data.len());
    output_file.write_all(&(encrypted_data.len() as u64).to_le_bytes())?; // Write the length of the encrypted data
    output_file.write_all(&encrypted_data)?;

    Ok(())
}

// File decryption using Kyber1024
fn decrypt_file(input_path: &str, output_path: &str, secret_key: &SecretKey) -> io::Result<()> {
    // Read input file
    let mut input_file = fs::File::open(input_path)?;
    let mut ciphertext_key = vec![0; 1568]; // Kyber1024 ciphertext size is 1568 bytes
    input_file.read_exact(&mut ciphertext_key)?;
    println!("Read ciphertext key of size: {} bytes. Expected size: 1568 bytes", ciphertext_key.len());

    let mut length_buffer = [0u8; 8];
    input_file.read_exact(&mut length_buffer)?;
    let encrypted_data_length = u64::from_le_bytes(length_buffer) as usize;
    println!("Encrypted data length read: {} bytes", encrypted_data_length);

    // Validate the encrypted data length to avoid overflow issues
    if encrypted_data_length > 10_000_000 { // Arbitrary upper limit to prevent excessive allocation
        panic!("Encrypted data length is unrealistically large: {} bytes", encrypted_data_length);
    }

    let mut encrypted_data = vec![0; encrypted_data_length];
    input_file.read_exact(&mut encrypted_data)?;
    println!("Read encrypted data of size: {} bytes", encrypted_data.len());

    // Decrypt key and data
    let shared_secret = decrypt_key(secret_key, &ciphertext_key);
    let decrypted_data = xor_encrypt(&encrypted_data, &shared_secret);

    // Write output file
    let mut output_file = fs::File::create(output_path)?;
    output_file.write_all(&decrypted_data)?;

    Ok(())
}

fn main() {
    // Load or generate keypair
    let keypair = if Path::new("public_key.bin").exists() && Path::new("secret_key.bin").exists() {
        println!("Loading keys from files...");
        load_keypair().expect("Failed to load keys from files")
    } else {
        println!("Generating new keys...");
        let keypair = keypair();
        save_keypair(&keypair.0, &keypair.1).expect("Failed to save keys to files");
        keypair
    };

    let (public_key, secret_key) = keypair;

    // Get user input for mode and file paths
    println!("Enter mode (E for encrypt, D for decrypt): ");
    let mut mode = String::new();
    stdin().read_line(&mut mode).expect("Failed to read mode");
    let mode = mode.trim().to_uppercase();

    println!("Enter input filename: ");
    let mut input_filename = String::new();
    stdin().read_line(&mut input_filename).expect("Failed to read input filename");
    let input_filename = input_filename.trim();

    println!("Enter output filename: ");
    let mut output_filename = String::new();
    stdin().read_line(&mut output_filename).expect("Failed to read output filename");
    let output_filename = output_filename.trim();

    match mode.as_str() {
        "E" => {
            // Encrypt the file
            match encrypt_file(input_filename, output_filename, &public_key) {
                Ok(_) => println!("File encrypted successfully!"),
                Err(e) => eprintln!("Error encrypting file: {}", e),
            }
        }
        "D" => {
            // Decrypt the file
            match decrypt_file(input_filename, output_filename, &secret_key) {
                Ok(_) => println!("File decrypted successfully!"),
                Err(e) => eprintln!("Error decrypting file: {}", e),
            }
        }
        _ => {
            eprintln!("Invalid mode entered. Please enter 'E' for encryption or 'D' for decryption.");
        }
    }
}

// Save keypair to files
fn save_keypair(public_key: &PublicKey, secret_key: &SecretKey) -> io::Result<()> {
    let mut public_key_file = fs::File::create("public_key.bin")?;
    public_key_file.write_all(public_key.as_bytes())?;

    let mut secret_key_file = fs::File::create("secret_key.bin")?;
    secret_key_file.write_all(secret_key.as_bytes())?;

    Ok(())
}

// Load keypair from files
fn load_keypair() -> io::Result<(PublicKey, SecretKey)> {
    let mut public_key_bytes = vec![0u8; 1568]; // Kyber1024 public key size is 1568 bytes
    let mut secret_key_bytes = vec![0u8; 3168]; // Kyber1024 secret key size is 3168 bytes

    let mut public_key_file = fs::File::open("public_key.bin")?;
    public_key_file.read_exact(&mut public_key_bytes)?;

    let mut secret_key_file = fs::File::open("secret_key.bin")?;
    secret_key_file.read_exact(&mut secret_key_bytes)?;

    let public_key = PublicKey::from_bytes(&public_key_bytes).expect("Failed to create public key from bytes");
    let secret_key = SecretKey::from_bytes(&secret_key_bytes).expect("Failed to create secret key from bytes");

    Ok((public_key, secret_key))
}