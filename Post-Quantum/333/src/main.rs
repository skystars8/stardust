use pqcrypto_frodo::frodokem640shake::*;
use pqcrypto_traits::kem::Ciphertext as CiphertextTrait;
use blake3;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use chacha20poly1305::Key;
use rand::Rng;
use rpassword::read_password;
use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::path::Path;

// Generate a strong post-quantum key using FrodoKEM and BLAKE3
fn generate_key() -> Vec<u8> {
    println!("Generating a new keypair using FrodoKEM...");
    let (public_key, _secret_key) = keypair();
    let (_, shared_secret) = encapsulate(&public_key);

    // Convert shared secret to bytes directly
    let shared_secret_bytes = shared_secret.as_bytes();
    println!("Shared secret generated successfully.");

    // Derive a strong symmetric key using BLAKE3 from the shared secret
    let hash = blake3::hash(shared_secret_bytes);
    let key = hash.as_bytes().to_vec();
    println!("Symmetric key derived using BLAKE3.");
    save_key_secure(&key).expect("Failed to save key to file");
    println!("Key saved securely to key.key.");
    key
}

// Save the generated key securely using a passphrase
fn save_key_secure(key: &[u8]) -> io::Result<()> {
    println!("Enter a passphrase to secure the key: ");
    let passphrase = read_password().expect("Failed to read passphrase");

    println!("Passphrase entered for encryption: {}", passphrase);

    // Derive an encryption key from the passphrase using BLAKE3
    let derived_key = blake3::hash(passphrase.as_bytes());
    let encryption_key = Key::from_slice(&derived_key.as_bytes()[..32]);

    println!("Derived key (hashed passphrase) for encryption: {:?}", derived_key);

    let cipher = XChaCha20Poly1305::new(encryption_key);

    // Generate a random nonce
    let nonce = XNonce::from(rand::thread_rng().gen::<[u8; 24]>());
    println!("Random nonce generated for securing key: {:?}", nonce);

    // Encrypt the key with XChaCha20-Poly1305
    let encrypted_key = match cipher.encrypt(&nonce, key.as_ref()) {
        Ok(encrypted_key) => encrypted_key,
        Err(_) => {
            eprintln!("Failed to encrypt key with XChaCha20-Poly1305.");
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Failed to encrypt key"));
        }
    };

    // Save nonce and encrypted key to the file
    let mut key_file = match fs::File::create("key.key") {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to create key file: {:?}", e);
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to create key file"));
        }
    };
    
    key_file.write_all(&nonce)?;
    key_file.write_all(&encrypted_key)?;

    println!("Key saved successfully.");
    Ok(())
}

// Load the key securely using a passphrase
fn load_key_secure() -> io::Result<Vec<u8>> {
    println!("Enter passphrase to unlock the key: ");
    let passphrase = read_password().expect("Failed to read passphrase");

    println!("Passphrase entered for decryption: {}", passphrase);

    let mut key_file = fs::File::open("key.key")?;
    let mut nonce = [0u8; 24]; // XChaCha20 requires a 24-byte nonce

    println!("Reading nonce from key file...");
    if let Err(e) = key_file.read_exact(&mut nonce) {
        eprintln!("Failed to read nonce from key file: {:?}", e);
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Failed to read nonce from key file"));
    }
    println!("Nonce read successfully: {:?}", nonce);

    let mut encrypted_key = Vec::new();
    println!("Reading encrypted key from key file...");
    if let Err(e) = key_file.read_to_end(&mut encrypted_key) {
        eprintln!("Failed to read encrypted key from key file: {:?}", e);
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Failed to read encrypted key from key file"));
    }
    println!("Encrypted key length: {}", encrypted_key.len());

    // Derive the decryption key from the passphrase
    let derived_key = blake3::hash(passphrase.as_bytes());
    let decryption_key = Key::from_slice(&derived_key.as_bytes()[..32]);

    println!("Derived key (hashed passphrase) for decryption: {:?}", derived_key);

    let cipher = XChaCha20Poly1305::new(decryption_key);

    println!("Attempting to decrypt key...");
    match cipher.decrypt(&nonce.into(), encrypted_key.as_ref()) {
        Ok(decrypted_key) => {
            println!("Key decrypted successfully.");
            Ok(decrypted_key)
        }
        Err(_) => {
            eprintln!("Failed to decrypt the key. Possible causes include an incorrect passphrase or a corrupted key file.");
            Err(io::Error::new(io::ErrorKind::InvalidData, "Failed to decrypt key"))
        }
    }
}

// Encrypt an entire file at once
fn encrypt_file(input_path: &str, output_path: &str) -> io::Result<()> {
    println!("Starting encryption process...");

    let mut input_file = fs::File::open(input_path)?;
    let mut output_file = fs::File::create(output_path)?;

    let key = if Path::new("key.key").exists() {
        println!("Loading key from file...");
        match load_key_secure() {
            Ok(key) => key,
            Err(_) => {
                eprintln!("Failed to load key from key file.");
                return Err(io::Error::new(io::ErrorKind::Other, "Failed to load key from file"));
            }
        }
    } else {
        println!("Generating new key...");
        generate_key()
    };

    println!("Encryption key loaded successfully.");
    let encryption_key = Key::from_slice(&key);
    let cipher = XChaCha20Poly1305::new(encryption_key);

    let nonce = XNonce::from(rand::thread_rng().gen::<[u8; 24]>());
    println!("Generated random nonce for file encryption: {:?}", nonce);

    // Write the nonce to the output file (it will be needed for decryption)
    output_file.write_all(&nonce)?;

    // Read the entire file into memory
    let mut data = Vec::new();
    input_file.read_to_end(&mut data)?;

    // Encrypt the entire file
    let encrypted_data = cipher.encrypt(&nonce, data.as_ref())
        .expect("Failed to encrypt the file data");

    output_file.write_all(&encrypted_data)?;

    println!("File encrypted successfully!");
    Ok(())
}

// Decrypt an entire file at once
fn decrypt_file(input_path: &str, output_path: &str) -> io::Result<()> {
    println!("Starting decryption process...");

    let mut input_file = BufReader::new(fs::File::open(input_path)?);
    let mut output_file = fs::File::create(output_path)?;

    println!("Loading the key...");
    let key = load_key_secure()?;

    let decryption_key = Key::from_slice(&key);
    let cipher = XChaCha20Poly1305::new(decryption_key);

    let mut nonce = [0u8; 24];
    input_file.read_exact(&mut nonce)?;
    println!("Nonce read successfully: {:?}", nonce);

    // Read the entire encrypted file into memory
    let mut encrypted_data = Vec::new();
    input_file.read_to_end(&mut encrypted_data)?;

    // Decrypt the entire file
    let decrypted_data = match cipher.decrypt(&nonce.into(), encrypted_data.as_ref()) {
        Ok(decrypted_data) => decrypted_data,
        Err(_) => {
            eprintln!("Failed to decrypt the file. This might indicate an incorrect key or a corrupted file.");
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Failed to decrypt file data"));
        }
    };

    output_file.write_all(&decrypted_data)?;

    println!("File decrypted successfully!");
    Ok(())
}

// Main function to provide user interface for encrypting or decrypting files
fn main() {
    println!("Enter mode (E for encrypt, D for decrypt): ");
    let mut mode = String::new();
    std::io::stdin().read_line(&mut mode).expect("Failed to read mode");
    let mode = mode.trim().to_uppercase();

    println!("Enter input filename: ");
    let mut input_filename = String::new();
    std::io::stdin().read_line(&mut input_filename).expect("Failed to read input filename");
    let input_filename = input_filename.trim();

    println!("Enter output filename: ");
    let mut output_filename = String::new();
    std::io::stdin().read_line(&mut output_filename).expect("Failed to read output filename");
    let output_filename = output_filename.trim();

    match mode.as_str() {
        "E" => {
            match encrypt_file(input_filename, output_filename) {
                Ok(_) => println!("File encrypted successfully!"),
                Err(e) => eprintln!("Error encrypting file: {}", e),
            }
        }
        "D" => {
            match decrypt_file(input_filename, output_filename) {
                Ok(_) => println!("File decrypted successfully!"),
                Err(e) => eprintln!("Error decrypting file: {}", e),
            }
        }
        _ => {
            eprintln!("Invalid mode entered. Please enter 'E' for encryption or 'D' for decryption.");
        }
    }
}
