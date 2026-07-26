use pqcrypto_frodo::frodokem640shake::*;
use pqcrypto_traits::kem::Ciphertext as CiphertextTrait;
use blake3;
use chacha20::cipher::{KeyIvInit, StreamCipher, generic_array::GenericArray}; // Correct import for GenericArray
use chacha20::ChaCha20;
use std::fs;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::io::stdin;


// Generate a strong post-quantum key using FrodoKEM and BLAKE3
fn generate_key() -> Vec<u8> {
    let (public_key, _secret_key) = keypair();
    let (_, shared_secret) = encapsulate(&public_key);
    
    // Convert shared secret to bytes directly
    let shared_secret_bytes = shared_secret.as_bytes();
    
    // Derive a strong symmetric key using BLAKE3 from the shared secret
    let hash = blake3::hash(shared_secret_bytes);
    let key = hash.as_bytes().to_vec();
    save_key(&key).expect("Failed to save key to file");
    key
}

// Save the generated key to a file called "key.key"
fn save_key(key: &[u8]) -> io::Result<()> {
    let mut key_file = fs::File::create("key.key")?;
    key_file.write_all(key)?;
    Ok(())
}

// Load the key from "key.key"
fn load_key() -> io::Result<Vec<u8>> {
    let mut key_bytes = vec![0u8; 32]; // BLAKE3 produces a 32-byte hash
    let mut key_file = fs::File::open("key.key")?;
    key_file.read_exact(&mut key_bytes)?;
    Ok(key_bytes)
}

// File encryption using the derived key (chunk-based, stream cipher)
fn encrypt_file(input_path: &str, output_path: &str) -> io::Result<()> {
    // Read input file
    let input_file = BufReader::new(fs::File::open(input_path)?);
    let mut output_file = BufWriter::new(fs::File::create(output_path)?);

    // Load or generate encryption key
    let key = if Path::new("key.key").exists() {
        println!("Loading key from file...");
        load_key().expect("Failed to load key from file")
    } else {
        println!("Generating new key...");
        generate_key()
    };

    // Set up ChaCha20 with a 32-byte key and a 12-byte nonce (can be static or generated)
    let key = GenericArray::from_slice(&key);  // Convert key to GenericArray
    let nonce = GenericArray::from_slice(&[0u8; 12]); // Convert nonce to GenericArray
    let mut cipher = ChaCha20::new(key, nonce);

    // Encrypt file contents in chunks
    let chunk_size = 4096; // 4 KB chunks
    let mut buffer = vec![0u8; chunk_size];
    let mut reader = input_file;

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }

        // Encrypt each chunk using the stream cipher
        let mut chunk = buffer[..n].to_vec();
        cipher.apply_keystream(&mut chunk);
        output_file.write_all(&chunk)?;
    }

    Ok(())
}

// File decryption using the derived key (chunk-based, stream cipher)
fn decrypt_file(input_path: &str, output_path: &str) -> io::Result<()> {
    // Read input file
    let mut input_file = BufReader::new(fs::File::open(input_path)?);
    let mut output_file = BufWriter::new(fs::File::create(output_path)?);

    // Load the key
    let key = load_key().expect("Failed to load key from file");

    // Set up ChaCha20 with the same key and nonce used during encryption
    let key = GenericArray::from_slice(&key);  // Convert key to GenericArray
    let nonce = GenericArray::from_slice(&[0u8; 12]); // Convert nonce to GenericArray
    let mut cipher = ChaCha20::new(key, nonce);

    // Decrypt file contents in chunks
    let chunk_size = 4096; // 4 KB chunks
    let mut buffer = vec![0u8; chunk_size];

    loop {
        let n = input_file.read(&mut buffer)?;
        if n == 0 {
            break;
        }

        // Decrypt each chunk using the stream cipher
        let mut chunk = buffer[..n].to_vec();
        cipher.apply_keystream(&mut chunk);
        output_file.write_all(&chunk)?;
    }

    Ok(())
}

fn main() {
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
            match encrypt_file(input_filename, output_filename) {
                Ok(_) => println!("File encrypted successfully!"),
                Err(e) => eprintln!("Error encrypting file: {}", e),
            }
        }
        "D" => {
            // Decrypt the file
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
