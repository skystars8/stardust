use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::process;
use argon2::{self, Algorithm, Argon2, Params, Version};
use rand::RngCore;
use rand::rngs::OsRng;

const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;

/// Generate a key based on the password using Argon2, with a random salt.
fn generate_key(password: &str, salt: &[u8]) -> Vec<u8> {
    const ARGON2_MEMORY_COST: u32 = 65536;
    const ARGON2_TIME_COST: u32 = 3;
    const ARGON2_PARALLELISM: u32 = 1;

    let params = Params::new(ARGON2_MEMORY_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM, Some(32))
        .expect("Failed to create Argon2 parameters");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut derived_key = vec![0u8; 32];

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut derived_key)
        .expect("Key derivation failed");

    derived_key
}

/// XOR encryption/decryption function using a nonce.
fn xor_encrypt_decrypt(data: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key[i % key.len()] ^ nonce[i % nonce.len()])
        .collect()
}

fn main() {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("Usage: {} <e|d> <input_file> <output_file> <password>", args[0]);
        process::exit(1);
    }

    let mode = &args[1];
    let input_file = &args[2];
    let output_file = &args[3];
    let password = &args[4];

    // Read the input file into memory
    let input_data = match fs::read(input_file) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("Failed to read input file: {}", err);
            process::exit(1);
        }
    };

    if mode == "e" {
        // Generate a random salt for encryption
        let mut salt = [0u8; SALT_LENGTH];
        OsRng.fill_bytes(&mut salt);

        // Generate a random nonce for encryption
        let mut nonce = [0u8; NONCE_LENGTH];
        OsRng.fill_bytes(&mut nonce);

        // Generate the encryption key
        let key = generate_key(password, &salt);

        // Encrypt the data using XOR
        let encrypted_data = xor_encrypt_decrypt(&input_data, &key, &nonce);

        // Write the salt, nonce, and encrypted data to the output file
        let output_data = [salt.as_ref(), nonce.as_ref(), encrypted_data.as_ref()].concat();
        match File::create(output_file).and_then(|mut file| file.write_all(&output_data)) {
            Ok(_) => println!("File successfully encrypted and saved to {}", output_file),
            Err(err) => {
                eprintln!("Failed to write output file: {}", err);
                process::exit(1);
            }
        }
    } else if mode == "d" {
        // Extract the salt and nonce from the beginning of the input data
        let (salt, rest) = input_data.split_at(SALT_LENGTH);
        let (nonce, encrypted_data) = rest.split_at(NONCE_LENGTH);

        // Generate the decryption key
        let key = generate_key(password, salt);

        // Decrypt the data using XOR
        let decrypted_data = xor_encrypt_decrypt(encrypted_data, &key, nonce);

        // Write the decrypted data to the output file
        match File::create(output_file).and_then(|mut file| file.write_all(&decrypted_data)) {
            Ok(_) => println!("File successfully decrypted and saved to {}", output_file),
            Err(err) => {
                eprintln!("Failed to write output file: {}", err);
                process::exit(1);
            }
        }
    } else {
        eprintln!("Invalid mode. Use 'e' for encryption or 'd' for decryption.");
        process::exit(1);
    }
}
