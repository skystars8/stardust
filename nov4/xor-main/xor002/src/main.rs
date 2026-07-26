use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::process;
use argon2::{self, Algorithm, Argon2, Params, Version};
use sha3::{Sha3_512, Digest};

/// Generate a deterministic key based on the password using Argon2.
/// The key will be as long as the file's content and will not repeat.
fn generate_key(password: &str, length: usize) -> Vec<u8> {
    const ARGON2_MEMORY_COST: u32 = 65536;
    const ARGON2_TIME_COST: u32 = 3;
    const ARGON2_PARALLELISM: u32 = 1;

    let params = Params::new(ARGON2_MEMORY_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM, Some(32))
        .expect("Failed to create Argon2 parameters");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Derive a deterministic salt from the password using SHA3-512
    let mut hasher = Sha3_512::new();
    hasher.update(password.as_bytes());
    let full_salt = hasher.finalize();
    let salt = &full_salt[..16]; // Truncate to 16 bytes to use as salt

    let mut derived_key = vec![0u8; 32];

    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut derived_key)
        .expect("Key derivation failed");

    // Extend or truncate the key to match the length of the file data
    let mut final_key = vec![0u8; length];
    for (i, byte) in derived_key.iter().cycle().enumerate().take(length) {
        final_key[i] = *byte;
    }

    final_key
}

/// XOR encryption/decryption function.
/// This is symmetric, so the same function can encrypt and decrypt.
fn xor_encrypt_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter().zip(key.iter()).map(|(d, k)| d ^ k).collect()
}

fn main() {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <input_file> <output_file> <password>", args[0]);
        process::exit(1);
    }

    let input_file = &args[1];
    let output_file = &args[2];
    let password = &args[3];

    // Read the input file into memory
    let input_data = match fs::read(input_file) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("Failed to read input file: {}", err);
            process::exit(1);
        }
    };

    // Generate the deterministic key based on the password and file length
    let key = generate_key(password, input_data.len());

    // XOR encryption/decryption
    let encrypted_data = xor_encrypt_decrypt(&input_data, &key);

    // Write the output data to the specified output file
    match File::create(output_file).and_then(|mut file| file.write_all(&encrypted_data)) {
        Ok(_) => println!("File successfully processed and saved to {}", output_file),
        Err(err) => {
            eprintln!("Failed to write output file: {}", err);
            process::exit(1);
        }
    }
}
