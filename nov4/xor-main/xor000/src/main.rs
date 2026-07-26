use std::env;
use std::fs::{self, File};
use std::io::Write; // Removed `Read` as it is unused
use std::process;

/// Generate a deterministic key based on the password.
/// The key will be as long as the file's content.
fn generate_key(password: &str, length: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(length);
    let mut password_bytes = password.as_bytes().iter().cycle(); // Repeat the password bytes

    for _ in 0..length {
        key.push(*password_bytes.next().unwrap());
    }

    key
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
