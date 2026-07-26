use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::process;
use ring::digest::{Context, SHA256};

/// Generate a deterministic key based on the password using repeated hashing.
/// The key will be as long as the file's content and will not repeat.
fn generate_key(password: &str, length: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(length);
    let mut context = Context::new(&SHA256);
    let mut counter: u64 = 0;

    while key.len() < length {
        // Update the hash context with the password and counter to generate unique output.
        context.update(password.as_bytes());
        context.update(&counter.to_le_bytes());
        let hash = context.clone().finish();

        // Add the hash output to the key, ensuring we don't exceed the required length.
        key.extend_from_slice(&hash.as_ref()[..]);
        counter += 1;
    }

    key.truncate(length);
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
