use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
use rand::RngCore;
use zeroize::Zeroize;
use std::fs::File;
use std::io::{self, Read, Write, BufReader, BufWriter};
use std::path::Path;
use std::convert::TryInto;
use std::env;
use rpassword::read_password;

// Type alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

const BLOCK_SIZE: usize = 16; // 128-bit block size
const NUM_ROUNDS: usize = 16; // Number of Feistel rounds
const IV_SIZE: usize = 16; // 128-bit IV
const HMAC_SIZE: usize = 32; // 256-bit HMAC

// Key schedule function to generate round keys
fn key_schedule(key: &[u8]) -> Vec<[u8; 32]> {
    let mut round_keys = Vec::with_capacity(NUM_ROUNDS);
    let mut hasher = Sha256::new();
    let mut current_key = key.to_vec();

    for _ in 0..NUM_ROUNDS {
        hasher.update(&current_key);
        let hash = hasher.finalize_reset();
        round_keys.push(hash.as_slice().try_into().unwrap());
        current_key = hash.to_vec();
    }
    round_keys
}

// Round function using SHA-256
fn round_function(right: &[u8], round_key: &[u8]) -> [u8; BLOCK_SIZE / 2] {
    let mut hasher = Sha256::new();
    hasher.update(right);
    hasher.update(round_key);
    let hash = hasher.finalize();
    hash[..BLOCK_SIZE / 2].try_into().unwrap()
}

// XOR operation
fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(&x1, &x2)| x1 ^ x2).collect()
}

// Padding function (PKCS#7)
fn pad(data: &[u8]) -> Vec<u8> {
    let padding_len = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
    let padding = vec![padding_len as u8; padding_len];
    [data, &padding].concat()
}

// Unpadding function
fn unpad(data: &[u8]) -> io::Result<Vec<u8>> {
    if data.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Data is empty"));
    }
    let padding_len = *data.last().unwrap() as usize;
    if padding_len == 0 || padding_len > BLOCK_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid padding"));
    }
    for &byte in &data[data.len() - padding_len..] {
        if byte as usize != padding_len {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid padding"));
        }
    }
    Ok(data[..data.len() - padding_len].to_vec())
}

// Encrypt a single block with IV integration
fn encrypt_block(block: &[u8], round_keys: &[[u8; 32]], iv: Option<&[u8; IV_SIZE]>) -> [u8; BLOCK_SIZE] {
    let mut left = block[..BLOCK_SIZE / 2].to_vec();
    let mut right = block[BLOCK_SIZE / 2..].to_vec();

    // XOR the first block with IV if provided
    if let Some(iv_bytes) = iv {
        left = xor(&left, iv_bytes);
    }

    for round_key in round_keys {
        let temp = right.clone();
        let f_output = round_function(&right, round_key);
        right = xor(&left, &f_output);
        left = temp;
    }

    [left, right].concat().try_into().unwrap()
}

// Decrypt a single block with IV integration
fn decrypt_block(block: &[u8], round_keys: &[[u8; 32]], iv: Option<&[u8; IV_SIZE]>) -> [u8; BLOCK_SIZE] {
    let mut left = block[..BLOCK_SIZE / 2].to_vec();
    let mut right = block[BLOCK_SIZE / 2..].to_vec();

    for round_key in round_keys.iter().rev() {
        let temp = left.clone();
        let f_output = round_function(&left, round_key);
        left = xor(&right, &f_output);
        right = temp;
    }

    // XOR the first block with IV if provided
    if let Some(iv_bytes) = iv {
        left = xor(&left, iv_bytes);
    }

    [left, right].concat().try_into().unwrap()
}

// Function to read a file into a byte vector using buffered reader
fn read_file<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;
    Ok(data)
}

// Function to write a byte vector to a file using buffered writer
fn write_file<P: AsRef<Path>>(path: P, data: &[u8]) -> io::Result<()> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    writer.write_all(data)?;
    writer.flush()?;
    Ok(())
}

// Function to generate a random IV
fn generate_iv() -> [u8; IV_SIZE] {
    let mut iv = [0u8; IV_SIZE];
    rand::thread_rng().fill_bytes(&mut iv);
    iv
}

// Function to compute HMAC
fn compute_hmac(key: &[u8], data: &[u8]) -> [u8; HMAC_SIZE] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    code_bytes[..HMAC_SIZE].try_into().unwrap()
}

// Securely read the key from user input
fn read_key() -> io::Result<Vec<u8>> {
    println!("Enter encryption key: ");
    let key = read_password()?;
    let key_bytes = key.into_bytes();
    Ok(key_bytes)
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        println!("Usage:");
        println!("  To encrypt: {} encrypt <input_file> <output_file>", args[0]);
        println!("  To decrypt: {} decrypt <input_file> <output_file>", args[0]);
        return Ok(());
    }

    let mode = &args[1];
    let input_file = &args[2];
    let output_file = &args[3];

    // Securely read the key
    let key = read_key()?;
    if key.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Key cannot be empty"));
    }

    // Generate round keys
    let round_keys = key_schedule(&key);

    match mode.as_str() {
        "encrypt" => {
            // Read input file
            let data = read_file(input_file)?;

            // Pad data
            let padded_data = pad(&data);

            // Generate IV
            let iv = generate_iv();

            // Encrypt data block by block
            let mut ciphertext = Vec::with_capacity(padded_data.len() + IV_SIZE);
            ciphertext.extend_from_slice(&iv);

            for (i, block) in padded_data.chunks(BLOCK_SIZE).enumerate() {
                let encrypted_block = if i == 0 {
                    encrypt_block(block, &round_keys, Some(&iv))
                } else {
                    encrypt_block(block, &round_keys, None)
                };
                ciphertext.extend_from_slice(&encrypted_block);
            }

            // Compute HMAC for integrity
            let hmac = compute_hmac(&key, &ciphertext);
            ciphertext.extend_from_slice(&hmac);

            // Write ciphertext to output file
            write_file(output_file, &ciphertext)?;

            println!("Encryption completed successfully.");
        },
        "decrypt" => {
            // Read input file
            let data = read_file(input_file)?;

            if data.len() < IV_SIZE + HMAC_SIZE {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "File too short to contain IV and HMAC"));
            }

            // Separate IV, ciphertext, and HMAC
            let iv = &data[..IV_SIZE];
            let hmac_received = &data[data.len() - HMAC_SIZE..];
            let ciphertext = &data[IV_SIZE..data.len() - HMAC_SIZE];

            // Verify HMAC
            let hmac_calculated = compute_hmac(&key, &data[..data.len() - HMAC_SIZE]);
            if hmac_received != hmac_calculated.as_ref() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "HMAC verification failed. Data may be tampered."));
            }

            // Decrypt data block by block
            let mut plaintext_padded = Vec::with_capacity(ciphertext.len());
            for (i, block) in ciphertext.chunks(BLOCK_SIZE).enumerate() {
                let decrypted_block = if i == 0 {
                    decrypt_block(block, &round_keys, Some(&iv.try_into().unwrap()))
                } else {
                    decrypt_block(block, &round_keys, None)
                };
                plaintext_padded.extend_from_slice(&decrypted_block);
            }

            // Unpad plaintext
            let plaintext = unpad(&plaintext_padded)?;

            // Write plaintext to output file
            write_file(output_file, &plaintext)?;

            println!("Decryption completed successfully.");
        },
        _ => {
            println!("Invalid mode. Use 'encrypt' or 'decrypt'.");
            return Ok(());
        }
    }

    // Zeroize sensitive data
    let mut key = key;
    key.zeroize();

    Ok(())
}
