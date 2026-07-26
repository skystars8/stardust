use rand::Rng;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use clap::{Arg, Command};

const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const DEFAULT_KEY_FILE: &str = "key.key";
const DEFAULT_NUM_ROUNDS: usize = 16;

fn main() {
    let matches = Command::new("Feistel Network Encryption CLI")
        .version("1.0")
        .author("OpenAI")
        .about("Encrypts and decrypts files using a Feistel network with AES S-box")
        .arg(
            Arg::new("mode")
                .help("Mode: encrypt or decrypt")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("input")
                .help("Input file to be encrypted or decrypted")
                .required(true)
                .index(2),
        )
        .arg(
            Arg::new("output")
                .help("Output file to store the result")
                .required(true)
                .index(3),
        )
        .arg(
            Arg::new("rounds")
                .short('r')
                .long("rounds")
                .help("Number of Feistel rounds")
                .num_args(1),
        )
        .get_matches();

    // Get mode, input file, and output file
    let mode = matches.get_one::<String>("mode").unwrap();
    let input_file = matches.get_one::<String>("input").unwrap();
    let output_file = matches.get_one::<String>("output").unwrap();
    let num_rounds = matches.get_one::<String>("rounds")
        .map(|s| s.parse::<usize>().unwrap_or(DEFAULT_NUM_ROUNDS))
        .unwrap_or(DEFAULT_NUM_ROUNDS);

    // Ensure the key file exists or create one
    let key = ensure_key_file(DEFAULT_KEY_FILE);

    // Read input file
    let input_data = fs::read(input_file).expect("Failed to read input file");

    // Encrypt or decrypt based on mode
    let output_data = match mode.as_str() {
        "encrypt" => feistel_encrypt(&input_data, &key, num_rounds),
        "decrypt" => feistel_decrypt(&input_data, &key, num_rounds),
        _ => panic!("Invalid mode. Use 'encrypt' or 'decrypt'."),
    };

    // Write output to specified output file
    fs::write(output_file, &output_data).expect("Failed to write output file");
    println!("Output written to: {}", output_file);
}

fn ensure_key_file(path: &str) -> Vec<u8> {
    if !Path::new(path).exists() {
        // Generate a random 16-byte key
        let key: Vec<u8> = (0..16).map(|_| rand::thread_rng().gen()).collect();
        let mut file = File::create(path).expect("Failed to create key file");
        file.write_all(&key).expect("Failed to write key file");
        println!("Key file 'key.key' created.");
        key
    } else {
        let mut file = File::open(path).expect("Failed to open key file");
        let mut key = Vec::new();
        file.read_to_end(&mut key).expect("Failed to read key file");
        key
    }
}

fn feistel_encrypt(data: &[u8], key: &[u8], rounds: usize) -> Vec<u8> {
    feistel_network(data, key, rounds, true)
}

fn feistel_decrypt(data: &[u8], key: &[u8], rounds: usize) -> Vec<u8> {
    feistel_network(data, key, rounds, false)
}

fn feistel_network(data: &[u8], key: &[u8], rounds: usize, encrypt: bool) -> Vec<u8> {
    let mut left = data[0..data.len() / 2].to_vec();
    let mut right = data[data.len() / 2..].to_vec();

    for i in 0..rounds {
        let round_key = if encrypt {
            key[i % key.len()]
        } else {
            key[(rounds - 1 - i) % key.len()]
        };

        // Apply round function to right half and XOR with left half
        let temp_right: Vec<u8> = right.iter().map(|&r| aes_sbox_transform(r ^ round_key)).collect();
        let new_left: Vec<u8> = left.iter().zip(temp_right.iter()).map(|(&l, &t)| l ^ t).collect();

        if i < rounds - 1 {
            // Swap halves except in the last round
            left = right;
            right = new_left;
        } else {
            left = new_left;
        }
    }

    [left, right].concat()
}

fn aes_sbox_transform(byte: u8) -> u8 {
    AES_SBOX[byte as usize]
}
