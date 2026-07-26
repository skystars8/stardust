use std::env;
use std::fs::{File, metadata};
use std::io::{Read, Write};
use std::process;

fn main() {
    // Collect command line arguments
    let args: Vec<String> = env::args().collect();

    // Ensure proper usage
    if args.len() != 3 {
        println!("Usage: {} <input file> <output file>", args[0]);
        process::exit(1);
    }

    // Get input and output file names from the arguments
    let input_filename = &args[1];
    let output_filename = &args[2];

    // Check if the key file exists at the start
    let key_filename = "key.key";
    let mut key_file = match File::open(key_filename) {
        Ok(file) => file,
        Err(_) => {
            println!("Key file 'key.key' not found. Please ensure the key file is present in the current directory.");
            process::exit(1);
        }
    };
    let mut key = Vec::new();
    key_file.read_to_end(&mut key).expect("Failed to read key file");

    // Open the input file
    let mut input_file = File::open(input_filename).expect("Unable to open input file");
    let mut input_data = Vec::new();
    input_file.read_to_end(&mut input_data).expect("Failed to read input file");

    // Ensure key length is at least as long as the input data
    if key.len() < input_data.len() {
        println!("Key is shorter than input data. Please provide a key of sufficient length.");
        process::exit(1);
    }

    // Encrypt or decrypt using XOR
    let processed_data = xor_process(&input_data, &key);

    // Write the processed data to the output file
    let mut output_file = File::create(output_filename).expect("Unable to create output file");
    output_file.write_all(&processed_data).expect("Failed to write to output file");

    // Verify output file size matches input file size
    let input_size = metadata(input_filename).expect("Unable to read input file metadata").len();
    let output_size = metadata(output_filename).expect("Unable to read output file metadata").len();
    if input_size != output_size {
        println!("Error: Output file size does not match input file size.");
        process::exit(1);
    }

    println!("Operation completed successfully.");
}

// Function to XOR the input data with the key
fn xor_process(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &data_byte)| data_byte ^ key[i % key.len()])
        .collect()
}
