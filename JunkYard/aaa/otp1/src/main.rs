use std::env;
use std::fs::{File, metadata};
use std::io::{Read, Write};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Collect command-line arguments
    let args: Vec<String> = env::args().collect();

    // Ensure proper usage
    if args.len() != 4 {
        eprintln!("Usage: {} <input file> <output file> <key file>", args[0]);
        return Err("Invalid number of arguments.".into());
    }

    // Get input, output, and key file names from the arguments
    let input_filename = &args[1];
    let output_filename = &args[2];
    let key_filename = &args[3];

    // Open the key file
    let mut key_file = File::open(key_filename).map_err(|_| {
        format!(
            "Key file '{}' not found. Please ensure the key file is present.",
            key_filename
        )
    })?;
    let mut key = Vec::new();
    key_file
        .read_to_end(&mut key)
        .map_err(|_| "Failed to read key file.")?;

    // Check if the key file is empty
    if key.is_empty() {
        return Err(format!("Key file '{}' is empty. Please provide a valid key.", key_filename).into());
    }

    // Open the input file
    let mut input_file = File::open(input_filename).map_err(|_| {
        format!("Unable to open input file '{}'.", input_filename)
    })?;
    let mut input_data = Vec::new();
    input_file
        .read_to_end(&mut input_data)
        .map_err(|_| "Failed to read input file.")?;

    // Check if the input file is empty
    if input_data.is_empty() {
        return Err(format!("Input file '{}' is empty. Nothing to process.", input_filename).into());
    }

    // Ensure key length is at least as long as the input data
    if key.len() < input_data.len() {
        return Err("Key is shorter than input data. Please provide a key of sufficient length.".into());
    }

    // Encrypt or decrypt using XOR
    let processed_data = xor_process(&input_data, &key);

    // Write the processed data to the output file
    let mut output_file = File::create(output_filename).map_err(|_| {
        format!("Unable to create output file '{}'.", output_filename)
    })?;
    output_file
        .write_all(&processed_data)
        .map_err(|_| "Failed to write to output file.")?;

    // Verify output file size matches input file size
    let input_size = metadata(input_filename)
        .map_err(|_| "Unable to read input file metadata.")?
        .len();
    let output_size = metadata(output_filename)
        .map_err(|_| "Unable to read output file metadata.")?
        .len();
    if input_size != output_size {
        return Err("Error: Output file size does not match input file size.".into());
    }

    println!("Operation completed successfully.");

    Ok(())
}

// Function to XOR the input data with the key
fn xor_process(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .zip(key.iter())
        .map(|(&data_byte, &key_byte)| data_byte ^ key_byte)
        .collect()
}
