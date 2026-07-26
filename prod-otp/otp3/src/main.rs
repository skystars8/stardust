use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::process;

const CHUNK_SIZE: usize = 4096; // Define the chunk size to be 4KB

fn main() {
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

    // Get input and output file names from the user
    println!("Enter input file name:");
    let mut input_filename = String::new();
    io::stdin().read_line(&mut input_filename).expect("Failed to read input file name");
    let input_filename = input_filename.trim();

    println!("Enter output file name:");
    let mut output_filename = String::new();
    io::stdin().read_line(&mut output_filename).expect("Failed to read output file name");
    let output_filename = output_filename.trim();

    // Open input and output files
    let input_file = File::open(input_filename).expect("Unable to open input file");
    let output_file = File::create(output_filename).expect("Unable to create output file");

    // Use buffered readers and writers for efficient streaming
    let mut input_reader = BufReader::new(input_file);
    let mut output_writer = BufWriter::new(output_file);

    // Ensure that the key is not empty
    if key.is_empty() {
        println!("Key file is empty. Please provide a valid key.");
        process::exit(1);
    }

    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut key_index = 0;

    loop {
        // Read a chunk from the input file
        let bytes_read = input_reader.read(&mut buffer).expect("Failed to read from input file");
        if bytes_read == 0 {
            break; // End of file reached
        }

        // XOR the chunk with the key
        for i in 0..bytes_read {
            buffer[i] ^= key[key_index];
            key_index = (key_index + 1) % key.len(); // Wrap around the key if necessary
        }

        // Write the processed chunk to the output file
        output_writer.write_all(&buffer[..bytes_read]).expect("Failed to write to output file");
    }

    println!("Operation completed successfully.");
}
