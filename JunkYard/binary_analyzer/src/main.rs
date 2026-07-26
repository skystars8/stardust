use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::Path;
use std::process;

fn main() {
    // Prompt the user for the filename
    println!("Enter the filename to analyze:");

    // Read the filename from stdin
    let mut filename = String::new();
    if let Err(e) = io::stdin().read_line(&mut filename) {
        eprintln!("Failed to read input: {}", e);
        process::exit(1);
    }

    // Trim the input to remove any trailing newline characters
    let filename = filename.trim();

    // Check if the file exists
    if !Path::new(&filename).exists() {
        eprintln!("File '{}' does not exist.", filename);
        process::exit(1);
    }

    // Open the file in read-only mode
    let file = match File::open(&filename) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open file '{}': {}", filename, e);
            process::exit(1);
        }
    };

    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();

    // Read the entire file into the buffer
    if let Err(e) = reader.read_to_end(&mut buffer) {
        eprintln!("Failed to read file '{}': {}", filename, e);
        process::exit(1);
    }

    // Initialize a frequency array for all 256 byte values
    let mut frequencies = [0u64; 256];

    for &byte in &buffer {
        frequencies[byte as usize] += 1;
    }

    // Prepare to write the report
    let report = match File::create("report.txt") { // Removed `mut` here
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to create report.txt: {}", e);
            process::exit(1);
        }
    };

    let mut writer = io::BufWriter::new(report);

    // Write the header
    if let Err(e) = writeln!(writer, "Binary Character Frequencies:\n") {
        eprintln!("Failed to write to report.txt: {}", e);
        process::exit(1);
    }

    // Write each byte and its count
    for (byte, &count) in frequencies.iter().enumerate() {
        // Display byte in hexadecimal for better readability
        if let Err(e) = writeln!(writer, "Byte {:02X} ({}): {}", byte, byte, count) {
            eprintln!("Failed to write to report.txt: {}", e);
            process::exit(1);
        }
    }

    // Add a separator
    if let Err(e) = writeln!(writer, "\nEntropy and Randomness Analysis:\n") {
        eprintln!("Failed to write to report.txt: {}", e);
        process::exit(1);
    }

    // Calculate entropy
    let entropy = calculate_entropy(&frequencies, buffer.len() as f64);
    if let Err(e) = writeln!(writer, "Shannon Entropy: {:.4} bits per byte", entropy) {
        eprintln!("Failed to write to report.txt: {}", e);
        process::exit(1);
    }

    // Additional randomness analysis can be added here
    // For example, Chi-Square test, Runs test, etc.

    if let Err(e) = writeln!(
        writer,
        "\nInterpretation:\n\
        - Entropy close to 8 bits per byte indicates high randomness.\n\
        - Lower entropy suggests patterns or redundancy in the data."
    ) {
        eprintln!("Failed to write to report.txt: {}", e);
        process::exit(1);
    }

    println!("Analysis complete. Report saved to 'report.txt'.");
}

/// Calculates the Shannon entropy of the data.
fn calculate_entropy(frequencies: &[u64; 256], total: f64) -> f64 {
    frequencies.iter().fold(0.0, |acc, &count| {
        if count == 0 {
            acc
        } else {
            let p = count as f64 / total;
            acc - p * p.log2()
        }
    })
}
