
use rand::rngs::OsRng;
use rand::RngCore;
use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

/// Parses the size string and returns the size in bytes.
fn parse_size(size_str: &str) -> Result<usize, String> {
    let size_str = size_str.to_lowercase();
    
    // Separate the numeric part and the unit part
    let (number_part, unit) = size_str
        .trim()
        .chars()
        .partition::<String, _>(|c| c.is_digit(10));
    
    // Parse the number part as usize
    let size: usize = number_part.parse().map_err(|_| "Invalid number format".to_string())?;
    
    // Match the unit to calculate the size in bytes
    let bytes = match unit.as_str() {
        "b" | "bytes" => size,
        "kb" => size * 1024,
        "mb" => size * 1024 * 1024,
        "gb" => size * 1024 * 1024 * 1024,
        _ => return Err("Unknown unit".to_string()),
    };

    Ok(bytes)
}

fn main() -> io::Result<()> {
    // Get command-line arguments
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args.len() > 3 {
        eprintln!("Usage: rkm <size> [output_file]");
        eprintln!("Example: rkm 32bytes");
        eprintln!("         rkm 20mb output.bin");
        eprintln!("         rkm 5gb");
        std::process::exit(1);
    }

    // Parse the size argument
    let size_in_bytes = match parse_size(&args[1]) {
        Ok(size) => size,
        Err(err) => {
            eprintln!("Error parsing size: {}", err);
            std::process::exit(1);
        }
    };

    // Determine the output file
    let output_file = if args.len() == 3 {
        &args[2]
    } else {
        "rand.key"
    };

    // Check if the file already exists
    if Path::new(output_file).exists() {
        eprintln!("Error: File '{}' already exists.", output_file);
        std::process::exit(1);
    }

    // Create the file
    let mut file = File::create(output_file)?;

    // Initialize the random number generator
    let mut rng = OsRng;

    // Set buffer size (either 1 MB or the file size, whichever is smaller)
    let buffer_size = std::cmp::min(1024 * 1024, size_in_bytes); // Max 1 MB
    let mut buffer = vec![0u8; buffer_size];
    let mut bytes_written = 0;

    // Write random data to the file in chunks
    while bytes_written < size_in_bytes {
        let bytes_to_write = std::cmp::min(buffer_size, size_in_bytes - bytes_written);

        // Fill the buffer with random bytes
        rng.fill_bytes(&mut buffer[..bytes_to_write]);

        // Write the buffer to the file
        file.write_all(&buffer[..bytes_to_write])?;
        bytes_written += bytes_to_write;
    }

    // Print success message
    println!(
        "Successfully generated '{}' with size {} bytes.",
        output_file, size_in_bytes
    );

    Ok(())
}
