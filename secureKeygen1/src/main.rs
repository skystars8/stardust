use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;


fn main() -> io::Result<()> {
    // Get user input for key size
    println!("Enter the key size (e.g., 1024B, 10MB, 1GB):");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();

    let key_length = match parse_size(&input) {
        Some(size) if size > 0 && size <= 5 * 1024 * 1024 * 1024 => size,
        _ => {
            eprintln!("Invalid size. Please enter a value between 1 byte and 5 GB.");
            return Ok(());
        }
    };

    // File output name and check if it already exists
    let file_name = "key.key";
    if Path::new(file_name).exists() {
        eprintln!("Error: The file '{}' already exists. To avoid overwriting, please delete or rename the existing file.", file_name);
        return Ok(());
    }

    // Open the file for writing
    let mut file = OpenOptions::new().create_new(true).write(true).open(file_name)?;
    let chunk_size = 1024 * 1024 * 10; // 10 MB chunks
    let mut rng = OsRng;
    let mut chunk = vec![0u8; chunk_size];
    let mut bytes_written = 0;

    while bytes_written < key_length {
        // Fill the chunk with random bytes
        rng.fill_bytes(&mut chunk);

        // Determine how many bytes to write in this iteration
        let bytes_to_write = (key_length - bytes_written).min(chunk_size);
        file.write_all(&chunk[..bytes_to_write])?;

        bytes_written += bytes_to_write;
    }

    println!("Random key of size {} bytes generated and saved to '{}'.", key_length, file_name);
    Ok(())
}

fn parse_size(input: &str) -> Option<usize> {
    if let Some(bytes) = input.strip_suffix("b") {
        bytes.trim().parse::<usize>().ok()
    } else if let Some(mb) = input.strip_suffix("mb") {
        mb.trim().parse::<usize>().ok().map(|v| v * 1024 * 1024)
    } else if let Some(gb) = input.strip_suffix("gb") {
        gb.trim().parse::<usize>().ok().map(|v| v * 1024 * 1024 * 1024)
    } else {
        input.parse::<usize>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_size() {
        assert_eq!(parse_size("1024b"), Some(1024));
        assert_eq!(parse_size("10mb"), Some(10 * 1024 * 1024));
        assert_eq!(parse_size("1gb"), Some(1 * 1024 * 1024 * 1024));
        assert_eq!(parse_size("5gb"), Some(5 * 1024 * 1024 * 1024));
        assert_eq!(parse_size("0"), Some(0));
        assert_eq!(parse_size("invalid"), None);
    }
}
