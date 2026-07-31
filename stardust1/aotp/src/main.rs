use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process;

struct Cli {
    mode: u8,
    file_in: String,
    file_out: String,
    key_file: String,
}

fn parse_args() -> Cli {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!("Invalid number of arguments. See readme.md for usage.");
        process::exit(1);
    }
    let mode = args[1].parse::<u8>().unwrap_or_else(|_| {
        eprintln!("Invalid mode. See readme.md for usage.");
        process::exit(1);
    });
    Cli {
        mode,
        file_in: args[2].clone(),
        file_out: args[3].clone(),
        key_file: args[4].clone(),
    }
}

fn main() {
    let args = parse_args();

    let current_dir = std::env::current_exe()
        .expect("Failed to determine executable path")
        .parent()
        .expect("Failed to determine executable directory")
        .to_path_buf();

    let file_in_path = current_dir.join(&args.file_in);
    let key_file_path = current_dir.join(&args.key_file);
    let file_out_path = current_dir.join(&args.file_out);

    // Open input and key files
    let mut file_in = match File::open(&file_in_path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Error opening input file: {}", e);
            process::exit(1);
        }
    };

    let mut key_file = match File::open(&key_file_path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Error opening key file: {}", e);
            process::exit(1);
        }
    };

    // Check if key is long enough
    let input_metadata = file_in.metadata().expect("Failed to get input file metadata");
    let key_metadata = key_file.metadata().expect("Failed to get key file metadata");

    if args.mode != 4 && key_metadata.len() < input_metadata.len() {
        eprintln!("Error: Key file is shorter than input file. Aborting.");
        process::exit(1);
    }

    // Choose the encryption method
    match args.mode {
        1 => read_entire_key_and_file(&mut file_in, &mut key_file, &file_out_path),
        2 => chunk_based_processing(&mut file_in, &mut key_file, &file_out_path),
        3 => overwrite_file(&mut file_in, &mut key_file, &file_in_path),
        4 => informal_key_wrapping(&mut file_in, &mut key_file, &file_out_path),
        _ => {
            eprintln!("Invalid mode. See readme.md for usage.");
            process::exit(1);
        }
    }
}

fn read_entire_key_and_file<R: Read>(file_in: &mut R, key_file: &mut R, file_out: &PathBuf) {
    let mut input_buffer = Vec::new();
    let mut key_buffer = Vec::new();

    if file_in.read_to_end(&mut input_buffer).is_err() {
        eprintln!("Error reading input file.");
        process::exit(1);
    }
    if key_file.read_to_end(&mut key_buffer).is_err() {
        eprintln!("Error reading key file.");
        process::exit(1);
    }

    let mut output_buffer = vec![0u8; input_buffer.len()];
    for i in 0..input_buffer.len() {
        output_buffer[i] = input_buffer[i] ^ key_buffer[i % key_buffer.len()];
    }

    let mut file_out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(file_out)
        .expect("Failed to create output file");
    if file_out.write_all(&output_buffer).is_err() {
        eprintln!("Error writing to output file.");
        process::exit(1);
    }
}

fn chunk_based_processing<R: Read>(file_in: &mut R, key_file: &mut R, file_out: &PathBuf) {
    let mut file_out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(file_out)
        .expect("Failed to create output file");

    let mut input_buffer = [0u8; 4096];
    let mut key_buffer = [0u8; 4096];

    loop {
        let bytes_read = match file_in.read(&mut input_buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                eprintln!("Error reading input file: {}", e);
                process::exit(1);
            }
        };

        let key_bytes_read = match key_file.read(&mut key_buffer[..bytes_read]) {
            Ok(n) if n < bytes_read => {
                eprintln!("Error: Key file ended unexpectedly.");
                process::exit(1);
            }
            Ok(n) => n,
            Err(e) => {
                eprintln!("Error reading key file: {}", e);
                process::exit(1);
            }
        };

        for i in 0..bytes_read {
            input_buffer[i] ^= key_buffer[i % key_bytes_read];
        }

        if file_out.write_all(&input_buffer[..bytes_read]).is_err() {
            eprintln!("Error writing to output file.");
            process::exit(1);
        }
    }
}

fn informal_key_wrapping<R: Read>(file_in: &mut R, key_file: &mut R, file_out: &PathBuf) {
    let mut input_buffer = Vec::new();
    let mut key_buffer = Vec::new();

    // Read entire input and key files into memory
    if file_in.read_to_end(&mut input_buffer).is_err() {
        eprintln!("Error reading input file.");
        process::exit(1);
    }
    if key_file.read_to_end(&mut key_buffer).is_err() {
        eprintln!("Error reading key file.");
        process::exit(1);
    }

    // Ensure key buffer is not empty
    if key_buffer.is_empty() {
        eprintln!("Error: Key file is empty. Cannot proceed with encryption.");
        process::exit(1);
    }

    let mut output_buffer = vec![0u8; input_buffer.len()];
    for i in 0..input_buffer.len() {
        output_buffer[i] = input_buffer[i] ^ key_buffer[i % key_buffer.len()];
    }

    // Write to the output file
    let mut file_out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(file_out)
        .expect("Failed to create output file");
    if file_out.write_all(&output_buffer).is_err() {
        eprintln!("Error writing to output file.");
        process::exit(1);
    }
}

fn overwrite_file<R: Read>(file_in: &mut R, key_file: &mut R, file_in_path: &PathBuf) {
    let mut input_buffer = Vec::new();
    let mut key_buffer = Vec::new();

    if file_in.read_to_end(&mut input_buffer).is_err() {
        eprintln!("Error reading input file.");
        process::exit(1);
    }
    if key_file.read_to_end(&mut key_buffer).is_err() {
        eprintln!("Error reading key file.");
        process::exit(1);
    }

    let mut output_buffer = vec![0u8; input_buffer.len()];
    for i in 0..input_buffer.len() {
        output_buffer[i] = input_buffer[i] ^ key_buffer[i % key_buffer.len()];
    }

    let temp_file_path = file_in_path.with_extension("tmp");
    let mut temp_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_file_path)
        .expect("Failed to create temporary file");
    if temp_file.write_all(&output_buffer).is_err() {
        eprintln!("Error writing to temporary file.");
        process::exit(1);
    }

    if std::fs::remove_file(file_in_path).is_err() {
        eprintln!("Error deleting original file.");
        process::exit(1);
    }

    if std::fs::rename(&temp_file_path, file_in_path).is_err() {
        eprintln!("Error renaming temporary file to original file.");
        process::exit(1);
    }
}
