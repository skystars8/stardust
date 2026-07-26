use clap::Parser;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;

/// Simple program to randomize a key file to a cryptographically secure key
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Input key file path
    #[arg(short, long, value_name = "FILE")]
    input: PathBuf,

    /// Output file path (optional). If not provided, the hash will be printed to stdout.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    // Read the input file
    let mut file = File::open(&args.input)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Hash the contents using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let result = hasher.finalize();

    // Convert the hash to a hexadecimal string
    let hex_result = hex::encode(result);

    // Output the result
    match args.output {
        Some(output_path) => {
            std::fs::write(output_path, hex_result)?;
            println!("Secure key written to the specified output file.");
        }
        None => {
            println!("Secure Key (SHA-256): {}", hex_result);
        }
    }

    Ok(())
}
