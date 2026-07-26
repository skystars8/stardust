use std::env;
use std::fs::{self, File};
use std::io::{self, prelude::*};

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        println!("Usage: {} <filename>", args[0]);
        return Ok(());
    }

    let filename = &args[1];

    let contents = fs::read(filename)?;

    // Built-in encryption key
    let key = 42;

    // Encrypt the contents of the file
    let encrypted = contents.iter().map(|b| b ^ key).collect::<Vec<u8>>();

    let mut file = File::create(filename)?;
    file.write_all(&encrypted)?;

    Ok(())
}