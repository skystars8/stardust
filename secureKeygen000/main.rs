use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::File;
use std::io::Write;

fn generate_random_key(length: usize) -> Vec<u8> {
    let mut key = vec![0u8; length];
    let mut rng = OsRng; // Uses the OS's cryptographically secure RNG
    rng.fill_bytes(&mut key);
    key
}

fn main() -> std::io::Result<()> {
    let key_length = 1024 * 1024 * 5; // 5 GB example key size
    let random_key = generate_random_key(key_length);
    
    // Optionally, write the key to a file
    let mut file = File::create("random_key.bin")?;
    file.write_all(&random_key)?;
    
    println!("Random key generated and saved to random_key.bin");
    Ok(())
}