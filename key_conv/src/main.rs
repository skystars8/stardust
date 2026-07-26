use std::env;
use std::fs;
use std::process;

/// Expected key length for AES-256 / XChaCha20 / ChaCha20
const EXPECTED_KEY_LEN: usize = 32;

const TEXT_FILE: &str = "in.txt";
const KEY_FILE: &str = "key.key";

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        return Err(format!(
            "Usage: {} <key|txt>\n\
             \n\
             Modes:\n\
               key  – read '{}' and write binary key to '{}'\n\
               txt  – read '{}' and write text numbers to '{}'\n\
             \n\
             Both modes overwrite the output file if it already exists.",
            args.first().map(|s| s.as_str()).unwrap_or("key_converter"),
            TEXT_FILE,
            KEY_FILE,
            KEY_FILE,
            TEXT_FILE
        ));
    }

    match args[1].as_str() {
        "key" => mode_key(),
        "txt" => mode_txt(),
        other => Err(format!(
            "Unknown mode '{}'. Use 'key' or 'txt'.\n\
             Run without arguments to see usage.",
            other
        )),
    }
}

/// "key" mode: parse strict text file → binary key
fn mode_key() -> Result<(), String> {
    let content = fs::read_to_string(TEXT_FILE)
        .map_err(|e| format!("Failed to read '{}': {}", TEXT_FILE, e))?;

    let bytes = parse_strict_key(&content)?;

    // Final length check (already enforced inside parse, but double-check)
    if bytes.len() != EXPECTED_KEY_LEN {
        return Err(format!(
            "Key must contain exactly {} bytes (got {}).\n\
             This is required for AES-256 / XChaCha20.",
            EXPECTED_KEY_LEN,
            bytes.len()
        ));
    }

    // fs::write always overwrites the file if it already exists
    fs::write(KEY_FILE, &bytes)
        .map_err(|e| format!("Failed to write '{}': {}", KEY_FILE, e))?;

    println!("✓ Successfully wrote {}-byte key to '{}'", bytes.len(), KEY_FILE);
    println!();
    println!("Key (hex):");
    print_hex(&bytes);
    println!();
    println!("You can verify the file with:");
    println!("  xxd {}", KEY_FILE);
    println!("  or  od -An -tx1 {}", KEY_FILE);

    Ok(())
}

/// "txt" mode: read binary key → write one-number-per-line text file
fn mode_txt() -> Result<(), String> {
    let bytes = fs::read(KEY_FILE)
        .map_err(|e| format!("Failed to read '{}': {}", KEY_FILE, e))?;

    if bytes.len() != EXPECTED_KEY_LEN {
        return Err(format!(
            "'{}' must contain exactly {} bytes (got {}).\n\
             This is required for AES-256 / XChaCha20.",
            KEY_FILE,
            EXPECTED_KEY_LEN,
            bytes.len()
        ));
    }

    let mut text = String::with_capacity(EXPECTED_KEY_LEN * 4);
    for b in &bytes {
        text.push_str(&format!("{}\n", b));
    }

    // Always overwrite
    fs::write(TEXT_FILE, text)
        .map_err(|e| format!("Failed to write '{}': {}", TEXT_FILE, e))?;

    println!("✓ Successfully wrote {} numbers to '{}'", bytes.len(), TEXT_FILE);

    Ok(())
}

/// Strict parser:
/// - Exactly one number per line
/// - Line must be only whitespace + a single integer 0..=255 + whitespace
/// - No empty lines in the middle
/// - Trailing newline at end of file is fine
/// - Reports the exact line number on any error
fn parse_strict_key(content: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(EXPECTED_KEY_LEN);
    let mut line_no = 0usize;

    for line in content.lines() {
        line_no += 1;
        let trimmed = line.trim();

        // Allow a completely empty line only if it is the very last line
        // (i.e. file ends with an extra newline). Reject empty lines otherwise.
        if trimmed.is_empty() {
            // If we already have all expected bytes, ignore trailing empty lines
            if bytes.len() == EXPECTED_KEY_LEN {
                continue;
            }
            return Err(format!(
                "{}:{}: empty line is not allowed (expected a number 0-255)",
                TEXT_FILE, line_no
            ));
        }

        // Reject if there is any non-digit character left after trim
        // (this catches "12 34", "12,34", "12a", "-1", "+5", etc.)
        if !trimmed.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!(
                "{}:{}: invalid content '{}'\n\
                 Each line must contain exactly one integer from 0 to 255.\n\
                 No spaces, commas, signs, or extra characters allowed.",
                TEXT_FILE, line_no, trimmed
            ));
        }

        match trimmed.parse::<u8>() {
            Ok(b) => bytes.push(b),
            Err(_) => {
                // parse::<u8> fails for numbers > 255 or empty (already checked)
                return Err(format!(
                    "{}:{}: value '{}' is out of range. Must be an integer 0–255.",
                    TEXT_FILE, line_no, trimmed
                ));
            }
        }

        // Prevent too many numbers early
        if bytes.len() > EXPECTED_KEY_LEN {
            return Err(format!(
                "{}:{}: too many numbers. Expected exactly {} bytes for AES-256 / XChaCha20.",
                TEXT_FILE, line_no, EXPECTED_KEY_LEN
            ));
        }
    }

    if bytes.len() < EXPECTED_KEY_LEN {
        return Err(format!(
            "Only {} number(s) found in '{}'. Exactly {} are required for AES-256 / XChaCha20.",
            bytes.len(),
            TEXT_FILE,
            EXPECTED_KEY_LEN
        ));
    }

    Ok(bytes)
}

fn print_hex(bytes: &[u8]) {
    for (i, chunk) in bytes.chunks(16).enumerate() {
        print!("  {:04x}: ", i * 16);
        for b in chunk {
            print!("{:02x} ", b);
        }
        println!();
    }
}