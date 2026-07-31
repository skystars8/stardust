//! One-time-pad style XOR with `key.key`.
//!
//! Streaming: never loads the full input or key into RAM.
//! Requires `key.key` length ≥ input length. Output refuses overwrite.

use crate::error::{AppError, Result};
use crate::fsutil::{self, AtomicOutput, IO_CHUNK};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use zeroize::Zeroize;

const KEY_NAME: &str = "key.key";

pub fn run(input: &Path, output: &Path) -> Result<()> {
    fsutil::refuse_if_exists(output)?;

    let key_path = Path::new(KEY_NAME);
    let in_len = fsutil::file_len(input)?;
    fsutil::require_key_len(key_path, in_len)?;

    let mut in_file = fsutil::open_input_buf(input)?;
    let mut key_file = File::open(key_path)?;
    let mut atomic = AtomicOutput::create(output)?;

    let mut data = vec![0u8; IO_CHUNK];
    let mut key = vec![0u8; IO_CHUNK];
    let mut remaining = in_len;

    while remaining > 0 {
        let n = (remaining as usize).min(IO_CHUNK);
        in_file.read_exact(&mut data[..n])?;
        key_file.read_exact(&mut key[..n]).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                AppError::msg("key.key ended early (race or concurrent truncate)")
            } else {
                AppError::from(e)
            }
        })?;

        for i in 0..n {
            data[i] ^= key[i];
        }

        atomic.write_all(&data[..n])?;
        remaining -= n as u64;
    }

    data.zeroize();
    key.zeroize();
    atomic.commit()?;
    eprintln!(
        "OTP XOR complete: {} → {} ({} bytes).",
        input.display(),
        output.display(),
        in_len
    );
    Ok(())
}
