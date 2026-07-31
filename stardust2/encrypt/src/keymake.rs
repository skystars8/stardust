//! Deterministic, non-repeating key generation from a password.
//!
//! Pipeline:
//!   1. Argon2id(password, fixed domain salt) → 32-byte master seed
//!   2. BLAKE3 XOF keyed by that seed (domain-separated) → arbitrary-length output
//!
//! The XOF never simply tiles/repeats a short block; every byte depends on a
//! cryptographic expand. Same password + size always yields the same key.key.

use crate::error::{AppError, Result};
use crate::fsutil::{self, AtomicOutput, IO_CHUNK};
use argon2::{Algorithm, Argon2, Params, Version};
use std::io::Write;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

/// Maximum key size: 20 GiB.
pub const MAX_KEY_BYTES: u64 = 20 * 1024 * 1024 * 1024;
pub const MIN_KEY_BYTES: u64 = 1;

/// Fixed domain salt so the same password always derives the same seed.
/// This is intentional for deterministic keymake; it is not a password-store salt.
const ARGON2_SALT: &[u8] = b"encrypt-cli-keymake-v1-salt!";

/// BLAKE3 derive_key context (must stay stable for determinism).
const BLAKE3_CONTEXT: &str = "encrypt-cli keymake v1 xof expand";

/// Argon2id parameters (memory-hard; reliability over speed).
fn argon2_instance() -> Result<Argon2<'static>> {
    // 64 MiB, 3 iterations, 1 lane, 32-byte output.
    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|e| AppError::Crypto(format!("argon2 params: {e}")))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn prompt_password_twice() -> Result<Zeroizing<String>> {
    let p1 = rpassword::prompt_password("Password: ")
        .map_err(|e| AppError::msg(format!("failed to read password: {e}")))?;
    if p1.is_empty() {
        return Err(AppError::EmptyPassword);
    }
    let p2 = rpassword::prompt_password("Confirm password: ")
        .map_err(|e| AppError::msg(format!("failed to read password: {e}")))?;
    if p1 != p2 {
        return Err(AppError::PasswordMismatch);
    }
    Ok(Zeroizing::new(p1))
}

/// Derive a 32-byte master seed from the password (deterministic).
fn derive_seed(password: &str) -> Result<Zeroizing<[u8; 32]>> {
    let argon2 = argon2_instance()?;
    let mut seed = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), ARGON2_SALT, seed.as_mut())
        .map_err(|e| AppError::Crypto(format!("argon2 failed: {e}")))?;
    Ok(seed)
}

/// Stream BLAKE3 XOF output of exactly `size` bytes into `out`.
fn expand_xof_to<W: Write>(seed: &[u8; 32], size: u64, out: &mut W) -> Result<()> {
    let mut hasher = blake3::Hasher::new_derive_key(BLAKE3_CONTEXT);
    hasher.update(seed);
    // Mix in the requested length so different sizes of the same password
    // do not share a simple prefix relationship that could aid attacks.
    hasher.update(&size.to_le_bytes());
    let mut xof = hasher.finalize_xof();

    let mut remaining = size;
    let mut buf = vec![0u8; IO_CHUNK];
    while remaining > 0 {
        let n = (remaining as usize).min(buf.len());
        xof.fill(&mut buf[..n]);
        out.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    buf.zeroize();
    Ok(())
}

/// `keymake <size_bytes>` → write deterministic `key.key` in the current directory.
pub fn run(size: u64) -> Result<()> {
    if !(MIN_KEY_BYTES..=MAX_KEY_BYTES).contains(&size) {
        return Err(AppError::InvalidKeySize(size));
    }

    let out_path = Path::new("key.key");
    fsutil::refuse_if_exists(out_path)?;

    let password = prompt_password_twice()?;
    eprintln!("Deriving master seed (Argon2id, 64 MiB)…");
    let seed = derive_seed(&password)?;
    // password dropped via Zeroizing

    eprintln!("Expanding {size} byte key via BLAKE3 XOF…");
    let mut atomic = AtomicOutput::create(out_path)?;
    expand_xof_to(&seed, size, atomic.writer()?)?;
    atomic.commit()?;

    eprintln!("Wrote {} ({} bytes).", out_path.display(), size);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_is_deterministic_and_non_repeating() {
        let seed = [7u8; 32];
        let mut a = Vec::new();
        let mut b = Vec::new();
        expand_xof_to(&seed, 4096, &mut a).unwrap();
        expand_xof_to(&seed, 4096, &mut b).unwrap();
        assert_eq!(a, b);
        // First 64 bytes must not equal next 64 (rules out naive tiling).
        assert_ne!(&a[0..64], &a[64..128]);
        // Not all zeros.
        assert!(a.iter().any(|&x| x != 0));
    }
}
