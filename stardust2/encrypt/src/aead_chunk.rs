//! Chunked AEAD file encryption for AES-256-GCM-SIV and XChaCha20-Poly1305.
//!
//! Format (version 1):
//!   magic[8] | version=1 u8 | file_nonce[N] |
//!   repeating:
//!     chunk_pt_len: u32 BE
//!     ciphertext || tag   (pt_len + TAG_SIZE bytes)
//!
//! Per-chunk nonce = BLAKE3(file_nonce || chunk_index_le)[0..N]
//! AAD             = magic || version || chunk_index_le || pt_len_be
//!
//! Auto mode: if input begins with `magic` → decrypt, else encrypt.
//! Streaming: one CRYPTO_CHUNK of plaintext (or ct+tag) in RAM at a time.

use crate::error::{AppError, Result};
use crate::fsutil::{self, AtomicOutput, CRYPTO_CHUNK};
use rand::RngCore;
use std::io::{Read, Write};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

pub const VERSION: u8 = 1;
pub const TAG_SIZE: usize = 16;

pub struct AeadParams {
    pub magic: [u8; 8],
    pub key_path: &'static str,
    pub key_len: usize,
    pub nonce_len: usize,
    pub alg_name: &'static str,
}

/// Encrypt or decrypt a single chunk. Implementations must be AEAD.
pub trait ChunkAead {
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;
    fn open(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
}

fn derive_chunk_nonce(file_nonce: &[u8], chunk_index: u64, out_len: usize) -> Vec<u8> {
    let mut h = blake3::Hasher::new_derive_key("encrypt-cli aead chunk nonce v1");
    h.update(file_nonce);
    h.update(&chunk_index.to_le_bytes());
    let mut out = vec![0u8; out_len];
    h.finalize_xof().fill(&mut out);
    out
}

fn make_aad(magic: &[u8; 8], version: u8, chunk_index: u64, pt_len: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + 1 + 8 + 4);
    aad.extend_from_slice(magic);
    aad.push(version);
    aad.extend_from_slice(&chunk_index.to_le_bytes());
    aad.extend_from_slice(&pt_len.to_be_bytes());
    aad
}

fn is_ciphertext(path: &Path, magic: &[u8; 8]) -> Result<bool> {
    let prefix = fsutil::peek_prefix(path, magic.len())?;
    Ok(prefix.as_slice() == magic)
}

pub fn run_aead<F>(params: &AeadParams, input: &Path, output: &Path, build: F) -> Result<()>
where
    F: FnOnce(&[u8]) -> Result<Box<dyn ChunkAead>>,
{
    fsutil::refuse_if_exists(output)?;

    let key_path = Path::new(params.key_path);
    let mut key = Zeroizing::new(fsutil::read_key_prefix(key_path, params.key_len)?);
    let cipher = build(&key)?;
    key.zeroize();

    if is_ciphertext(input, &params.magic)? {
        decrypt(params, cipher.as_ref(), input, output)
    } else {
        encrypt(params, cipher.as_ref(), input, output)
    }
}

fn encrypt(params: &AeadParams, cipher: &dyn ChunkAead, input: &Path, output: &Path) -> Result<()> {
    let mut reader = fsutil::open_input_buf(input)?;
    let mut atomic = AtomicOutput::create(output)?;

    let mut file_nonce = vec![0u8; params.nonce_len];
    rand::thread_rng().fill_bytes(&mut file_nonce);

    atomic.write_all(&params.magic)?;
    atomic.write_all(&[VERSION])?;
    atomic.write_all(&file_nonce)?;

    let mut pt = vec![0u8; CRYPTO_CHUNK];
    let mut chunk_index: u64 = 0;
    let mut total_pt: u64 = 0;

    loop {
        let n = reader.read(&mut pt)?;
        if n == 0 {
            break;
        }
        let pt_len = n as u32;
        let nonce = derive_chunk_nonce(&file_nonce, chunk_index, params.nonce_len);
        let aad = make_aad(&params.magic, VERSION, chunk_index, pt_len);
        let ct = cipher.seal(&nonce, &aad, &pt[..n])?;
        // ct must be n + TAG_SIZE
        if ct.len() != n + TAG_SIZE {
            return Err(AppError::Crypto(format!(
                "unexpected ciphertext length {} (want {})",
                ct.len(),
                n + TAG_SIZE
            )));
        }
        fsutil::write_u32_be(&mut atomic, pt_len)?;
        atomic.write_all(&ct)?;
        total_pt += n as u64;
        chunk_index = chunk_index
            .checked_add(1)
            .ok_or_else(|| AppError::msg("chunk index overflow"))?;
    }

    // Empty file: still a valid header with zero chunks.
    pt.zeroize();
    file_nonce.zeroize();
    atomic.commit()?;
    eprintln!(
        "{} encrypt: {} → {} ({} plaintext bytes, {} chunks).",
        params.alg_name,
        input.display(),
        output.display(),
        total_pt,
        chunk_index
    );
    Ok(())
}

fn decrypt(params: &AeadParams, cipher: &dyn ChunkAead, input: &Path, output: &Path) -> Result<()> {
    let mut reader = fsutil::open_input_buf(input)?;
    let mut atomic = AtomicOutput::create(output)?;

    let magic = fsutil::read_exact_n(&mut reader, 8)?;
    if magic.as_slice() != params.magic {
        return Err(AppError::InvalidCiphertext);
    }
    let ver = fsutil::read_exact_n(&mut reader, 1)?;
    if ver[0] != VERSION {
        return Err(AppError::msg(format!(
            "unsupported {} ciphertext version {}",
            params.alg_name, ver[0]
        )));
    }
    let file_nonce = fsutil::read_exact_n(&mut reader, params.nonce_len)?;

    let mut chunk_index: u64 = 0;
    let mut total_pt: u64 = 0;

    loop {
        // Detect clean EOF between chunks.
        let mut len_buf = [0u8; 4];
        match reader.read(&mut len_buf)? {
            0 => break,
            4 => {}
            _ => return Err(AppError::InvalidCiphertext),
        }
        let pt_len = u32::from_be_bytes(len_buf);
        if pt_len as usize > CRYPTO_CHUNK {
            return Err(AppError::msg(format!(
                "chunk length {pt_len} exceeds maximum {}",
                CRYPTO_CHUNK
            )));
        }
        let ct_len = pt_len as usize + TAG_SIZE;
        let ct = fsutil::read_exact_n(&mut reader, ct_len)?;
        let nonce = derive_chunk_nonce(&file_nonce, chunk_index, params.nonce_len);
        let aad = make_aad(
            &params.magic,
            VERSION,
            chunk_index,
            pt_len,
        );
        let pt = cipher.open(&nonce, &aad, &ct)?;
        if pt.len() != pt_len as usize {
            return Err(AppError::InvalidCiphertext);
        }
        atomic.write_all(&pt)?;
        total_pt += pt_len as u64;
        chunk_index = chunk_index
            .checked_add(1)
            .ok_or_else(|| AppError::msg("chunk index overflow"))?;
    }

    atomic.commit()?;
    eprintln!(
        "{} decrypt: {} → {} ({} plaintext bytes, {} chunks).",
        params.alg_name,
        input.display(),
        output.display(),
        total_pt,
        chunk_index
    );
    Ok(())
}
