//! Chunked authenticated CTR mode for raw block ciphers (Serpent, Threefish).
//!
//! Format (version 1):
//!   magic[8] | version=1 u8 | iv[BLOCK] |
//!   repeating:
//!     chunk_pt_len: u32 BE
//!     ciphertext: pt_len bytes
//!     tag: 32-byte HMAC-SHA256
//!
//! Keystream: CTR with big-endian block counter starting at `iv`.
//! MAC key: BLAKE3 derive_key from full key material (domain-separated).
//! AAD for HMAC: magic || version || chunk_index_le || pt_len_be || ciphertext
//!
//! Auto mode: input starts with magic → decrypt, else encrypt.

use crate::error::{AppError, Result};
use crate::fsutil::{self, AtomicOutput, CRYPTO_CHUNK};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::io::{Read, Write};
use std::path::Path;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub const VERSION: u8 = 1;
pub const MAC_SIZE: usize = 32;

type HmacSha256 = Hmac<Sha256>;

pub struct BlockParams {
    pub magic: [u8; 8],
    pub key_path: &'static str,
    pub key_len: usize,
    pub block_size: usize,
    pub alg_name: &'static str,
    pub mac_context: &'static str,
}

/// Encrypts a counter block into keystream bytes (length = block_size).
pub trait BlockCtr: Send {
    fn block_size(&self) -> usize;
    fn encrypt_block_inplace(&self, block: &mut [u8]);
}

fn derive_mac_key(context: &str, key_material: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    let mut h = blake3::Hasher::new_derive_key(context);
    h.update(key_material);
    h.finalize_xof().fill(out.as_mut());
    out
}

/// Increment a big-endian counter block by 1.
fn ctr_increment(counter: &mut [u8]) {
    for b in counter.iter_mut().rev() {
        let (v, overflow) = b.overflowing_add(1);
        *b = v;
        if !overflow {
            break;
        }
    }
}

/// XOR `data` with CTR keystream starting at `counter` (updated in place).
fn ctr_xor(cipher: &dyn BlockCtr, counter: &mut [u8], data: &mut [u8]) {
    let bs = cipher.block_size();
    debug_assert_eq!(counter.len(), bs);
    let mut ks = vec![0u8; bs];
    let mut offset = 0;
    while offset < data.len() {
        ks.copy_from_slice(counter);
        cipher.encrypt_block_inplace(&mut ks);
        let n = (data.len() - offset).min(bs);
        for i in 0..n {
            data[offset + i] ^= ks[i];
        }
        ctr_increment(counter);
        offset += n;
    }
    ks.zeroize();
}

fn hmac_tag(mac_key: &[u8; 32], aad_prefix: &[u8], ciphertext: &[u8]) -> Result<[u8; MAC_SIZE]> {
    let mut mac = HmacSha256::new_from_slice(mac_key)
        .map_err(|e| AppError::Crypto(format!("hmac init: {e}")))?;
    mac.update(aad_prefix);
    mac.update(ciphertext);
    let result = mac.finalize().into_bytes();
    let mut tag = [0u8; MAC_SIZE];
    tag.copy_from_slice(&result);
    Ok(tag)
}

fn verify_hmac(mac_key: &[u8; 32], aad_prefix: &[u8], ciphertext: &[u8], tag: &[u8]) -> Result<()> {
    let expected = hmac_tag(mac_key, aad_prefix, ciphertext)?;
    if tag.len() != MAC_SIZE || !bool::from(expected.ct_eq(tag)) {
        return Err(AppError::AuthFailed);
    }
    Ok(())
}

fn make_aad_prefix(magic: &[u8; 8], version: u8, chunk_index: u64, pt_len: u32) -> Vec<u8> {
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

pub fn run_block_cipher<F>(params: &BlockParams, input: &Path, output: &Path, build: F) -> Result<()>
where
    F: FnOnce(&[u8]) -> Result<Box<dyn BlockCtr>>,
{
    fsutil::refuse_if_exists(output)?;

    let key_path = Path::new(params.key_path);
    let key = Zeroizing::new(fsutil::read_key_prefix(key_path, params.key_len)?);
    let mac_key = derive_mac_key(params.mac_context, &key);
    let cipher = build(&key)?;

    if is_ciphertext(input, &params.magic)? {
        decrypt(params, cipher.as_ref(), &mac_key, input, output)
    } else {
        encrypt(params, cipher.as_ref(), &mac_key, input, output)
    }
}

fn encrypt(
    params: &BlockParams,
    cipher: &dyn BlockCtr,
    mac_key: &[u8; 32],
    input: &Path,
    output: &Path,
) -> Result<()> {
    let mut reader = fsutil::open_input_buf(input)?;
    let mut atomic = AtomicOutput::create(output)?;

    let mut counter = vec![0u8; params.block_size];
    rand::thread_rng().fill_bytes(&mut counter);
    // Copy IV for header (counter advances during encryption).
    let iv = counter.clone();

    atomic.write_all(&params.magic)?;
    atomic.write_all(&[VERSION])?;
    atomic.write_all(&iv)?;

    let mut buf = vec![0u8; CRYPTO_CHUNK];
    let mut chunk_index: u64 = 0;
    let mut total_pt: u64 = 0;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let pt_len = n as u32;
        ctr_xor(cipher, &mut counter, &mut buf[..n]);
        let aad = make_aad_prefix(&params.magic, VERSION, chunk_index, pt_len);
        let tag = hmac_tag(mac_key, &aad, &buf[..n])?;

        fsutil::write_u32_be(&mut atomic, pt_len)?;
        atomic.write_all(&buf[..n])?;
        atomic.write_all(&tag)?;

        total_pt += n as u64;
        chunk_index = chunk_index
            .checked_add(1)
            .ok_or_else(|| AppError::msg("chunk index overflow"))?;
    }

    buf.zeroize();
    counter.zeroize();
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

fn decrypt(
    params: &BlockParams,
    cipher: &dyn BlockCtr,
    mac_key: &[u8; 32],
    input: &Path,
    output: &Path,
) -> Result<()> {
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
    let mut counter = fsutil::read_exact_n(&mut reader, params.block_size)?;

    let mut chunk_index: u64 = 0;
    let mut total_pt: u64 = 0;

    loop {
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
        let mut ct = fsutil::read_exact_n(&mut reader, pt_len as usize)?;
        let tag = fsutil::read_exact_n(&mut reader, MAC_SIZE)?;

        let aad = make_aad_prefix(&params.magic, VERSION, chunk_index, pt_len);
        verify_hmac(mac_key, &aad, &ct, &tag)?;

        ctr_xor(cipher, &mut counter, &mut ct);
        atomic.write_all(&ct)?;

        total_pt += pt_len as u64;
        chunk_index = chunk_index
            .checked_add(1)
            .ok_or_else(|| AppError::msg("chunk index overflow"))?;
        ct.zeroize();
    }

    counter.zeroize();
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
