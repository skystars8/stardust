//! XChaCha20-Poly1305 file encrypt/decrypt using `key.key` (first 32 bytes).

use crate::aead_chunk::{self, AeadParams, ChunkAead, TAG_SIZE};
use crate::error::{AppError, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use std::path::Path;

const PARAMS: AeadParams = AeadParams {
    magic: *b"ENC1XCH\x01",
    key_path: "key.key",
    key_len: 32,
    nonce_len: 24,
    alg_name: "XChaCha20-Poly1305",
};

struct XchaImpl(XChaCha20Poly1305);

impl ChunkAead for XchaImpl {
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let n = XNonce::from_slice(nonce);
        self.0
            .encrypt(
                n,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| AppError::Crypto("XChaCha20-Poly1305 encrypt failed".into()))
    }

    fn open(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < TAG_SIZE {
            return Err(AppError::InvalidCiphertext);
        }
        let n = XNonce::from_slice(nonce);
        self.0
            .decrypt(
                n,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| AppError::AuthFailed)
    }
}

pub fn run(input: &Path, output: &Path) -> Result<()> {
    aead_chunk::run_aead(&PARAMS, input, output, |key| {
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| AppError::Crypto(format!("XChaCha key init: {e}")))?;
        Ok(Box::new(XchaImpl(cipher)))
    })
}
