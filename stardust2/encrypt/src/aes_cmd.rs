//! AES-256-GCM-SIV file encrypt/decrypt using `aes.key` (first 32 bytes).

use crate::aead_chunk::{self, AeadParams, ChunkAead, TAG_SIZE};
use crate::error::{AppError, Result};
use aes_gcm_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes256GcmSiv, Nonce,
};
use std::path::Path;

const PARAMS: AeadParams = AeadParams {
    magic: *b"ENC1AES\x01",
    key_path: "aes.key",
    key_len: 32,
    nonce_len: 12,
    alg_name: "AES-256-GCM-SIV",
};

struct AesImpl(Aes256GcmSiv);

impl ChunkAead for AesImpl {
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let n = Nonce::from_slice(nonce);
        self.0
            .encrypt(
                n,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| AppError::Crypto("AES-GCM-SIV encrypt failed".into()))
    }

    fn open(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < TAG_SIZE {
            return Err(AppError::InvalidCiphertext);
        }
        let n = Nonce::from_slice(nonce);
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
        let cipher = Aes256GcmSiv::new_from_slice(key)
            .map_err(|e| AppError::Crypto(format!("AES key init: {e}")))?;
        Ok(Box::new(AesImpl(cipher)))
    })
}
