//! Serpent-256 (CTR + HMAC-SHA256) using `key.key` (first 32 bytes).

use crate::block_chunk::{self, BlockCtr, BlockParams};
use crate::error::{AppError, Result};
use cipher::{Block, BlockEncrypt, KeyInit};
use serpent::Serpent;
use std::path::Path;

const PARAMS: BlockParams = BlockParams {
    magic: *b"ENC1SER\x01",
    key_path: "key.key",
    key_len: 32,
    block_size: 16,
    alg_name: "Serpent-256-CTR-HMAC",
    mac_context: "encrypt-cli serpent-256 mac v1",
};

struct SerpentCtr(Serpent);

impl BlockCtr for SerpentCtr {
    fn block_size(&self) -> usize {
        16
    }

    fn encrypt_block_inplace(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), 16);
        let mut ga = *Block::<Serpent>::from_slice(block);
        self.0.encrypt_block(&mut ga);
        block.copy_from_slice(ga.as_slice());
    }
}

pub fn run(input: &Path, output: &Path) -> Result<()> {
    block_chunk::run_block_cipher(&PARAMS, input, output, |key| {
        // 32-byte key → Serpent-256
        let cipher = Serpent::new_from_slice(key)
            .map_err(|_| AppError::Crypto("Serpent key init failed (need 16..=32 bytes)".into()))?;
        Ok(Box::new(SerpentCtr(cipher)))
    })
}
