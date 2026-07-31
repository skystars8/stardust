//! Threefish-1024 (CTR + HMAC-SHA256) using `key.key` (first 128 bytes).

use crate::block_chunk::{self, BlockCtr, BlockParams};
use crate::error::Result;
use std::path::Path;
use threefish::Threefish1024;

const PARAMS: BlockParams = BlockParams {
    magic: *b"ENC1TF\x01\x00",
    key_path: "key.key",
    key_len: 128,
    block_size: 128,
    alg_name: "Threefish-1024-CTR-HMAC",
    mac_context: "encrypt-cli threefish-1024 mac v1",
};

struct TfCtr(Threefish1024);

impl BlockCtr for TfCtr {
    fn block_size(&self) -> usize {
        128
    }

    fn encrypt_block_inplace(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), 128);
        let mut words = [0u64; 16];
        for (w, chunk) in words.iter_mut().zip(block.chunks_exact(8)) {
            *w = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        self.0.encrypt_block_u64(&mut words);
        for (chunk, w) in block.chunks_exact_mut(8).zip(words.iter()) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
    }
}

pub fn run(input: &Path, output: &Path) -> Result<()> {
    block_chunk::run_block_cipher(&PARAMS, input, output, |key| {
        let mut k = [0u8; 128];
        k.copy_from_slice(key);
        // Zero tweak: randomness comes from the per-file CTR IV in the header.
        let cipher = Threefish1024::new_with_tweak(&k, &[0u8; 16]);
        // Zeroize stack key copy
        k.iter_mut().for_each(|b| *b = 0);
        Ok(Box::new(TfCtr(cipher)))
    })
}
