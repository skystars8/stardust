#![forbid(unsafe_code)]

use std::fmt;
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use aes_gcm_siv::aead::{AeadInPlace, KeyInit as AeadKeyInit};
use aes_gcm_siv::{Aes256GcmSiv, Nonce as AesNonce};
use anyhow::{Context, Result, anyhow, bail, ensure};
use argon2::{Algorithm as ArgonAlgorithm, Argon2, Block as ArgonBlock, Params, Version};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use clap::ValueEnum;
use hmac::{Hmac, Mac};
use serpent::Serpent;
use serpent::cipher::{Block, BlockCipherEncrypt, KeyInit as BlockKeyInit};
use sha2::Sha256;
use tempfile::{Builder as TempBuilder, NamedTempFile};
use threefish::Threefish1024;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"SECRv001";
const FORMAT_VERSION: u8 = 1;
const HEADER_LEN: usize = 64;
const CHUNK_SIZE: usize = 1024 * 1024;
const AEAD_TAG_LEN: u64 = 16;
const HMAC_TAG_LEN: u64 = 32;
const MIN_CRYPTO_KEY_FILE_LEN: u64 = 32;
const MAX_KEYMAKE_SIZE: u64 = 20_000_000_000;
const IO_BUFFER_SIZE: usize = 1024 * 1024;
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_LANES: u32 = 1;
const ARGON2_SALT: &[u8] = b"secure/keymake/argon2id/v1";

type HmacSha256 = Hmac<Sha256>;
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

pub fn install_interrupt_handler() -> Result<()> {
    ctrlc::set_handler(|| INTERRUPTED.store(true, Ordering::SeqCst))
        .map_err(|error| anyhow!("cannot install Ctrl+C handler: {error}"))
}

fn check_interrupted() -> Result<()> {
    ensure!(!INTERRUPTED.load(Ordering::SeqCst), "operation interrupted");
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum Mode {
    Auto,
    Encrypt,
    Decrypt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

impl fmt::Display for Operation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encrypt => formatter.write_str("encrypt"),
            Self::Decrypt => formatter.write_str("decrypt"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    Aes256GcmSiv,
    XChaCha20Poly1305,
    Serpent256,
    Threefish1024,
}

impl Algorithm {
    fn id(self) -> u8 {
        match self {
            Self::Aes256GcmSiv => 1,
            Self::XChaCha20Poly1305 => 2,
            Self::Serpent256 => 3,
            Self::Threefish1024 => 4,
        }
    }

    fn from_id(id: u8) -> Result<Self> {
        match id {
            1 => Ok(Self::Aes256GcmSiv),
            2 => Ok(Self::XChaCha20Poly1305),
            3 => Ok(Self::Serpent256),
            4 => Ok(Self::Threefish1024),
            _ => bail!("unsupported algorithm identifier {id}"),
        }
    }

    fn key_filename(self) -> &'static str {
        match self {
            Self::Aes256GcmSiv => "aes.key",
            Self::XChaCha20Poly1305 | Self::Serpent256 | Self::Threefish1024 => "key.key",
        }
    }

    fn key_context(self) -> &'static str {
        match self {
            Self::Aes256GcmSiv => "secure/file-key-master/aes-256-gcm-siv/v1",
            Self::XChaCha20Poly1305 => "secure/file-key-master/xchacha20-poly1305/v1",
            Self::Serpent256 => "secure/file-key-master/serpent-256-ctr-hmac-sha256/v1",
            Self::Threefish1024 => "secure/file-key-master/threefish-1024-ctr-hmac-sha256/v1",
        }
    }

    fn file_context(self) -> &'static [u8] {
        match self {
            Self::Aes256GcmSiv => b"secure/per-file/aes-256-gcm-siv/v1",
            Self::XChaCha20Poly1305 => b"secure/per-file/xchacha20-poly1305/v1",
            Self::Serpent256 => b"secure/per-file/serpent-256-ctr-hmac-sha256/v1",
            Self::Threefish1024 => b"secure/per-file/threefish-1024-ctr-hmac-sha256/v1",
        }
    }

    fn tag_len(self) -> u64 {
        match self {
            Self::Aes256GcmSiv | Self::XChaCha20Poly1305 => AEAD_TAG_LEN,
            Self::Serpent256 | Self::Threefish1024 => HMAC_TAG_LEN,
        }
    }

    fn material_len(self) -> usize {
        match self {
            Self::Aes256GcmSiv | Self::XChaCha20Poly1305 => 32,
            Self::Serpent256 => 64,
            Self::Threefish1024 => 160,
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aes256GcmSiv => formatter.write_str("AES-256-GCM-SIV"),
            Self::XChaCha20Poly1305 => formatter.write_str("XChaCha20-Poly1305"),
            Self::Serpent256 => formatter.write_str("Serpent-256"),
            Self::Threefish1024 => formatter.write_str("Threefish-1024"),
        }
    }
}

#[derive(Clone)]
struct Header {
    algorithm: Algorithm,
    plaintext_len: u64,
    salt: [u8; 32],
    encoded: [u8; HEADER_LEN],
}

impl Header {
    fn new(algorithm: Algorithm, plaintext_len: u64) -> Result<Self> {
        let mut salt = [0_u8; 32];
        getrandom::fill(&mut salt)
            .map_err(|error| anyhow!("operating-system random number generator failed: {error}"))?;

        let mut encoded = [0_u8; HEADER_LEN];
        encoded[..8].copy_from_slice(MAGIC);
        encoded[8] = FORMAT_VERSION;
        encoded[9] = algorithm.id();
        encoded[10..12].copy_from_slice(&0_u16.to_le_bytes());
        encoded[12..16].copy_from_slice(&(CHUNK_SIZE as u32).to_le_bytes());
        encoded[16..24].copy_from_slice(&plaintext_len.to_le_bytes());
        encoded[24..56].copy_from_slice(&salt);

        Ok(Self {
            algorithm,
            plaintext_len,
            salt,
            encoded,
        })
    }

    fn parse(encoded: [u8; HEADER_LEN]) -> Result<Self> {
        ensure!(
            &encoded[..8] == MAGIC,
            "input has no secure encrypted-file header"
        );
        ensure!(
            encoded[8] == FORMAT_VERSION,
            "unsupported encrypted-file format version {}",
            encoded[8]
        );
        let algorithm = Algorithm::from_id(encoded[9])?;
        ensure!(
            encoded[10..12] == [0, 0],
            "unsupported encrypted-file flags"
        );
        let chunk_size = u32::from_le_bytes([encoded[12], encoded[13], encoded[14], encoded[15]]);
        ensure!(
            chunk_size as usize == CHUNK_SIZE,
            "unsupported encrypted-file chunk size {chunk_size}"
        );
        ensure!(
            encoded[56..].iter().all(|byte| *byte == 0),
            "encrypted-file header has unsupported extensions"
        );

        let plaintext_len = u64::from_le_bytes([
            encoded[16],
            encoded[17],
            encoded[18],
            encoded[19],
            encoded[20],
            encoded[21],
            encoded[22],
            encoded[23],
        ]);
        let mut salt = [0_u8; 32];
        salt.copy_from_slice(&encoded[24..56]);
        Ok(Self {
            algorithm,
            plaintext_len,
            salt,
            encoded,
        })
    }
}

struct AtomicOutput {
    destination: PathBuf,
    temporary: NamedTempFile,
}

impl AtomicOutput {
    fn new(destination: &Path) -> Result<Self> {
        ensure_destination_absent(destination)?;
        let parent = useful_parent(destination);
        ensure!(
            parent.is_dir(),
            "output parent is not a directory: {}",
            parent.display()
        );
        let temporary = TempBuilder::new()
            .prefix(".secure-")
            .tempfile_in(parent)
            .with_context(|| {
                format!(
                    "cannot create temporary output in directory {}",
                    parent.display()
                )
            })?;
        Ok(Self {
            destination: destination.to_owned(),
            temporary,
        })
    }

    fn writer(&mut self) -> &mut File {
        self.temporary.as_file_mut()
    }

    fn commit(mut self) -> Result<()> {
        check_interrupted()?;
        self.temporary
            .as_file_mut()
            .flush()
            .context("cannot flush temporary output")?;
        self.temporary
            .as_file()
            .sync_all()
            .context("cannot synchronize temporary output")?;
        let destination = self.destination.clone();
        let persisted = self
            .temporary
            .persist_noclobber(&destination)
            .map_err(|error| error.error)
            .with_context(|| {
                format!(
                    "cannot publish output without overwriting {}",
                    destination.display()
                )
            })?;
        persisted
            .sync_all()
            .context("cannot synchronize published output")?;
        sync_parent_directory(&destination)?;
        Ok(())
    }
}

pub fn keymake(size: u64, password: &[u8]) -> Result<()> {
    keymake_at(Path::new("key.key"), size, password)
}

fn keymake_at(destination: &Path, size: u64, password: &[u8]) -> Result<()> {
    check_interrupted()?;
    ensure!(
        (1..=MAX_KEYMAKE_SIZE).contains(&size),
        "key size must be from 1 through {MAX_KEYMAKE_SIZE} bytes"
    );
    ensure!(!password.is_empty(), "password must not be empty");

    let mut output = AtomicOutput::new(destination)?;
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_LANES, Some(32))
        .map_err(|error| anyhow!("invalid built-in Argon2id parameters: {error}"))?;
    let argon2 = Argon2::new(ArgonAlgorithm::Argon2id, Version::V0x13, params);
    let mut seed = Zeroizing::new([0_u8; 32]);
    let mut argon_memory = Zeroizing::new(vec![ArgonBlock::default(); ARGON2_MEMORY_KIB as usize]);
    argon2
        .hash_password_into_with_memory(
            password,
            ARGON2_SALT,
            seed.as_mut(),
            argon_memory.as_mut_slice(),
        )
        .map_err(|error| anyhow!("Argon2id password derivation failed: {error}"))?;
    check_interrupted()?;
    drop(argon_memory);

    let mut hasher = Zeroizing::new(blake3::Hasher::new_keyed(&seed));
    drop(seed);
    hasher.update(b"secure/keymake/blake3-xof/v1");
    hasher.update(&size.to_le_bytes());
    let mut reader = Zeroizing::new(hasher.finalize_xof());
    drop(hasher);
    let mut buffer = Zeroizing::new(vec![0_u8; IO_BUFFER_SIZE]);
    let mut remaining = size;
    while remaining > 0 {
        check_interrupted()?;
        let amount = remaining.min(IO_BUFFER_SIZE as u64) as usize;
        reader.fill(&mut buffer[..amount]);
        output
            .writer()
            .write_all(&buffer[..amount])
            .context("cannot write generated key")?;
        remaining -= amount as u64;
    }
    output.commit()
}

pub fn otp(input_path: &Path, output_path: &Path) -> Result<()> {
    let mut input = open_regular_file(input_path, "input")?;
    let input_len = input.metadata().context("cannot inspect input file")?.len();
    ensure_destination_absent(output_path)?;
    let key_path = adjacent_key_path(input_path, "key.key");
    ensure_distinct_files(input_path, &key_path, "input and key")?;
    let mut key = open_regular_file(&key_path, "key")?;
    let key_len = key.metadata().context("cannot inspect key file")?.len();
    ensure!(
        key_len >= input_len,
        "{} is too short: need at least {input_len} bytes, found {key_len}",
        key_path.display()
    );

    let mut output = AtomicOutput::new(output_path)?;
    let mut input_buffer = Zeroizing::new(vec![0_u8; IO_BUFFER_SIZE]);
    let mut key_buffer = Zeroizing::new(vec![0_u8; IO_BUFFER_SIZE]);
    let mut remaining = input_len;
    while remaining > 0 {
        check_interrupted()?;
        let amount = remaining.min(IO_BUFFER_SIZE as u64) as usize;
        input
            .read_exact(&mut input_buffer[..amount])
            .context("input file changed or could not be read")?;
        key.read_exact(&mut key_buffer[..amount])
            .context("key file changed or could not be read")?;
        for (byte, key_byte) in input_buffer[..amount].iter_mut().zip(&key_buffer[..amount]) {
            *byte ^= *key_byte;
        }
        output
            .writer()
            .write_all(&input_buffer[..amount])
            .context("cannot write XOR output")?;
        remaining -= amount as u64;
    }
    ensure_end_of_file(&mut input, "input file grew while it was being read")?;
    output.commit()
}

pub fn crypt_file(
    algorithm: Algorithm,
    input_path: &Path,
    output_path: &Path,
    mode: Mode,
) -> Result<Operation> {
    let mut input = open_regular_file(input_path, "input")?;
    let input_len = input.metadata().context("cannot inspect input file")?.len();
    let operation = detect_operation(&mut input, mode)?;

    match operation {
        Operation::Encrypt => {
            ensure_destination_absent(output_path)?;
            let key_path = adjacent_key_path(input_path, algorithm.key_filename());
            ensure_distinct_files(input_path, &key_path, "input and key")?;
            let master_key = derive_master_key(&key_path, algorithm)?;
            let mut output = AtomicOutput::new(output_path)?;
            let header = Header::new(algorithm, input_len)?;
            let material = derive_file_material(algorithm, &master_key, &header.salt);
            encrypt_stream(&mut input, output.writer(), &header, material.as_ref())?;
            output.commit()?;
        }
        Operation::Decrypt => {
            let header = read_header(&mut input)?;
            ensure!(
                header.algorithm == algorithm,
                "input uses {}, not {algorithm}",
                header.algorithm
            );
            validate_encrypted_length(input_len, &header)?;
            ensure_destination_absent(output_path)?;
            let key_path = adjacent_key_path(input_path, algorithm.key_filename());
            ensure_distinct_files(input_path, &key_path, "input and key")?;
            let master_key = derive_master_key(&key_path, algorithm)?;
            let mut output = AtomicOutput::new(output_path)?;
            let material = derive_file_material(algorithm, &master_key, &header.salt);
            decrypt_stream(&mut input, output.writer(), &header, material.as_ref())?;
            output.commit()?;
        }
    }
    Ok(operation)
}

fn detect_operation(input: &mut File, mode: Mode) -> Result<Operation> {
    match mode {
        Mode::Encrypt => Ok(Operation::Encrypt),
        Mode::Decrypt => Ok(Operation::Decrypt),
        Mode::Auto => {
            let mut prefix = [0_u8; 8];
            let count = input
                .read(&mut prefix)
                .context("cannot inspect input file header")?;
            input
                .seek(SeekFrom::Start(0))
                .context("cannot rewind input file")?;
            if count == prefix.len() && &prefix == MAGIC {
                Ok(Operation::Decrypt)
            } else {
                Ok(Operation::Encrypt)
            }
        }
    }
}

fn encrypt_stream(
    input: &mut File,
    output: &mut File,
    header: &Header,
    material: &[u8],
) -> Result<()> {
    output
        .write_all(&header.encoded)
        .context("cannot write encrypted-file header")?;
    let chunks = chunk_count(header.plaintext_len);
    let mut buffer = Zeroizing::new(vec![0_u8; CHUNK_SIZE]);
    for index in 0..chunks {
        check_interrupted()?;
        let amount = chunk_plaintext_len(header.plaintext_len, index)?;
        input
            .read_exact(&mut buffer[..amount])
            .with_context(|| format!("input changed while reading chunk {index}"))?;
        encrypt_chunk(header, material, index, &mut buffer[..amount], output)
            .with_context(|| format!("cannot encrypt chunk {index}"))?;
    }
    ensure_end_of_file(input, "input file grew while it was being encrypted")
}

fn decrypt_stream(
    input: &mut File,
    output: &mut File,
    header: &Header,
    material: &[u8],
) -> Result<()> {
    let chunks = chunk_count(header.plaintext_len);
    let mut buffer = Zeroizing::new(vec![0_u8; CHUNK_SIZE]);
    for index in 0..chunks {
        check_interrupted()?;
        let amount = chunk_plaintext_len(header.plaintext_len, index)?;
        input
            .read_exact(&mut buffer[..amount])
            .with_context(|| format!("encrypted input ended in chunk {index}"))?;
        decrypt_chunk(header, material, index, &mut buffer[..amount], input)
            .with_context(|| format!("authentication failed at chunk {index}"))?;
        output
            .write_all(&buffer[..amount])
            .with_context(|| format!("cannot write plaintext chunk {index}"))?;
    }
    ensure_end_of_file(input, "encrypted input has unauthenticated trailing data")
}

fn encrypt_chunk(
    header: &Header,
    material: &[u8],
    index: u64,
    chunk: &mut [u8],
    output: &mut File,
) -> Result<()> {
    let aad = chunk_aad(header, index, chunk.len());
    match header.algorithm {
        Algorithm::Aes256GcmSiv => {
            let cipher = Aes256GcmSiv::new_from_slice(material)
                .map_err(|_| anyhow!("invalid internal AES key length"))?;
            let nonce_bytes = aead_nonce::<12>(index);
            let tag = cipher
                .encrypt_in_place_detached(AesNonce::from_slice(&nonce_bytes), &aad, chunk)
                .map_err(|_| anyhow!("AES-GCM-SIV encryption failed"))?;
            output.write_all(chunk)?;
            output.write_all(tag.as_slice())?;
        }
        Algorithm::XChaCha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(material)
                .map_err(|_| anyhow!("invalid internal XChaCha20 key length"))?;
            let nonce_bytes = aead_nonce::<24>(index);
            let tag = cipher
                .encrypt_in_place_detached(XNonce::from_slice(&nonce_bytes), &aad, chunk)
                .map_err(|_| anyhow!("XChaCha20-Poly1305 encryption failed"))?;
            output.write_all(chunk)?;
            output.write_all(tag.as_slice())?;
        }
        Algorithm::Serpent256 => {
            serpent_ctr_xor(&material[..32], index, chunk)?;
            let tag = make_hmac(&material[32..64], &aad, chunk)?;
            output.write_all(chunk)?;
            output.write_all(&tag)?;
        }
        Algorithm::Threefish1024 => {
            threefish_ctr_xor(&material[..128], index, chunk)?;
            let tag = make_hmac(&material[128..160], &aad, chunk)?;
            output.write_all(chunk)?;
            output.write_all(&tag)?;
        }
    }
    Ok(())
}

fn decrypt_chunk(
    header: &Header,
    material: &[u8],
    index: u64,
    chunk: &mut [u8],
    input: &mut File,
) -> Result<()> {
    let aad = chunk_aad(header, index, chunk.len());
    match header.algorithm {
        Algorithm::Aes256GcmSiv => {
            let mut tag = [0_u8; AEAD_TAG_LEN as usize];
            input.read_exact(&mut tag)?;
            let cipher = Aes256GcmSiv::new_from_slice(material)
                .map_err(|_| anyhow!("invalid internal AES key length"))?;
            let nonce_bytes = aead_nonce::<12>(index);
            cipher
                .decrypt_in_place_detached(
                    AesNonce::from_slice(&nonce_bytes),
                    &aad,
                    chunk,
                    aes_gcm_siv::Tag::from_slice(&tag),
                )
                .map_err(|_| anyhow!("wrong key or damaged encrypted input"))?;
        }
        Algorithm::XChaCha20Poly1305 => {
            let mut tag = [0_u8; AEAD_TAG_LEN as usize];
            input.read_exact(&mut tag)?;
            let cipher = XChaCha20Poly1305::new_from_slice(material)
                .map_err(|_| anyhow!("invalid internal XChaCha20 key length"))?;
            let nonce_bytes = aead_nonce::<24>(index);
            cipher
                .decrypt_in_place_detached(
                    XNonce::from_slice(&nonce_bytes),
                    &aad,
                    chunk,
                    chacha20poly1305::Tag::from_slice(&tag),
                )
                .map_err(|_| anyhow!("wrong key or damaged encrypted input"))?;
        }
        Algorithm::Serpent256 => {
            let mut tag = [0_u8; HMAC_TAG_LEN as usize];
            input.read_exact(&mut tag)?;
            verify_hmac(&material[32..64], &aad, chunk, &tag)?;
            serpent_ctr_xor(&material[..32], index, chunk)?;
        }
        Algorithm::Threefish1024 => {
            let mut tag = [0_u8; HMAC_TAG_LEN as usize];
            input.read_exact(&mut tag)?;
            verify_hmac(&material[128..160], &aad, chunk, &tag)?;
            threefish_ctr_xor(&material[..128], index, chunk)?;
        }
    }
    Ok(())
}

fn serpent_ctr_xor(key: &[u8], chunk_index: u64, data: &mut [u8]) -> Result<()> {
    let cipher =
        Serpent::new_from_slice(key).map_err(|_| anyhow!("invalid internal Serpent key length"))?;
    let blocks_per_chunk = (CHUNK_SIZE / 16) as u128;
    let first_counter = u128::from(chunk_index)
        .checked_mul(blocks_per_chunk)
        .ok_or_else(|| anyhow!("Serpent counter overflow"))?;
    for (offset, bytes) in data.chunks_mut(16).enumerate() {
        check_interrupted()?;
        let counter = first_counter
            .checked_add(offset as u128)
            .ok_or_else(|| anyhow!("Serpent counter overflow"))?;
        let mut block = Block::<Serpent>::default();
        block.copy_from_slice(&counter.to_le_bytes());
        cipher.encrypt_block(&mut block);
        for (byte, stream_byte) in bytes.iter_mut().zip(block.iter()) {
            *byte ^= stream_byte;
        }
    }
    Ok(())
}

fn threefish_ctr_xor(key: &[u8], chunk_index: u64, data: &mut [u8]) -> Result<()> {
    let key: &[u8; 128] = key
        .try_into()
        .map_err(|_| anyhow!("invalid internal Threefish key length"))?;
    let cipher = Threefish1024::new_with_tweak(key, &[0_u8; 16]);
    let blocks_per_chunk = (CHUNK_SIZE / 128) as u128;
    let first_counter = u128::from(chunk_index)
        .checked_mul(blocks_per_chunk)
        .ok_or_else(|| anyhow!("Threefish counter overflow"))?;
    for (offset, bytes) in data.chunks_mut(128).enumerate() {
        check_interrupted()?;
        let counter = first_counter
            .checked_add(offset as u128)
            .ok_or_else(|| anyhow!("Threefish counter overflow"))?;
        let mut block = [0_u64; 16];
        block[0] = counter as u64;
        block[1] = (counter >> 64) as u64;
        cipher.encrypt_block_u64(&mut block);
        for (word_index, word) in block.iter().enumerate() {
            let stream_bytes = word.to_le_bytes();
            let start = word_index * 8;
            if start >= bytes.len() {
                break;
            }
            let end = (start + 8).min(bytes.len());
            for (byte, stream_byte) in bytes[start..end]
                .iter_mut()
                .zip(&stream_bytes[..end - start])
            {
                *byte ^= stream_byte;
            }
        }
    }
    Ok(())
}

fn make_hmac(key: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|_| anyhow!("invalid internal MAC key"))?;
    mac.update(aad);
    mac.update(ciphertext);
    Ok(mac.finalize().into_bytes().into())
}

fn verify_hmac(key: &[u8], aad: &[u8], ciphertext: &[u8], tag: &[u8]) -> Result<()> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|_| anyhow!("invalid internal MAC key"))?;
    mac.update(aad);
    mac.update(ciphertext);
    mac.verify_slice(tag)
        .map_err(|_| anyhow!("wrong key or damaged encrypted input"))
}

fn derive_master_key(key_path: &Path, algorithm: Algorithm) -> Result<Zeroizing<[u8; 32]>> {
    let mut key_file = open_regular_file(key_path, "key")?;
    let expected_len = key_file
        .metadata()
        .with_context(|| format!("cannot inspect key file {}", key_path.display()))?
        .len();
    ensure!(
        expected_len >= MIN_CRYPTO_KEY_FILE_LEN,
        "{} must contain at least {MIN_CRYPTO_KEY_FILE_LEN} bytes",
        key_path.display()
    );

    let mut hasher = Zeroizing::new(blake3::Hasher::new_derive_key(algorithm.key_context()));
    hasher.update(&expected_len.to_le_bytes());
    let mut buffer = Zeroizing::new(vec![0_u8; IO_BUFFER_SIZE]);
    let mut observed_len = 0_u64;
    loop {
        check_interrupted()?;
        let count = key_file
            .read(buffer.as_mut_slice())
            .with_context(|| format!("cannot read key file {}", key_path.display()))?;
        if count == 0 {
            break;
        }
        observed_len = observed_len
            .checked_add(count as u64)
            .ok_or_else(|| anyhow!("key file is too large"))?;
        hasher.update(&buffer[..count]);
    }
    ensure!(
        observed_len == expected_len,
        "key file changed while it was being read"
    );

    let mut result = Zeroizing::new([0_u8; 32]);
    let digest = Zeroizing::new(hasher.finalize());
    result.copy_from_slice(digest.as_bytes());
    Ok(result)
}

fn derive_file_material(
    algorithm: Algorithm,
    master_key: &[u8; 32],
    salt: &[u8; 32],
) -> Zeroizing<Vec<u8>> {
    let mut hasher = Zeroizing::new(blake3::Hasher::new_keyed(master_key));
    hasher.update(algorithm.file_context());
    hasher.update(salt);
    let mut material = Zeroizing::new(vec![0_u8; algorithm.material_len()]);
    let mut reader = Zeroizing::new(hasher.finalize_xof());
    reader.fill(material.as_mut_slice());
    material
}

fn chunk_aad(header: &Header, index: u64, length: usize) -> [u8; HEADER_LEN + 12] {
    let mut aad = [0_u8; HEADER_LEN + 12];
    aad[..HEADER_LEN].copy_from_slice(&header.encoded);
    aad[HEADER_LEN..HEADER_LEN + 8].copy_from_slice(&index.to_le_bytes());
    aad[HEADER_LEN + 8..].copy_from_slice(&(length as u32).to_le_bytes());
    aad
}

fn aead_nonce<const N: usize>(index: u64) -> [u8; N] {
    let mut nonce = [0_u8; N];
    nonce[N - 8..].copy_from_slice(&index.to_le_bytes());
    nonce
}

fn chunk_count(plaintext_len: u64) -> u64 {
    if plaintext_len == 0 {
        1
    } else {
        plaintext_len.div_ceil(CHUNK_SIZE as u64)
    }
}

fn chunk_plaintext_len(plaintext_len: u64, index: u64) -> Result<usize> {
    if plaintext_len == 0 {
        ensure!(index == 0, "invalid empty-file chunk index");
        return Ok(0);
    }
    let offset = index
        .checked_mul(CHUNK_SIZE as u64)
        .ok_or_else(|| anyhow!("chunk offset overflow"))?;
    let remaining = plaintext_len
        .checked_sub(offset)
        .ok_or_else(|| anyhow!("invalid chunk index"))?;
    Ok(remaining.min(CHUNK_SIZE as u64) as usize)
}

fn validate_encrypted_length(actual_len: u64, header: &Header) -> Result<()> {
    let tag_bytes = chunk_count(header.plaintext_len)
        .checked_mul(header.algorithm.tag_len())
        .ok_or_else(|| anyhow!("encrypted-file size overflow"))?;
    let expected_len = (HEADER_LEN as u64)
        .checked_add(header.plaintext_len)
        .and_then(|length| length.checked_add(tag_bytes))
        .ok_or_else(|| anyhow!("encrypted-file size overflow"))?;
    ensure!(
        actual_len == expected_len,
        "encrypted-file length is invalid: expected {expected_len} bytes, found {actual_len}"
    );
    Ok(())
}

fn read_header(input: &mut File) -> Result<Header> {
    input
        .seek(SeekFrom::Start(0))
        .context("cannot rewind encrypted input")?;
    let mut encoded = [0_u8; HEADER_LEN];
    input
        .read_exact(&mut encoded)
        .context("encrypted-file header is truncated")?;
    Header::parse(encoded)
}

fn open_regular_file(path: &Path, description: &str) -> Result<File> {
    let file = File::open(path)
        .with_context(|| format!("cannot open {description} file {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("cannot inspect {description} file {}", path.display()))?;
    ensure!(
        metadata.is_file(),
        "{description} path is not a regular file: {}",
        path.display()
    );
    Ok(file)
}

fn ensure_destination_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!("refusing to overwrite existing path: {}", path.display()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("cannot inspect output path {}", path.display()))
        }
    }
}

fn ensure_distinct_files(first: &Path, second: &Path, description: &str) -> Result<()> {
    let first = fs::canonicalize(first)
        .with_context(|| format!("cannot resolve path {}", first.display()))?;
    let second = fs::canonicalize(second)
        .with_context(|| format!("cannot resolve path {}", second.display()))?;
    ensure!(first != second, "{description} must be different files");
    Ok(())
}

fn ensure_end_of_file(file: &mut File, message: &str) -> Result<()> {
    let mut extra = [0_u8; 1];
    ensure!(file.read(&mut extra)? == 0, "{message}");
    Ok(())
}

fn adjacent_key_path(input_path: &Path, filename: &str) -> PathBuf {
    useful_parent(input_path).join(filename)
}

fn useful_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<()> {
    File::open(useful_parent(path))
        .context("cannot open output directory for synchronization")?
        .sync_all()
        .context("cannot synchronize output directory")
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| (index.wrapping_mul(131).wrapping_add(17) & 0xff) as u8)
            .collect()
    }

    #[test]
    fn all_algorithms_round_trip_empty_and_small_files() {
        for algorithm in [
            Algorithm::Aes256GcmSiv,
            Algorithm::XChaCha20Poly1305,
            Algorithm::Serpent256,
            Algorithm::Threefish1024,
        ] {
            for plaintext in [Vec::new(), bytes(4099)] {
                let directory = tempfile::tempdir().unwrap();
                fs::write(directory.path().join(algorithm.key_filename()), bytes(257)).unwrap();
                let input = directory.path().join("plain");
                let encrypted = directory.path().join("encrypted");
                let decrypted = directory.path().join("decrypted");
                fs::write(&input, &plaintext).unwrap();

                assert_eq!(
                    crypt_file(algorithm, &input, &encrypted, Mode::Auto).unwrap(),
                    Operation::Encrypt
                );
                assert_eq!(
                    crypt_file(algorithm, &encrypted, &decrypted, Mode::Auto).unwrap(),
                    Operation::Decrypt
                );
                assert_eq!(fs::read(decrypted).unwrap(), plaintext);
            }
        }
    }

    #[test]
    fn xchacha_round_trips_across_chunk_boundary() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("key.key"), bytes(97)).unwrap();
        let input = directory.path().join("plain");
        let encrypted = directory.path().join("encrypted");
        let decrypted = directory.path().join("decrypted");
        let plaintext = bytes(CHUNK_SIZE + 17);
        fs::write(&input, &plaintext).unwrap();

        crypt_file(
            Algorithm::XChaCha20Poly1305,
            &input,
            &encrypted,
            Mode::Encrypt,
        )
        .unwrap();
        crypt_file(
            Algorithm::XChaCha20Poly1305,
            &encrypted,
            &decrypted,
            Mode::Decrypt,
        )
        .unwrap();
        assert_eq!(fs::read(decrypted).unwrap(), plaintext);
    }

    #[test]
    fn corruption_is_rejected_without_publishing_plaintext() {
        for algorithm in [
            Algorithm::Aes256GcmSiv,
            Algorithm::XChaCha20Poly1305,
            Algorithm::Serpent256,
            Algorithm::Threefish1024,
        ] {
            let directory = tempfile::tempdir().unwrap();
            fs::write(directory.path().join(algorithm.key_filename()), bytes(64)).unwrap();
            let input = directory.path().join("plain");
            let encrypted = directory.path().join("encrypted");
            let output = directory.path().join("output");
            fs::write(&input, b"authenticated content").unwrap();
            crypt_file(algorithm, &input, &encrypted, Mode::Encrypt).unwrap();

            let mut damaged = fs::read(&encrypted).unwrap();
            let last = damaged.len() - 1;
            damaged[last] ^= 1;
            fs::write(&encrypted, damaged).unwrap();

            assert!(crypt_file(algorithm, &encrypted, &output, Mode::Decrypt).is_err());
            assert!(!output.exists());
        }
    }

    #[test]
    fn no_operation_overwrites_a_destination() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("key.key"), bytes(64)).unwrap();
        let input = directory.path().join("input");
        let output = directory.path().join("output");
        fs::write(&input, b"input").unwrap();
        fs::write(&output, b"keep me").unwrap();

        assert!(otp(&input, &output).is_err());
        assert!(crypt_file(Algorithm::XChaCha20Poly1305, &input, &output, Mode::Encrypt).is_err());
        assert_eq!(fs::read(output).unwrap(), b"keep me");
    }

    #[test]
    fn wrong_key_and_invalid_lengths_never_publish_plaintext() {
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("key.key");
        fs::write(&key_path, bytes(64)).unwrap();
        let input = directory.path().join("plain");
        let encrypted = directory.path().join("encrypted");
        fs::write(&input, b"secret material").unwrap();
        crypt_file(
            Algorithm::XChaCha20Poly1305,
            &input,
            &encrypted,
            Mode::Encrypt,
        )
        .unwrap();

        fs::write(&key_path, vec![0x55; 64]).unwrap();
        let wrong_key_output = directory.path().join("wrong-key-output");
        assert!(
            crypt_file(
                Algorithm::XChaCha20Poly1305,
                &encrypted,
                &wrong_key_output,
                Mode::Decrypt
            )
            .is_err()
        );
        assert!(!wrong_key_output.exists());

        fs::write(&key_path, bytes(64)).unwrap();
        let mut trailing = fs::read(&encrypted).unwrap();
        trailing.push(0);
        let malformed = directory.path().join("malformed");
        fs::write(&malformed, trailing).unwrap();
        let malformed_output = directory.path().join("malformed-output");
        assert!(
            crypt_file(
                Algorithm::XChaCha20Poly1305,
                &malformed,
                &malformed_output,
                Mode::Decrypt
            )
            .is_err()
        );
        assert!(!malformed_output.exists());
    }

    #[test]
    fn fresh_salts_make_ciphertexts_distinct_and_forced_decrypt_rejects_plaintext() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("key.key"), bytes(64)).unwrap();
        let input = directory.path().join("plain");
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        fs::write(&input, b"same plaintext").unwrap();

        crypt_file(Algorithm::Serpent256, &input, &first, Mode::Encrypt).unwrap();
        crypt_file(Algorithm::Serpent256, &input, &second, Mode::Encrypt).unwrap();
        assert_ne!(fs::read(first).unwrap(), fs::read(second).unwrap());

        let output = directory.path().join("output");
        assert!(crypt_file(Algorithm::Serpent256, &input, &output, Mode::Decrypt).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn otp_round_trips_and_rejects_short_keys() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input");
        let encrypted = directory.path().join("encrypted");
        let decrypted = directory.path().join("decrypted");
        let plaintext = bytes(IO_BUFFER_SIZE + 3);
        fs::write(&input, &plaintext).unwrap();
        fs::write(directory.path().join("key.key"), bytes(plaintext.len())).unwrap();

        otp(&input, &encrypted).unwrap();
        otp(&encrypted, &decrypted).unwrap();
        assert_eq!(fs::read(decrypted).unwrap(), plaintext);

        let short_directory = tempfile::tempdir().unwrap();
        fs::write(short_directory.path().join("input"), b"1234").unwrap();
        fs::write(short_directory.path().join("key.key"), b"123").unwrap();
        assert!(
            otp(
                &short_directory.path().join("input"),
                &short_directory.path().join("output")
            )
            .is_err()
        );
    }

    #[test]
    fn keymake_is_deterministic_and_size_bound() {
        let first_directory = tempfile::tempdir().unwrap();
        let second_directory = tempfile::tempdir().unwrap();
        let first = first_directory.path().join("key.key");
        let second = second_directory.path().join("key.key");

        keymake_at(&first, 97, b"a strong test password").unwrap();
        keymake_at(&second, 97, b"a strong test password").unwrap();
        assert_eq!(fs::read(&first).unwrap(), fs::read(second).unwrap());
        assert!(keymake_at(&first, 97, b"a different password").is_err());
        assert!(keymake_at(&first_directory.path().join("zero.key"), 0, b"password").is_err());
        assert!(
            keymake_at(
                &first_directory.path().join("huge.key"),
                MAX_KEYMAKE_SIZE + 1,
                b"password"
            )
            .is_err()
        );
    }
}
