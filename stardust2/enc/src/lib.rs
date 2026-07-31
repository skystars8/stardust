//! Authenticated, streaming file encryption used by the enc CLI.
//!
//! The format is a fixed, versioned header followed by an authenticated header
//! tag and independently authenticated encrypted chunks. The original file is
//! never modified. A result becomes visible only after the complete temporary
//! output has been flushed to storage.

mod key;

use std::ffi::OsStr;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail, ensure};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};
use tempfile::{Builder, NamedTempFile};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"ENCFILE\0";
const FORMAT_VERSION: u8 = 1;
const ALGORITHM_XCHACHA20_POLY1305: u8 = 1;
const HEADER_LEN: usize = 40;
const TAG_LEN: usize = 16;
const NONCE_PREFIX_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const CHUNK_SIZE: usize = 1024 * 1024;
const MAX_CHUNK_SIZE: usize = 8 * 1024 * 1024;
const HEADER_NONCE_COUNTER: u64 = u64::MAX;

/// The operation requested by the command line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

impl Operation {
    /// Parses E or D, ignoring ASCII case.
    pub fn parse(value: &OsStr) -> Result<Self> {
        match value.to_str() {
            Some(value) if value.eq_ignore_ascii_case("e") => Ok(Self::Encrypt),
            Some(value) if value.eq_ignore_ascii_case("d") => Ok(Self::Decrypt),
            _ => bail!("operation must be E (encrypt) or D (decrypt)"),
        }
    }
}

/// Encrypts or decrypts input and returns the newly created output path.
pub fn process_file(input: &Path, operation: Operation) -> Result<PathBuf> {
    match operation {
        Operation::Encrypt => encrypt_file(input),
        Operation::Decrypt => decrypt_file(input),
    }
}

/// Encrypts a file to a sibling path ending in .enc.
pub fn encrypt_file(input: &Path) -> Result<PathBuf> {
    encrypt_file_with_key(input, &key::KEY)
}

/// Decrypts a file to a sibling path ending in .dec.
///
/// For example, report.pdf.enc becomes report.pdf.dec. This intentionally
/// avoids overwriting the original plaintext if it is still present.
pub fn decrypt_file(input: &Path) -> Result<PathBuf> {
    decrypt_file_with_key(input, &key::KEY)
}

fn encrypt_file_with_key(input: &Path, key_bytes: &[u8; 32]) -> Result<PathBuf> {
    let mut source = open_input(input)?;
    let initial_metadata = validate_regular_file(input, &source)?;
    let plaintext_len = initial_metadata.len();
    let output = encrypted_output_path(input)?;
    ensure_distinct_paths(input, &output)?;
    ensure_output_absent(&output)?;

    let mut nonce_prefix = [0_u8; NONCE_PREFIX_LEN];
    getrandom::fill(&mut nonce_prefix)
        .context("the operating system's secure random-number generator failed")?;
    let header = Header::new(plaintext_len, nonce_prefix).encode();
    let cipher = cipher(key_bytes);

    write_atomically(&output, |destination| {
        destination
            .write_all(&header)
            .context("could not write the encrypted-file header")?;

        let mut empty = [];
        let header_tag = cipher
            .encrypt_in_place_detached(
                &make_nonce(&nonce_prefix, HEADER_NONCE_COUNTER),
                &header,
                &mut empty,
            )
            .map_err(|_| anyhow!("could not authenticate the encrypted-file header"))?;
        destination
            .write_all(&header_tag)
            .context("could not write the encrypted-file header tag")?;

        let mut buffer = Zeroizing::new(vec![0_u8; CHUNK_SIZE]);
        let mut remaining = plaintext_len;
        let mut chunk_index = 0_u64;

        while remaining > 0 {
            let plaintext_size = usize::try_from(remaining.min(CHUNK_SIZE as u64))
                .expect("the selected chunk size always fits in usize");
            source
                .read_exact(&mut buffer[..plaintext_size])
                .with_context(|| {
                    format!(
                        "input changed or became unreadable while encrypting chunk {chunk_index}"
                    )
                })?;

            let aad = chunk_aad(&header, chunk_index);
            let tag = cipher
                .encrypt_in_place_detached(
                    &make_nonce(&nonce_prefix, chunk_index),
                    &aad,
                    &mut buffer[..plaintext_size],
                )
                .map_err(|_| anyhow!("encryption failed at chunk {chunk_index}"))?;

            destination
                .write_all(&buffer[..plaintext_size])
                .with_context(|| format!("could not write encrypted chunk {chunk_index}"))?;
            destination
                .write_all(&tag)
                .with_context(|| format!("could not write the tag for chunk {chunk_index}"))?;

            buffer[..plaintext_size].zeroize();
            remaining -= plaintext_size as u64;
            chunk_index = chunk_index
                .checked_add(1)
                .ok_or_else(|| anyhow!("input is too large to encrypt"))?;
        }

        let mut extra = [0_u8; 1];
        ensure!(
            source
                .read(&mut extra)
                .context("could not finish reading input")?
                == 0,
            "input grew while it was being encrypted; no output was created"
        );
        ensure_source_unchanged(input, &source, &initial_metadata)?;
        Ok(())
    })?;

    Ok(output)
}

fn decrypt_file_with_key(input: &Path, key_bytes: &[u8; 32]) -> Result<PathBuf> {
    let mut source = open_input(input)?;
    let initial_metadata = validate_regular_file(input, &source)?;
    let encrypted_len = initial_metadata.len();

    let mut encoded_header = [0_u8; HEADER_LEN];
    source
        .read_exact(&mut encoded_header)
        .context("file is too short to contain a valid encrypted-file header")?;
    let header = Header::decode(&encoded_header)?;

    let expected_len = header.encrypted_file_len()?;
    ensure!(
        encrypted_len == expected_len,
        "encrypted file has the wrong length (expected {expected_len} bytes, found {encrypted_len}); it may be truncated, corrupted, or have extra data"
    );

    let cipher = cipher(key_bytes);
    let mut header_tag_bytes = [0_u8; TAG_LEN];
    source
        .read_exact(&mut header_tag_bytes)
        .context("file is missing its header authentication tag")?;
    let mut empty = [];
    cipher
        .decrypt_in_place_detached(
            &make_nonce(&header.nonce_prefix, HEADER_NONCE_COUNTER),
            &encoded_header,
            &mut empty,
            Tag::from_slice(&header_tag_bytes),
        )
        .map_err(|_| {
            anyhow!(
                "authentication failed: the file is damaged, was encrypted by a different build, or is not an enc file"
            )
        })?;

    let output = decrypted_output_path(input)?;
    ensure_distinct_paths(input, &output)?;
    ensure_output_absent(&output)?;

    write_atomically(&output, |destination| {
        let chunk_size = header.chunk_size as usize;
        let mut buffer = Zeroizing::new(vec![0_u8; chunk_size]);
        let mut remaining = header.plaintext_len;
        let mut chunk_index = 0_u64;

        while remaining > 0 {
            let plaintext_size = usize::try_from(remaining.min(header.chunk_size as u64))
                .expect("validated chunk size always fits in usize");
            source
                .read_exact(&mut buffer[..plaintext_size])
                .with_context(|| format!("encrypted chunk {chunk_index} is truncated"))?;

            let mut tag_bytes = [0_u8; TAG_LEN];
            source
                .read_exact(&mut tag_bytes)
                .with_context(|| format!("tag for encrypted chunk {chunk_index} is missing"))?;

            let aad = chunk_aad(&encoded_header, chunk_index);
            cipher
                .decrypt_in_place_detached(
                    &make_nonce(&header.nonce_prefix, chunk_index),
                    &aad,
                    &mut buffer[..plaintext_size],
                    Tag::from_slice(&tag_bytes),
                )
                .map_err(|_| {
                    anyhow!(
                        "authentication failed at chunk {chunk_index}: the file is damaged or the key is wrong"
                    )
                })?;

            destination
                .write_all(&buffer[..plaintext_size])
                .with_context(|| format!("could not write decrypted chunk {chunk_index}"))?;

            buffer[..plaintext_size].zeroize();
            remaining -= plaintext_size as u64;
            chunk_index = chunk_index
                .checked_add(1)
                .ok_or_else(|| anyhow!("encrypted file contains too many chunks"))?;
        }

        let mut extra = [0_u8; 1];
        ensure!(
            source
                .read(&mut extra)
                .context("could not finish reading encrypted input")?
                == 0,
            "encrypted file contains unexpected trailing data"
        );
        ensure_source_unchanged(input, &source, &initial_metadata)?;
        Ok(())
    })?;

    Ok(output)
}

fn cipher(key_bytes: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(Key::from_slice(key_bytes))
}

fn make_nonce(prefix: &[u8; NONCE_PREFIX_LEN], counter: u64) -> XNonce {
    let mut nonce = XNonce::default();
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_LEN..NONCE_LEN].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn chunk_aad(header: &[u8; HEADER_LEN], chunk_index: u64) -> [u8; HEADER_LEN + 8] {
    let mut aad = [0_u8; HEADER_LEN + 8];
    aad[..HEADER_LEN].copy_from_slice(header);
    aad[HEADER_LEN..].copy_from_slice(&chunk_index.to_be_bytes());
    aad
}

fn open_input(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);

    // Windows share flags are enforced by the OS and prevent a second process
    // from opening this input for mutation while this process holds it.
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        options.share_mode(FILE_SHARE_READ);
    }

    options
        .open(path)
        .with_context(|| format!("could not open input file '{}'", path.display()))
}

fn validate_regular_file(path: &Path, file: &File) -> Result<Metadata> {
    let metadata = file
        .metadata()
        .with_context(|| format!("could not inspect input file '{}'", path.display()))?;
    ensure!(
        metadata.is_file(),
        "input '{}' is not a regular file",
        path.display()
    );
    Ok(metadata)
}

fn ensure_source_unchanged(path: &Path, file: &File, initial: &Metadata) -> Result<()> {
    let final_metadata = file
        .metadata()
        .with_context(|| format!("could not re-check input file '{}'", path.display()))?;
    ensure!(
        initial.len() == final_metadata.len(),
        "input changed size during processing; no output was created"
    );

    if let (Ok(before), Ok(after)) = (initial.modified(), final_metadata.modified()) {
        ensure!(
            before == after,
            "input was modified during processing; no output was created"
        );
    }
    Ok(())
}

fn write_atomically(
    output: &Path,
    write_contents: impl FnOnce(&mut File) -> Result<()>,
) -> Result<()> {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let mut temporary = Builder::new()
        .prefix(".enc-tmp-")
        .tempfile_in(parent)
        .with_context(|| {
            format!(
                "could not create a temporary output in '{}'",
                parent.display()
            )
        })?;

    write_contents(temporary.as_file_mut())?;
    temporary
        .as_file()
        .sync_all()
        .context("could not flush the completed output to storage")?;

    persist_without_overwrite(temporary, output)?;
    sync_parent_directory(parent)?;
    Ok(())
}

fn persist_without_overwrite(temporary: NamedTempFile, output: &Path) -> Result<()> {
    temporary.persist_noclobber(output).map_err(|error| {
        if error.error.kind() == ErrorKind::AlreadyExists {
            anyhow!(
                "refusing to overwrite existing output '{}'; move or rename it first",
                output.display()
            )
        } else {
            anyhow!(error.error).context(format!(
                "could not publish completed output '{}'",
                output.display()
            ))
        }
    })?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> Result<()> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| {
            format!(
                "output was created, but its directory '{}' could not be flushed to storage",
                parent.display()
            )
        })
}

#[cfg(not(unix))]
fn sync_parent_directory(_parent: &Path) -> Result<()> {
    Ok(())
}

fn ensure_distinct_paths(input: &Path, output: &Path) -> Result<()> {
    ensure!(
        input != output,
        "input and output resolve to the same path '{}'",
        input.display()
    );
    Ok(())
}

fn ensure_output_absent(output: &Path) -> Result<()> {
    match fs::symlink_metadata(output) {
        Ok(_) => bail!(
            "refusing to overwrite existing output '{}'; move or rename it first",
            output.display()
        ),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "could not check whether output '{}' already exists",
                output.display()
            )
        }),
    }
}

fn encrypted_output_path(input: &Path) -> Result<PathBuf> {
    append_to_file_name(input, ".enc")
}

fn decrypted_output_path(input: &Path) -> Result<PathBuf> {
    let extension_is_enc = input
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| extension.eq_ignore_ascii_case("enc"));

    if extension_is_enc {
        Ok(input.with_extension("dec"))
    } else {
        append_to_file_name(input, ".dec")
    }
}

fn append_to_file_name(input: &Path, suffix: &str) -> Result<PathBuf> {
    let file_name = input
        .file_name()
        .ok_or_else(|| anyhow!("input path '{}' has no file name", input.display()))?;
    let mut output_name = file_name.to_os_string();
    output_name.push(suffix);
    Ok(input.with_file_name(output_name))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Header {
    chunk_size: u32,
    plaintext_len: u64,
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
}

impl Header {
    fn new(plaintext_len: u64, nonce_prefix: [u8; NONCE_PREFIX_LEN]) -> Self {
        Self {
            chunk_size: CHUNK_SIZE as u32,
            plaintext_len,
            nonce_prefix,
        }
    }

    fn encode(self) -> [u8; HEADER_LEN] {
        let mut encoded = [0_u8; HEADER_LEN];
        encoded[0..8].copy_from_slice(MAGIC);
        encoded[8] = FORMAT_VERSION;
        encoded[9] = ALGORITHM_XCHACHA20_POLY1305;
        encoded[10..12].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        encoded[12..16].copy_from_slice(&self.chunk_size.to_be_bytes());
        encoded[16..24].copy_from_slice(&self.plaintext_len.to_be_bytes());
        encoded[24..40].copy_from_slice(&self.nonce_prefix);
        encoded
    }

    fn decode(encoded: &[u8; HEADER_LEN]) -> Result<Self> {
        ensure!(&encoded[0..8] == MAGIC, "not an enc encrypted file");
        ensure!(
            encoded[8] == FORMAT_VERSION,
            "unsupported encrypted-file version {}",
            encoded[8]
        );
        ensure!(
            encoded[9] == ALGORITHM_XCHACHA20_POLY1305,
            "unsupported encryption algorithm {}",
            encoded[9]
        );

        let encoded_header_len = u16::from_be_bytes([encoded[10], encoded[11]]) as usize;
        ensure!(
            encoded_header_len == HEADER_LEN,
            "unsupported encrypted-file header length {encoded_header_len}"
        );

        let chunk_size =
            u32::from_be_bytes(encoded[12..16].try_into().expect("fixed header field"));
        ensure!(
            chunk_size > 0 && chunk_size as usize <= MAX_CHUNK_SIZE,
            "invalid encrypted-file chunk size {chunk_size}"
        );

        let plaintext_len =
            u64::from_be_bytes(encoded[16..24].try_into().expect("fixed header field"));
        let nonce_prefix = encoded[24..40]
            .try_into()
            .expect("fixed nonce-prefix field");

        Ok(Self {
            chunk_size,
            plaintext_len,
            nonce_prefix,
        })
    }

    fn encrypted_file_len(self) -> Result<u64> {
        let chunk_size = self.chunk_size as u64;
        let chunks = if self.plaintext_len == 0 {
            0
        } else {
            ((self.plaintext_len - 1) / chunk_size) + 1
        };
        let tag_bytes = chunks
            .checked_mul(TAG_LEN as u64)
            .ok_or_else(|| anyhow!("encrypted-file size overflows the supported range"))?;
        (HEADER_LEN as u64 + TAG_LEN as u64)
            .checked_add(self.plaintext_len)
            .and_then(|size| size.checked_add(tag_bytes))
            .ok_or_else(|| anyhow!("encrypted-file size overflows the supported range"))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    const WRONG_KEY: [u8; 32] = [0x55; 32];

    #[test]
    fn operation_parsing_is_case_insensitive() {
        assert_eq!(
            Operation::parse(OsStr::new("E")).unwrap(),
            Operation::Encrypt
        );
        assert_eq!(
            Operation::parse(OsStr::new("e")).unwrap(),
            Operation::Encrypt
        );
        assert_eq!(
            Operation::parse(OsStr::new("D")).unwrap(),
            Operation::Decrypt
        );
        assert_eq!(
            Operation::parse(OsStr::new("d")).unwrap(),
            Operation::Decrypt
        );
        assert!(Operation::parse(OsStr::new("x")).is_err());
    }

    #[test]
    fn output_names_are_predictable_and_non_destructive() {
        assert_eq!(
            encrypted_output_path(Path::new("report.pdf")).unwrap(),
            PathBuf::from("report.pdf.enc")
        );
        assert_eq!(
            decrypted_output_path(Path::new("report.pdf.enc")).unwrap(),
            PathBuf::from("report.pdf.dec")
        );
        assert_eq!(
            decrypted_output_path(Path::new("REPORT.ENC")).unwrap(),
            PathBuf::from("REPORT.dec")
        );
        assert_eq!(
            decrypted_output_path(Path::new("unknown.bin")).unwrap(),
            PathBuf::from("unknown.bin.dec")
        );
    }

    #[test]
    fn round_trip_empty_small_and_multi_chunk_files() {
        for (case, size) in [
            ("empty", 0),
            ("small", 31),
            ("one_chunk", CHUNK_SIZE),
            ("multi_chunk", CHUNK_SIZE * 2 + 137),
        ] {
            let directory = tempdir().unwrap();
            let input = directory.path().join(format!("{case}.bin"));
            let original: Vec<u8> = (0..size)
                .map(|index| (index.wrapping_mul(31) % 251) as u8)
                .collect();
            fs::write(&input, &original).unwrap();

            let encrypted = encrypt_file(&input).unwrap();
            let decrypted = decrypt_file(&encrypted).unwrap();

            assert_eq!(fs::read(&input).unwrap(), original);
            assert_eq!(fs::read(&decrypted).unwrap(), original);
        }
    }

    #[test]
    fn randomized_nonce_makes_ciphertexts_different() {
        let first_directory = tempdir().unwrap();
        let second_directory = tempdir().unwrap();
        let first = first_directory.path().join("same.bin");
        let second = second_directory.path().join("same.bin");
        fs::write(&first, b"identical plaintext").unwrap();
        fs::write(&second, b"identical plaintext").unwrap();

        let first_encrypted = encrypt_file(&first).unwrap();
        let second_encrypted = encrypt_file(&second).unwrap();

        assert_ne!(
            fs::read(first_encrypted).unwrap(),
            fs::read(second_encrypted).unwrap()
        );
    }

    #[test]
    fn refuses_to_overwrite_an_existing_output() {
        let directory = tempdir().unwrap();
        let input = directory.path().join("data.bin");
        let expected_output = directory.path().join("data.bin.enc");
        fs::write(&input, b"important").unwrap();
        fs::write(&expected_output, b"keep me").unwrap();

        let error = encrypt_file(&input).unwrap_err();

        assert!(error.to_string().contains("refusing to overwrite"));
        assert_eq!(fs::read(&expected_output).unwrap(), b"keep me");
        assert_eq!(fs::read(&input).unwrap(), b"important");
        assert_no_temporary_files(directory.path());
    }

    #[test]
    fn tampered_header_is_rejected_without_plaintext_output() {
        let directory = tempdir().unwrap();
        let input = directory.path().join("data.bin");
        fs::write(&input, b"important data").unwrap();
        let encrypted = encrypt_file(&input).unwrap();
        let expected_output = directory.path().join("data.bin.dec");

        let mut bytes = fs::read(&encrypted).unwrap();
        bytes[24] ^= 0x01;
        fs::write(&encrypted, bytes).unwrap();

        assert!(decrypt_file(&encrypted).is_err());
        assert!(!expected_output.exists());
        assert_no_temporary_files(directory.path());
    }

    #[test]
    fn tampered_ciphertext_is_rejected_without_plaintext_output() {
        let directory = tempdir().unwrap();
        let input = directory.path().join("data.bin");
        fs::write(&input, b"important data").unwrap();
        let encrypted = encrypt_file(&input).unwrap();
        let expected_output = directory.path().join("data.bin.dec");

        let mut bytes = fs::read(&encrypted).unwrap();
        bytes[HEADER_LEN + TAG_LEN] ^= 0x01;
        fs::write(&encrypted, bytes).unwrap();

        assert!(decrypt_file(&encrypted).is_err());
        assert!(!expected_output.exists());
        assert_no_temporary_files(directory.path());
    }

    #[test]
    fn truncation_and_trailing_data_are_rejected() {
        for append_data in [false, true] {
            let directory = tempdir().unwrap();
            let input = directory.path().join("data.bin");
            fs::write(&input, b"important data").unwrap();
            let encrypted = encrypt_file(&input).unwrap();
            let expected_output = directory.path().join("data.bin.dec");
            let mut bytes = fs::read(&encrypted).unwrap();
            if append_data {
                bytes.push(0);
            } else {
                bytes.pop();
            }
            fs::write(&encrypted, bytes).unwrap();

            assert!(decrypt_file(&encrypted).is_err());
            assert!(!expected_output.exists());
            assert_no_temporary_files(directory.path());
        }
    }

    #[test]
    fn wrong_key_is_rejected_without_plaintext_output() {
        let directory = tempdir().unwrap();
        let input = directory.path().join("data.bin");
        fs::write(&input, b"important data").unwrap();
        let encrypted = encrypt_file(&input).unwrap();
        let expected_output = directory.path().join("data.bin.dec");

        assert!(decrypt_file_with_key(&encrypted, &WRONG_KEY).is_err());
        assert!(!expected_output.exists());
        assert_no_temporary_files(directory.path());
    }

    #[test]
    fn malformed_claimed_size_is_rejected_before_output_creation() {
        let directory = tempdir().unwrap();
        let input = directory.path().join("bad.enc");
        let mut bytes = vec![0_u8; HEADER_LEN + TAG_LEN];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = FORMAT_VERSION;
        bytes[9] = ALGORITHM_XCHACHA20_POLY1305;
        bytes[10..12].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        bytes[12..16].copy_from_slice(&(CHUNK_SIZE as u32).to_be_bytes());
        bytes[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
        fs::write(&input, bytes).unwrap();

        assert!(decrypt_file(&input).is_err());
        assert!(!directory.path().join("bad.dec").exists());
        assert_no_temporary_files(directory.path());
    }

    #[test]
    fn encrypted_file_length_calculation_is_checked() {
        let header = Header {
            chunk_size: 1,
            plaintext_len: u64::MAX,
            nonce_prefix: [0; NONCE_PREFIX_LEN],
        };
        assert!(header.encrypted_file_len().is_err());
    }

    fn assert_no_temporary_files(directory: &Path) {
        let names: Vec<_> = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with(".enc-tmp-"))
            .collect();
        assert!(names.is_empty(), "temporary files remain: {names:?}");
    }
}
