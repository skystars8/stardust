//! Safe file helpers: refuse overwrite, atomic commit, streaming I/O.

use crate::error::{AppError, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

/// Default buffered I/O size (1 MiB). Keeps RAM bounded for multi-GB files.
pub const IO_CHUNK: usize = 1024 * 1024;

/// Ciphertext payload chunk size (plaintext bytes per AEAD/CTR chunk).
pub const CRYPTO_CHUNK: usize = 1024 * 1024;

/// Refuse to proceed if `path` already exists.
pub fn refuse_if_exists(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(AppError::RefuseOverwrite(path.to_path_buf()));
    }
    Ok(())
}

/// Open an existing input file for sequential read.
pub fn open_input(path: &Path) -> Result<File> {
    if !path.is_file() {
        return Err(AppError::InputNotFound(path.to_path_buf()));
    }
    File::open(path).map_err(AppError::from)
}

/// Buffered reader over an existing input file.
pub fn open_input_buf(path: &Path) -> Result<BufReader<File>> {
    Ok(BufReader::with_capacity(IO_CHUNK, open_input(path)?))
}

/// Length of a file in bytes.
pub fn file_len(path: &Path) -> Result<u64> {
    Ok(fs::metadata(path)?.len())
}

/// Peek the first `n` bytes without consuming the logical stream position
/// for a freshly opened file. Returns fewer bytes if the file is shorter.
pub fn peek_prefix(path: &Path, n: usize) -> Result<Vec<u8>> {
    let mut f = open_input(path)?;
    let mut buf = vec![0u8; n];
    let read = f.read(&mut buf)?;
    buf.truncate(read);
    Ok(buf)
}

/// Temporary path next to the final destination (same volume for atomic rename).
fn temp_path_for(dest: &Path) -> PathBuf {
    let mut name = dest
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| "output".into());
    name.push(format!(".{}.partial", std::process::id()));
    dest.with_file_name(name)
}

/// A file opened for writing that will only become the final path on successful
/// `commit()`. On drop without commit, the partial file is deleted.
pub struct AtomicOutput {
    dest: PathBuf,
    temp: PathBuf,
    file: Option<BufWriter<File>>,
    committed: bool,
}

impl AtomicOutput {
    /// Create a new exclusive temp file for `dest`. Refuses if `dest` exists.
    pub fn create(dest: &Path) -> Result<Self> {
        refuse_if_exists(dest)?;

        let temp = temp_path_for(dest);
        // Best-effort: remove a leftover partial from a crashed prior run.
        let _ = fs::remove_file(&temp);

        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|e| {
                AppError::msg(format!(
                    "failed to create temporary file {}: {e}",
                    temp.display()
                ))
            })?;

        Ok(Self {
            dest: dest.to_path_buf(),
            temp,
            file: Some(BufWriter::with_capacity(IO_CHUNK, file)),
            committed: false,
        })
    }

    pub fn writer(&mut self) -> Result<&mut BufWriter<File>> {
        self.file
            .as_mut()
            .ok_or_else(|| AppError::msg("atomic output already closed"))
    }

    /// Flush buffers, fsync to disk, then rename temp → dest.
    pub fn commit(mut self) -> Result<()> {
        let mut writer = self
            .file
            .take()
            .ok_or_else(|| AppError::msg("atomic output already closed"))?;

        writer.flush()?;
        let file = writer
            .into_inner()
            .map_err(|e| AppError::msg(format!("flush failed: {e}")))?;
        file.sync_all()?;
        drop(file);

        // Final race check: refuse if dest appeared after we started.
        if self.dest.exists() {
            let _ = fs::remove_file(&self.temp);
            return Err(AppError::RefuseOverwrite(self.dest.clone()));
        }

        fs::rename(&self.temp, &self.dest).map_err(|e| {
            let _ = fs::remove_file(&self.temp);
            AppError::msg(format!(
                "failed to finalize {}: {e}",
                self.dest.display()
            ))
        })?;

        self.committed = true;
        Ok(())
    }
}

impl Drop for AtomicOutput {
    fn drop(&mut self) {
        if !self.committed {
            // Drop writer first so Windows can delete the file handle.
            self.file.take();
            let _ = fs::remove_file(&self.temp);
        }
    }
}

impl Write for AtomicOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer()
            .map_err(|e| io::Error::other(e.to_string()))?
            .write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer()
            .map_err(|e| io::Error::other(e.to_string()))?
            .flush()
    }
}

/// Read exactly `n` bytes, or error if EOF is hit early.
pub fn read_exact_n<R: Read>(r: &mut R, n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            AppError::InvalidCiphertext
        } else {
            AppError::from(e)
        }
    })?;
    Ok(buf)
}

pub fn write_u32_be<W: Write>(w: &mut W, v: u32) -> Result<()> {
    w.write_all(&v.to_be_bytes())?;
    Ok(())
}

/// Read key material from a path, requiring at least `min_len` bytes.
/// Only the first `min_len` bytes are retained in memory (important for huge OTP keys
/// when only a fixed-size cipher key is needed).
pub fn read_key_prefix(path: &Path, min_len: usize) -> Result<Vec<u8>> {
    if !path.is_file() {
        return Err(AppError::KeyNotFound(path.to_path_buf()));
    }
    let len = file_len(path)?;
    if len < min_len as u64 {
        return Err(AppError::KeyTooShort {
            path: path.to_path_buf(),
            got: len,
            need: min_len as u64,
        });
    }
    let mut f = File::open(path)?;
    let mut key = vec![0u8; min_len];
    f.read_exact(&mut key)?;
    Ok(key)
}

/// Ensure key file exists and is at least `need` bytes long (does not load it).
pub fn require_key_len(path: &Path, need: u64) -> Result<()> {
    if !path.is_file() {
        return Err(AppError::KeyNotFound(path.to_path_buf()));
    }
    let got = file_len(path)?;
    if got < need {
        return Err(AppError::KeyTooShort {
            path: path.to_path_buf(),
            got,
            need,
        });
    }
    Ok(())
}

