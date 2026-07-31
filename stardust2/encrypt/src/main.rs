//! Production-grade streaming encryption CLI.
//!
//! Subcommands:
//!   keymake <bytes>          — deterministic key.key (1 B .. 20 GiB), no overwrite
//!   otp  <in> <out>          — XOR with key.key (key ≥ input), no overwrite
//!   aes  <in> <out>          — AES-256-GCM-SIV via aes.key, auto encrypt/decrypt
//!   xcha <in> <out>          — XChaCha20-Poly1305 via key.key, auto encrypt/decrypt
//!   ser  <in> <out>          — Serpent-256-CTR-HMAC via key.key, auto encrypt/decrypt
//!   tf   <in> <out>          — Threefish-1024-CTR-HMAC via key.key, auto encrypt/decrypt

mod aead_chunk;
mod aes_cmd;
mod block_chunk;
mod error;
mod fsutil;
mod keymake;
mod otp;
mod ser_cmd;
mod tf_cmd;
mod xcha_cmd;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "encrypt",
    version,
    about = "Production-grade streaming encryption CLI",
    long_about = "Reliable file encryption/decryption with bounded memory.\n\
                  Authenticated modes auto-detect: ciphertext magic → decrypt, else encrypt.\n\
                  All outputs refuse to overwrite existing files. Writes are atomic (temp + fsync + rename)."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create deterministic key.key from a password (prompted twice). Refuses overwrite.
    Keymake {
        /// Desired key size in bytes (1 .. 21474836480 inclusive = 20 GiB).
        size: u64,
    },
    /// XOR input with key.key (one-time-pad style). Key must be ≥ input length.
    Otp {
        /// Input file path.
        input: PathBuf,
        /// Output file path (must not exist).
        output: PathBuf,
    },
    /// AES-256-GCM-SIV encrypt/decrypt. Expects aes.key (≥32 bytes) in the working directory.
    Aes {
        input: PathBuf,
        output: PathBuf,
    },
    /// XChaCha20-Poly1305 encrypt/decrypt. Expects key.key (≥32 bytes) in the working directory.
    Xcha {
        input: PathBuf,
        output: PathBuf,
    },
    /// Serpent-256 (CTR + HMAC-SHA256) encrypt/decrypt. Expects key.key (≥32 bytes).
    Ser {
        input: PathBuf,
        output: PathBuf,
    },
    /// Threefish-1024 (CTR + HMAC-SHA256) encrypt/decrypt. Expects key.key (≥128 bytes).
    Tf {
        input: PathBuf,
        output: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Keymake { size } => keymake::run(size),
        Commands::Otp { input, output } => otp::run(&input, &output),
        Commands::Aes { input, output } => aes_cmd::run(&input, &output),
        Commands::Xcha { input, output } => xcha_cmd::run(&input, &output),
        Commands::Ser { input, output } => ser_cmd::run(&input, &output),
        Commands::Tf { input, output } => tf_cmd::run(&input, &output),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
