use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};
use secure::{Algorithm, Mode};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    name = "secure",
    version,
    about = "Reliable streaming file encryption",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Deterministically create key.key from a password (1 to 20,000,000,000 bytes).
    Keymake {
        /// Exact key size in bytes.
        size: u64,
    },
    /// XOR a file with key.key. Running it again decrypts it.
    Otp(OtpArgs),
    /// Encrypt or decrypt using AES-256-GCM-SIV and aes.key.
    Aes(FileArgs),
    /// Encrypt or decrypt using XChaCha20-Poly1305 and key.key.
    Xcha(FileArgs),
    /// Encrypt or decrypt using Serpent-256-CTR-HMAC-SHA-256 and key.key.
    Ser(FileArgs),
    /// Encrypt or decrypt using Threefish-1024-CTR-HMAC-SHA-256 and key.key.
    Tf(FileArgs),
}

#[derive(Debug, Args)]
struct FileArgs {
    /// Existing input file.
    input: PathBuf,
    /// New output file. Existing directory entries are never overwritten.
    output: PathBuf,
    /// Select encryption, decryption, or authenticated-header autodetection.
    #[arg(long, value_enum, default_value_t = Mode::Auto)]
    mode: Mode,
}

#[derive(Debug, Args)]
struct OtpArgs {
    /// Existing input file.
    input: PathBuf,
    /// New output file. Existing directory entries are never overwritten.
    output: PathBuf,
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keymake { size } => {
            if std::fs::symlink_metadata("key.key").is_ok() {
                bail!("refusing to overwrite existing path: key.key");
            }
            let password = Zeroizing::new(rpassword::prompt_password("Password: ")?);
            let confirmation = Zeroizing::new(rpassword::prompt_password("Password (again): ")?);
            if password.is_empty() {
                bail!("password must not be empty");
            }
            if password.as_bytes() != confirmation.as_bytes() {
                bail!("passwords do not match");
            }
            secure::install_interrupt_handler()?;
            secure::keymake(size, password.as_bytes())?;
            println!("created key.key ({size} bytes)");
        }
        Command::Otp(args) => {
            secure::install_interrupt_handler()?;
            secure::otp(&args.input, &args.output)?;
            println!("created {}", args.output.display());
        }
        Command::Aes(args) => run_cipher(Algorithm::Aes256GcmSiv, args)?,
        Command::Xcha(args) => run_cipher(Algorithm::XChaCha20Poly1305, args)?,
        Command::Ser(args) => run_cipher(Algorithm::Serpent256, args)?,
        Command::Tf(args) => run_cipher(Algorithm::Threefish1024, args)?,
    }
    Ok(())
}

fn run_cipher(algorithm: Algorithm, args: FileArgs) -> Result<()> {
    secure::install_interrupt_handler()?;
    let operation = secure::crypt_file(algorithm, &args.input, &args.output, args.mode)?;
    println!("{operation}ed {}", args.output.display());
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
