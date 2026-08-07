//! Presentation-only command-line interface for the experimental encryptor.

use clap::{Args, Parser, Subcommand};
use encryptor::{
    decrypt_file, encrypt_file, export_public_key, generate_key_bundle, load_signing_identity,
    load_verification_key, DecryptOptions, EncryptOptions, Error, Password, PublicationOutcome,
    Result,
};
use rpassword::{prompt_password, prompt_password_with_config, ConfigBuilder};
use std::error::Error as _;
use std::io::{self, IsTerminal};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "chacha20_poly1305",
    version,
    about = "Experimental custom ChaCha20-Poly1305 file encryption",
    long_about = "Experimental custom ChaCha20-Poly1305 file encryption.\n\nThis educational implementation is not independently audited and must not be used to protect important data."
)]
struct Cli {
    /// Include underlying non-secret error sources.
    #[arg(long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a regular file into the CPV2 format.
    Encrypt(EncryptArgs),
    /// Authenticate and decrypt a CPV2 file.
    Decrypt(DecryptArgs),
    /// Generate one password-encrypted EDEKV2 signing-key bundle.
    Keygen(KeygenArgs),
    /// Export the public Ed25519 key from an EDEKV2 bundle.
    ExportPublic(ExportPublicArgs),
}

#[derive(Args)]
struct EncryptArgs {
    /// Plaintext input file. Symlinks are rejected.
    input: PathBuf,
    /// New encrypted output file. Existing paths are never replaced.
    output: PathBuf,
    /// Optional EDEKV2 signing-key bundle.
    #[arg(long, value_name = "KEYPAIR.ekey")]
    sign_key: Option<PathBuf>,
}

#[derive(Args)]
struct DecryptArgs {
    /// CPV2 input file. Symlinks are rejected.
    input: PathBuf,
    /// New plaintext output file. Existing paths are never replaced.
    output: PathBuf,
    /// Public Ed25519 key required for signed CPV2 inputs.
    #[arg(long, value_name = "PUBLIC.key")]
    verify_key: Option<PathBuf>,
}

#[derive(Args)]
struct KeygenArgs {
    /// New encrypted EDEKV2 key-bundle path.
    output: PathBuf,
}

#[derive(Args)]
struct ExportPublicArgs {
    /// Existing EDEKV2 key bundle.
    bundle: PathBuf,
    /// New raw 32-byte Ed25519 public-key path.
    output: PathBuf,
}

fn read_password(prompt: &str) -> Result<Password> {
    let value = if io::stdin().is_terminal() {
        prompt_password(prompt)
    } else {
        let config = ConfigBuilder::new()
            .input_reader(io::stdin())
            .output_writer(io::stdout())
            .build();
        prompt_password_with_config(prompt, config)
    }
    .map_err(|source| Error::Io {
        operation: "reading a password",
        source,
    })?;
    Password::new(value)
}

fn read_confirmed_password(first_prompt: &str, confirmation_prompt: &str) -> Result<Password> {
    let first = read_password(first_prompt)?;
    let confirmation = read_password(confirmation_prompt)?;
    if !first.matches(&confirmation) {
        return Err(Error::InvalidPassword(
            "password confirmation did not match",
        ));
    }
    Ok(first)
}

fn warn_on_residue(outcome: PublicationOutcome) {
    if outcome == PublicationOutcome::CommittedWithResidue {
        eprintln!(
            "warning: output was committed, but an internal temporary filename could not be removed"
        );
    }
}

fn run(cli: &Cli) -> Result<()> {
    match &cli.command {
        Command::Encrypt(args) => {
            let identity = if let Some(path) = &args.sign_key {
                let key_password = read_password("Signing-key password: ")?;
                Some(load_signing_identity(path, &key_password)?)
            } else {
                None
            };
            let password = read_confirmed_password("File password: ", "Confirm file password: ")?;
            let options = identity
                .as_ref()
                .map_or_else(EncryptOptions::unsigned, EncryptOptions::signed);
            warn_on_residue(encrypt_file(&args.input, &args.output, &password, options)?);
        }
        Command::Decrypt(args) => {
            let verification_key = args
                .verify_key
                .as_deref()
                .map(load_verification_key)
                .transpose()?;
            let password = read_password("File password: ")?;
            let options = verification_key
                .as_ref()
                .map_or_else(DecryptOptions::unsigned, DecryptOptions::require_signature);
            warn_on_residue(decrypt_file(&args.input, &args.output, &password, options)?);
        }
        Command::Keygen(args) => {
            let password = read_confirmed_password(
                "Signing-key password: ",
                "Confirm signing-key password: ",
            )?;
            warn_on_residue(generate_key_bundle(&args.output, &password)?);
        }
        Command::ExportPublic(args) => {
            warn_on_residue(export_public_key(&args.bundle, &args.output)?);
        }
    }
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    if let Err(error) = run(&cli) {
        eprintln!("{error}");
        if cli.verbose {
            let mut source = error.source();
            while let Some(current) = source {
                eprintln!("caused by: {current}");
                source = current.source();
            }
        }
        std::process::exit(1);
    }
}
