//! `delulu-sigil` — Delulu's official publisher tool for DAD local addons.
//!
//! It does exactly three things and nothing else:
//! 1. hash each platform binary and write its `sha256` into the manifest,
//! 2. (optionally) derive the release-asset `download_url` for a GitHub repo,
//! 3. ed25519-sign the manifest's canonical payload.
//!
//! It does NOT build addons (the SDK's `dad-local build` does) and does NOT
//! upload artifacts (GitHub releases do). The signature covers the manifest,
//! which binds the code through `platform_assets[*].sha256` and the download
//! destination through `platform_assets[*].download_url` — both are inside the
//! signed bytes.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod keygen;
mod keystore;
mod signing;

#[derive(Parser)]
#[command(
    name = "delulu-sigil",
    version,
    about = "Hash an addon's binaries, fill the manifest, and ed25519-sign it."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new ed25519 keypair and store it in Windows Credential Manager.
    ///
    /// The private key is never written to disk or printed. Public key is stored in the store.
    Keygen {
        /// Key id to store in Windows Credential Manager.
        #[arg(long, default_value = "delulu-official-v2")]
        key_id: String,
        /// Overwrite an existing key in the store.
        #[arg(long)]
        new: bool,
    },

    /// Show the public key stored in Windows Credential Manager.
    Pubkey {
        /// Key id in Windows Credential Manager.
        #[arg(long, default_value = "delulu-official-v2")]
        key_id: String,
    },

    /// Compute per-platform sha256, (optionally) fill download URLs, sign, and
    /// write the manifest. Signs using the key from Windows Credential Manager.
    Sign {
        /// Path to the authoring-state `manifest.json`.
        #[arg(long)]
        manifest: PathBuf,

        /// One or more `PLATFORM=PATH` pairs, e.g. `windows-x64=dist/addon.exe`.
        /// Every named platform must already exist in `platform_assets`.
        #[arg(long = "artifact", value_name = "PLATFORM=PATH", required = true, num_args = 1..)]
        artifacts: Vec<String>,

        /// Key id in Windows Credential Manager.
        #[arg(long, default_value = "delulu-official-v2")]
        key_id: String,

        /// Output path. Default: rewrite the input manifest in place.
        #[arg(long)]
        out: Option<PathBuf>,

        /// GitHub `owner/repo`. Enables deriving each `download_url` as a
        /// release-asset URL (the URL is signed, so it must be final first).
        #[arg(long)]
        repo: Option<String>,

        /// Release tag for derived URLs. Default: `v{version}`.
        #[arg(long)]
        tag: Option<String>,
    },

    /// Verify a signed manifest against a public key.
    Verify {
        #[arg(long)]
        manifest: PathBuf,

        /// Public key as 32-byte hex.
        #[arg(long)]
        pubkey_hex: Option<String>,

        /// File containing the 32-byte hex public key.
        #[arg(long)]
        pubkey_file: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Keygen { key_id, new } => keygen::run(&key_id, new),
        Command::Pubkey { key_id } => {
            #[cfg(windows)]
            {
                match keystore::read_pubkey_hex(&key_id) {
                    Ok(hex) => {
                        println!("{hex}");
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            #[cfg(not(windows))]
            {
                let _ = key_id;
                Err("Windows Credential Manager is required".to_string())
            }
        }
        Command::Sign {
            manifest,
            artifacts,
            key_id,
            out,
            repo,
            tag,
        } => signing::run_sign(
            &manifest,
            &artifacts,
            &key_id,
            out.as_deref(),
            repo.as_deref(),
            tag.as_deref(),
        ),
        Command::Verify {
            manifest,
            pubkey_hex,
            pubkey_file,
        } => signing::run_verify(&manifest, pubkey_hex.as_deref(), pubkey_file.as_deref()),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}
