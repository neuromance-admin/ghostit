use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "chitin")]
#[command(about = "Encrypted document layer for Mycelium vaults")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a plaintext vault into a Chitin encrypted vault
    Encrypt {
        /// Path to the plaintext vault directory
        #[arg(short, long)]
        source: PathBuf,

        /// Path for the encrypted output directory
        #[arg(short, long)]
        target: PathBuf,

        /// Encryption passphrase (omit to be prompted)
        #[arg(short, long)]
        passphrase: Option<String>,
    },

    /// Decrypt a Chitin vault back to plaintext
    Decrypt {
        /// Path to the encrypted vault directory
        #[arg(short, long)]
        source: PathBuf,

        /// Path for the decrypted output directory
        #[arg(short, long)]
        target: PathBuf,

        /// Decryption passphrase (omit to be prompted)
        #[arg(short, long)]
        passphrase: Option<String>,
    },

    /// Unlock a vault to a temporary workspace for a session
    Unlock {
        /// Path to the encrypted vault directory
        #[arg(short, long)]
        vault: PathBuf,

        /// Decryption passphrase (omit to be prompted)
        #[arg(short, long)]
        passphrase: Option<String>,
    },

    /// Re-encrypt a temporary workspace and clean up
    Lock {
        /// Path to the unlocked temporary workspace
        #[arg(short, long)]
        workspace: PathBuf,

        /// Path to the encrypted vault directory to update
        #[arg(short, long)]
        vault: PathBuf,

        /// Encryption passphrase (omit to be prompted)
        #[arg(short, long)]
        passphrase: Option<String>,
    },
}

fn get_passphrase(provided: Option<String>) -> String {
    match provided {
        Some(p) => p,
        None => {
            eprint!("Passphrase: ");
            let mut input = String::new();
            std::io::stdin()
                .read_line(&mut input)
                .expect("Failed to read passphrase");
            input.trim().to_string()
        }
    }
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Encrypt {
            source,
            target,
            passphrase,
        } => {
            let pass = get_passphrase(passphrase);
            eprintln!("Encrypting vault: {}", source.display());
            chitin::vault::encrypt_vault(&source, &target, &pass)
        }

        Commands::Decrypt {
            source,
            target,
            passphrase,
        } => {
            let pass = get_passphrase(passphrase);
            eprintln!("Decrypting vault: {}", source.display());
            chitin::vault::decrypt_vault(&source, &target, &pass)
        }

        Commands::Unlock { vault, passphrase } => {
            let pass = get_passphrase(passphrase);
            eprintln!("Unlocking vault: {}", vault.display());
            match chitin::vault::unlock_vault(&vault, &pass) {
                Ok(temp_path) => {
                    println!("{}", temp_path.display());
                    eprintln!("Vault unlocked. Workspace at: {}", temp_path.display());
                    eprintln!("Run `chitin lock` when done to re-encrypt.");
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }

        Commands::Lock {
            workspace,
            vault,
            passphrase,
        } => {
            let pass = get_passphrase(passphrase);
            eprintln!("Re-encrypting workspace: {}", workspace.display());
            let result = chitin::vault::encrypt_vault(&workspace, &vault, &pass);

            if result.is_ok() {
                // Wipe the plaintext workspace
                if let Err(e) = std::fs::remove_dir_all(&workspace) {
                    eprintln!("Warning: failed to clean up workspace: {e}");
                } else {
                    eprintln!("Workspace wiped.");
                }
            }

            result
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
