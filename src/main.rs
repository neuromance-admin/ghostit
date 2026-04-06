use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ghostid")]
#[command(about = "Encrypt any folder on your drive. No account. No server. Your key, your data.")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a folder into a GhostID encrypted directory
    Encrypt {
        /// Path to the source folder
        #[arg(short, long)]
        source: PathBuf,

        /// Path for the encrypted output directory
        #[arg(short, long, required_unless_present = "in_place")]
        target: Option<PathBuf>,

        /// Encrypt in place (verify round-trip, then replace original)
        #[arg(long, conflicts_with = "target")]
        in_place: bool,

        /// Encryption passphrase (omit to be prompted)
        #[arg(short, long)]
        passphrase: Option<String>,
    },

    /// Decrypt a GhostID directory back to its original form
    Decrypt {
        /// Path to the encrypted directory
        #[arg(short, long)]
        source: PathBuf,

        /// Path for the decrypted output directory
        #[arg(short, long, required_unless_present = "in_place")]
        target: Option<PathBuf>,

        /// Decrypt in place (verify round-trip, then replace encrypted with plaintext)
        #[arg(long, conflicts_with = "target")]
        in_place: bool,

        /// Decryption passphrase (omit to be prompted)
        #[arg(short, long)]
        passphrase: Option<String>,
    },

    /// Unlock an encrypted directory to a temporary workspace
    Unlock {
        /// Path to the encrypted directory
        #[arg(short, long)]
        dir: PathBuf,

        /// Decryption passphrase (omit to be prompted)
        #[arg(short, long)]
        passphrase: Option<String>,
    },

    /// Re-encrypt a temporary workspace and wipe the plaintext
    Lock {
        /// Path to the unlocked temporary workspace
        #[arg(short, long)]
        workspace: PathBuf,

        /// Path to the encrypted directory to update
        #[arg(short, long)]
        dir: PathBuf,

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

fn get_passphrase_for_encryption(provided: Option<String>) -> Result<String, String> {
    match provided {
        Some(p) => Ok(p),
        None => {
            eprintln!();
            eprintln!("  WARNING: If you lose this passphrase, your data is permanently unrecoverable.");
            eprintln!("  There is no reset. There is no backdoor. There is no support.");
            eprintln!();
            eprint!("  Enter passphrase (min 12 characters): ");
            let mut input = String::new();
            std::io::stdin()
                .read_line(&mut input)
                .expect("Failed to read passphrase");
            let pass = input.trim().to_string();

            eprint!("  Confirm passphrase: ");
            let mut confirm = String::new();
            std::io::stdin()
                .read_line(&mut confirm)
                .expect("Failed to read passphrase");
            let confirm = confirm.trim().to_string();

            if pass != confirm {
                return Err("Passphrases do not match. Nothing was encrypted.".to_string());
            }

            eprintln!();
            Ok(pass)
        }
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            source,
            target,
            in_place,
            passphrase,
        } => {
            let pass = get_passphrase_for_encryption(passphrase)?;
            if in_place {
                eprintln!("Encrypting in place: {}", source.display());
                ghostid::vault::encrypt_in_place(&source, &pass)
            } else {
                let target = target.unwrap();
                eprintln!("Encrypting: {}", source.display());
                ghostid::vault::encrypt_dir(&source, &target, &pass)
            }
        }

        Commands::Decrypt {
            source,
            target,
            in_place,
            passphrase,
        } => {
            let pass = get_passphrase(passphrase);
            if in_place {
                eprintln!("Decrypting in place: {}", source.display());
                ghostid::vault::decrypt_in_place(&source, &pass)
            } else {
                let target = target.unwrap();
                eprintln!("Decrypting: {}", source.display());
                ghostid::vault::decrypt_dir(&source, &target, &pass)
            }
        }

        Commands::Unlock { dir, passphrase } => {
            let pass = get_passphrase(passphrase);
            eprintln!("Unlocking: {}", dir.display());
            match ghostid::vault::unlock_dir(&dir, &pass) {
                Ok(temp_path) => {
                    println!("{}", temp_path.display());
                    eprintln!("Unlocked. Workspace at: {}", temp_path.display());
                    eprintln!("Run `ghostid lock` when done to re-encrypt.");
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }

        Commands::Lock {
            workspace,
            dir,
            passphrase,
        } => {
            let pass = get_passphrase_for_encryption(passphrase)?;
            eprintln!("Re-encrypting: {}", workspace.display());
            let result = ghostid::vault::encrypt_dir(&workspace, &dir, &pass);

            if result.is_ok() {
                if let Err(e) = std::fs::remove_dir_all(&workspace) {
                    eprintln!("Warning: failed to clean up workspace: {e}");
                } else {
                    eprintln!("Workspace wiped.");
                }
            }

            result
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
