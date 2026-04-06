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
        #[arg(short, long)]
        target: PathBuf,

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

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Encrypt {
            source,
            target,
            in_place,
            passphrase,
        } => {
            let pass = get_passphrase(passphrase);
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
            passphrase,
        } => {
            let pass = get_passphrase(passphrase);
            eprintln!("Decrypting: {}", source.display());
            ghostid::vault::decrypt_dir(&source, &target, &pass)
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
            let pass = get_passphrase(passphrase);
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
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
