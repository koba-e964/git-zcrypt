use anyhow::Result;
use clap::{Parser, Subcommand};
use std::io::{self, Read, Write};
use std::path::PathBuf;

mod blob;
mod compression;
mod crypto;
mod git_config;
mod index_json;
mod kdf;
mod key_store;

#[derive(Debug, Parser)]
#[command(name = "git-zcrypt")]
#[command(about = "Compressing and encrypting Git clean/smudge filter")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create local git-zcrypt state in the current Git repository.
    Init,
    /// Generate and store a raw 32-byte key.
    GenerateKey {
        #[arg(long, alias = "name")]
        key: String,
    },
    /// Import a raw 32-byte key file.
    ImportKey {
        #[arg(long, alias = "name")]
        key: String,
        #[arg(long)]
        input: PathBuf,
    },
    /// Derive and store a raw key from a password.
    DeriveKey {
        #[arg(long, alias = "name")]
        key: String,
        #[arg(long)]
        stdin: bool,
    },
    /// Export a stored raw key file.
    ExportKey {
        #[arg(long, alias = "name")]
        key: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Install local Git filter config.
    InstallFilter {
        #[arg(long, alias = "name")]
        key: String,
    },
    /// Report local git-zcrypt state and filter config.
    Status,
    /// Compress and encrypt stdin to stdout.
    Clean {
        #[arg(long)]
        key: String,
    },
    /// Decrypt and decompress stdin to stdout.
    Smudge,
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Init => {
            let store = key_store::KeyStore::discover()?;
            store.init()
        }
        Command::GenerateKey { key } => {
            let store = key_store::KeyStore::discover()?;
            store.generate_key(&key)
        }
        Command::ImportKey { key, input } => {
            let store = key_store::KeyStore::discover()?;
            store.import_key(&key, &input)
        }
        Command::DeriveKey { key, stdin } => {
            let store = key_store::KeyStore::discover()?;
            let mut derived_key = if stdin {
                kdf::derive_key_from_stdin()?
            } else {
                kdf::derive_key_from_prompt()?
            };
            let result = store.store_key(&key, &derived_key);
            zeroize::Zeroize::zeroize(&mut derived_key);
            result
        }
        Command::ExportKey { key, output } => {
            let store = key_store::KeyStore::discover()?;
            store.export_key(&key, &output)
        }
        Command::InstallFilter { key } => git_config::install_filter(&key),
        Command::Status => git_config::print_status(),
        Command::Clean { key } => clean(&key),
        Command::Smudge => smudge(),
    }
}

fn clean(key_name: &str) -> Result<()> {
    let store = key_store::KeyStore::discover()?;
    let (key, key_id) = store.read_key_with_id(key_name)?;
    let input = read_stdin()?;
    let compressed = compression::compress(&input)?;
    let encrypted = crypto::encrypt(&key, &key_id, &compressed)?;
    let encoded = blob::encode(&encrypted.key_id, &encrypted.nonce, &encrypted.ciphertext)?;
    write_stdout(&encoded)
}

fn smudge() -> Result<()> {
    let store = key_store::KeyStore::discover()?;
    let input = read_stdin()?;
    let encrypted = blob::decode(&input)?;
    let key = store.read_key_by_id(&encrypted.key_id)?;
    let compressed = crypto::decrypt(&key, &encrypted)?;
    let plaintext = compression::decompress(&compressed)?;
    write_stdout(&plaintext)
}

fn read_stdin() -> Result<Vec<u8>> {
    let mut input = Vec::new();
    io::stdin().lock().read_to_end(&mut input)?;
    Ok(input)
}

fn write_stdout(bytes: &[u8]) -> Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(bytes)?;
    stdout.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::Parser;

    #[test]
    fn parses_planned_subcommands() {
        for args in [
            vec!["git-zcrypt", "init"],
            vec!["git-zcrypt", "generate-key", "--key", "default"],
            vec![
                "git-zcrypt",
                "import-key",
                "--key",
                "default",
                "--input",
                "key.bin",
            ],
            vec!["git-zcrypt", "derive-key", "--key", "default"],
            vec!["git-zcrypt", "derive-key", "--key", "default", "--stdin"],
            vec![
                "git-zcrypt",
                "export-key",
                "--key",
                "default",
                "--output",
                "key.bin",
            ],
            vec!["git-zcrypt", "install-filter", "--key", "default"],
            vec!["git-zcrypt", "status"],
            vec!["git-zcrypt", "clean", "--key", "default"],
            vec!["git-zcrypt", "smudge"],
        ] {
            Cli::try_parse_from(args).expect("subcommand should parse");
        }
    }

    #[test]
    fn parses_key_option_for_key_commands() {
        for args in [
            vec!["git-zcrypt", "generate-key", "--key", "default"],
            vec![
                "git-zcrypt",
                "import-key",
                "--key",
                "default",
                "--input",
                "key.bin",
            ],
            vec!["git-zcrypt", "derive-key", "--key", "default"],
            vec!["git-zcrypt", "derive-key", "--key", "default", "--stdin"],
            vec![
                "git-zcrypt",
                "export-key",
                "--key",
                "default",
                "--output",
                "key.bin",
            ],
            vec!["git-zcrypt", "install-filter", "--key", "default"],
            vec!["git-zcrypt", "clean", "--key", "default"],
        ] {
            Cli::try_parse_from(args).expect("--key should parse");
        }
    }
}
