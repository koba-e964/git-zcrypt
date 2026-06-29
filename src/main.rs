use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod compression;
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
        #[arg(long)]
        name: String,
    },
    /// Import a raw 32-byte key file.
    ImportKey {
        #[arg(long)]
        name: String,
        #[arg(long)]
        input: PathBuf,
    },
    /// Export a stored raw key file.
    ExportKey {
        #[arg(long)]
        name: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Install local Git filter config.
    InstallFilter {
        #[arg(long)]
        name: String,
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
        Command::GenerateKey { name } => {
            let store = key_store::KeyStore::discover()?;
            store.generate_key(&name)
        }
        Command::ImportKey { name, input } => {
            let store = key_store::KeyStore::discover()?;
            store.import_key(&name, &input)
        }
        Command::ExportKey { name, output } => {
            let store = key_store::KeyStore::discover()?;
            store.export_key(&name, &output)
        }
        Command::InstallFilter { .. } => stub("install-filter"),
        Command::Status => stub("status"),
        Command::Clean { .. } => stub("clean"),
        Command::Smudge => stub("smudge"),
    }
}

fn stub(command: &str) -> Result<()> {
    bail!("{command} is not implemented yet")
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::Parser;

    #[test]
    fn parses_planned_subcommands() {
        for args in [
            vec!["git-zcrypt", "init"],
            vec!["git-zcrypt", "generate-key", "--name", "default"],
            vec![
                "git-zcrypt",
                "import-key",
                "--name",
                "default",
                "--input",
                "key.bin",
            ],
            vec![
                "git-zcrypt",
                "export-key",
                "--name",
                "default",
                "--output",
                "key.bin",
            ],
            vec!["git-zcrypt", "install-filter", "--name", "default"],
            vec!["git-zcrypt", "status"],
            vec!["git-zcrypt", "clean", "--key", "default"],
            vec!["git-zcrypt", "smudge"],
        ] {
            Cli::try_parse_from(args).expect("subcommand should parse");
        }
    }
}
