use anyhow::Result;
use std::io::{self, Read, Write};

mod blob;
mod cli;
mod compression;
mod crypto;
mod git_config;
mod index_json;
mod kdf;
mod key_store;

use cli::{Cli, Command};

fn main() {
    let result = Cli::parse_env().and_then(run);
    if let Err(error) = result {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Help => {
            println!("{}", cli::usage());
            Ok(())
        }
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
        Command::DeleteKey { key } => {
            let store = key_store::KeyStore::discover()?;
            store.delete_key(&key)
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
