use crate::error::Result;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

mod blob;
mod cli;
mod compression;
mod crypto;
mod error;
mod git_config;
mod index_json;
mod kdf;
mod key_manifest;
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
        Command::InitManifest { path } => key_manifest::init_manifest(&path).map(|_| ()),
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
        Command::Clean { key, path } => clean(&key, &path),
        Command::Smudge { path } => smudge(&path),
        Command::Register {
            manifest_dir,
            paths,
        } => register(manifest_dir.as_deref(), &paths),
    }
}

fn clean(key_name: &str, path: &Path) -> Result<()> {
    let store = key_store::KeyStore::discover()?;
    let (key, key_id) = store.read_key_with_id(key_name)?;
    let input = read_stdin()?;
    let compressed = compression::compress(&input)?;
    let encrypted = crypto::encrypt(&key, &key_id, &compressed)?;
    key_manifest::add_key_for_path(path, &encrypted.key_id, key_name)?;
    let encoded = blob::encode(&encrypted.key_id, &encrypted.nonce, &encrypted.ciphertext)?;
    write_stdout(&encoded)
}

fn smudge(path: &Path) -> Result<()> {
    let store = key_store::KeyStore::discover()?;
    let input = read_stdin()?;
    let encrypted = blob::decode(&input)?;
    match key_manifest::authorize_key_for_path(path, &encrypted.key_id)? {
        key_manifest::Authorization::Allowed => {}
        key_manifest::Authorization::KeyNotDeclared => {
            crate::bail!(
                "key {} is not declared for {}",
                encrypted.key_id,
                path.display()
            );
        }
        key_manifest::Authorization::MissingManifest => {
            eprintln!(
                "warning: no git-zcrypt-keys.json found for {}; leaving encrypted bytes unchanged",
                path.display()
            );
            return write_stdout(&input);
        }
    }
    let Some(key) = store.try_read_key_by_id(&encrypted.key_id)? else {
        eprintln!(
            "warning: no local key is registered for {}; leaving encrypted bytes for {}",
            encrypted.key_id,
            path.display()
        );
        return write_stdout(&input);
    };
    let compressed = crypto::decrypt(&key, &encrypted)?;
    let plaintext = compression::decompress(&compressed)?;
    write_stdout(&plaintext)
}

fn register(manifest_dir: Option<&Path>, paths: &[PathBuf]) -> Result<()> {
    let store = key_store::KeyStore::discover()?;
    let manifest = key_manifest::resolve_selected_manifest_dir(manifest_dir)?;
    for path in paths {
        let resolved = key_manifest::resolve_worktree_file(path)?;
        key_manifest::ensure_manifest_covers_path(&manifest, &resolved.repo_path)?;
        let input = std::fs::read(&resolved.worktree_path).map_err(|error| {
            crate::error::Error::msg(format!(
                "failed to read encrypted file {}: {error}",
                resolved.worktree_path.display()
            ))
        })?;
        let encrypted = blob::decode(&input).map_err(|error| {
            crate::error::Error::msg(format!(
                "failed to decode encrypted file {}: {error:#}",
                resolved.input_path.display()
            ))
        })?;
        if let Some(key_name) = store.key_name_for_id(&encrypted.key_id)? {
            key_manifest::add_key_to_manifest(&manifest.path, &encrypted.key_id, &key_name)?;
        } else {
            eprintln!(
                "warning: no local key is registered for {}; leaving manifest entry absent for {}",
                encrypted.key_id,
                resolved.repo_path.display()
            );
            key_manifest::ensure_manifest(&manifest.path)?;
        }
    }
    Ok(())
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
