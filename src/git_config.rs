use crate::error::{Context, Error, Result};
use crate::key_store::{self, KeyStatus, KeyStore};
use std::process::Command;

const FILTER_NAME: &str = "git-zcrypt";
const CLEAN_KEY: &str = "filter.git-zcrypt.clean";
const SMUDGE_KEY: &str = "filter.git-zcrypt.smudge";
const REQUIRED_KEY: &str = "filter.git-zcrypt.required";

pub fn install_filter(key_name: &str) -> Result<()> {
    key_store::validate_key_name(key_name)?;
    git_config_set(
        CLEAN_KEY,
        &format!("git-zcrypt clean --key {key_name} --path %f"),
    )?;
    git_config_set(SMUDGE_KEY, "git-zcrypt smudge --path %f")?;
    git_config_set(REQUIRED_KEY, "true")?;
    Ok(())
}

pub fn print_status() -> Result<()> {
    let store = KeyStore::discover()?;
    let (keys, warnings) = store.indexed_keys()?;
    let config = filter_config()?;

    println!("state: {}", store.root().display());
    println!(
        "state_exists: {}",
        if store.keys_dir().is_dir() {
            "yes"
        } else {
            "no"
        }
    );
    println!("keys: {}", format_keys(&keys));
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
    println!(
        "filter_installed: {}",
        if config.is_installed() { "yes" } else { "no" }
    );
    println!("clean: {}", config.clean.as_deref().unwrap_or("(unset)"));
    println!("smudge: {}", config.smudge.as_deref().unwrap_or("(unset)"));
    println!(
        "required: {}",
        config.required.as_deref().unwrap_or("(unset)")
    );
    Ok(())
}

fn format_keys(keys: &[KeyStatus]) -> String {
    if keys.is_empty() {
        return "(none)".to_owned();
    }
    keys.iter()
        .map(|key| format!("{} ({})", key.name, key.key_id))
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Debug, PartialEq, Eq)]
struct FilterConfig {
    clean: Option<String>,
    smudge: Option<String>,
    required: Option<String>,
}

impl FilterConfig {
    fn is_installed(&self) -> bool {
        self.clean.as_deref().is_some_and(|value| {
            value.starts_with(&format!("{FILTER_NAME} clean --key "))
                && value.contains(" --path %f")
        }) && self.smudge.as_deref() == Some("git-zcrypt smudge --path %f")
            && self.required.as_deref() == Some("true")
    }
}

fn filter_config() -> Result<FilterConfig> {
    Ok(FilterConfig {
        clean: git_config_get(CLEAN_KEY)?,
        smudge: git_config_get(SMUDGE_KEY)?,
        required: git_config_get(REQUIRED_KEY)?,
    })
}

fn git_config_set(key: &str, value: &str) -> Result<()> {
    let output = Command::new("git")
        .args(["config", "--local", key, value])
        .output()
        .with_context(|| format!("failed to set local Git config {key}"))?;

    if !output.status.success() {
        return Err(Error::msg(format!(
            "failed to set local Git config {key}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    Ok(())
}

fn git_config_get(key: &str) -> Result<Option<String>> {
    let output = Command::new("git")
        .args(["config", "--local", "--get", key])
        .output()
        .with_context(|| format!("failed to read local Git config {key}"))?;

    if output.status.success() {
        let value = String::from_utf8(output.stdout)
            .with_context(|| format!("local Git config {key} is not UTF-8"))?;
        return Ok(Some(value.trim_end_matches(&['\r', '\n'][..]).to_owned()));
    }

    match output.status.code() {
        Some(1) => Ok(None),
        _ => Err(Error::msg(format!(
            "failed to read local Git config {key}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{filter_config, format_keys, install_filter};
    use crate::key_store::{KeyStatus, KeyStore};
    use std::process::Command;
    use tempfile::TempDir;

    #[test]
    fn install_filter_writes_local_git_config() {
        let temp = TempDir::new().expect("tempdir");
        let status = Command::new("git")
            .arg("init")
            .current_dir(temp.path())
            .status()
            .expect("git init");
        assert!(status.success());

        let original_dir = std::env::current_dir().expect("current dir");
        std::env::set_current_dir(temp.path()).expect("chdir temp repo");
        let result = (|| {
            install_filter("default")?;
            let config = filter_config()?;
            assert_eq!(
                config.clean.as_deref(),
                Some("git-zcrypt clean --key default --path %f")
            );
            assert_eq!(
                config.smudge.as_deref(),
                Some("git-zcrypt smudge --path %f")
            );
            assert_eq!(config.required.as_deref(), Some("true"));
            assert!(config.is_installed());
            Ok::<_, crate::error::Error>(())
        })();
        std::env::set_current_dir(original_dir).expect("restore cwd");

        result.expect("install filter");
    }

    #[test]
    fn install_filter_rejects_invalid_key_name() {
        install_filter("../bad").expect_err("invalid key name");
    }

    #[test]
    fn status_lists_aliases_with_hash_prefixed_key_ids() {
        let keys = vec![
            KeyStatus {
                name: "alpha".to_owned(),
                key_id: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
            },
            KeyStatus {
                name: "beta".to_owned(),
                key_id: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_owned(),
            },
        ];
        assert_eq!(
            format_keys(&keys),
            "alpha (sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa), beta (sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)"
        );
    }

    #[test]
    fn status_lists_local_key_files() {
        let temp = TempDir::new().expect("tempdir");
        let status = Command::new("git")
            .arg("init")
            .current_dir(temp.path())
            .status()
            .expect("git init");
        assert!(status.success());

        let result = (|| {
            let store = KeyStore::discover_from(temp.path())?;
            store.store_key("default", &[1_u8; 32])?;
            let (keys, warnings) = store.indexed_keys()?;
            assert!(warnings.is_empty());
            assert_eq!(keys.len(), 1);
            assert_eq!(keys[0].name, "default");
            assert!(keys[0].key_id.starts_with("sha256:"));
            Ok::<_, crate::error::Error>(())
        })();

        result.expect("status local key listing");
    }
}
