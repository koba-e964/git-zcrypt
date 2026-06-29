use crate::key_store::{self, KeyStore};
use anyhow::{Context, Result, anyhow};
use std::process::Command;

const FILTER_NAME: &str = "git-zcrypt";
const CLEAN_KEY: &str = "filter.git-zcrypt.clean";
const SMUDGE_KEY: &str = "filter.git-zcrypt.smudge";
const REQUIRED_KEY: &str = "filter.git-zcrypt.required";

pub fn install_filter(key_name: &str) -> Result<()> {
    key_store::validate_key_name(key_name)?;
    git_config_set(CLEAN_KEY, &format!("git-zcrypt clean --key {key_name}"))?;
    git_config_set(SMUDGE_KEY, "git-zcrypt smudge")?;
    git_config_set(REQUIRED_KEY, "true")?;
    Ok(())
}

pub fn print_status() -> Result<()> {
    let store = KeyStore::discover()?;
    let keys = store.key_names()?;
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
    println!(
        "keys: {}",
        if keys.is_empty() {
            "(none)".to_owned()
        } else {
            keys.join(", ")
        }
    );
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

#[derive(Debug, PartialEq, Eq)]
struct FilterConfig {
    clean: Option<String>,
    smudge: Option<String>,
    required: Option<String>,
}

impl FilterConfig {
    fn is_installed(&self) -> bool {
        self.clean
            .as_deref()
            .is_some_and(|value| value.starts_with(&format!("{FILTER_NAME} clean --key ")))
            && self.smudge.as_deref() == Some("git-zcrypt smudge")
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
        return Err(anyhow!(
            "failed to set local Git config {key}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
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
        _ => Err(anyhow!(
            "failed to read local Git config {key}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{filter_config, install_filter};
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
                Some("git-zcrypt clean --key default")
            );
            assert_eq!(config.smudge.as_deref(), Some("git-zcrypt smudge"));
            assert_eq!(config.required.as_deref(), Some("true"));
            assert!(config.is_installed());
            Ok::<_, anyhow::Error>(())
        })();
        std::env::set_current_dir(original_dir).expect("restore cwd");

        result.expect("install filter");
    }

    #[test]
    fn install_filter_rejects_invalid_key_name() {
        install_filter("../bad").expect_err("invalid key name");
    }
}
