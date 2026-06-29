use anyhow::{Context, Result, anyhow, bail};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct KeyStore {
    root: PathBuf,
}

impl KeyStore {
    pub fn discover() -> Result<Self> {
        let git_dir = git_dir()?;
        Ok(Self {
            root: git_dir.join("git-zcrypt"),
        })
    }

    pub fn init(&self) -> Result<()> {
        fs::create_dir_all(self.keys_dir()).with_context(|| {
            format!(
                "failed to create git-zcrypt key directory at {}",
                self.keys_dir().display()
            )
        })?;
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.root.join("keys")
    }

    pub fn key_path(&self, name: &str) -> Result<PathBuf> {
        validate_key_name(name)?;
        Ok(self.keys_dir().join(format!("{name}.key")))
    }
}

pub fn validate_key_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("key name must not be empty");
    }

    if name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        Ok(())
    } else {
        bail!("key name may only contain ASCII letters, digits, '_' and '-'")
    }
}

fn git_dir() -> Result<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--absolute-git-dir"])
        .output()
        .context("failed to locate Git directory")?;

    if !output.status.success() {
        return Err(anyhow!(
            "not inside a Git repository: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let stdout = String::from_utf8(output.stdout).context("Git directory path is not UTF-8")?;
    let path = stdout.trim();
    if path.is_empty() {
        bail!("Git directory path is empty");
    }

    Ok(PathBuf::from(path))
}

#[cfg(test)]
mod tests {
    use super::{KeyStore, validate_key_name};
    use std::process::Command;
    use tempfile::TempDir;

    #[test]
    fn validates_key_names() {
        for valid in ["default", "team_1", "release-key", "A1_b-2"] {
            validate_key_name(valid).expect("valid key name");
        }

        for invalid in ["", "../key", "key.name", "key name", "鍵"] {
            validate_key_name(invalid).expect_err("invalid key name");
        }
    }

    #[test]
    fn init_creates_keys_directory_in_git_dir() {
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
            let store = KeyStore::discover()?;
            store.init()?;
            assert!(store.root().ends_with(".git/git-zcrypt"));
            assert!(store.keys_dir().is_dir());
            assert!(store.key_path("default")?.ends_with("keys/default.key"));
            Ok::<_, anyhow::Error>(())
        })();
        std::env::set_current_dir(original_dir).expect("restore cwd");

        result.expect("key store init");
    }
}
