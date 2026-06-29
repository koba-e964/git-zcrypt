use anyhow::{Context, Result, anyhow, bail, ensure};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use zeroize::{Zeroize, Zeroizing};

pub const RAW_KEY_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct KeyStore {
    root: PathBuf,
}

impl KeyStore {
    pub fn discover() -> Result<Self> {
        let git_dir = git_dir(None)?;
        Ok(Self {
            root: git_dir.join("git-zcrypt"),
        })
    }

    pub fn discover_from(cwd: &Path) -> Result<Self> {
        let git_dir = git_dir(Some(cwd))?;
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

    pub fn generate_key(&self, name: &str) -> Result<()> {
        let mut key = [0_u8; RAW_KEY_LEN];
        getrandom::fill(&mut key).context("failed to generate key material")?;
        let result = self.write_key(name, &key);
        key.zeroize();
        result
    }

    pub fn import_key(&self, name: &str, input: &Path) -> Result<()> {
        let bytes = Zeroizing::new(
            fs::read(input)
                .with_context(|| format!("failed to read key from {}", input.display()))?,
        );
        ensure!(
            bytes.len() == RAW_KEY_LEN,
            "raw key must be exactly {RAW_KEY_LEN} bytes, got {} bytes",
            bytes.len()
        );

        let mut key = [0_u8; RAW_KEY_LEN];
        key.copy_from_slice(&bytes);
        let result = self.write_key(name, &key);
        key.zeroize();
        result
    }

    pub fn export_key(&self, name: &str, output: &Path) -> Result<()> {
        let key = self.read_key(name)?;
        write_secret_file(output, &key)
            .with_context(|| format!("failed to export key to {}", output.display()))
    }

    pub fn read_key(&self, name: &str) -> Result<Zeroizing<Vec<u8>>> {
        let path = self.key_path(name)?;
        let bytes = Zeroizing::new(
            fs::read(&path).with_context(|| format!("failed to read key {}", path.display()))?,
        );
        ensure!(
            bytes.len() == RAW_KEY_LEN,
            "stored key {name} must be exactly {RAW_KEY_LEN} bytes, got {} bytes",
            bytes.len()
        );
        Ok(bytes)
    }

    fn write_key(&self, name: &str, key: &[u8; RAW_KEY_LEN]) -> Result<()> {
        self.init()?;
        let path = self.key_path(name)?;
        write_secret_file(&path, key)
            .with_context(|| format!("failed to write key {}", path.display()))
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

fn git_dir(cwd: Option<&Path>) -> Result<PathBuf> {
    let mut command = Command::new("git");
    command.args(["rev-parse", "--absolute-git-dir"]);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let output = command.output().context("failed to locate Git directory")?;

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

#[cfg(unix)]
fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{KeyStore, validate_key_name};
    use std::fs;
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

        let result = (|| {
            let store = KeyStore::discover_from(temp.path())?;
            store.init()?;
            assert!(store.root().ends_with(".git/git-zcrypt"));
            assert!(store.keys_dir().is_dir());
            assert!(store.key_path("default")?.ends_with("keys/default.key"));
            Ok::<_, anyhow::Error>(())
        })();

        result.expect("key store init");
    }

    #[test]
    fn generate_import_and_export_require_raw_32_byte_keys() {
        let temp = TempDir::new().expect("tempdir");
        let status = Command::new("git")
            .arg("init")
            .current_dir(temp.path())
            .status()
            .expect("git init");
        assert!(status.success());

        let result = (|| {
            let store = KeyStore::discover_from(temp.path())?;
            store.generate_key("generated")?;
            assert_eq!(fs::read(store.key_path("generated")?)?.len(), 32);

            let invalid = temp.path().join("invalid.key");
            fs::write(&invalid, [7_u8; 31])?;
            store
                .import_key("invalid", &invalid)
                .expect_err("invalid key length");

            let imported = temp.path().join("imported.key");
            fs::write(&imported, [9_u8; 32])?;
            store.import_key("imported", &imported)?;

            let exported = temp.path().join("exported.key");
            store.export_key("imported", &exported)?;
            assert_eq!(fs::read(exported)?, [9_u8; 32]);
            Ok::<_, anyhow::Error>(())
        })();

        result.expect("raw key commands");
    }
}
