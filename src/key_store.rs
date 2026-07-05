use crate::error::{Context, Error, Result};
use crate::index_json;
use crate::{bail, ensure};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use zeroize::{Zeroize, Zeroizing};

pub const RAW_KEY_LEN: usize = 32;
const KEY_ID_PREFIX: &str = "sha256:";
const INDEX_FILE: &str = "index.json";
const KEY_FILE_MAGIC: [u8; 8] = *b"GZCKEY\0\0";
const KEY_FILE_VERSION: u8 = 1;
const KEY_FILE_HEADER_LEN: usize = 12;

#[derive(Debug, Clone)]
pub struct KeyStore {
    root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyStatus {
    pub name: String,
    pub key_id: String,
}

impl KeyStore {
    pub fn discover() -> Result<Self> {
        let git_dir = git_dir(None)?;
        Ok(Self {
            root: git_dir.join("git-zcrypt"),
        })
    }

    #[cfg(test)]
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

    pub fn index_path(&self) -> PathBuf {
        self.root.join(INDEX_FILE)
    }

    pub fn key_path(&self, name: &str) -> Result<PathBuf> {
        validate_key_name(name)?;
        Ok(self.keys_dir().join(format!("{name}.key")))
    }

    pub fn key_names(&self) -> Result<Vec<String>> {
        let keys_dir = self.keys_dir();
        if !keys_dir.exists() {
            return Ok(Vec::new());
        }

        let mut names = Vec::new();
        for entry in fs::read_dir(&keys_dir)
            .with_context(|| format!("failed to list key directory {}", keys_dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("key") {
                continue;
            }
            if let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) {
                names.push(stem.to_owned());
            }
        }
        names.sort();
        Ok(names)
    }

    pub fn indexed_keys(&self) -> Result<(Vec<KeyStatus>, Vec<String>)> {
        let index = self.read_index()?;
        let mut warnings = Vec::new();
        let mut statuses = Vec::new();
        let mut indexed_names = BTreeSet::new();

        for (key_id, name) in &index {
            indexed_names.insert(name.clone());
            match self.read_key(name) {
                Ok(key) => {
                    let actual = key_id_for_key_bytes(&key)?;
                    if actual == *key_id {
                        statuses.push(KeyStatus {
                            name: name.clone(),
                            key_id: key_id.clone(),
                        });
                    } else {
                        warnings.push(format!(
                            "key index mismatch: {name} is indexed as {key_id} but computes to {actual}"
                        ));
                    }
                }
                Err(error) => warnings.push(format!(
                    "key index mismatch: {key_id} points to {name}, but the key cannot be read: {error:#}"
                )),
            }
        }

        for name in self.key_names()? {
            if !indexed_names.contains(&name) {
                warnings.push(format!(
                    "key index mismatch: {name} exists but is not indexed"
                ));
            }
        }

        statuses.sort_by(|left, right| left.name.cmp(&right.name));
        Ok((statuses, warnings))
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

    pub fn store_key(&self, name: &str, key: &[u8; RAW_KEY_LEN]) -> Result<()> {
        self.write_key(name, key)
    }

    pub fn export_key(&self, name: &str, output: &Path) -> Result<()> {
        let key = self.read_key(name)?;
        write_secret_file(output, &key)
            .with_context(|| format!("failed to export key to {}", output.display()))
    }

    pub fn delete_key(&self, name: &str) -> Result<()> {
        let path = self.key_path(name)?;
        let mut index = self.read_index()?;
        let original_len = index.len();
        index.retain(|_, indexed_name| indexed_name != name);
        let was_indexed = index.len() != original_len;
        let key_file_exists = path.exists();

        ensure!(key_file_exists || was_indexed, "key {name} does not exist");

        if was_indexed {
            self.write_index(&index)?;
        }
        if key_file_exists {
            fs::remove_file(&path)
                .with_context(|| format!("failed to delete key {}", path.display()))?;
            sync_dir(&self.keys_dir())?;
        }
        Ok(())
    }

    pub fn read_key_with_id(&self, name: &str) -> Result<(Zeroizing<Vec<u8>>, String)> {
        let key = self.read_key(name)?;
        let key_id = key_id_for_key_bytes(&key)?;
        Ok((key, key_id))
    }

    pub fn read_key_by_id(&self, key_id: &str) -> Result<Zeroizing<Vec<u8>>> {
        validate_key_id(key_id)?;
        let index = self.read_index()?;
        let name = index
            .get(key_id)
            .with_context(|| format!("no local key is registered for {key_id}"))?;
        let key = self.read_key(name)?;
        let actual = key_id_for_key_bytes(&key)?;
        if actual != key_id {
            eprintln!(
                "warning: key index mismatch: {key_id} points to {name}, but the key computes to {actual}"
            );
            bail!("key index mismatch for {key_id}");
        }
        Ok(key)
    }

    pub fn read_key(&self, name: &str) -> Result<Zeroizing<Vec<u8>>> {
        let path = self.key_path(name)?;
        let bytes = Zeroizing::new(
            fs::read(&path).with_context(|| format!("failed to read key {}", path.display()))?,
        );
        decode_key_file(name, &bytes)
    }

    fn write_key(&self, name: &str, key: &[u8; RAW_KEY_LEN]) -> Result<()> {
        self.init()?;
        let path = self.key_path(name)?;
        ensure!(
            !path.exists(),
            "key {name} already exists; refusing to overwrite"
        );

        let mut index = self.read_index()?;
        ensure!(
            !index.values().any(|existing| existing == name),
            "key alias {name} is already registered"
        );
        let key_id = key_id_for_key(key);
        ensure!(
            !index.contains_key(&key_id),
            "key material is already registered as {key_id}"
        );

        let encoded = Zeroizing::new(encode_key_file(key));
        write_secret_file(&path, &encoded)
            .with_context(|| format!("failed to write key {}", path.display()))?;
        index.insert(key_id, name.to_owned());
        self.write_index(&index)
    }

    fn read_index(&self) -> Result<BTreeMap<String, String>> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(BTreeMap::new());
        }

        let input = fs::read_to_string(&path)
            .with_context(|| format!("failed to read key index {}", path.display()))?;
        let index = index_json::parse_string_map(&input)
            .with_context(|| format!("failed to parse key index {}", path.display()))?;
        for (key_id, name) in &index {
            validate_key_id(key_id)?;
            validate_key_name(name)?;
        }
        Ok(index)
    }

    fn write_index(&self, index: &BTreeMap<String, String>) -> Result<()> {
        self.init()?;
        let path = self.index_path();
        let temp_path = self.root.join(format!("{INDEX_FILE}.tmp"));
        let json = index_json::format_string_map(index);

        {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&temp_path)
                .with_context(|| {
                    format!("failed to open temporary key index {}", temp_path.display())
                })?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
        }

        fs::rename(&temp_path, &path).with_context(|| {
            format!(
                "failed to replace key index {} with {}",
                path.display(),
                temp_path.display()
            )
        })?;
        sync_dir(&self.root)?;
        Ok(())
    }
}

fn encode_key_file(key: &[u8; RAW_KEY_LEN]) -> Vec<u8> {
    let mut output = Vec::with_capacity(KEY_FILE_HEADER_LEN + RAW_KEY_LEN);
    output.extend_from_slice(&KEY_FILE_MAGIC);
    output.push(KEY_FILE_VERSION);
    output.push(RAW_KEY_LEN as u8);
    output.push(0);
    output.push(0);
    output.extend_from_slice(key);
    output
}

fn decode_key_file(name: &str, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        bytes.len() >= KEY_FILE_HEADER_LEN,
        "stored key {name} is shorter than key file header"
    );
    ensure!(
        bytes[..KEY_FILE_MAGIC.len()] == KEY_FILE_MAGIC,
        "stored key {name} has invalid key file magic"
    );
    ensure!(
        bytes[8] == KEY_FILE_VERSION,
        "stored key {name} has unsupported key file version {}",
        bytes[8]
    );
    ensure!(
        bytes[9] as usize == RAW_KEY_LEN,
        "stored key {name} declares invalid raw key length {}",
        bytes[9]
    );
    ensure!(
        bytes[10] == 0 && bytes[11] == 0,
        "stored key {name} has non-zero reserved key file header bytes"
    );
    ensure!(
        bytes.len() == KEY_FILE_HEADER_LEN + RAW_KEY_LEN,
        "stored key {name} must contain a {RAW_KEY_LEN}-byte raw key payload, got {} payload bytes",
        bytes.len().saturating_sub(KEY_FILE_HEADER_LEN)
    );
    Ok(Zeroizing::new(bytes[KEY_FILE_HEADER_LEN..].to_vec()))
}

pub fn key_id_for_key(key: &[u8; RAW_KEY_LEN]) -> String {
    let digest = Sha256::digest(key);
    format!("{KEY_ID_PREFIX}{}", hex_lower(&digest))
}

pub fn validate_key_id(key_id: &str) -> Result<()> {
    let hash = key_id
        .strip_prefix(KEY_ID_PREFIX)
        .context("key id must start with 'sha256:'")?;
    ensure!(hash.len() == 64, "sha256 key id must contain 64 hex chars");
    ensure!(
        hash.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "sha256 key id must use lowercase hex"
    );
    Ok(())
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

fn key_id_for_key_bytes(key: &[u8]) -> Result<String> {
    ensure!(
        key.len() == RAW_KEY_LEN,
        "raw key must be exactly {RAW_KEY_LEN} bytes, got {} bytes",
        key.len()
    );
    let mut fixed = [0_u8; RAW_KEY_LEN];
    fixed.copy_from_slice(key);
    let key_id = key_id_for_key(&fixed);
    fixed.zeroize();
    Ok(key_id)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn git_dir(cwd: Option<&Path>) -> Result<PathBuf> {
    let mut command = Command::new("git");
    command.args(["rev-parse", "--absolute-git-dir"]);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let output = command.output().context("failed to locate Git directory")?;

    if !output.status.success() {
        return Err(Error::msg(format!(
            "not inside a Git repository: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
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

#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<()> {
    let dir = fs::File::open(path)
        .with_context(|| format!("failed to open directory {} for sync", path.display()))?;
    dir.sync_all()
        .with_context(|| format!("failed to sync directory {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        KEY_FILE_HEADER_LEN, KEY_FILE_MAGIC, KEY_FILE_VERSION, KeyStore, RAW_KEY_LEN,
        key_id_for_key, validate_key_name,
    };
    use crate::index_json::{format_string_map, parse_string_map};
    use std::collections::BTreeMap;
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
            Ok::<_, crate::error::Error>(())
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
            let generated = fs::read(store.key_path("generated")?)?;
            assert_eq!(generated.len(), KEY_FILE_HEADER_LEN + RAW_KEY_LEN);
            assert_eq!(&generated[..KEY_FILE_MAGIC.len()], &KEY_FILE_MAGIC);
            assert_eq!(generated[8], KEY_FILE_VERSION);
            assert_eq!(generated[9] as usize, RAW_KEY_LEN);
            assert_eq!(&generated[10..12], &[0, 0]);

            let invalid = temp.path().join("invalid.key");
            fs::write(&invalid, [7_u8; 31])?;
            store
                .import_key("invalid", &invalid)
                .expect_err("invalid key length");

            let imported = temp.path().join("imported.key");
            fs::write(&imported, [9_u8; 32])?;
            store.import_key("imported", &imported)?;
            assert_eq!(store.read_key("imported")?.as_slice(), &[9_u8; 32]);

            let exported = temp.path().join("exported.key");
            store.export_key("imported", &exported)?;
            assert_eq!(fs::read(exported)?, [9_u8; 32]);
            Ok::<_, crate::error::Error>(())
        })();

        result.expect("raw key commands");
    }

    #[test]
    fn delete_key_removes_key_file_and_index_entry() {
        let temp = TempDir::new().expect("tempdir");
        let status = Command::new("git")
            .arg("init")
            .current_dir(temp.path())
            .status()
            .expect("git init");
        assert!(status.success());

        let result = (|| {
            let store = KeyStore::discover_from(temp.path())?;
            store.store_key("default", &[8_u8; 32])?;
            assert!(store.key_path("default")?.exists());
            assert!(!store.read_index()?.is_empty());

            store.delete_key("default")?;
            assert!(!store.key_path("default")?.exists());
            assert!(store.read_index()?.is_empty());
            store
                .delete_key("default")
                .expect_err("missing key should fail");
            Ok::<_, crate::error::Error>(())
        })();

        result.expect("delete key");
    }

    #[test]
    fn versioned_key_files_reject_malformed_headers() {
        let temp = TempDir::new().expect("tempdir");
        let status = Command::new("git")
            .arg("init")
            .current_dir(temp.path())
            .status()
            .expect("git init");
        assert!(status.success());

        let result = (|| {
            let store = KeyStore::discover_from(temp.path())?;
            store.store_key("default", &[7_u8; 32])?;
            let valid = fs::read(store.key_path("default")?)?;

            let mut bad_magic = valid.clone();
            bad_magic[0] = b'X';
            fs::write(store.key_path("bad_magic")?, bad_magic)?;
            store.read_key("bad_magic").expect_err("bad magic");

            let mut bad_version = valid.clone();
            bad_version[8] = KEY_FILE_VERSION + 1;
            fs::write(store.key_path("bad_version")?, bad_version)?;
            store.read_key("bad_version").expect_err("bad version");

            let mut bad_key_len = valid.clone();
            bad_key_len[9] = 31;
            fs::write(store.key_path("bad_key_len")?, bad_key_len)?;
            store.read_key("bad_key_len").expect_err("bad key length");

            let mut bad_reserved = valid.clone();
            bad_reserved[10] = 1;
            fs::write(store.key_path("bad_reserved")?, bad_reserved)?;
            store
                .read_key("bad_reserved")
                .expect_err("bad reserved byte");

            let mut truncated = valid;
            truncated.pop();
            fs::write(store.key_path("truncated")?, truncated)?;
            store.read_key("truncated").expect_err("truncated payload");
            Ok::<_, crate::error::Error>(())
        })();

        result.expect("malformed key files");
    }

    #[test]
    fn key_id_for_key_uses_sha256_prefix() {
        let key = [0_u8; 32];
        assert_eq!(
            key_id_for_key(&key),
            "sha256:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
        );
    }

    #[test]
    fn index_json_round_trips_sorted_key_ids() {
        let mut index = BTreeMap::new();
        index.insert(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
            "beta".to_owned(),
        );
        index.insert(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            "alpha".to_owned(),
        );

        let json = format_string_map(&index);
        assert!(json.find("sha256:aaaa").unwrap() < json.find("sha256:bbbb").unwrap());
        assert_eq!(parse_string_map(&json).expect("parse index"), index);
    }

    #[test]
    fn index_json_rejects_invalid_shapes() {
        for invalid in [
            "[]",
            "{\"a\": {}}",
            "{\"a\": 1}",
            "{\"a\": \"b\", \"a\": \"c\"}",
            "{\"a\": \"b\"} trailing",
            "{\"a\": \"\\u0000\"}",
        ] {
            parse_string_map(invalid).expect_err("invalid index json");
        }
    }

    #[test]
    fn register_key_rejects_duplicate_key_material() {
        let temp = TempDir::new().expect("tempdir");
        let status = Command::new("git")
            .arg("init")
            .current_dir(temp.path())
            .status()
            .expect("git init");
        assert!(status.success());

        let result = (|| {
            let store = KeyStore::discover_from(temp.path())?;
            store.store_key("first", &[5_u8; 32])?;
            store
                .store_key("second", &[5_u8; 32])
                .expect_err("duplicate key material");
            Ok::<_, crate::error::Error>(())
        })();

        result.expect("duplicate rejection");
    }
}
