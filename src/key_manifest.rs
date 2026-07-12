use crate::error::{Context, Error, Result};
use crate::index_json;
use crate::key_store;
use crate::{bail, ensure};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

pub const MANIFEST_FILE: &str = "git-zcrypt-keys.json";

pub fn init_manifest(path: &Path) -> Result<PathBuf> {
    let root = worktree_root()?;
    let dir = resolve_dir(&root, path)?;
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create manifest directory {}", dir.display()))?;
    let manifest = dir.join(MANIFEST_FILE);
    if manifest.exists() {
        read_manifest(&manifest)?;
        return Ok(manifest);
    }
    write_manifest(&manifest, &BTreeMap::new())?;
    Ok(manifest)
}

pub fn add_key_for_path(path: &Path, key_id: &str, key_name: &str) -> Result<PathBuf> {
    key_store::validate_key_id(key_id)?;
    key_store::validate_key_name(key_name)?;
    let root = worktree_root()?;
    let manifest = find_manifest_path(&root, path)?.unwrap_or_else(|| root.join(MANIFEST_FILE));
    let mut keys = if manifest.exists() {
        read_manifest(&manifest)?
    } else {
        BTreeMap::new()
    };
    if let Some(existing) = keys.get(key_id) {
        ensure!(
            existing == key_name,
            "manifest {} maps {key_id} to {existing}, not {key_name}",
            manifest.display()
        );
        return Ok(manifest);
    }
    keys.insert(key_id.to_owned(), key_name.to_owned());
    write_manifest(&manifest, &keys)?;
    Ok(manifest)
}

pub fn key_allowed_for_path(path: &Path, key_id: &str) -> Result<bool> {
    key_store::validate_key_id(key_id)?;
    let root = worktree_root()?;
    let manifest = find_manifest_path(&root, path)?.with_context(|| {
        format!(
            "no {MANIFEST_FILE} found for {}; run git-zcrypt init-manifest",
            path.display()
        )
    })?;
    let keys = read_manifest(&manifest)?;
    Ok(keys.contains_key(key_id))
}

pub fn read_manifest(path: &Path) -> Result<BTreeMap<String, String>> {
    let input = fs::read_to_string(path)
        .with_context(|| format!("failed to read key manifest {}", path.display()))?;
    let keys = index_json::parse_string_map(&input)
        .with_context(|| format!("failed to parse key manifest {}", path.display()))?;
    for (key_id, name) in &keys {
        key_store::validate_key_id(key_id)?;
        key_store::validate_key_name(name)?;
    }
    Ok(keys)
}

fn find_manifest_path(root: &Path, target: &Path) -> Result<Option<PathBuf>> {
    let mut dir = target_dir(root, target)?;
    loop {
        let manifest = dir.join(MANIFEST_FILE);
        if manifest.exists() {
            return Ok(Some(manifest));
        }
        if dir == root {
            return Ok(None);
        }
        if !dir.pop() {
            return Ok(None);
        }
    }
}

fn target_dir(root: &Path, target: &Path) -> Result<PathBuf> {
    ensure!(
        !target.as_os_str().is_empty(),
        "filter path must not be empty"
    );
    ensure!(
        !target.is_absolute(),
        "filter path must be repository-relative: {}",
        target.display()
    );
    for component in target.components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            bail!(
                "filter path must stay inside the repository: {}",
                target.display()
            );
        }
    }
    Ok(root.join(target).parent().unwrap_or(root).to_path_buf())
}

fn resolve_dir(root: &Path, path: &Path) -> Result<PathBuf> {
    ensure!(
        !path.is_absolute(),
        "manifest path must be relative: {}",
        path.display()
    );
    for component in path.components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            bail!(
                "manifest path must stay inside the repository: {}",
                path.display()
            );
        }
    }

    let current_dir = env::current_dir().context("failed to get current directory")?;
    let dir = if path.as_os_str().is_empty() || path == Path::new(".") {
        current_dir
    } else {
        current_dir.join(path)
    };
    ensure!(
        dir.starts_with(root),
        "manifest path must stay inside the repository: {}",
        path.display()
    );
    Ok(dir)
}

fn write_manifest(path: &Path, keys: &BTreeMap<String, String>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create manifest directory {}", parent.display()))?;
    }
    let temp_path = path.with_extension("json.tmp");
    let json = index_json::format_string_map(keys);
    {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp_path)
            .with_context(|| {
                format!("failed to open temporary manifest {}", temp_path.display())
            })?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(&temp_path, path).with_context(|| {
        format!(
            "failed to replace key manifest {} with {}",
            path.display(),
            temp_path.display()
        )
    })?;
    Ok(())
}

fn worktree_root() -> Result<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("failed to locate Git worktree root")?;
    if !output.status.success() {
        return Err(Error::msg(format!(
            "not inside a Git worktree: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let stdout = String::from_utf8(output.stdout).context("Git worktree root is not UTF-8")?;
    let path = stdout.trim();
    ensure!(!path.is_empty(), "Git worktree root path is empty");
    Ok(PathBuf::from(path))
}

#[cfg(test)]
mod tests {
    use super::{MANIFEST_FILE, read_manifest};
    use crate::index_json;
    use std::collections::BTreeMap;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn manifest_uses_index_style_map() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join(MANIFEST_FILE);
        fs::write(
            &path,
            "{\n  \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\": \"default\"\n}\n",
        )
        .expect("write manifest");
        let keys = read_manifest(&path).expect("read manifest");
        assert_eq!(
            keys.get("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            Some(&"default".to_owned())
        );
    }

    #[test]
    fn formatter_writes_empty_manifest() {
        let keys = BTreeMap::new();
        assert_eq!(index_json::format_string_map(&keys), "{\n}\n");
    }
}
