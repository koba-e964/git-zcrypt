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

#[derive(Debug)]
pub struct SelectedManifest {
    pub path: PathBuf,
    dir: PathBuf,
}

#[derive(Debug)]
pub struct ResolvedWorktreeFile {
    pub input_path: PathBuf,
    pub worktree_path: PathBuf,
    pub repo_path: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Authorization {
    Allowed,
    MissingManifest,
    KeyNotDeclared,
}

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
    add_key_to_manifest(&manifest, key_id, key_name)?;
    Ok(manifest)
}

pub fn authorize_key_for_path(path: &Path, key_id: &str) -> Result<Authorization> {
    key_store::validate_key_id(key_id)?;
    let root = worktree_root()?;
    let Some(manifest) = find_manifest_path(&root, path)? else {
        return Ok(Authorization::MissingManifest);
    };
    let keys = read_manifest(&manifest)?;
    if keys.contains_key(key_id) {
        Ok(Authorization::Allowed)
    } else {
        Ok(Authorization::KeyNotDeclared)
    }
}

pub fn resolve_worktree_file(path: &Path) -> Result<ResolvedWorktreeFile> {
    ensure!(
        !path.as_os_str().is_empty(),
        "register path must not be empty"
    );
    ensure!(
        !path.is_absolute(),
        "register path must be relative: {}",
        path.display()
    );
    let root = worktree_root()?;
    let current_dir = env::current_dir().context("failed to get current directory")?;
    let worktree_path = normalize_path(&current_dir.join(path));
    ensure!(
        worktree_path.starts_with(&root),
        "register path must stay inside the repository: {}",
        path.display()
    );
    let repo_path = worktree_path
        .strip_prefix(&root)
        .with_context(|| {
            format!(
                "register path must stay inside the repository: {}",
                path.display()
            )
        })?
        .to_path_buf();
    ensure!(
        !repo_path.as_os_str().is_empty(),
        "register path must name a file"
    );
    Ok(ResolvedWorktreeFile {
        input_path: path.to_path_buf(),
        worktree_path,
        repo_path,
    })
}

pub fn resolve_selected_manifest_dir(path: Option<&Path>) -> Result<SelectedManifest> {
    let root = worktree_root()?;
    let dir = match path {
        Some(path) => resolve_cwd_relative_dir(&root, path)?,
        None => env::current_dir().context("failed to get current directory")?,
    };
    let dir = normalize_path(&dir);
    ensure!(
        dir.starts_with(&root),
        "manifest path must stay inside the repository: {}",
        path.unwrap_or_else(|| Path::new(".")).display()
    );
    Ok(SelectedManifest {
        path: dir.join(MANIFEST_FILE),
        dir,
    })
}

pub fn ensure_manifest_covers_path(manifest: &SelectedManifest, repo_path: &Path) -> Result<()> {
    let root = worktree_root()?;
    let file_path = root.join(repo_path);
    ensure!(
        file_path.starts_with(&manifest.dir),
        "manifest {} does not cover {}",
        manifest.path.display(),
        repo_path.display()
    );
    Ok(())
}

pub fn ensure_manifest(path: &Path) -> Result<()> {
    if path.exists() {
        read_manifest(path)?;
    } else {
        write_manifest(path, &BTreeMap::new())?;
    }
    Ok(())
}

pub fn add_key_to_manifest(path: &Path, key_id: &str, key_name: &str) -> Result<()> {
    key_store::validate_key_id(key_id)?;
    key_store::validate_key_name(key_name)?;
    let mut keys = if path.exists() {
        read_manifest(path)?
    } else {
        BTreeMap::new()
    };
    if let Some(existing) = keys.get(key_id) {
        ensure!(
            existing == key_name,
            "manifest {} maps {key_id} to {existing}, not {key_name}",
            path.display()
        );
        return Ok(());
    }
    keys.insert(key_id.to_owned(), key_name.to_owned());
    write_manifest(path, &keys)
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

fn resolve_cwd_relative_dir(root: &Path, path: &Path) -> Result<PathBuf> {
    ensure!(
        !path.is_absolute(),
        "manifest path must be relative: {}",
        path.display()
    );
    let current_dir = env::current_dir().context("failed to get current directory")?;
    let dir = if path.as_os_str().is_empty() || path == Path::new(".") {
        current_dir
    } else {
        current_dir.join(path)
    };
    let dir = normalize_path(&dir);
    ensure!(
        dir.starts_with(root),
        "manifest path must stay inside the repository: {}",
        path.display()
    );
    Ok(dir)
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    normalized
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
