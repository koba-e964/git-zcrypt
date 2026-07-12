use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::TempDir;

fn git_zcrypt() -> &'static str {
    env!("CARGO_BIN_EXE_git-zcrypt")
}

fn init_repo() -> TempDir {
    let temp = TempDir::new().expect("tempdir");
    let status = Command::new("git")
        .arg("init")
        .current_dir(temp.path())
        .status()
        .expect("git init");
    assert!(status.success());

    let status = Command::new(git_zcrypt())
        .arg("init")
        .current_dir(temp.path())
        .status()
        .expect("git-zcrypt init");
    assert!(status.success());

    let status = Command::new(git_zcrypt())
        .args(["generate-key", "--key", "default"])
        .current_dir(temp.path())
        .status()
        .expect("git-zcrypt generate-key");
    assert!(status.success());

    temp
}

fn init_empty_repo() -> TempDir {
    let temp = TempDir::new().expect("tempdir");
    let status = Command::new("git")
        .arg("init")
        .current_dir(temp.path())
        .status()
        .expect("git init");
    assert!(status.success());

    let status = Command::new(git_zcrypt())
        .arg("init")
        .current_dir(temp.path())
        .status()
        .expect("git-zcrypt init");
    assert!(status.success());

    temp
}

fn filter(repo: &TempDir, args: &[&str], input: &[u8]) -> std::process::Output {
    let mut child = Command::new(git_zcrypt())
        .args(args)
        .current_dir(repo.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn git-zcrypt");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input)
        .expect("write stdin");

    child.wait_with_output().expect("wait git-zcrypt")
}

fn key_id_from_blob(blob: &[u8]) -> &str {
    let key_id_start = 12;
    let key_id_len = blob[9] as usize;
    std::str::from_utf8(&blob[key_id_start..key_id_start + key_id_len]).expect("key id utf8")
}

#[test]
fn init_manifest_creates_committed_key_manifest() {
    let repo = init_empty_repo();

    let root = filter(&repo, &["init-manifest"], b"");
    assert!(
        root.status.success(),
        "{}",
        String::from_utf8_lossy(&root.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(repo.path().join("git-zcrypt-keys.json")).expect("root manifest"),
        "{\n}\n"
    );

    std::fs::create_dir_all(repo.path().join("secrets/team-a")).expect("mkdir");
    let nested = filter(&repo, &["init-manifest", "--path", "secrets/team-a"], b"");
    assert!(
        nested.status.success(),
        "{}",
        String::from_utf8_lossy(&nested.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(repo.path().join("secrets/team-a/git-zcrypt-keys.json"))
            .expect("nested manifest"),
        "{\n}\n"
    );

    std::fs::create_dir_all(repo.path().join("secrets/team-b")).expect("mkdir");
    let subdir = Command::new(git_zcrypt())
        .arg("init-manifest")
        .current_dir(repo.path().join("secrets/team-b"))
        .output()
        .expect("git-zcrypt init-manifest in subdir");
    assert!(
        subdir.status.success(),
        "{}",
        String::from_utf8_lossy(&subdir.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(repo.path().join("secrets/team-b/git-zcrypt-keys.json"))
            .expect("subdir manifest"),
        "{\n}\n"
    );
}

#[test]
fn clean_updates_committed_key_manifest() {
    let repo = init_repo();

    let clean = filter(
        &repo,
        &["clean", "--key", "default", "--path", "secrets/secret.txt"],
        b"secret",
    );
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );

    let manifest =
        std::fs::read_to_string(repo.path().join("git-zcrypt-keys.json")).expect("read manifest");
    assert!(manifest.contains(key_id_from_blob(&clean.stdout)));
    assert!(manifest.contains("default"));
}

#[test]
fn raw_key_round_trip_uses_hash_prefixed_key_id() {
    let repo = init_repo();
    let input: Vec<u8> = (0_u8..=255).chain([0, 255, 10, 13, 42]).collect();

    let clean = filter(
        &repo,
        &["clean", "--key", "default", "--path", "secrets/secret.txt"],
        &input,
    );
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    assert_ne!(clean.stdout, input);
    assert!(key_id_from_blob(&clean.stdout).starts_with("sha256:"));

    let smudge = filter(
        &repo,
        &["smudge", "--path", "secrets/secret.txt"],
        &clean.stdout,
    );
    assert!(
        smudge.status.success(),
        "{}",
        String::from_utf8_lossy(&smudge.stderr)
    );
    assert_eq!(smudge.stdout, input);
}

#[test]
fn password_derived_key_round_trips_from_stdin_setup() {
    let repo = init_empty_repo();
    let derive = filter(
        &repo,
        &["derive-key", "--key", "password", "--stdin"],
        b"correct horse battery staple\n",
    );
    assert!(
        derive.status.success(),
        "{}",
        String::from_utf8_lossy(&derive.stderr)
    );

    let clean = filter(
        &repo,
        &["clean", "--key", "password", "--path", "secrets/secret.txt"],
        b"password secret",
    );
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    assert!(key_id_from_blob(&clean.stdout).starts_with("sha256:"));

    let smudge = filter(
        &repo,
        &["smudge", "--path", "secrets/secret.txt"],
        &clean.stdout,
    );
    assert!(
        smudge.status.success(),
        "{}",
        String::from_utf8_lossy(&smudge.stderr)
    );
    assert_eq!(smudge.stdout, b"password secret");
}

#[test]
fn duplicate_password_derived_key_fails() {
    let repo = init_empty_repo();
    let first = filter(
        &repo,
        &["derive-key", "--key", "first", "--stdin"],
        b"same password\n",
    );
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );

    let duplicate = filter(
        &repo,
        &["derive-key", "--key", "second", "--stdin"],
        b"same password\n",
    );
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("already registered"));
}

#[test]
fn delete_key_removes_local_key_material() {
    let repo = init_repo();

    let clean = filter(
        &repo,
        &["clean", "--key", "default", "--path", "secrets/secret.txt"],
        b"secret",
    );
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );

    let delete = filter(&repo, &["delete-key", "--key", "default"], b"");
    assert!(
        delete.status.success(),
        "{}",
        String::from_utf8_lossy(&delete.stderr)
    );
    assert!(
        !repo
            .path()
            .join(".git/git-zcrypt/keys/default.key")
            .exists()
    );

    let smudge = filter(
        &repo,
        &["smudge", "--path", "secrets/secret.txt"],
        &clean.stdout,
    );
    assert!(
        smudge.status.success(),
        "{}",
        String::from_utf8_lossy(&smudge.stderr)
    );
    assert_eq!(smudge.stdout, clean.stdout);
    assert!(String::from_utf8_lossy(&smudge.stderr).contains("no local key is registered"));
}

#[test]
fn empty_input_round_trips() {
    let repo = init_repo();

    let clean = filter(
        &repo,
        &["clean", "--key", "default", "--path", "secrets/secret.txt"],
        b"",
    );
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );

    let smudge = filter(
        &repo,
        &["smudge", "--path", "secrets/secret.txt"],
        &clean.stdout,
    );
    assert!(
        smudge.status.success(),
        "{}",
        String::from_utf8_lossy(&smudge.stderr)
    );
    assert_eq!(smudge.stdout, b"");
}

#[test]
fn tampered_ciphertext_fails() {
    let repo = init_repo();

    let clean = filter(
        &repo,
        &["clean", "--key", "default", "--path", "secrets/secret.txt"],
        b"secret",
    );
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );

    let mut tampered = clean.stdout;
    let last = tampered.last_mut().expect("ciphertext byte");
    *last ^= 1;

    let smudge = filter(
        &repo,
        &["smudge", "--path", "secrets/secret.txt"],
        &tampered,
    );
    assert!(!smudge.status.success());
}

#[test]
fn unknown_key_id_fails() {
    let repo = init_repo();

    let clean = filter(
        &repo,
        &["clean", "--key", "default", "--path", "secrets/secret.txt"],
        b"secret",
    );
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );

    let mut unknown_key = clean.stdout;
    let key_id_start = 12;
    unknown_key[key_id_start] = b'x';

    let smudge = filter(
        &repo,
        &["smudge", "--path", "secrets/secret.txt"],
        &unknown_key,
    );
    assert!(!smudge.status.success());
}

fn git(repo: &std::path::Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(repo)
        .status()
        .expect("git command");
    assert!(status.success(), "git {:?} failed", args);
}

fn configure_git_identity(repo: &std::path::Path) {
    git(repo, &["config", "user.email", "test@example.com"]);
    git(repo, &["config", "user.name", "Test User"]);
}

fn configure_filter(repo: &std::path::Path) {
    let clean = format!("{} clean --key default --path %f", git_zcrypt());
    let smudge = format!("{} smudge --path %f", git_zcrypt());
    git(
        repo,
        &["config", "--local", "filter.git-zcrypt.clean", &clean],
    );
    git(
        repo,
        &["config", "--local", "filter.git-zcrypt.smudge", &smudge],
    );
    git(
        repo,
        &["config", "--local", "filter.git-zcrypt.required", "true"],
    );
}

#[test]
fn clone_without_local_key_checks_out_encrypted_blob_and_restore_resmudges() {
    let source = init_repo();
    configure_git_identity(source.path());
    configure_filter(source.path());

    std::fs::create_dir_all(source.path().join("secrets")).expect("mkdir secrets");
    std::fs::write(
        source.path().join(".gitattributes"),
        "secrets/** filter=git-zcrypt diff=git-zcrypt\n",
    )
    .expect("write attributes");
    std::fs::write(source.path().join("secrets/secret.txt"), b"clone secret\n")
        .expect("write secret");
    git(
        source.path(),
        &["add", ".gitattributes", "secrets/secret.txt"],
    );
    git(source.path(), &["add", "git-zcrypt-keys.json"]);
    git(source.path(), &["commit", "-m", "add encrypted secret"]);

    let exported_key = source.path().join("default.key");
    let export = Command::new(git_zcrypt())
        .args(["export-key", "--key", "default", "--output"])
        .arg(&exported_key)
        .current_dir(source.path())
        .status()
        .expect("export key");
    assert!(export.success());

    let parent = TempDir::new().expect("clone parent");
    let clone_path = parent.path().join("clone");
    let clean = format!("{} clean --key default --path %f", git_zcrypt());
    let smudge = format!("{} smudge --path %f", git_zcrypt());
    let clone_status = Command::new("git")
        .arg("-c")
        .arg(format!("filter.git-zcrypt.clean={clean}"))
        .arg("-c")
        .arg(format!("filter.git-zcrypt.smudge={smudge}"))
        .arg("-c")
        .arg("filter.git-zcrypt.required=true")
        .arg("clone")
        .arg(source.path())
        .arg(&clone_path)
        .status()
        .expect("git clone");
    assert!(clone_status.success());

    let checked_out = std::fs::read(clone_path.join("secrets/secret.txt")).expect("read checkout");
    assert_ne!(checked_out, b"clone secret\n");
    assert!(checked_out.starts_with(b"GZC1\0\0\0\0"));

    configure_filter(&clone_path);
    let init = Command::new(git_zcrypt())
        .arg("init")
        .current_dir(&clone_path)
        .status()
        .expect("init clone");
    assert!(init.success());
    let import = Command::new(git_zcrypt())
        .args(["import-key", "--key", "default", "--input"])
        .arg(&exported_key)
        .current_dir(&clone_path)
        .status()
        .expect("import key");
    assert!(import.success());

    git(
        &clone_path,
        &[
            "restore",
            "--source=HEAD",
            "--worktree",
            "--",
            "secrets/secret.txt",
        ],
    );
    let restored = std::fs::read(clone_path.join("secrets/secret.txt")).expect("read restored");
    assert_eq!(restored, b"clone secret\n");
}

#[test]
fn smudge_fails_when_manifest_is_missing() {
    let repo = init_repo();
    let clean = filter(
        &repo,
        &["clean", "--key", "default", "--path", "secrets/secret.txt"],
        b"secret",
    );
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    std::fs::remove_file(repo.path().join("git-zcrypt-keys.json")).expect("remove manifest");

    let smudge = filter(
        &repo,
        &["smudge", "--path", "secrets/secret.txt"],
        &clean.stdout,
    );
    assert!(!smudge.status.success());
    assert!(String::from_utf8_lossy(&smudge.stderr).contains("no git-zcrypt-keys.json found"));
}

#[test]
fn smudge_rejects_manifest_mismatch() {
    let repo = init_repo();
    let clean = filter(
        &repo,
        &["clean", "--key", "default", "--path", "secrets/secret.txt"],
        b"secret",
    );
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    std::fs::write(repo.path().join("git-zcrypt-keys.json"), "{\n}\n").expect("clear manifest");

    let smudge = filter(
        &repo,
        &["smudge", "--path", "secrets/secret.txt"],
        &clean.stdout,
    );
    assert!(!smudge.status.success());
    assert!(String::from_utf8_lossy(&smudge.stderr).contains("is not declared"));
}
