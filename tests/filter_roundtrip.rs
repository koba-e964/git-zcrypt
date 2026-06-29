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
        .args(["generate-key", "--name", "default"])
        .current_dir(temp.path())
        .status()
        .expect("git-zcrypt generate-key");
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

#[test]
fn binary_bytes_round_trip() {
    let repo = init_repo();
    let input: Vec<u8> = (0_u8..=255).chain([0, 255, 10, 13, 42]).collect();

    let clean = filter(&repo, &["clean", "--key", "default"], &input);
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    assert_ne!(clean.stdout, input);

    let smudge = filter(&repo, &["smudge"], &clean.stdout);
    assert!(
        smudge.status.success(),
        "{}",
        String::from_utf8_lossy(&smudge.stderr)
    );
    assert_eq!(smudge.stdout, input);
}

#[test]
fn empty_input_round_trips() {
    let repo = init_repo();

    let clean = filter(&repo, &["clean", "--key", "default"], b"");
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );

    let smudge = filter(&repo, &["smudge"], &clean.stdout);
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

    let clean = filter(&repo, &["clean", "--key", "default"], b"secret");
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );

    let mut tampered = clean.stdout;
    let last = tampered.last_mut().expect("ciphertext byte");
    *last ^= 1;

    let smudge = filter(&repo, &["smudge"], &tampered);
    assert!(!smudge.status.success());
}

#[test]
fn unknown_key_id_fails() {
    let repo = init_repo();

    let clean = filter(&repo, &["clean", "--key", "default"], b"secret");
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );

    let mut unknown_key = clean.stdout;
    let key_id_start = 12;
    unknown_key[key_id_start] = b'x';

    let smudge = filter(&repo, &["smudge"], &unknown_key);
    assert!(!smudge.status.success());
}
