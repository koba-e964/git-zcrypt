use crate::blob::{self, Blob, NONCE_LEN};
use crate::key_store::{self, RAW_KEY_LEN};
use anyhow::{Context, Result, anyhow, ensure};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

pub fn encrypt(key: &[u8], key_id: &str, plaintext: &[u8]) -> Result<Blob> {
    ensure_key_len(key)?;
    key_store::validate_key_name(key_id)?;

    let mut nonce_bytes = [0_u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes).context("failed to generate encryption nonce")?;

    let cipher = cipher_from_key(key)?;
    let aad = blob::aad_for_key_id(key_id.as_bytes());
    let nonce = Nonce::try_from(&nonce_bytes[..]).expect("nonce length is fixed");
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("encryption failed"))?;

    Ok(Blob {
        key_id: key_id.to_owned(),
        nonce: nonce_bytes,
        ciphertext,
    })
}

pub fn decrypt(key: &[u8], blob: &Blob) -> Result<Vec<u8>> {
    ensure_key_len(key)?;

    let cipher = cipher_from_key(key)?;
    let nonce = Nonce::try_from(&blob.nonce[..]).expect("nonce length is fixed");
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &blob.ciphertext,
                aad: &blob.aad(),
            },
        )
        .map_err(|_| anyhow!("decryption failed"))
}

fn cipher_from_key(key: &[u8]) -> Result<ChaCha20Poly1305> {
    ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow!("raw key must be exactly {RAW_KEY_LEN} bytes"))
}

fn ensure_key_len(key: &[u8]) -> Result<()> {
    ensure!(
        key.len() == RAW_KEY_LEN,
        "raw key must be exactly {RAW_KEY_LEN} bytes, got {} bytes",
        key.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt};

    #[test]
    fn encrypt_decrypt_round_trips() {
        let key = [7_u8; 32];
        let blob = encrypt(&key, "default", b"plaintext").expect("encrypt");
        let plaintext = decrypt(&key, &blob).expect("decrypt");
        assert_eq!(plaintext, b"plaintext");
    }

    #[test]
    fn fresh_nonce_changes_ciphertext() {
        let key = [7_u8; 32];
        let first = encrypt(&key, "default", b"plaintext").expect("encrypt first");
        let second = encrypt(&key, "default", b"plaintext").expect("encrypt second");
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn tampered_ciphertext_or_metadata_fails() {
        let key = [7_u8; 32];
        let blob = encrypt(&key, "default", b"plaintext").expect("encrypt");

        let mut tampered_ciphertext = blob.clone();
        tampered_ciphertext.ciphertext[0] ^= 1;
        decrypt(&key, &tampered_ciphertext).expect_err("tampered ciphertext");

        let mut tampered_metadata = blob;
        tampered_metadata.key_id = "other".to_owned();
        decrypt(&key, &tampered_metadata).expect_err("tampered metadata");
    }

    #[test]
    fn rejects_wrong_key_length() {
        encrypt(&[0_u8; 31], "default", b"plaintext").expect_err("short key");
    }
}
