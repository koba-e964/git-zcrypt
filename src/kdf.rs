use crate::ensure;
use crate::error::{Context, Error, Result};
use crate::key_store::RAW_KEY_LEN;
use argon2::{Algorithm, Argon2, Params, Version};
use std::io::{self, Read};
use zeroize::Zeroizing;

const ARGON2_MEMORY_KIB: u32 = 32 * 1024;
const ARGON2_ITERATIONS: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;
const PASSWORD_DOMAIN: &[u8] = b"git-zcrypt password key v1";

pub fn derive_key_from_stdin() -> Result<[u8; RAW_KEY_LEN]> {
    let mut password = Zeroizing::new(Vec::new());
    io::stdin()
        .lock()
        .read_to_end(&mut password)
        .context("failed to read password from stdin")?;
    trim_single_trailing_newline(&mut password);
    derive_key_from_password(&password)
}

pub fn derive_key_from_prompt() -> Result<[u8; RAW_KEY_LEN]> {
    let first = Zeroizing::new(
        rpassword::prompt_password("Password: ").context("failed to read password")?,
    );
    let second = Zeroizing::new(
        rpassword::prompt_password("Confirm password: ")
            .context("failed to read password confirmation")?,
    );
    ensure!(
        first.as_bytes() == second.as_bytes(),
        "passwords do not match"
    );
    derive_key_from_password(first.as_bytes())
}

pub fn derive_key_from_password(password: &[u8]) -> Result<[u8; RAW_KEY_LEN]> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(RAW_KEY_LEN),
    )
    .map_err(|error| Error::msg(format!("invalid Argon2id parameters: {error:?}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; RAW_KEY_LEN];
    argon2
        .hash_password_into(password, PASSWORD_DOMAIN, &mut key)
        .map_err(|error| Error::msg(format!("failed to derive key from password: {error:?}")))?;
    Ok(key)
}

fn trim_single_trailing_newline(bytes: &mut Vec<u8>) {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
}

#[cfg(test)]
pub fn confirm_passwords_for_test(first: &[u8], second: &[u8]) -> Result<()> {
    ensure!(first == second, "passwords do not match");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        confirm_passwords_for_test, derive_key_from_password, trim_single_trailing_newline,
    };

    #[test]
    fn argon2id_derives_expected_32_byte_key() {
        let key = derive_key_from_password(b"password").expect("derive key");
        assert_eq!(key.len(), 32);
        assert_eq!(
            hex_for_test(&key),
            "4fa631b6f1efa130f281c5cca3658b78cc6352f24469a4620bfc83909e0cf483"
        );
    }

    #[test]
    fn derive_key_from_password_stdin_trims_single_trailing_newline() {
        let mut unix = b"password\n".to_vec();
        trim_single_trailing_newline(&mut unix);
        assert_eq!(unix, b"password");

        let mut windows = b"password\r\n".to_vec();
        trim_single_trailing_newline(&mut windows);
        assert_eq!(windows, b"password");

        let mut none = b"password".to_vec();
        trim_single_trailing_newline(&mut none);
        assert_eq!(none, b"password");
    }

    #[test]
    fn hidden_prompt_confirmation_mismatch_fails() {
        confirm_passwords_for_test(b"first", b"second").expect_err("mismatch");
    }

    fn hex_for_test(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        output
    }
}
