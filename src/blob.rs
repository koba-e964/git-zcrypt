use anyhow::{Context, Result, bail, ensure};

pub const MAGIC: [u8; 8] = *b"GZC1\0\0\0\0";
pub const VERSION: u8 = 1;
pub const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob {
    pub key_id: String,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl Blob {
    pub fn aad(&self) -> Vec<u8> {
        aad_for_key_id(self.key_id.as_bytes())
    }
}

pub fn encode(key_id: &str, nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        key_id.len() <= u8::MAX as usize,
        "key id is too long for blob format"
    );

    let mut output = Vec::with_capacity(HEADER_LEN + key_id.len() + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&MAGIC);
    output.push(VERSION);
    output.push(key_id.len() as u8);
    output.push(NONCE_LEN as u8);
    output.push(0);
    output.extend_from_slice(key_id.as_bytes());
    output.extend_from_slice(nonce);
    output.extend_from_slice(ciphertext);
    Ok(output)
}

pub fn decode(input: &[u8]) -> Result<Blob> {
    ensure!(input.len() >= HEADER_LEN, "blob is shorter than header");
    ensure!(input[..MAGIC.len()] == MAGIC, "invalid blob magic");
    ensure!(input[8] == VERSION, "unsupported blob version {}", input[8]);

    let key_id_len = input[9] as usize;
    let nonce_len = input[10] as usize;
    ensure!(nonce_len == NONCE_LEN, "invalid nonce length {nonce_len}");
    ensure!(input[11] == 0, "reserved blob header byte must be zero");

    let key_id_start = HEADER_LEN;
    let nonce_start = key_id_start + key_id_len;
    let ciphertext_start = nonce_start + NONCE_LEN;
    ensure!(
        input.len() >= ciphertext_start,
        "blob is too short for declared key id and nonce lengths"
    );

    let key_id = std::str::from_utf8(&input[key_id_start..nonce_start])
        .context("blob key id is not UTF-8")?;
    if key_id.is_empty() {
        bail!("blob key id must not be empty");
    }

    let nonce = input[nonce_start..ciphertext_start]
        .try_into()
        .expect("nonce length already validated");
    let ciphertext = input[ciphertext_start..].to_vec();

    Ok(Blob {
        key_id: key_id.to_owned(),
        nonce,
        ciphertext,
    })
}

pub fn aad_for_key_id(key_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_LEN + key_id.len());
    aad.extend_from_slice(&MAGIC);
    aad.push(VERSION);
    aad.push(key_id.len() as u8);
    aad.push(NONCE_LEN as u8);
    aad.push(0);
    aad.extend_from_slice(key_id);
    aad
}

#[cfg(test)]
mod tests {
    use super::{MAGIC, NONCE_LEN, VERSION, decode, encode};

    #[test]
    fn blob_round_trips() {
        let nonce = [3_u8; NONCE_LEN];
        let encoded = encode("default", &nonce, b"ciphertext").expect("encode");
        let decoded = decode(&encoded).expect("decode");
        assert_eq!(decoded.key_id, "default");
        assert_eq!(decoded.nonce, nonce);
        assert_eq!(decoded.ciphertext, b"ciphertext");
        assert_eq!(&decoded.aad()[..8], &MAGIC);
    }

    #[test]
    fn rejects_malformed_headers() {
        decode(b"short").expect_err("short header");

        let nonce = [0_u8; NONCE_LEN];
        let valid = encode("default", &nonce, b"ciphertext").expect("encode");

        let mut bad_magic = valid.clone();
        bad_magic[0] = b'X';
        decode(&bad_magic).expect_err("bad magic");

        let mut bad_version = valid.clone();
        bad_version[8] = VERSION + 1;
        decode(&bad_version).expect_err("bad version");

        let mut bad_nonce_len = valid.clone();
        bad_nonce_len[10] = 24;
        decode(&bad_nonce_len).expect_err("bad nonce length");

        let mut bad_reserved = valid.clone();
        bad_reserved[11] = 1;
        decode(&bad_reserved).expect_err("bad reserved byte");

        let mut bad_key_len = valid;
        bad_key_len[9] = 200;
        decode(&bad_key_len).expect_err("bad key id length");
    }

    #[test]
    fn rejects_empty_key_id() {
        let nonce = [0_u8; NONCE_LEN];
        let encoded = encode("", &nonce, b"ciphertext").expect("encode");
        decode(&encoded).expect_err("empty key id");
    }
}
