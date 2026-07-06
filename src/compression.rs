use crate::error::{Context, Result};
use flate2::Compression;
use flate2::read::{ZlibDecoder, ZlibEncoder};
use std::io::Read;

pub fn compress(input: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(input, Compression::default());
    let mut output = Vec::new();
    encoder
        .read_to_end(&mut output)
        .context("failed to compress input")?;
    Ok(output)
}

pub fn decompress(input: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(input);
    let mut output = Vec::new();
    decoder
        .read_to_end(&mut output)
        .context("failed to decompress input")?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{compress, decompress};

    #[test]
    fn empty_input_round_trips() {
        let compressed = compress(b"").expect("compress empty");
        let decompressed = decompress(&compressed).expect("decompress empty");
        assert_eq!(decompressed, b"");
    }

    #[test]
    fn binary_input_round_trips() {
        let input: Vec<u8> = (0_u8..=255).chain([0, 0, 255, 42, 10]).collect();
        let compressed = compress(&input).expect("compress binary");
        let decompressed = decompress(&compressed).expect("decompress binary");
        assert_eq!(decompressed, input);
    }

    #[test]
    fn malformed_input_is_rejected() {
        decompress(b"not a zlib stream").expect_err("invalid stream");
    }
}
