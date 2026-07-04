use anyhow::{Context, Result, bail, ensure};
use std::collections::BTreeMap;

pub(crate) fn format_string_map(index: &BTreeMap<String, String>) -> String {
    let mut output = String::from("{\n");
    let len = index.len();
    for (i, (key_id, name)) in index.iter().enumerate() {
        output.push_str("  \"");
        output.push_str(&escape_json_string(key_id));
        output.push_str("\": \"");
        output.push_str(&escape_json_string(name));
        output.push('"');
        if i + 1 != len {
            output.push(',');
        }
        output.push('\n');
    }
    output.push_str("}\n");
    output
}

pub(crate) fn parse_string_map(input: &str) -> Result<BTreeMap<String, String>> {
    JsonParser::new(input).parse_object()
}

fn escape_json_string(input: &str) -> String {
    let mut output = String::new();
    for byte in input.bytes() {
        match byte {
            b'"' => output.push_str("\\\""),
            b'\\' => output.push_str("\\\\"),
            b'\n' => output.push_str("\\n"),
            b'\r' => output.push_str("\\r"),
            b'\t' => output.push_str("\\t"),
            0x20..=0x7e => output.push(byte as char),
            _ => output.push_str(&format!("\\u{byte:04x}")),
        }
    }
    output
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            bytes: input.as_bytes(),
            position: 0,
        }
    }

    fn parse_object(&mut self) -> Result<BTreeMap<String, String>> {
        let mut map = BTreeMap::new();
        self.skip_ws();
        self.expect(b'{')?;
        self.skip_ws();
        if self.consume(b'}') {
            self.finish()?;
            return Ok(map);
        }

        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            ensure!(!map.contains_key(&key), "duplicate JSON key {key}");
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.parse_string()?;
            map.insert(key, value);
            self.skip_ws();
            if self.consume(b'}') {
                self.finish()?;
                return Ok(map);
            }
            self.expect(b',')?;
        }
    }

    fn parse_string(&mut self) -> Result<String> {
        self.expect(b'"')?;
        let mut output = String::new();
        while let Some(byte) = self.next() {
            match byte {
                b'"' => return Ok(output),
                b'\\' => {
                    let escaped = self.next().context("unterminated JSON escape")?;
                    match escaped {
                        b'"' => output.push('"'),
                        b'\\' => output.push('\\'),
                        b'/' => output.push('/'),
                        b'b' => output.push('\u{0008}'),
                        b'f' => output.push('\u{000c}'),
                        b'n' => output.push('\n'),
                        b'r' => output.push('\r'),
                        b't' => output.push('\t'),
                        _ => bail!("invalid JSON escape"),
                    }
                }
                0x00..=0x1f => bail!("unescaped control byte in JSON string"),
                _ => output.push(byte as char),
            }
        }
        bail!("unterminated JSON string")
    }

    fn skip_ws(&mut self) {
        while let Some(byte) = self.peek() {
            if matches!(byte, b' ' | b'\n' | b'\r' | b'\t') {
                self.position += 1;
            } else {
                break;
            }
        }
    }

    fn finish(&mut self) -> Result<()> {
        self.skip_ws();
        ensure!(
            self.position == self.bytes.len(),
            "trailing data after JSON object"
        );
        Ok(())
    }

    fn expect(&mut self, expected: u8) -> Result<()> {
        let actual = self.next().context("unexpected end of JSON")?;
        ensure!(
            actual == expected,
            "expected JSON byte '{}' but found '{}'",
            expected as char,
            actual as char
        );
        Ok(())
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.position += 1;
        Some(byte)
    }
}
