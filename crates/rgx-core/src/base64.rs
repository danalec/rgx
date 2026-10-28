// SPDX-License-Identifier: Apache-2.0

//! Base64 encode/decode (RFC 4648).
//!
//! Independent reimplementation of the RFC 4648 base64 transform: the §4
//! standard alphabet with `=` padding, the §5 URL-safe alphabet with `-`
//! and `_`, and the §3.5 canonical-encoding rule the strict decoders
//! enforce. rgx uses the strict entry points wherever a decode *failure*
//! is itself a signal — a format check for the `tiktoken` adapter, a
//! content guard for MIME attachments — because a lenient decoder would
//! silently widen both.
//!
//! # Contract
//!
//! Encode maps each 3-byte quantum to 4 sextets over the configured
//! alphabet, left-padded to 3 bytes on a short final quantum and filled
//! with `=` (or nothing, when `pad` is false) to a 4-character group.
//!
//! Decode first drops ASCII whitespace — MIME bodies wrap at 76 columns
//! and a header value may arrive with the wrapping still in it — then
//! treats the remaining bytes as a sequence of 4-character quanta. A
//! leftover of one character is impossible (6 bits cannot cover a byte)
//! and is rejected in both modes. `strict` additionally requires the
//! canonical padding count of §3.5 and zero pad bits in the final
//! quantum; the lenient mode accepts an unpadded tail and drops whatever
//! the unused low bits of the last sextet held, because that is what
//! decades of MIME decoders do and what the mail adapters need.

use alloc::borrow::Cow;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

#[derive(Debug, Clone)]
pub struct Base64Error {
    pub message: String,
    pub position: usize,
}

impl fmt::Display for Base64Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Base64 error at position {}: {}",
            self.position, self.message
        )
    }
}

impl core::error::Error for Base64Error {}

#[derive(Debug, Clone, Copy)]
pub struct Base64Config {
    pub charset: &'static [u8; 64],
    pub pad: bool,
}

/// The RFC 4648 §4 alphabet (`A-Za-z0-9+/`) with `=` padding.
pub const STANDARD: Base64Config = Base64Config {
    charset: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    pad: true,
};

/// The §4 alphabet without padding, as used in e.g. JWT payloads.
pub const STANDARD_NO_PAD: Base64Config = Base64Config {
    charset: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    pad: false,
};

/// The RFC 4648 §5 URL-safe alphabet (`A-Za-z0-9-_`) with `=` padding.
pub const URL_SAFE: Base64Config = Base64Config {
    charset: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    pad: true,
};

/// The §5 alphabet without padding, as used in e.g. unpadded URL tokens.
pub const URL_SAFE_NO_PAD: Base64Config = Base64Config {
    charset: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    pad: false,
};

/// Inverse of a 64-byte alphabet: `DECODE[c]` is the sextet value of
/// byte `c`, or `0xFF` when `c` is not in the alphabet. Built at compile
/// time from the alphabet itself so no runtime init is paid.
const DECODE_TABLE_URL_SAFE: [u8; 256] = build_decode_table(URL_SAFE_NO_PAD.charset);

const DECODE_TABLE_STANDARD: [u8; 256] = build_decode_table(STANDARD.charset);

const fn build_decode_table(charset: &[u8; 64]) -> [u8; 256] {
    let mut table = [0xFFu8; 256];
    let mut i = 0;
    while i < 64 {
        table[charset[i] as usize] = i as u8;
        i += 1;
    }
    table
}

fn decode_table_for(charset: &[u8; 64]) -> Cow<'_, [u8; 256]> {
    if charset == STANDARD.charset.as_slice() {
        Cow::Borrowed(&DECODE_TABLE_STANDARD)
    } else if charset == URL_SAFE_NO_PAD.charset.as_slice() {
        Cow::Borrowed(&DECODE_TABLE_URL_SAFE)
    } else {
        // A caller-supplied alphabet has no shared inverse table; none of
        // the in-tree call sites take this branch.
        Cow::Owned(build_decode_table(charset))
    }
}

pub fn base64_encode(input: &[u8]) -> String {
    base64_encode_with(input, STANDARD)
}

/// Encode over the §5 alphabet with no padding.
pub fn base64_encode_url(input: &[u8]) -> String {
    base64_encode_with(input, URL_SAFE_NO_PAD)
}

pub fn base64_encode_with(input: &[u8], config: Base64Config) -> String {
    let charset = config.charset;
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);

    for chunk in input.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        output.push(charset[b0 >> 2] as char);
        output.push(charset[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if chunk.len() > 1 {
            output.push(charset[((b1 & 0x0F) << 2) | (b2 >> 6)] as char);
            if chunk.len() > 2 {
                output.push(charset[b2 & 0x3F] as char);
            } else if config.pad {
                output.push('=');
            }
        } else if config.pad {
            output.push('=');
            output.push('=');
        }
    }

    output
}

pub fn base64_decode(input: &str) -> Result<Vec<u8>, Base64Error> {
    base64_decode_with(input, STANDARD)
}

/// Lenient decode over the §5 alphabet.
pub fn base64_decode_url(input: &str) -> Result<Vec<u8>, Base64Error> {
    base64_decode_with(input, URL_SAFE_NO_PAD)
}

/// Strict RFC 4648 §3.5 decoding: canonical padding is required and
/// non-zero trailing bits in the final quantum are rejected.
///
/// The lenient [`base64_decode`] accepts unpadded input and silently drops
/// non-zero trailing bits, which is convenient for MIME but wrong for a
/// format check — `"Zh=="` would decode to `b"f"` even though the only
/// canonical encoding of `f` is `"Zg=="`.
pub fn base64_decode_strict(input: &str) -> Result<Vec<u8>, Base64Error> {
    base64_decode_with_strict(input, STANDARD)
}

pub fn base64_decode_with(input: &str, config: Base64Config) -> Result<Vec<u8>, Base64Error> {
    decode_bytes(input.as_bytes(), config, false)
}

pub fn base64_decode_with_strict(
    input: &str,
    config: Base64Config,
) -> Result<Vec<u8>, Base64Error> {
    decode_bytes(input.as_bytes(), config, true)
}

/// Decode from raw bytes, so callers holding a byte buffer do not have to
/// round-trip through `&str` first. Whitespace is filtered exactly as in
/// the `&str` path.
pub fn base64_decode_bytes_strict(
    input: &[u8],
    config: Base64Config,
) -> Result<Vec<u8>, Base64Error> {
    decode_bytes(input, config, true)
}

/// Lenient decode of raw bytes for MIME bodies, where line breaks are
/// legal whitespace between base64 quanta. Errors are returned, but the
/// typical caller (mail / mbox adapters) only cares about whether the
/// decode succeeded.
pub fn base64_decode_skipping_ws(
    input: &[u8],
    config: Base64Config,
) -> Result<Vec<u8>, Base64Error> {
    decode_bytes(input, config, false)
}

fn decode_bytes(input: &[u8], config: Base64Config, strict: bool) -> Result<Vec<u8>, Base64Error> {
    let decode_table = decode_table_for(config.charset);

    // The hot path is a buffer with no whitespace — a config blob or a
    // header value handed over as it arrived. One scan decides between
    // borrowing the input and allocating a filtered copy; the copy is
    // only built when whitespace is actually present.
    let owned_buf;
    let data: &[u8] = if input.iter().any(|&b| b.is_ascii_whitespace()) {
        let mut buf = Vec::with_capacity(input.len());
        for &b in input {
            if !b.is_ascii_whitespace() {
                buf.push(b);
            }
        }
        owned_buf = buf;
        &owned_buf
    } else {
        input
    };

    // The canonical-padding check of §3.5 counts the `=` characters the
    // caller sent; the data path then sees only the alphabet characters.
    let pad_count = data.iter().filter(|&&c| c == b'=').count();
    let data = strip_trailing_padding(data);

    // One leftover character is 6 bits — not a byte, and not a legal
    // quantum, padded or not.
    if data.len() % 4 == 1 {
        return Err(Base64Error {
            message: "Invalid length".into(),
            position: 0,
        });
    }

    if strict {
        // A quantum of n data characters carries exactly `4 - n` pads:
        // 0 data chars is an empty input (0 pads), 2 → 2, 3 → 1, 4 → 0.
        let expected_padding = match data.len() % 4 {
            0 => 0,
            2 => 2,
            3 => 1,
            _ => 0,
        };
        if pad_count != expected_padding {
            return Err(Base64Error {
                message: format!("Invalid padding: expected {expected_padding}, found {pad_count}"),
                position: data.len(),
            });
        }
    }

    let mut output = Vec::with_capacity(data.len() / 4 * 3);
    let quanta = data.len().div_ceil(4);

    for (chunk_idx, chunk) in data.chunks(4).enumerate() {
        let base = chunk_idx * 4;
        let v0 = decode_value(chunk[0], base, &decode_table)?;
        let v1 = decode_value(chunk[1], base + 1, &decode_table)?;

        output.push((v0 << 2) | (v1 >> 4));

        if chunk.len() >= 3 {
            let v2 = decode_value(chunk[2], base + 2, &decode_table)?;
            output.push(((v1 & 0x0F) << 4) | (v2 >> 2));

            if chunk.len() >= 4 {
                let v3 = decode_value(chunk[3], base + 3, &decode_table)?;
                output.push(((v2 & 0x03) << 6) | v3);
            } else if strict && chunk_idx + 1 == quanta && v2 & 0x03 != 0 {
                // The 2 bits the final byte did not need must be zero in
                // a canonical encoding.
                return Err(Base64Error {
                    message: "Non-zero trailing bits in final quantum".into(),
                    position: data.len(),
                });
            }
        } else if strict && chunk_idx + 1 == quanta && v1 & 0x0F != 0 {
            // Same rule for the 4 bits a 2-character quantum leaves over.
            return Err(Base64Error {
                message: "Non-zero trailing bits in final quantum".into(),
                position: data.len(),
            });
        }
    }

    Ok(output)
}

fn strip_trailing_padding(input: &[u8]) -> &[u8] {
    let mut end = input.len();
    while end > 0 && input[end - 1] == b'=' {
        end -= 1;
    }
    &input[..end]
}

fn decode_value(c: u8, pos: usize, table: &[u8; 256]) -> Result<u8, Base64Error> {
    let v = table[c as usize];
    if v == 0xFF {
        return Err(Base64Error {
            message: format!("Invalid character '{}'", c as char),
            position: pos,
        });
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_matches_rfc4648_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn strict_roundtrip() {
        let inputs: &[&[u8]] = &[
            b"",
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            &[0, 1, 2, 3, 255, 254, 253],
        ];
        for input in inputs {
            let encoded = base64_encode(input);
            assert_eq!(base64_decode_strict(&encoded).unwrap(), *input, "{encoded}");
        }
    }

    #[test]
    fn strict_rejects_missing_padding() {
        assert!(base64_decode("Zg").is_ok());
        assert!(base64_decode_strict("Zg").is_err());
        assert!(base64_decode_strict("Zm8").is_err());
        assert!(base64_decode_strict("Zm9v").is_ok(), "no padding needed");
    }

    #[test]
    fn strict_rejects_wrong_padding_count() {
        assert!(base64_decode_strict("Zg=").is_err());
        assert!(base64_decode_strict("Zg===").is_err());
        assert!(base64_decode_strict("Zm8==").is_err());
        assert!(base64_decode_strict("====").is_err());
    }

    #[test]
    fn strict_rejects_non_zero_trailing_bits() {
        assert_eq!(base64_decode("Zh==").unwrap(), b"f");
        assert!(base64_decode_strict("Zh==").is_err());
        assert!(base64_decode_strict("Zm9=").is_err());
    }

    #[test]
    fn strict_rejects_bad_alphabet() {
        assert!(base64_decode_strict("Zm9v!").is_err());
        assert!(base64_decode_strict("Zg==$").is_err());
    }

    #[test]
    fn strict_ignores_interior_whitespace_like_mime() {
        assert_eq!(base64_decode_strict("Zm9v\nYmFy").unwrap(), b"foobar");
        assert_eq!(base64_decode_strict(" Z m 9 v ").unwrap(), b"foo");
    }

    #[test]
    fn decode_bytes_matches_str_path() {
        let s = "Zm9vYmFy";
        let b = s.as_bytes();
        assert_eq!(
            base64_decode_bytes_strict(b, STANDARD).unwrap(),
            base64_decode_strict(s).unwrap()
        );
        assert!(base64_decode_bytes_strict(b"\xff\xfe", STANDARD).is_err());
    }

    #[test]
    fn url_safe_roundtrip() {
        let input = b"\xff\xfe\xfd\xfc";
        let encoded = base64_encode_url(input);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
        assert_eq!(base64_decode_url(&encoded).unwrap(), input);
    }

    #[test]
    fn a_quantum_of_one_data_character_is_never_valid() {
        // 6 bits cannot produce a byte; the length check runs before any
        // alphabet lookup, so these fail on length alone.
        for s in ["A", "AAAAA", "Zm9vA"] {
            assert!(base64_decode(s).is_err(), "{s}");
            assert!(base64_decode_strict(s).is_err(), "{s}");
        }
    }

    #[test]
    fn strict_padding_is_canonical_after_a_full_quantum() {
        // The padding count is over the whole input, not per final
        // quantum: "Zm9vZg" is two quanta and needs exactly two pads.
        assert_eq!(base64_decode_strict("Zm9vZg==").unwrap(), b"foof");
        assert!(base64_decode_strict("Zm9vZg=").is_err());
        assert!(base64_decode_strict("Zm9vZg").is_err());
        assert!(base64_decode_strict("Zm9vZg===").is_err());
    }

    #[test]
    fn interior_padding_is_rejected_in_both_modes() {
        // `=` is not an alphabet character, so it can only sit at the
        // end; anywhere else it is a decode error, not a pad.
        assert!(base64_decode("Z=g=").is_err());
        assert!(base64_decode_strict("Zm9v=YmFy").is_err());
    }

    #[test]
    fn the_two_alphabets_do_not_share_characters() {
        // §4 and §5 differ exactly in the 62nd/63rd symbols: a `+`/`/`
        // input is not URL-safe, a `-`/`_` input is not standard.
        assert!(base64_decode_url("ab+d").is_err());
        assert!(base64_decode_url("ab/d").is_err());
        assert!(base64_decode_strict("ab-d").is_err());
        assert!(base64_decode_strict("ab_d").is_err());
        // The same sextet sequence decodes on each side of the split
        // when each side gets its own alphabet.
        assert_eq!(
            base64_decode_with("ab-d", URL_SAFE_NO_PAD).unwrap(),
            base64_decode("ab+d").unwrap()
        );
    }

    #[test]
    fn url_safe_padded_config_roundtrips() {
        // URL_SAFE pads; URL_SAFE_NO_PAD does not. Both decode either
        // form — padding is a decode-time count, not an alphabet fact.
        let input = b"\xff\xfe\xfd\xfc\xfb";
        let padded = base64_encode_with(input, URL_SAFE);
        assert!(padded.contains('='));
        assert_eq!(base64_decode_with_strict(&padded, URL_SAFE).unwrap(), input);
        assert_eq!(base64_decode_url(&padded).unwrap(), input);
    }

    #[test]
    fn no_pad_configs_encode_without_padding() {
        assert_eq!(base64_encode_with(b"f", STANDARD_NO_PAD), "Zg");
        assert_eq!(base64_encode_with(b"fo", STANDARD_NO_PAD), "Zm8");
        assert_eq!(base64_encode_with(b"f", URL_SAFE_NO_PAD), "Zg");
    }

    #[cfg(feature = "std")]
    #[test]
    fn decode_never_panics_on_arbitrary_bytes() {
        let corpus: Vec<(&'static str, Vec<u8>)> = vec![
            ("valid", b"Zm9vYmFy".to_vec()),
            ("padded", b"Zg==".to_vec()),
            ("url", b"ab-_".to_vec()),
            ("wrapped", b"Zm9v\nYmFy".to_vec()),
            ("pads", b"====".to_vec()),
        ];
        crate::fuzzkit::assert_never_panics(corpus, 200, "base64", |data| {
            let _ = base64_decode_skipping_ws(data, STANDARD);
            let _ = base64_decode_bytes_strict(data, STANDARD);
            let _ = base64_decode_skipping_ws(data, URL_SAFE_NO_PAD);
            let _ = base64_decode_bytes_strict(data, URL_SAFE_NO_PAD);
            let _ = base64_decode_bytes_strict(data, URL_SAFE);
        });
    }
}
