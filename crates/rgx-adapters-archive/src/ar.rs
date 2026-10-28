// SPDX-License-Identifier: Apache-2.0

//! Unix ar archive and Debian package (.deb) adapter.
//!
//! Handles Unix `ar` archives (magic `!<arch>\n`), commonly used for static
//! libraries (`.a`), archives (`.ar`), and Debian packages (`.deb`).
//! Supports GNU, BSD, and common long-filename tables (`//`).

use crate::budget::MemberSink;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str;
use rgx_core::{decline, Adapter, Context, Outcome, Result};

pub struct Ar;

impl Adapter for Ar {
    fn name(&self) -> &'static str {
        "ar"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["a", "ar", "deb"]
    }

    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < 8 || &data[..8] != b"!<arch>\n" {
            decline!("not an ar archive (bad magic)");
        }

        let parse_ascii_dec = |b: &[u8]| -> Result<u64> {
            let s = str::from_utf8(b).context("ar field not ascii")?.trim();
            if s.is_empty() {
                return Ok(0);
            }
            s.parse::<u64>().context("invalid decimal in ar header")
        };

        let mut pos = 8usize;
        let mut string_table: Option<Vec<u8>> = None;
        let mut sink = MemberSink::new();

        while pos + 60 <= data.len() {
            let hdr = &data[pos..pos + 60];
            if &hdr[58..60] != b"`\n" {
                break;
            }

            let raw_name = &hdr[0..16];
            let size = parse_ascii_dec(&hdr[48..58])? as usize;
            let data_start = pos + 60;
            let data_end = data_start + size;
            if data_end > data.len() {
                break;
            }

            let member_data = &data[data_start..data_end];

            if raw_name.starts_with(b"//") {
                string_table = Some(member_data.to_vec());
            } else if raw_name.starts_with(b"/")
                && raw_name.get(1).is_some_and(|b| b.is_ascii_digit())
            {
                let offset = parse_ascii_dec(&raw_name[1..])? as usize;
                let name = if let Some(ref st) = string_table {
                    if offset < st.len() {
                        let name_slice = &st[offset..];
                        let len = name_slice
                            .iter()
                            .position(|&b| b == b'/' || b == b'\n' || b == 0)
                            .unwrap_or(name_slice.len());
                        String::from_utf8_lossy(&name_slice[..len]).to_string()
                    } else {
                        format!("member_{offset}")
                    }
                } else {
                    format!("member_{offset}")
                };
                if !sink.reserve(size as u64) || !sink.push(name, member_data.to_vec()) {
                    break;
                }
            } else if raw_name.starts_with(b"#1/") {
                let name_len = parse_ascii_dec(&raw_name[3..])? as usize;
                if name_len <= size {
                    let name = String::from_utf8_lossy(&member_data[..name_len])
                        .trim_matches('\0')
                        .to_string();
                    let file_bytes = &member_data[name_len..];
                    if !sink.reserve(file_bytes.len() as u64)
                        || !sink.push(name, file_bytes.to_vec())
                    {
                        break;
                    }
                }
            } else {
                let name = str::from_utf8(raw_name)
                    .unwrap_or("")
                    .trim()
                    .trim_end_matches('/')
                    .to_string();
                if !name.is_empty()
                    && (!sink.reserve(size as u64) || !sink.push(name, member_data.to_vec()))
                {
                    break;
                }
            }

            pos = (data_end + 1) & !1;
        }

        Ok(Outcome::Members(sink.finish()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_simple_ar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::from(b"!<arch>\n");
        for (name, data) in entries {
            let mut hdr = [b' '; 60];
            let name_bytes = format!("{}/", name);
            let nlen = name_bytes.len().min(16);
            hdr[..nlen].copy_from_slice(&name_bytes.as_bytes()[..nlen]);
            hdr[16..28].copy_from_slice(b"12345678    ");
            hdr[28..34].copy_from_slice(b"1000  ");
            hdr[34..40].copy_from_slice(b"1000  ");
            hdr[40..48].copy_from_slice(b"100644  ");
            let size_str = format!("{:<10}", data.len());
            hdr[48..58].copy_from_slice(size_str.as_bytes());
            hdr[58..60].copy_from_slice(b"`\n");

            out.extend_from_slice(&hdr);
            out.extend_from_slice(data);
            if data.len() % 2 == 1 {
                out.push(b'\n');
            }
        }
        out
    }

    #[test]
    fn extracts_members() {
        let ar = build_simple_ar(&[
            ("debian-binary", b"2.0\n"),
            ("control.tar.gz", b"fake_control_bytes"),
            ("data.tar.xz", b"fake_data_bytes"),
        ]);
        let outcome = Ar.extract(&ar, "test.deb").unwrap();
        match outcome {
            Outcome::Members(m) => {
                assert_eq!(m.len(), 3);
                assert_eq!(m[0].0, "debian-binary");
                assert_eq!(m[0].1, b"2.0\n");
                assert_eq!(m[1].0, "control.tar.gz");
                assert_eq!(m[2].0, "data.tar.xz");
            }
            _ => panic!("expected Members outcome"),
        }
    }

    #[test]
    fn rejects_non_ar() {
        assert!(Ar.extract(b"not an ar", "test.a").is_err());
    }
}
