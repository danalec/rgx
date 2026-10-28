// SPDX-License-Identifier: Apache-2.0

//! Extra mail adapters: Outlook `.msg` (OLE2/CFB) and Apple Mail `.emlx`.
//!
//! `.msg` uses the OLE2 Compound File Binary format — the same container as
//! old `.doc`/`.xls`. The shared CFB reader now lives in rgx-core
//! (`rgx_core::cfb`) so the office `.doc` adapter uses the same code.

#[cfg(feature = "msg")]
use alloc::string::String;
#[cfg(feature = "msg")]
use alloc::vec::Vec;
#[cfg(feature = "msg")]
use core::fmt::Write as _;
#[cfg(feature = "msg")]
use rgx_core::cfb::Cfb;
#[cfg(feature = "msg")]
use rgx_core::cfb::Entry;
#[cfg(feature = "msg")]
use rgx_core::decline;
#[cfg(any(feature = "msg", feature = "emlx"))]
use rgx_core::Result;
#[cfg(any(feature = "msg", feature = "emlx"))]
use rgx_core::{Adapter, Outcome};

/// Outlook `.msg`: MAPI properties stored as named streams inside a CFB.
/// We read the standard ones: subject, body (ANSI or UTF-16), sender,
/// recipients, attachment inventory.
#[cfg(feature = "msg")]
pub struct Msg;
#[cfg(feature = "msg")]
impl Adapter for Msg {
    fn name(&self) -> &'static str {
        "msg"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["msg"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let cfb = Cfb::parse(data)?;
        let find = |suffix: &str| -> Option<Vec<u8>> {
            cfb.find_stream_suffix(suffix).map(|e| cfb.read_stream(e))
        };

        let mut out = String::new();
        let mut has_content = false;

        let decode = |raw: &[u8], utf16: bool| -> String {
            if utf16 {
                let units: Vec<u16> = raw
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16_lossy(&units)
            } else {
                String::from_utf8_lossy(raw).into_owned()
            }
        };

        // subject: 0037 (001E = ANSI, 001F = UTF-16)
        for suf in ["_0037001F", "_0037001E"] {
            if let Some(raw) = find(suf) {
                let _ = writeln!(out, "subject: {}", decode(&raw, suf.ends_with('F')).trim());
                has_content = true;
                break;
            }
        }
        // body: 1000 (001E ANSI / 001F UTF-16)
        for suf in ["_1000001F", "_1000001E"] {
            if let Some(raw) = find(suf) {
                let body = decode(&raw, suf.ends_with('F'));
                if !body.trim().is_empty() {
                    out.push_str(body.trim());
                    out.push('\n');
                    has_content = true;
                }
                break;
            }
        }

        // attachment inventory: __attach_version1.0_ streams
        let attach_dirs: Vec<&Entry> = cfb
            .entries
            .iter()
            .filter(|e| e.kind == 2 && e.name.contains("__attach"))
            .collect();
        let mut attach_names = Vec::new();
        for e in &attach_dirs {
            // long filename 3707 / display name 3001
            if e.name.ends_with("_3707001F") || e.name.ends_with("_3001001F") {
                let raw = cfb.read_stream(e);
                let name = decode(&raw, true);
                if !name.is_empty() && !attach_names.contains(&name) {
                    attach_names.push(name);
                }
            }
        }
        for (i, name) in attach_names.iter().enumerate() {
            let _ = writeln!(out, "attachment {i}: {name}");
        }

        if !has_content && attach_names.is_empty() {
            decline!("no readable MAPI properties in .msg");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// Apple Mail `.emlx`: an RFC-822 message followed by `\n<message-count>\n`
/// and a binary plist. We strip the trailer and reuse the eml adapter, so
/// attachments inside emlx files recurse through the full adapter chain.
#[cfg(feature = "emlx")]
pub struct Emlx;
#[cfg(feature = "emlx")]
impl Adapter for Emlx {
    fn name(&self) -> &'static str {
        "emlx"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["emlx"]
    }
    fn extract(&self, data: &[u8], path: &str) -> Result<Outcome> {
        // find the end of the RFC-822 part: the trailer starts at the last
        // "\n<digits>\n" boundary before the plist — search from a position
        // past the headers to avoid matching header lines.
        let split_at = (1..data.len())
            .filter(|&i| data[i - 1] == b'\n' && data[i].is_ascii_digit())
            .find(|&i| {
                // digits then newline then 'bplist' (binary plist magic)
                let mut j = i;
                while j < data.len() && data[j].is_ascii_digit() {
                    j += 1;
                }
                j + 1 < data.len()
                    && data[j] == b'\n'
                    && data.len() >= j + 7
                    && &data[j + 1..j + 7] == b"bplist"
            });
        let raw = match split_at {
            Some(i) => &data[..i - 1],
            None => data,
        };
        super::Eml.extract(raw, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // The `emlx` reader builds no string of its own; the test needs one to
    // read the text back.
    #[cfg(feature = "emlx")]
    use alloc::string::String;
    #[cfg(feature = "msg")]
    use core::iter;

    /// Build a minimal CFB: 1 FAT sector, 1 dir sector, mini stream in
    /// sector 2. Layout: sector0 = FAT, sector1 = directory, sector2 = mini
    /// stream, sector3 = miniFAT.
    #[cfg(feature = "msg")]
    pub(crate) fn build_cfb(streams: &[(u16, &str, &[u8])]) -> Vec<u8> {
        // stream ids are mini-sector indices here; we lay streams
        // consecutively from mini-sector 0.
        let mut image = vec![0u8; 512]; // header
        image[0..8].copy_from_slice(&rgx_core::cfb::CFB_SIG);
        image[30..32].copy_from_slice(&9u16.to_le_bytes()); // 512 sector
        image[32..34].copy_from_slice(&6u16.to_le_bytes()); // 64 mini sector
        image[44..48].copy_from_slice(&1u32.to_le_bytes()); // 1 FAT sector
        image[48..52].copy_from_slice(&1u32.to_le_bytes()); // first dir sector
        image[56..60].copy_from_slice(&4096u32.to_le_bytes()); // mini cutoff
        image[60..64].copy_from_slice(&3u32.to_le_bytes()); // first miniFAT
        image[64..68].copy_from_slice(&1u32.to_le_bytes()); // num miniFAT
        image[68..72].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // no more DIFAT
        image[76..80].copy_from_slice(&0u32.to_le_bytes()); // FAT sector = 0
                                                            // fill remaining header DIFAT with ENDOFCHAIN
        for k in 1..109 {
            let o = 76 + k * 4;
            image[o..o + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        }

        let mut fat = vec![0xFFu8; 512];
        // sector 1 (dir) -> ENDOFCHAIN, sector 2 (ministream), 3 (minifat)
        fat[4..8].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
        fat[8..12].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
        fat[12..16].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
        image.extend_from_slice(&fat); // sector 0

        // directory sector (sector 1): root + N stream entries
        let mut dir = vec![0u8; 128];
        let root_name: Vec<u8> = "Root Entry"
            .encode_utf16()
            .chain(iter::once(0u16))
            .flat_map(|u| u.to_le_bytes())
            .collect();
        dir[0..root_name.len()].copy_from_slice(&root_name);
        dir[64..66].copy_from_slice(&(root_name.len() as u16).to_le_bytes());
        dir[66] = 5; // root storage
        dir[116..120].copy_from_slice(&2u32.to_le_bytes()); // root chain at sector 2
        let mut ministream_len = 0usize;
        let mut minifat = vec![0xFFu8; 512]; // sector 3
        for (id, name, bytes) in streams.iter() {
            let mut e = vec![0u8; 128];
            let n: Vec<u8> = name
                .encode_utf16()
                .chain(iter::once(0u16))
                .flat_map(|u| u.to_le_bytes())
                .collect();
            e[0..n.len()].copy_from_slice(&n);
            e[64..66].copy_from_slice(&(n.len() as u16).to_le_bytes());
            e[66] = 2; // stream
            e[116..120].copy_from_slice(&(*id as u32).to_le_bytes());
            e[120..124].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
            dir.extend_from_slice(&e);
            // mini chain: sectors of 64 bytes
            let nsec = bytes.len().div_ceil(64);
            for k in 0..nsec {
                let cur = *id as usize + k;
                let next = if k + 1 < nsec { cur + 1 } else { 0xFFFF_FFFE };
                minifat[cur * 4..cur * 4 + 4].copy_from_slice(&(next as u32).to_le_bytes());
            }
            ministream_len = ministream_len.max((*id as usize + nsec) * 64);
        }
        // root storage size = bytes of mini stream actually used
        dir[120..124].copy_from_slice(&(ministream_len as u32).to_le_bytes());
        while dir.len() < 512 {
            dir.extend_from_slice(&[0u8; 128]);
        }
        image.extend_from_slice(&dir); // sector 1
        let mut ms = vec![0u8; 512.max(ministream_len.next_multiple_of(512))];
        for (id, _, bytes) in streams {
            let off = *id as usize * 64;
            ms[off..off + bytes.len()].copy_from_slice(bytes);
        }
        image.extend_from_slice(&ms); // sector 2 (mini stream)
        image.extend_from_slice(&minifat); // sector 3 (miniFAT)
        image
    }

    #[cfg(feature = "msg")]
    #[test]
    fn msg_reads_subject_and_body() {
        let subject = "ZIRCALOY inspection";
        let subject_u16: Vec<u8> = subject
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let body = "check the coolant pump seals";
        let cfb = build_cfb(&[
            (0, "__substg1.0_0037001F", &subject_u16),
            (1, "__substg1.0_1000001E", body.as_bytes()),
        ]);
        let out = Msg.extract(&cfb, "m.msg").unwrap();
        let Outcome::Text(t) = out else {
            panic!("text")
        };
        let s = String::from_utf8(t).unwrap();
        assert!(s.contains("subject: ZIRCALOY inspection"), "{s}");
        assert!(s.contains("check the coolant pump seals"), "{s}");
    }

    #[cfg(feature = "emlx")]
    #[test]
    fn emlx_strips_plist_trailer() {
        let raw = b"From: a@b.c\r\nSubject: ZIRCALOY note\r\n\r\nbody text\r\n";
        let mut d = raw.to_vec();
        d.extend_from_slice(b"\n1\nbplist00\x85\x01_");
        let out = Emlx.extract(&d, "m.emlx").unwrap();
        let Outcome::Text(t) = out else {
            panic!("text")
        };
        let s = String::from_utf8(t).unwrap();
        assert!(s.contains("ZIRCALOY note"), "{s}");
        assert!(s.contains("body text"), "{s}");
        assert!(!s.contains("bplist"), "{s}");
    }

    #[cfg(any(feature = "msg", feature = "emlx"))]
    mod fuzz {
        use super::*;

        #[cfg(feature = "msg")]
        fn msg_fixture() -> Vec<u8> {
            let subject_u16: Vec<u8> = "ZIRCALOY inspection"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect();
            build_cfb(&[
                (0, "__substg1.0_0037001F", &subject_u16),
                (1, "__substg1.0_1000001E", b"check the coolant pump seals"),
            ])
        }

        #[cfg(feature = "msg")]
        #[test]
        fn msg_cfb_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("valid-msg", msg_fixture()),
                    ("sig-only", rgx_core::cfb::CFB_SIG.to_vec()),
                    ("empty", vec![]),
                ],
                1500,
                "msg-cfb",
                |data| {
                    let _ = Msg.extract(data, "fuzz.msg");
                },
            );
        }

        #[cfg(feature = "emlx")]
        #[test]
        fn emlx_never_panics_on_mutation() {
            let raw = b"From: a@b.c\r\nSubject: x\r\n\r\nbody\r\n".to_vec();
            rgx_core::fuzzkit::assert_never_panics(
                vec![("valid-emlx", raw), ("empty", vec![])],
                800,
                "emlx",
                |data| {
                    let _ = Emlx.extract(data, "fuzz.emlx");
                },
            );
        }
    }
}
