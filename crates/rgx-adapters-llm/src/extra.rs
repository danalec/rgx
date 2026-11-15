// SPDX-License-Identifier: Apache-2.0

//! Extra ML-harness adapters: Jupyter notebooks, Keras v3 archives,
//! PyTorch checkpoints, generic pickles. See lib.rs for the core formats.

use alloc::string::String;
use alloc::vec::Vec;
use rgx_core::decline;
use rgx_core::Adapter;
use rgx_core::Outcome;
use rgx_core::Result;

// Only the keras adapter writes into its report.
#[cfg(feature = "keras")]
use core::fmt::Write as _;

// Only the keras adapter reads a member as text.
#[cfg(feature = "keras")]
use core::str;

// The keras and torch adapters spend the archive crate's producer budget
// on the zip they read, so they are the two families that pull that
// crate in.
#[cfg(any(feature = "keras", feature = "torch"))]
use rgx_adapters_archive::budget;

// The keras and torch adapters attach a context to a failure.
#[cfg(any(feature = "keras", feature = "torch"))]
use rgx_core::Context;

/// Extract printable ASCII runs (>= 4 chars) from binary pickles — module
/// paths, tensor/storage names, class names. Bounded output.
#[cfg(any(feature = "torch", feature = "pickle"))]
pub(crate) fn printable_strings(data: &[u8], max_out: usize) -> String {
    let mut out = String::new();
    let mut run = Vec::new();
    for &b in data {
        if (0x20..=0x7e).contains(&b) {
            run.push(b);
        } else {
            if run.len() >= 4 {
                out.push_str(&String::from_utf8_lossy(&run));
                out.push('\n');
                if out.len() >= max_out {
                    return out;
                }
            }
            run.clear();
        }
    }
    if run.len() >= 4 {
        out.push_str(&String::from_utf8_lossy(&run));
        out.push('\n');
    }
    out
}

/// Read a zip container's member list (bounded per member).
///
/// The ceilings are the archive crate's shared producer budget, the same one
/// its own zip adapter spends: `ZipReader::new` pinned them to
/// `default_byte_limit()` and a local `.take(1024)`, which ignored `-M` and
/// `RGX_MAX_MEMBER_BYTES` and dropped whatever they excluded without a word.
/// [`budget::MemberSink`] now carries them and prepends the searchable
/// truncation note, which reaches the pipeline as an ordinary member.
#[cfg(any(feature = "keras", feature = "torch"))]
pub(crate) fn zip_members(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    if !data.starts_with(b"PK") {
        decline!("not a zip container");
    }
    let archive = rgx_core::zip::ZipReader::with_limit(data, budget::budget().bytes)
        .map_err(rgx_core::Error::msg)
        .context("unreadable zip container")?;
    let mut sink = budget::MemberSink::new();
    sink.declare(archive.list().len());
    // `extract_index`, not `extract(&name)` — see the office adapter: the
    // name lookup builds a `BTreeMap<String, usize>` over the whole archive on
    // first use, and `.enumerate()` already has the index.
    for (i, entry) in archive.list().iter().enumerate() {
        if entry.name.ends_with('/') {
            continue;
        }
        if entry.size as usize > (4 << 20) {
            continue;
        }
        // Checked against the declared size, before the member is decoded.
        if !sink.reserve(entry.size as u64) {
            break;
        }
        match archive.extract_index(i) {
            Ok(bytes) => {
                if !sink.push(entry.name.clone(), bytes) {
                    break;
                }
            }
            // A member we cannot decode must not sink the archive; one the
            // byte budget stopped is different — it was readable up to a
            // limit, and saying nothing would read as "no match in it".
            Err(_) => {
                let (limit, spent) = archive.budget();
                if spent >= limit {
                    sink.stop(budget::Stopped::Bytes);
                }
            }
        }
    }
    Ok(sink.finish())
}

/// The truncation note the sink prepends, if this archive was capped.
#[cfg(feature = "keras")]
fn truncation_note(members: &[(String, Vec<u8>)]) -> Option<String> {
    members
        .iter()
        .find(|(name, _)| name == budget::TRUNCATION_MEMBER)
        .map(|(_, note)| String::from_utf8_lossy(note).into_owned())
}

/// Keras v3 `.keras` archives: zip with config.json + metadata.json. We
/// emit those JSON parts (the architecture lives in config.json); weight
/// blobs stay unread — multi-GB float payloads are not searchable text.
#[cfg(feature = "keras")]
pub struct KerasZip;
#[cfg(feature = "keras")]
impl Adapter for KerasZip {
    fn name(&self) -> &'static str {
        "keras"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["keras"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let members = zip_members(data)?;
        let notice = truncation_note(&members);
        let mut out = String::new();
        let mut found = 0usize;
        for (name, bytes) in &members {
            if !name.ends_with(".json") {
                continue;
            }
            let Ok(text) = str::from_utf8(bytes) else {
                continue;
            };
            let Ok(arena) = rgx_core::djson::parse(text) else {
                continue;
            };
            let pretty = rgx_core::djson::to_string_pretty(arena.root(), &arena);
            let _ = writeln!(out, "=== {name} ===\n{pretty}");
            found += 1;
        }
        if found == 0 && notice.is_none() {
            decline!("no JSON config in keras archive");
        }
        // A byte budget that stopped the archive is the only answer there is
        // once the JSON is gone: bailing would fall back to a raw search of
        // the zip bytes and take the note with it.
        if let Some(text) = notice {
            out.insert_str(0, &text);
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// PyTorch `.pt`/`.pth` checkpoints. The modern format is a zip whose
/// `data.pkl` pickle holds the tensor tree (names, shapes via storages);
/// the legacy format is a raw pickle. Both are mined for printable strings
/// plus the zip member inventory — never for weight values.
#[cfg(feature = "torch")]
pub struct Torch;
#[cfg(feature = "torch")]
impl Adapter for Torch {
    fn name(&self) -> &'static str {
        "torch"
    }
    fn extensions(&self) -> &'static [&'static str] {
        // `pt2` belongs here, not to Protobuf: a `.pt2` is the same zipped
        // checkpoint as a `.pt` under another name, so the reader is identical.
        // Protobuf claimed it first, and a reader that cannot parse the format
        // prints its refusal as if the file were unreadable.
        &["pt", "pt2", "pth", "ptl", "bin"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.starts_with(b"PK") {
            // Return members so the pipeline recurses: every member's
            // content becomes searchable (data.pkl lands on the pickle
            // adapter, plain members on raw search). A zip renamed to
            // .bin — firmware, bundles, generic archives — used to get
            // only a name listing here, hiding all content from search.
            let members = zip_members(data)?;
            Ok(Outcome::Members(members))
        } else {
            // legacy pickle checkpoint: strings only. Pickles start with
            // the PROTO opcode 0x80; anything else is not ours (plain .bin
            // blobs, firmware, ...) and must fall back to raw search.
            if !data.starts_with(&[0x80]) {
                // not ours: plain .bin blobs must fall back to raw search
                return Ok(Outcome::Bail("no PROTO opcode".into()));
            }
            let strings = printable_strings(data, 1 << 20);
            if strings.trim().is_empty() {
                decline!("no readable strings in checkpoint");
            }
            Ok(Outcome::Text(strings.into_bytes()))
        }
    }
}

/// Generic Python pickles (joblib dumps, legacy HF model files without the
/// torch zip layout, ...): printable-string scan.
#[cfg(feature = "pickle")]
pub struct PickleStrings;
#[cfg(feature = "pickle")]
impl Adapter for PickleStrings {
    fn name(&self) -> &'static str {
        "pickle"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["pkl", "pickle"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.starts_with(b"PK") {
            decline!("zip-based pickle belongs to the torch adapter");
        }
        if !data.starts_with(&[0x80]) {
            return Ok(Outcome::Bail("no PROTO opcode".into()));
        }
        let strings = printable_strings(data, 1 << 20);
        if strings.trim().is_empty() {
            decline!("no readable strings in pickle");
        }
        Ok(Outcome::Text(strings.into_bytes()))
    }
}

#[cfg(all(test, any(feature = "keras", feature = "torch", feature = "pickle")))]
mod tests {
    use super::*;

    // The tests that change the producer budget take this lock: it is a
    // process-wide global and the test harness runs in parallel.
    #[cfg(any(feature = "keras", feature = "torch"))]
    use std::sync::Mutex;

    /// The producer budget is a process-wide global (it has to be: see
    /// `rgx_adapters_archive::budget`), and this binary runs its tests in
    /// parallel, so a test that lowers it would otherwise change what the
    /// zip-reading tests next door extract.
    #[cfg(any(feature = "keras", feature = "torch"))]
    static BUDGET: Mutex<()> = Mutex::new(());

    #[cfg(any(feature = "keras", feature = "torch"))]
    fn locked<R>(f: impl FnOnce() -> R) -> R {
        let _guard = BUDGET.lock().unwrap_or_else(|e| e.into_inner());
        f()
    }

    #[cfg(any(feature = "keras", feature = "torch"))]
    fn under_budget<R>(members: usize, bytes: u64, f: impl FnOnce() -> R) -> R {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                budget::reset_budget();
            }
        }
        locked(|| {
            budget::set_budget(budget::Budget { members, bytes });
            let _reset = Reset;
            f()
        })
    }

    #[cfg(any(feature = "keras", feature = "torch"))]
    fn mini_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        // stored-entry zip, same builder as the office crate tests
        fn crc32(b: &[u8]) -> u32 {
            let mut crc = 0xFFFF_FFFFu32;
            for &byte in b {
                crc ^= byte as u32;
                for _ in 0..8 {
                    crc = if crc & 1 != 0 {
                        (crc >> 1) ^ 0xEDB8_8320
                    } else {
                        crc >> 1
                    };
                }
            }
            !crc
        }
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data) in entries {
            let offset = out.len() as u32;
            let crc = crc32(data);
            let nlen = name.len() as u16;
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&[0u8; 4]); // flags, method
            out.extend_from_slice(&[0u8; 4]); // time, date
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&nlen.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(data);
            central.extend_from_slice(b"PK\x01\x02");
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&[0u8; 4]);
            central.extend_from_slice(&[0u8; 4]);
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&nlen.to_le_bytes());
            central.extend_from_slice(&[0u8; 6]); // extra, comment, disk
            central.extend_from_slice(&[0u8; 6]); // internal attrs (u16) + external attrs (u32)
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_offset = out.len() as u32;
        let cd_size = central.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0u8; 4]); // disk numbers (2 x u16)
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[cfg(feature = "keras")]
    #[test]
    fn keras_reads_config_json() {
        let zip = mini_zip(&[
            (
                "config.json",
                br#"{"class_name": "Functional", "name": "zircaloy_net"}"#,
            ),
            ("metadata.json", br#"{"keras_version": "3.5.0"}"#),
            ("model.weights.h5", b"\x89HDF\r\n\x1a\n................"),
        ]);
        let out = locked(|| KerasZip.extract(&zip, "m.keras").unwrap());
        let Outcome::Text(t) = out else {
            panic!("text")
        };
        let s = String::from_utf8(t).unwrap();
        assert!(s.contains("zircaloy_net"), "{s}");
        assert!(s.contains("keras_version"), "{s}");
        assert!(!s.contains("HDF"), "weight blob must not leak: {s}");
    }

    #[cfg(feature = "torch")]
    #[test]
    fn torch_zip_lists_members_and_pickle_strings() {
        let pkl =
            b"\x80\x02ctorch._utils\n_rebuild_tensor_v2\nq\x00X\x0c\x00\x00\x00ZIRCALOY_W1q\x01";
        let zip = mini_zip(&[
            ("archive/data.pkl", pkl),
            ("archive/version", b"3\n"),
            ("archive/byteorder", b"little\n"),
        ]);
        let out = locked(|| Torch.extract(&zip, "m.pt").unwrap());
        let Outcome::Members(m) = out else {
            panic!("members")
        };
        let pkl = m
            .iter()
            .find(|(n, _)| n == "archive/data.pkl")
            .expect("data.pkl member");
        let s = String::from_utf8_lossy(&pkl.1);
        assert!(s.contains("ZIRCALOY_W1"), "{s}");
        assert!(m.iter().any(|(n, _)| n == "archive/version"), "{m:?}");
    }

    /// `-M` and `RGX_MAX_MEMBER_BYTES` have to reach this zip reader, the
    /// way they reach the archive crate's own zip adapter.
    ///
    /// It called `ZipReader::new`, which pins the ceiling to
    /// `default_byte_limit()` — `Ctx::default().max_file_size`, 1 GiB
    /// (`crates/rgx-core/src/zip.rs:48`) — and its local `.take(1024)`
    /// capped the members with nothing said about it. A capped checkpoint
    /// came back with the weight blobs simply absent.
    #[cfg(feature = "torch")]
    #[test]
    fn a_checkpoint_zip_the_byte_budget_stops_says_so() {
        let pkl =
            b"\x80\x02ctorch._utils\n_rebuild_tensor_v2\nq\x00X\x0c\x00\x00\x00ZIRCALOY_W1q\x01";
        let zip = mini_zip(&[
            ("archive/data.pkl", pkl),
            ("archive/large.bin", &vec![b'A'; 1 << 20]),
        ]);
        let out = under_budget(4096, 4096, || Torch.extract(&zip, "m.pt").unwrap());
        let Outcome::Members(m) = out else {
            panic!("members")
        };
        assert_eq!(
            m[0].0,
            budget::TRUNCATION_MEMBER,
            "{:?}",
            m.iter().map(|(n, _)| n).collect::<Vec<_>>()
        );
        let note = String::from_utf8_lossy(&m[0].1);
        assert!(note.contains("archive truncated"), "{note}");
        assert!(note.contains("member byte budget"), "{note}");
        assert!(note.contains("2 entries declared"), "{note}");
        assert!(
            m.iter().any(|(n, _)| n == "archive/data.pkl"),
            "the member that fits: {m:?}"
        );
        assert!(
            !m.iter().any(|(n, _)| n == "archive/large.bin"),
            "a member over the budget is not decoded"
        );

        // The other half: a checkpoint under the cap says nothing.
        let small = mini_zip(&[("archive/data.pkl", pkl)]);
        let out = under_budget(4096, 4096, || Torch.extract(&small, "m.pt").unwrap());
        let Outcome::Members(m) = out else {
            panic!("members")
        };
        assert_eq!(m.len(), 1, "{m:?}");
        assert_eq!(m[0].0, "archive/data.pkl");
    }

    /// The keras arm renders its members to text, so the note has to be
    /// folded in rather than passed through as a member — and it is the only
    /// answer left once the byte budget has taken the JSON.
    #[cfg(feature = "keras")]
    #[test]
    fn a_keras_archive_the_byte_budget_stops_says_so() {
        let zip = mini_zip(&[
            (
                "config.json",
                br#"{"class_name": "Functional", "name": "zircaloy_net"}"#,
            ),
            ("weights.h5", &vec![b'A'; 1 << 20]),
        ]);
        let out = under_budget(4096, 4096, || KerasZip.extract(&zip, "m.keras").unwrap());
        let Outcome::Text(t) = out else {
            panic!("text")
        };
        let s = String::from_utf8(t).unwrap();
        assert!(s.contains("archive truncated"), "{s}");
        assert!(s.contains("member byte budget"), "{s}");

        // And when the JSON went with it, the note is still the answer
        // rather than a bail that falls back to a raw search of the zip.
        let zip = mini_zip(&[("config.json", &vec![b'A'; 1 << 20])]);
        let out = under_budget(4096, 4096, || KerasZip.extract(&zip, "m.keras").unwrap());
        let Outcome::Text(t) = out else {
            panic!("text")
        };
        assert!(String::from_utf8(t).unwrap().contains("archive truncated"));
    }

    #[cfg(feature = "torch")]
    #[test]
    fn torch_legacy_pickle_strings() {
        let data = b"\x80\x02cmyapp.model\nZIRCALOYClassifier\nq\x00)\x81q\x01.";
        let out = Torch.extract(data, "old.pt").unwrap();
        let Outcome::Text(t) = out else {
            panic!("text")
        };
        assert!(String::from_utf8(t).unwrap().contains("ZIRCALOYClassifier"));
    }

    #[cfg(feature = "pickle")]
    #[test]
    fn pickle_strings_basic() {
        let data = b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00\x8c\x0cZIRCALOY_TAG\x94.";
        let out = PickleStrings.extract(data, "c.pkl").unwrap();
        let Outcome::Text(t) = out else {
            panic!("text")
        };
        assert!(String::from_utf8(t).unwrap().contains("ZIRCALOY_TAG"));
    }

    #[cfg(all(test, any(feature = "keras", feature = "torch", feature = "pickle")))]
    mod fuzz {
        use super::*;

        #[cfg(feature = "keras")]
        #[test]
        fn keras_zip_never_panics_on_mutation() {
            let zip = mini_zip(&[("config.json", br#"{"class_name": "Functional"}"#)]);
            rgx_core::fuzzkit::assert_never_panics(
                vec![("keras", zip), ("empty", vec![])],
                800,
                "keras-zip",
                |data| {
                    let _ = KerasZip.extract(data, "fuzz.keras");
                },
            );
        }

        #[cfg(feature = "torch")]
        #[test]
        fn torch_never_panics_on_mutation() {
            let pkl = b"\x80\x02ctorch._utils\n_rebuild_tensor_v2\nq\x00X\x0c\x00\x00\x00ZIRCALOY_W1q\x01";
            let zip = mini_zip(&[("archive/data.pkl", pkl)]);
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("torch-zip", zip),
                    (
                        "legacy-pickle",
                        b"\x80\x02cmyapp.model\nZIRCALOYClassifier\nq\x00)\x81q\x01.".to_vec(),
                    ),
                    ("empty", vec![]),
                ],
                1000,
                "torch",
                |data| {
                    let _ = Torch.extract(data, "fuzz.pt");
                },
            );
        }

        #[cfg(feature = "pickle")]
        #[test]
        fn pickle_strings_never_panics_on_mutation() {
            let pkl =
                b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00\x8c\x0cZIRCALOY_TAG\x94.".to_vec();
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("proto4", pkl),
                    ("proto2", b"\x80\x02cmod\nCls\nq\x00)\x81q\x01.".to_vec()),
                    ("empty", vec![]),
                ],
                1200,
                "pickle-strings",
                |data| {
                    let _ = PickleStrings.extract(data, "fuzz.pkl");
                },
            );
        }
    }
}
