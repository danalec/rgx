// SPDX-License-Identifier: Apache-2.0

//! Version-control backup containers: git bundles and Subversion dumps.
//!
//! **Git bundle** is a packfile with a text header in front of it, so the
//! pack reader does the work and this only finds where the header ends.
//! That is worth an adapter of its own because `.bundle` is what
//! `git bundle create` writes and ripgrep calls it binary: the objects
//! inside are unreachable without one.
//!
//! **Subversion dumps** are already text, so ripgrep reads them — which is
//! exactly why this one is [`Reach::Render`] with
//! [`reach_needs_bytes`](super) true: the record structure it prints (node
//! paths, actions, revisions) is a *view* of bytes ripgrep already reads,
//! and under `Policy::Source` the pipeline unions the two. A `Reach::Reveal`
//! answer here would be a regression, because the payload text would stop
//! being searched.

use alloc::string::{String, ToString};
use core::fmt::Write as _;

#[cfg(feature = "svn-dump")]
use rgx_core::{bail, Reach};
use rgx_core::{decline, Adapter, Outcome, Result};

#[cfg(feature = "git-bundle")]
pub struct GitBundle;
#[cfg(feature = "git-bundle")]
impl Adapter for GitBundle {
    fn name(&self) -> &'static str {
        "git-bundle"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["bundle"]
    }
    fn extract(&self, data: &[u8], path: &str) -> Result<Outcome> {
        // "# v2 git bundle\n" then prerequisite/ref lines, then a blank
        // line, then the pack. Searching for the pack's own magic is more
        // robust than counting header lines, and a bundle v3 header carries
        // capabilities the reader does not act on either way.
        let mut at = None;
        for p in (0..data.len().saturating_sub(4)).step_by(1) {
            if data[p..].starts_with(b"\nPACK") {
                at = Some(p + 1);
                break;
            }
            if p > 64 * 1024 {
                break;
            }
        }
        let Some(at) = at else {
            decline!("no packfile after the bundle header");
        };
        let header = String::from_utf8_lossy(&data[..at]);
        let mut out = String::new();
        for line in header.lines().skip(1) {
            if line.starts_with('@') || line.starts_with('-') {
                let _ = writeln!(out, "ref: {line}");
            }
        }
        let Outcome::Members(mut members) = crate::git_pack::GitPack.extract(&data[at..], path)?
        else {
            decline!("the bundle's payload is not a packfile");
        };
        if !out.is_empty() {
            members.push(("bundle-header.txt".to_string(), out.into_bytes()));
        }
        Ok(Outcome::Members(members))
    }
}

#[cfg(feature = "svn-dump")]
pub struct SvnDump;
#[cfg(feature = "svn-dump")]
impl Adapter for SvnDump {
    fn name(&self) -> &'static str {
        "svn-dump"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["dump"]
    }
    fn reach(&self) -> Reach {
        Reach::Render
    }
    fn reach_needs_bytes(&self) -> bool {
        true
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        // `data.get(..4096)` is `None` for every file under 4096 bytes, which is
        // most of them: the clamp has to be on the length, not only on the
        // range.
        let head = &data[..data.len().min(4096)];
        if !head.starts_with(b"SVN-fs-dump-format-version:") {
            decline!("not a Subversion dump (no format-version record)");
        }
        let mut out = String::new();
        let mut p = 0usize;
        let mut records = 0usize;
        let mut guard = 0usize;
        while p < data.len() {
            guard += 1;
            if guard > 1_000_000 {
                break;
            }
            // One record: a block of `Key: value` headers, then its content.
            let mut content_len = 0usize;
            let mut headers = 0usize;
            while p < data.len() {
                let Some(eol) = memfind(data, b'\n', p) else {
                    p = data.len();
                    break;
                };
                let line = &data[p..eol];
                if line.is_empty() {
                    p = eol + 1;
                    break;
                }
                let Some(colon) = line.iter().position(|b| *b == b':') else {
                    // Not a header: the block ended and this is content.
                    break;
                };
                let (key, value) = line.split_at(colon);
                let value = String::from_utf8_lossy(&value[1..]).trim().to_string();
                match key {
                    b"Content-length" => content_len = value.parse().unwrap_or(0),
                    b"Node-path" => {
                        let _ = writeln!(out, "path {value}");
                    }
                    b"Node-action" => {
                        let _ = writeln!(out, "  action {value}");
                    }
                    b"Node-kind" => {
                        let _ = writeln!(out, "  kind {value}");
                    }
                    b"Node-copyfrom-rev" => {
                        let _ = writeln!(out, "  copied-from rev {value}");
                    }
                    b"Txn-action" => {
                        let _ = writeln!(out, "txn {}", value.trim_start_matches("  "));
                    }
                    b"Txn-user" => {
                        let _ = writeln!(out, "  by {value}");
                    }
                    b"Revision-number" => {
                        let _ = writeln!(out, "revision {value}");
                    }
                    b"UUID" => {
                        let _ = writeln!(out, "uuid {value}");
                    }
                    b"SVN-fs-dump-format-version" => {
                        let _ = writeln!(out, "format version {value}");
                    }
                    _ => {}
                }
                headers += 1;
                p = eol + 1;
            }
            if headers == 0 {
                break;
            }
            records += 1;
            // The payload follows the header block verbatim; skipping it by
            // its declared length is what keeps a binary property block
            // from being read as the next record's headers.
            p = p.saturating_add(content_len);
            // svnadmin writes a newline after the content
            if data.get(p) == Some(&b'\n') {
                p += 1;
            }
        }
        let _ = writeln!(out, "records: {records}");
        if records == 0 {
            bail!("dump holds no records");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

#[cfg(feature = "svn-dump")]
fn memfind(hay: &[u8], needle: u8, from: usize) -> Option<usize> {
    hay[from.min(hay.len())..]
        .iter()
        .position(|b| *b == needle)
        .map(|i| i + from)
}

#[cfg(all(test, any(feature = "git-bundle", feature = "svn-dump")))]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    #[cfg(feature = "git-bundle")]
    use rgx_core::compress::zlib::ZlibEncoder;

    #[cfg(feature = "git-bundle")]
    fn pack_with_blob(content: &[u8]) -> Vec<u8> {
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes());
        let size = content.len();
        let hdr = (3u8 << 4) | ((size as u8) & 0x0F);
        if size > 15 {
            pack.push(hdr | 0x80);
            pack.push((size >> 4) as u8);
        } else {
            pack.push(hdr);
        }
        pack.extend_from_slice(&ZlibEncoder::new().encode(content));
        pack.extend_from_slice(&[0u8; 20]);
        pack
    }

    #[cfg(feature = "git-bundle")]
    fn members(out: Outcome) -> Vec<(String, Vec<u8>)> {
        match out {
            Outcome::Members(m) => m,
            _ => panic!("expected Members"),
        }
    }

    #[cfg(feature = "svn-dump")]
    fn text(out: Outcome) -> String {
        match out {
            Outcome::Text(t) => String::from_utf8_lossy(&t).into_owned(),
            _ => panic!("expected Text"),
        }
    }

    #[cfg(feature = "git-bundle")]
    #[test]
    fn a_bundle_yields_its_objects_and_its_refs() {
        let mut b = b"# v2 git bundle\n@aaaaaaa comment\n".to_vec();
        b.extend_from_slice(b"-bbbbbbb refs/heads/main\n");
        b.push(b'\n');
        b.extend_from_slice(&pack_with_blob(b"invoice total 42\n"));
        let m = members(GitBundle.extract(&b, "history.bundle").expect("bundle"));
        let blob = m
            .iter()
            .find(|(n, _)| n.starts_with("blob_"))
            .expect("blob");
        assert_eq!(blob.1, b"invoice total 42\n");
        let head = m
            .iter()
            .find(|(n, _)| n == "bundle-header.txt")
            .expect("header");
        let head = String::from_utf8_lossy(&head.1);
        assert!(head.contains("refs/heads/main"), "{head}");
        assert!(head.contains("comment"), "{head}");
    }

    #[cfg(feature = "git-bundle")]
    #[test]
    fn a_bundle_without_a_pack_declines() {
        assert!(GitBundle
            .extract(b"# v2 git bundle\n\nnothing", "x.bundle")
            .is_err());
        assert!(GitBundle.extract(b"random bytes", "x.bundle").is_err());
    }

    #[cfg(feature = "svn-dump")]
    #[test]
    fn a_svn_dump_is_a_rendering_of_bytes_ripgrep_already_reads() {
        let d = SvnDump;
        assert_eq!(d.reach(), Reach::Render);
        assert!(d.reach_needs_bytes());
    }

    #[cfg(feature = "svn-dump")]
    #[test]
    fn svn_dump_records_are_read_and_the_payload_is_skipped() {
        let body = b"\x00\x01binaryproperty\x00\xff";
        let mut d = Vec::new();
        d.extend_from_slice(b"SVN-fs-dump-format-version: 3\n");
        d.extend_from_slice(b"UUID: 6f1a2b3c\n\n");
        d.extend_from_slice(b"Node-path: trunk\nNode-action: add\nNode-kind: file\n");
        d.extend_from_slice(format!("Content-length: {}\n", body.len()).as_bytes());
        d.push(b'\n');
        d.extend_from_slice(body);
        d.push(b'\n');
        d.extend_from_slice(b"Revision-number: 42\n\n");

        let out = text(SvnDump.extract(&d, "repo.dump").expect("dump"));
        assert!(out.contains("path trunk"), "{out}");
        assert!(out.contains("action add"), "{out}");
        assert!(out.contains("kind file"), "{out}");
        assert!(out.contains("revision 42"), "{out}");
        assert!(out.contains("uuid 6f1a2b3c"), "{out}");
        // The binary property block must not be read as headers.
        assert!(!out.contains("binaryproperty"), "{out}");
        // format-version record, node record, revision record
        assert!(out.contains("records: 3"), "{out}");
    }

    #[cfg(feature = "svn-dump")]
    #[test]
    fn svn_dump_declines_a_file_without_the_format_record() {
        assert!(SvnDump.extract(b"SQLite format 3\0", "x.dump").is_err());
    }
}
