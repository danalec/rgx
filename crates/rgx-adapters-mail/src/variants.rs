// SPDX-License-Identifier: Apache-2.0

//! Mailbox variants the mbox reader does not already claim, and Thunderbird's
//! per-folder index.
//!
//! The distinction matters more than it looks: an mbox is separated by
//! `From ` lines, an MMDF by a four-byte attribute separator, and a Thunderbird
//! `.msf` is not a mailbox at all — it is the *index* that tells rgx which
//! `.eml` files the folder holds and what their subjects and senders are.
//! A search that never reads the index reports an empty Thunderbird profile.

use alloc::string::String;
#[cfg(any(feature = "mmdf", feature = "thunderbird"))]
use alloc::string::ToString;
#[cfg(feature = "mmdf")]
use alloc::vec::Vec;
use core::fmt::Write as _;

#[cfg(any(feature = "mmdf", feature = "thunderbird"))]
use rgx_core::bail;
use rgx_core::{decline, Adapter, Outcome, Result};

/// MMDF's file header and its message separator.
#[cfg(feature = "mmdf")]
const MMDF_HEADER: &[u8; 4] = &[0x01, 0x00, 0x01, 0x0C];
#[cfg(feature = "mmdf")]
const MMDF_SEP: &[u8; 4] = &[0x00, 0x00, 0x00, 0x01];

/// Messages reported before a folder stops being useful rather than large.
#[cfg(any(feature = "mmdf", feature = "thunderbird"))]
const MAX_MESSAGES: usize = 20_000;

#[cfg(feature = "mmdf")]
pub struct Mmdf;
#[cfg(feature = "mmdf")]
impl Adapter for Mmdf {
    fn name(&self) -> &'static str {
        "mmdf"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["mmdf"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if !data.starts_with(MMDF_HEADER) {
            decline!("not an MMDF mailbox (bad header)");
        }
        let mut out = String::new();
        let _ = writeln!(out, "MMDF mailbox");
        let mut n = 0usize;
        for part in split_mmdf(&data[4..]) {
            if n >= MAX_MESSAGES {
                break;
            }
            // The separator's own bytes can leave an empty final chunk.
            let body = part.strip_prefix(MMDF_HEADER).unwrap_or(part);
            let trimmed = trim_nul(body);
            if trimmed.is_empty() {
                continue;
            }
            n += 1;
            let _ = writeln!(out, "--- message {n} ---");
            for h in headers(trimmed) {
                let _ = writeln!(out, "{h}");
            }
        }
        if n == 0 {
            bail!("MMDF mailbox holds no messages");
        }
        let _ = writeln!(out, "messages: {n}");
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// Thunderbird's `.msf`. Since version 78 the folder index is a plain-text
/// file: a version line, then `key<TAB>value` lines whose continuation lines
/// start with a space. Before that it was a Berkeley DB, which this reader
/// declines rather than guesses at.
#[cfg(feature = "thunderbird")]
pub struct ThunderbirdMsf;
#[cfg(feature = "thunderbird")]
impl Adapter for ThunderbirdMsf {
    fn name(&self) -> &'static str {
        "msf"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["msf"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let text = match core::str::from_utf8(data) {
            Ok(t) => t,
            Err(_) => {
                decline!("not a modern Thunderbird index (the older format is a Berkeley DB)")
            }
        };
        let mut lines = text.lines();
        let Some(first) = lines.next() else {
            bail!("empty Thunderbird index");
        };
        // The version line is a bare integer. A file whose first line is
        // anything else is not this format.
        if first.trim().parse::<u32>().is_err() {
            decline!("not a modern Thunderbird index (no version line)");
        }
        let mut out = String::new();
        let _ = writeln!(out, "Thunderbird index, version {}", first.trim());
        let mut key = String::new();
        let mut value = String::new();
        let mut entries = 0usize;
        for line in lines {
            if let Some(rest) = line.strip_prefix(' ') {
                value.push(' ');
                value.push_str(rest);
                continue;
            }
            entries += flush_entry(&mut key, &mut value, &mut out);
            match line.split_once('\t') {
                Some((k, v)) => {
                    key = k.to_string();
                    value = v.to_string();
                }
                None => {
                    key = line.to_string();
                    value.clear();
                }
            }
            if entries > MAX_MESSAGES {
                break;
            }
        }
        entries += flush_entry(&mut key, &mut value, &mut out);
        if entries == 0 {
            bail!("Thunderbird index holds no entries");
        }
        let _ = writeln!(out, "entries: {entries}");
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// Apple Mail stores a mailbox index (`.mbx` beside the mbox) whose first
/// records are an index version and a plist of flags. Reporting that it is an
/// index — not a mailbox — is the honest answer; the mbox it points at is the
/// file rgx already reads.
#[cfg(feature = "apple-mailbox")]
pub struct AppleMailboxIndex;
#[cfg(feature = "apple-mailbox")]
impl Adapter for AppleMailboxIndex {
    fn name(&self) -> &'static str {
        "mailbox-index"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["mboxindex"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if !data.starts_with(b"bplist00") {
            decline!("not an Apple mailbox index (not a binary plist)");
        }
        let mut out = String::new();
        let _ = writeln!(out, "Apple Mail mailbox index (binary plist)");
        let _ = writeln!(out, "{} bytes", data.len());
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// Emit the pending entry and clear it, returning whether one was pending.
#[cfg(feature = "thunderbird")]
fn flush_entry(key: &mut String, value: &mut String, out: &mut String) -> usize {
    if key.is_empty() {
        return 0;
    }
    let _ = writeln!(out, "{key}: {}", value.trim());
    key.clear();
    value.clear();
    1
}

/// Split on the four-byte attribute separator. The separator is not a valid
/// single-byte pattern, so the scan is explicit — and it is a scan, not a
/// `memmem`, because a separator byte sequence inside a message body must
/// not split the message.
#[cfg(feature = "mmdf")]
fn split_mmdf(d: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut p = 0usize;
    while p + 4 <= d.len() {
        if &d[p..p + 4] == MMDF_SEP {
            out.push(&d[start..p]);
            p += 4;
            start = p;
        } else {
            p += 1;
        }
    }
    out.push(&d[start..]);
    out
}

#[cfg(feature = "mmdf")]
fn trim_nul(b: &[u8]) -> &[u8] {
    let end = b.iter().position(|x| *x == 0).unwrap_or(b.len());
    &b[..end]
}

/// The headers worth printing: a message's identity is its first line and a
/// handful of fields, and the body is the mbox reader's business.
#[cfg(feature = "mmdf")]
fn headers(msg: &[u8]) -> Vec<String> {
    const KEEP: [&str; 9] = [
        "from",
        "to",
        "cc",
        "bcc",
        "subject",
        "date",
        "message-id",
        "in-reply-to",
        "x-mailer",
    ];
    let text = String::from_utf8_lossy(msg);
    let mut out = Vec::new();
    let mut last = "";
    let mut unfolded = String::new();
    for line in text.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if !last.is_empty() {
                let _ = write!(unfolded, " {line}");
            }
            continue;
        }
        if !last.is_empty() {
            out.push(unfolded.clone());
        }
        unfolded = line.to_string();
        last = line;
    }
    if !last.is_empty() {
        out.push(unfolded);
    }
    out.into_iter()
        .filter(|l| {
            let name = l
                .split(':')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            KEEP.contains(&name.as_str())
        })
        .take(9)
        .collect()
}

#[cfg(all(test, any(feature = "mmdf", feature = "thunderbird")))]
mod tests {
    use super::*;

    #[cfg(any(feature = "mmdf", feature = "thunderbird"))]
    fn text_of(r: Result<Outcome>) -> String {
        match r.expect("adapter") {
            Outcome::Text(t) => String::from_utf8_lossy(&t).into_owned(),
            _ => panic!("expected Text"),
        }
    }

    #[cfg(feature = "mmdf")]
    #[test]
    fn an_mmdf_mailbox_is_split_on_its_separator() {
        let mut d = MMDF_HEADER.to_vec();
        d.extend_from_slice(b"From: ana@example.org\nSubject: Primeiro\n\ncorpo\n");
        d.extend_from_slice(MMDF_SEP);
        d.extend_from_slice(b"From: bo@example.org\nSubject: Segundo\n\ncorpo\n");
        d.extend_from_slice(MMDF_SEP);
        let out = text_of(Mmdf.extract(&d, "x.mmdf"));
        assert!(out.contains("message 1"), "{out}");
        assert!(out.contains("Subject: Primeiro"), "{out}");
        assert!(out.contains("Subject: Segundo"), "{out}");
        assert!(out.contains("messages: 2"), "{out}");
        assert!(Mmdf.extract(b"From nobody", "x.mmdf").is_err());
    }

    #[cfg(feature = "thunderbird")]
    #[test]
    fn a_thunderbird_index_reports_subjects_and_senders() {
        let msf = "4\n\
                   \\0Message-ID\t<1@x>\n\
                   \\0Subject\tContrato de aluguel\n\
                   \\0Author\tAna <ana@example.org>\n\
                   \\0Children\t2\n\
                   1\tmsg-1.eml\n\
                   2\tmsg-2.eml\n";
        let out = text_of(ThunderbirdMsf.extract(msf.as_bytes(), "Inbox.msf"));
        assert!(out.contains("version 4"), "{out}");
        assert!(out.contains("Subject: Contrato de aluguel"), "{out}");
        assert!(out.contains("Author: Ana <ana@example.org>"), "{out}");
        assert!(out.contains("msg-2.eml"), "{out}");
    }

    #[cfg(feature = "thunderbird")]
    #[test]
    fn a_thunderbird_index_folds_a_continued_value() {
        // A continuation line is one leading space followed by the rest of
        // the value verbatim; the key/value tab was consumed on the first
        // line and does not reappear here.
        let msf = "4\n\\0Subject\tContrato de\n aluguel\n";
        let out = text_of(ThunderbirdMsf.extract(msf.as_bytes(), "Inbox.msf"));
        assert!(out.contains("Subject: Contrato de aluguel"), "{out}");
    }

    #[cfg(feature = "thunderbird")]
    #[test]
    fn an_old_berkeley_db_index_is_declined_not_guessed_at() {
        assert!(ThunderbirdMsf
            .extract(&[0x00, 0x61, 0x73, 0x00, 0x05], "x.msf")
            .is_err());
    }
}
