// SPDX-License-Identifier: Apache-2.0

//! E-mail adapters: mbox archives and single .eml messages.
//!
//! Message bodies become searchable text; MIME attachments become
//! [`Outcome::Members`] so the pipeline recurses into them with the full
//! adapter chain (a PDF attachment is still a PDF).

#![no_std]

#[macro_use]
extern crate alloc;

// `std` is linked in only when the `std` feature asks for it: the crate is
// `#![no_std]` + `alloc` by default, and the one thing `std` buys is the
// `std::error::Error` impl on `PstErr`. A test build links it either way.
#[cfg(any(test, feature = "std"))]
extern crate std;

use alloc::boxed::Box;
#[cfg(any(feature = "mbox", feature = "eml"))]
use alloc::string::String;
#[cfg(any(feature = "mbox", feature = "eml"))]
use alloc::string::ToString;
use alloc::vec::Vec;
#[cfg(feature = "mbox")]
use core::fmt::Write as _;
#[cfg(feature = "mbox")]
use core::mem;
#[cfg(feature = "mbox")]
use rgx_core::decline;
use rgx_core::Adapter;
#[cfg(any(feature = "mbox", feature = "eml"))]
use rgx_core::{bail, Result};
#[cfg(any(feature = "mbox", feature = "eml"))]
use rgx_core::{Field, Outcome};

#[cfg(any(feature = "msg", feature = "emlx"))]
mod extra;
#[cfg(feature = "pst")]
mod pst;
#[cfg(any(feature = "mmdf", feature = "thunderbird", feature = "apple-mailbox"))]
mod variants;
#[cfg(feature = "wab")]
pub mod wab;

pub fn adapters() -> Vec<Box<dyn Adapter>> {
    vec![
        #[cfg(feature = "mbox")]
        Box::new(Mbox),
        #[cfg(feature = "eml")]
        Box::new(Eml),
        #[cfg(feature = "msg")]
        Box::new(extra::Msg),
        #[cfg(feature = "emlx")]
        Box::new(extra::Emlx),
        #[cfg(feature = "pst")]
        Box::new(pst::PstAdapter),
        #[cfg(feature = "wab")]
        Box::new(wab::Wab),
        #[cfg(feature = "mmdf")]
        Box::new(variants::Mmdf),
        #[cfg(feature = "thunderbird")]
        Box::new(variants::ThunderbirdMsf),
        #[cfg(feature = "apple-mailbox")]
        Box::new(variants::AppleMailboxIndex),
    ]
}

/// One MIME message → (headers + decoded body text, attachments).
///
/// Operates on `&[u8]` directly: header parsing, boundary
/// detection, and base64 payload decoding all stay in byte space
/// until the final body string is built. The `from_utf8_lossy`
/// path used to allocate a per-message `String` for the whole
/// header block before scanning it line by line.
#[cfg(any(feature = "mbox", feature = "eml"))]
fn parse_message(raw: &[u8]) -> (String, Vec<(String, Vec<u8>)>) {
    let mut headers = String::new();
    let mut body_out = String::new();
    let mut attachments = Vec::new();
    let Some((h_end, sep_len)) = header_end(raw) else {
        return (String::from_utf8_lossy(raw).into_owned(), attachments);
    };
    let hdr_bytes = &raw[..h_end];
    append_lines_to_string(hdr_bytes, &mut headers);
    // RFC 2047: a header value may carry its own encoding, and the
    // encoded-word is the one place a mail client is told what the bytes
    // mean. `Subject: =?UTF-8?B?...?=` is the most valuable line in a
    // message and, undecoded, it is a search for a base64 blob.
    if headers.contains("=?") {
        headers = decode_encoded_words(&headers);
    }
    let body = &raw[h_end + sep_len..];
    // `header_value` is a case-insensitive byte scan: parsing stays in
    // byte space rather than copying the header block into a String.
    let content_type = header_value(hdr_bytes, "content-type").unwrap_or_default();
    let boundary = boundary_of(&content_type);
    if let Some(boundary) = boundary {
        let mut delim = Vec::with_capacity(boundary.len() + 2);
        delim.extend_from_slice(b"--");
        delim.extend_from_slice(boundary.as_bytes());
        for part in split_on(body, &delim).skip(1) {
            let part = if part.starts_with(b"\r\n") {
                &part[2..]
            } else if part.starts_with(b"\n") {
                &part[1..]
            } else {
                part
            };
            if part.starts_with(b"--") {
                break;
            }
            let Some((ph_end, ph_sep_len)) = find_subslice(part, b"\r\n\r\n")
                .map(|i| (i, 4))
                .or_else(|| find_subslice(part, b"\n\n").map(|i| (i, 2)))
            else {
                continue;
            };
            let ph = &part[..ph_end];
            let pb = &part[ph_end + ph_sep_len..];
            // Parse headers directly off the byte slice. The previous
            // shape allocated a `String` per part via `from_utf8_lossy`
            // before any test, which was 1.5 KB of heap per MIME part
            // for nothing -- `header_value` is a case-insensitive
            // byte scan and the body of the value is plain ASCII.
            let p_ct = header_value(ph, "content-type").unwrap_or_default();
            let cd = header_value(ph, "content-disposition").unwrap_or_default();
            let filename = filename_of(&cd).map(|f| f.to_string());
            // The value keeps its own case: `header_value` folds the
            // header's NAME, not its value. `attachment_count` reads
            // the same two rules, and the two have to agree.
            let is_attachment = cd.starts_with("attachment") || filename.is_some();
            let transfer_lower = header_value(ph, "content-transfer-encoding").unwrap_or_default();
            // Same case-fold trick: the encoding is one of a small
            // set of ASCII keywords, so we never need a heap String.
            let is_base64 = transfer_lower.as_bytes().contains_ascii_ci("base64");
            let is_qp = !is_base64
                && transfer_lower
                    .as_bytes()
                    .contains_ascii_ci("quoted-printable");
            let decoded: Vec<u8> = if is_base64 {
                rgx_core::base64::base64_decode_skipping_ws(pb, rgx_core::base64::STANDARD)
                    .unwrap_or_default()
            } else if is_qp {
                decode_qp(pb)
            } else {
                pb.to_vec()
            };
            if is_attachment {
                let name = filename.unwrap_or_else(|| "attachment.bin".into());
                attachments.push((name, decoded));
            } else if p_ct.starts_with("text/") || p_ct.is_empty() {
                body_out.push_str(&decode_text(&decoded, charset_of(&p_ct)));
                body_out.push('\n');
            }
        }
    } else {
        let transfer_lower =
            header_value(hdr_bytes, "content-transfer-encoding").unwrap_or_default();
        let is_base64 = transfer_lower.as_bytes().contains_ascii_ci("base64");
        let is_qp = !is_base64
            && transfer_lower
                .as_bytes()
                .contains_ascii_ci("quoted-printable");
        let decoded: Vec<u8> = if is_base64 {
            rgx_core::base64::base64_decode_skipping_ws(body, rgx_core::base64::STANDARD)
                .unwrap_or_default()
        } else if is_qp {
            decode_qp(body)
        } else {
            body.to_vec()
        };
        body_out.push_str(&decode_text(&decoded, charset_of(&content_type)));
    }
    let mut text = headers;
    text.push_str(&body_out);
    (text, attachments)
}

#[cfg(any(feature = "mbox", feature = "eml"))]
fn append_lines_to_string(bytes: &[u8], out: &mut String) {
    let mut start = 0usize;
    for i in 0..bytes.len() {
        if bytes[i] == b'\n' {
            let end = if i > start && bytes[i - 1] == b'\r' {
                i - 1
            } else {
                i
            };
            push_utf8_line(&bytes[start..end], out);
            out.push('\n');
            start = i + 1;
        }
    }
    if start < bytes.len() {
        push_utf8_line(&bytes[start..], out);
        out.push('\n');
    }
}

#[cfg(any(feature = "mbox", feature = "eml"))]
fn push_utf8_line(line: &[u8], out: &mut String) {
    if let Ok(s) = core::str::from_utf8(line) {
        out.push_str(s);
    } else {
        // A header value may carry a raw 8-bit byte -- old mail does, and
        // a name with an accent in it is exactly what a search is for.
        // Reading it as UTF-8 would replace the byte with U+FFFD, so the
        // lenient reading is used instead: it keeps the byte.
        out.push_str(
            &String::from_utf8(rgx_core::charset::decode_lenient(line)).unwrap_or_default(),
        );
    }
}

#[cfg(any(feature = "mbox", feature = "eml"))]
fn split_on<'a>(hay: &'a [u8], delim: &'a [u8]) -> Split<'a> {
    Split { hay, delim }
}

#[cfg(any(feature = "mbox", feature = "eml"))]
struct Split<'a> {
    hay: &'a [u8],
    delim: &'a [u8],
}

#[cfg(any(feature = "mbox", feature = "eml"))]
impl<'a> Iterator for Split<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        if self.hay.is_empty() {
            return None;
        }
        match find_subslice(self.hay, self.delim) {
            Some(i) => {
                let head = &self.hay[..i];
                self.hay = &self.hay[i + self.delim.len()..];
                Some(head)
            }
            None => {
                let tail = self.hay;
                self.hay = &[];
                Some(tail)
            }
        }
    }
}

#[cfg(any(feature = "mbox", feature = "eml"))]
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    rgx_core::memchr::memmem::find(hay, needle)
}

/// The value of a header, as bytes.
///
/// The line iterator here scans for `\n` and treats `\r` as part of the
/// line content; MIME header lines are split by `\r\n` or `\n`, and a
/// continuation starts with whitespace on the next line. The
/// previous shape accepted a `&str` and called `.lines()`, which
/// forced an `&str` to exist -- and the only way the caller got
/// one was `String::from_utf8_lossy(ph).into_owned()` per MIME
/// part, which is the allocation the audit flagged.
#[cfg(any(feature = "mbox", feature = "eml"))]
fn header_value_bytes(headers: &[u8], name: &str) -> Option<Vec<u8>> {
    let mut value: Vec<u8> = Vec::new();
    let mut in_header = false;
    let mut start = 0usize;
    while start < headers.len() {
        let end = memchr2(b'\n', headers, start).unwrap_or(headers.len());
        let line = &headers[start..end];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line
            .first()
            .map(|b| b.is_ascii_whitespace())
            .unwrap_or(false)
            && in_header
        {
            value.push(b' ');
            let trimmed = line
                .iter()
                .position(|b| !b.is_ascii_whitespace())
                .map(|o| &line[o..])
                .unwrap_or(&[]);
            value.extend_from_slice(trimmed);
        } else {
            in_header = false;
            if let Some(colon) = line.iter().position(|&b| b == b':') {
                let (k, v) = line.split_at(colon);
                let v = &v[1..];
                if ascii_eq_ignore_case(k, name.as_bytes()) {
                    value.clear();
                    let trimmed = v
                        .iter()
                        .position(|b| !b.is_ascii_whitespace())
                        .map(|o| &v[o..])
                        .unwrap_or(&[]);
                    let trimmed_end = trimmed
                        .iter()
                        .rposition(|b| !b.is_ascii_whitespace())
                        .map(|i| i + 1)
                        .unwrap_or(0);
                    value.extend_from_slice(&trimmed[..trimmed_end]);
                    in_header = true;
                }
            }
        }
        start = end + 1;
    }
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// The value of a header, as a string.
///
/// A value that is not UTF-8 has no string form, and such a header is
/// then as if it were not there.
#[cfg(any(feature = "mbox", feature = "eml"))]
fn header_value(headers: &[u8], name: &str) -> Option<String> {
    header_value_bytes(headers, name).and_then(|v| String::from_utf8(v).ok())
}

/// The value of a header, as a string, with the bytes that are not
/// UTF-8 replaced.
///
/// This is the one the facts use: a header that is not UTF-8 still
/// says something, and the replacement character says which part of it
/// did not survive.
#[cfg(any(feature = "mbox", feature = "eml"))]
fn header_value_lossy(headers: &[u8], name: &str) -> Option<String> {
    header_value_bytes(headers, name).map(|v| String::from_utf8_lossy(&v).into_owned())
}

/// True iff `a` and `b` match under ASCII case-folding.
#[cfg(any(feature = "mbox", feature = "eml"))]
fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// Sub-slice contains a needle, case-insensitively (ASCII only).
#[cfg(any(feature = "mbox", feature = "eml"))]
trait AsciiCi {
    fn contains_ascii_ci(&self, needle: &str) -> bool;
}
#[cfg(any(feature = "mbox", feature = "eml"))]
impl AsciiCi for [u8] {
    fn contains_ascii_ci(&self, needle: &str) -> bool {
        let n = needle.as_bytes();
        if n.is_empty() || n.len() > self.len() {
            return n.is_empty();
        }
        let mut i = 0;
        while i + n.len() <= self.len() {
            if ascii_eq_ignore_case(&self[i..i + n.len()], n) {
                return true;
            }
            i += 1;
        }
        false
    }
}

/// memchr-style byte search through `hay` starting at `from`.
#[cfg(any(feature = "mbox", feature = "eml"))]
fn memchr2(needle: u8, hay: &[u8], from: usize) -> Option<usize> {
    rgx_core::memchr::memchr(needle, &hay[from..]).map(|p| p + from)
}

/// minimal quoted-printable decoder (enough for e-mail bodies)
#[cfg(any(feature = "mbox", feature = "eml"))]
fn decode_qp(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'=' if i + 2 < input.len() && input[i + 1] == b'\r' && input[i + 2] == b'\n' => i += 3,
            b'=' if i + 1 < input.len() && input[i + 1] == b'\n' => i += 2,
            b'=' if i + 2 < input.len() => {
                let h = |c: u8| (c as char).to_digit(16);
                match (h(input[i + 1]), h(input[i + 2])) {
                    (Some(a), Some(b)) => {
                        out.push((a * 16 + b) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(b'=');
                        i += 1;
                    }
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Where the headers end: the offset of the blank line that ends them
/// and the length of that line.
///
/// The blank line is `\r\n\r\n` when the message uses CRLF and `\n\n`
/// when it does not, and the first of the two wins -- a message whose
/// headers hold a lone `\n` inside a value is not a message whose
/// headers end there.
#[cfg(any(feature = "mbox", feature = "eml"))]
fn header_end(raw: &[u8]) -> Option<(usize, usize)> {
    find_subslice(raw, b"\r\n\r\n")
        .map(|i| (i, 4))
        .or_else(|| find_subslice(raw, b"\n\n").map(|i| (i, 2)))
}

/// The header block of a message: everything before the blank line.
///
/// A message with no blank line has no body that anyone can tell, and
/// the whole of it is headers as far as the facts are concerned.
#[cfg(any(feature = "mbox", feature = "eml"))]
fn header_block(raw: &[u8]) -> &[u8] {
    match header_end(raw) {
        Some((end, _)) => &raw[..end],
        None => raw,
    }
}

/// The boundary of a multipart `Content-Type`, if it names one.
#[cfg(any(feature = "mbox", feature = "eml"))]
fn boundary_of(content_type: &str) -> Option<String> {
    content_type
        .split(';')
        .skip(1)
        .filter_map(|p| p.trim().strip_prefix("boundary="))
        .map(|b| b.trim_matches('"').to_string())
        .next()
}

/// The filename of a `Content-Disposition`, if it names one.
#[cfg(any(feature = "mbox", feature = "eml"))]
fn filename_of(disposition: &str) -> Option<&str> {
    disposition
        .split(';')
        .skip(1)
        .filter_map(|p| p.trim().strip_prefix("filename="))
        .map(|f| f.trim_matches('"'))
        .next()
}

/// The address of a header value: the addr-spec inside the angle
/// brackets when the header carries one, the value itself otherwise.
///
/// `From: Jane Doe <jane@example.com>` reports `jane@example.com`. A
/// filter asks about the address, and the address is the whole of it:
/// the display name is a name, and a value that stops at the `@`
/// answers a question nobody asked.
#[cfg(any(feature = "mbox", feature = "eml"))]
fn addr_spec(value: &str) -> &str {
    let v = value.trim();
    if let Some(open) = v.find('<') {
        if let Some(close) = v[open..].find('>') {
            return v[open + 1..open + close].trim();
        }
    }
    v
}

/// How many attachments a message has, without decoding them.
///
/// The count is what `parse_message` puts in its attachment list: a
/// MIME part whose `Content-Disposition` says `attachment`, or whose
/// parameters carry a `filename=`. The payloads are not touched, so
/// asking for the facts does not pay for a second base64 pass over
/// them.
///
/// The rules are a copy of `parse_message`'s, and they have to stay in
/// step with it: a fact that says the message has attachments while
/// the adapter extracted none is a fact the user can check and find
/// wrong.
#[cfg(any(feature = "mbox", feature = "eml"))]
fn attachment_count(raw: &[u8]) -> usize {
    let Some((h_end, sep_len)) = header_end(raw) else {
        return 0;
    };
    let hdr = &raw[..h_end];
    let body = &raw[h_end + sep_len..];
    let content_type = header_value(hdr, "content-type").unwrap_or_default();
    let Some(boundary) = boundary_of(&content_type) else {
        return 0;
    };
    let mut delim = Vec::with_capacity(boundary.len() + 2);
    delim.extend_from_slice(b"--");
    delim.extend_from_slice(boundary.as_bytes());
    let mut count = 0usize;
    for part in split_on(body, &delim).skip(1) {
        let part = if part.starts_with(b"\r\n") {
            &part[2..]
        } else if part.starts_with(b"\n") {
            &part[1..]
        } else {
            part
        };
        if part.starts_with(b"--") {
            break;
        }
        let Some((ph_end, _)) = header_end(part) else {
            continue;
        };
        let cd = header_value(&part[..ph_end], "content-disposition").unwrap_or_default();
        if cd.starts_with("attachment") || filename_of(&cd).is_some() {
            count += 1;
        }
    }
    count
}

/// The facts of one message's headers.
///
/// The values are the raw header values, decoded as UTF-8 with the
/// bytes that are not replaced. The crate has no RFC 2047 decoder, so
/// an encoded word (`=?UTF-8?B?...?=`) is reported as it stands and
/// not as the text it stands for: a filter that asks for
/// `mail:subject:"calibration"` still finds the plain subjects, and
/// the encoded ones stay searchable as the text they are.
#[cfg(any(feature = "mbox", feature = "eml"))]
fn header_facts(raw: &[u8], out: &mut Vec<Field>) {
    let hdr = header_block(raw);
    if let Some(from) = header_value_lossy(hdr, "from") {
        let addr = addr_spec(&from);
        if !addr.is_empty() {
            out.push(Field::new("mail.from", addr));
        }
    }
    if let Some(to) = header_value_lossy(hdr, "to") {
        out.push(Field::new("mail.to", &to));
    }
    if let Some(subject) = header_value_lossy(hdr, "subject") {
        out.push(Field::new("mail.subject", &subject));
    }
    if let Some(date) = header_value_lossy(hdr, "date") {
        out.push(Field::new("mail.date", &date));
    }
}

/// The messages of an mbox, as the byte ranges between the `From `
/// lines.
///
/// The first line of the file is the envelope of the first message and
/// belongs to it, and every later `From ` line starts the next
/// message. The ranges are the ones `Mbox::extract` splits on.
#[cfg(feature = "mbox")]
fn mbox_messages(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut pos = 0usize;
    while pos < data.len() {
        let end = memchr2(b'\n', data, pos).unwrap_or(data.len());
        if pos > 0 && data[pos..end].starts_with(b"From ") {
            out.push(&data[start..pos]);
            start = pos;
        }
        pos = end + 1;
    }
    if start < data.len() {
        out.push(&data[start..]);
    }
    out
}

/// Whether the bytes look like an mbox: the first line starts with
/// `From `, as `Mbox::extract` insists.
#[cfg(feature = "mbox")]
fn looks_like_mbox(data: &[u8]) -> bool {
    let end = memchr2(b'\n', data, 0).unwrap_or(data.len());
    data[..end].starts_with(b"From ")
}

/// The `charset` parameter of a `Content-Type` value, if it has one.
///
/// The value arrives case-folded from [`header_value`], which is harmless
/// here: a charset name is ASCII and the lookup is case-insensitive.
#[cfg(any(feature = "mbox", feature = "eml"))]
fn charset_of(content_type: &str) -> Option<&str> {
    content_type
        .split(';')
        .skip(1)
        .filter_map(|p| p.trim().strip_prefix("charset="))
        .map(|c| c.trim().trim_matches('"'))
        .find(|c| !c.is_empty())
}

/// Decode a body in the charset the message declares.
///
/// **Why the declaration is honoured and not ignored.** The bytes of a
/// latin-1 body are not UTF-8, and reading them as UTF-8 does not read
/// them differently -- it *replaces* every byte above 0x7F with U+FFFD.
/// The character is then gone from the answer, and a search for it cannot
/// find it even though the byte is still on the disk. Decoding in the
/// declared charset puts the character back, as the UTF-8 the matcher
/// works in.
///
/// A charset this module cannot decode falls back to the lenient reading,
/// which keeps every byte (as Latin-1) and never loses one.
#[cfg(any(feature = "mbox", feature = "eml"))]
fn decode_text(bytes: &[u8], charset: Option<&str>) -> String {
    let decoded = match charset.and_then(|name| rgx_core::charset::decode_named(name, bytes)) {
        Some(text) => text,
        None => rgx_core::charset::decode_lenient(bytes),
    };
    String::from_utf8(decoded)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// RFC 2047 encoded-words: `=?charset?encoding?text?=`.
///
/// `encoding` is `B` (base64) or `Q` (quoted-printable, with `_` standing
/// for a space). An encoded-word that cannot be read is left exactly as it
/// was: a header that is a little broken is better than a header that is
/// broken differently.
#[cfg(any(feature = "mbox", feature = "eml"))]
fn decode_encoded_words(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    let mut last_end = 0usize;
    let mut prev_encoded = false;
    while i < b.len() {
        if b[i] == b'=' && b.get(i + 1) == Some(&b'?') {
            if let Some((text, end)) = parse_encoded_word(b, i) {
                let gap = &s[last_end..i];
                // RFC 2047 §6.2: the whitespace between two adjacent
                // encoded-words is not part of the text.
                if !(prev_encoded && gap.trim().is_empty()) {
                    out.push_str(gap);
                }
                out.push_str(&text);
                i = end;
                last_end = end;
                prev_encoded = true;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&s[last_end..]);
    out
}

/// One encoded-word at `start`: its decoded text and the offset just past
/// its closing `?=`.
#[cfg(any(feature = "mbox", feature = "eml"))]
fn parse_encoded_word(b: &[u8], start: usize) -> Option<(String, usize)> {
    let rest = b.get(start + 2..)?;
    let charset_end = rest.iter().position(|&c| c == b'?')?;
    let charset = core::str::from_utf8(&rest[..charset_end]).ok()?;
    if charset.is_empty() || charset.contains(' ') {
        return None;
    }
    let enc = *rest.get(charset_end + 1)?;
    if !matches!(enc, b'B' | b'b' | b'Q' | b'q') {
        return None;
    }
    let after = rest.get(charset_end + 3..)?;
    let text_end = find_subslice(after, b"?=")?;
    let raw = &after[..text_end];
    let bytes = match enc {
        b'B' | b'b' => {
            rgx_core::base64::base64_decode_skipping_ws(raw, rgx_core::base64::STANDARD).ok()?
        }
        _ => decode_q_word(raw),
    };
    let text = match rgx_core::charset::decode_named(charset, &bytes) {
        Some(v) => String::from_utf8(v).unwrap_or_default(),
        None => String::from_utf8(rgx_core::charset::decode_lenient(&bytes)).unwrap_or_default(),
    };
    Some((text, start + 2 + charset_end + 3 + text_end + 2))
}

/// RFC 2047's `Q` encoding: `=XX` is a byte and `_` is a space.
///
/// This is not the body's quoted-printable: there are no soft line breaks
/// here, and `_` means something.
#[cfg(any(feature = "mbox", feature = "eml"))]
fn decode_q_word(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'_' => {
                out.push(b' ');
                i += 1;
            }
            b'=' if i + 2 < input.len() => {
                let h = |c: u8| (c as char).to_digit(16);
                match (h(input[i + 1]), h(input[i + 2])) {
                    (Some(a), Some(b)) => {
                        out.push((a * 16 + b) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(b'=');
                        i += 1;
                    }
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// mbox: split on `^From ` lines; each message is its own searchable unit
/// plus its attachments as members.
#[cfg(feature = "mbox")]
pub struct Mbox;
#[cfg(feature = "mbox")]
impl Adapter for Mbox {
    fn name(&self) -> &'static str {
        "mbox"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["mbox", "mbx"]
    }
    /// The facts of the box.
    ///
    /// A box holds many messages, and one `mail.from` for all of them
    /// is a lie the moment two senders share a mailbox. The headers
    /// reported are the first message's -- the box's own convention
    /// for who it is from -- and `mail.messages` says how many there
    /// are, so a filter can ask for a box of one.
    ///
    /// `has.attachments` counts the attachments of the whole box: the
    /// question it answers is whether the file has attachments, and
    /// the file is the box.
    fn facts(&self, data: &[u8], _path: &str) -> Vec<Field> {
        if !looks_like_mbox(data) {
            return Vec::new();
        }
        let messages = mbox_messages(data);
        let Some(first) = messages.first() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        header_facts(first, &mut out);
        out.push(Field::new("mail.messages", &messages.len().to_string()));
        let attachments: usize = messages.iter().map(|m| attachment_count(m)).sum();
        if attachments > 0 {
            out.push(Field::new("has.attachments", &attachments.to_string()));
        }
        out
    }
    fn extract(&self, data: &[u8], path: &str) -> Result<Outcome> {
        // sanity: first line must look like a From_ line
        let first = data
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| &data[..i])
            .unwrap_or(data);
        if !first.starts_with(b"From ") {
            decline!("not an mbox (no 'From ' first line)");
        }
        // **The split is over bytes, not over a decoded string.** The
        // previous shape read the whole file as `from_utf8_lossy` and then
        // split *that*, so every byte above 0x7F in every message was
        // already U+FFFD before a single message was separated -- and no
        // per-message charset could recover it, because the bytes were
        // gone. A latin-1 mbox lost its accented characters here, at the
        // one point where they were still on the disk.
        let mut raws: Vec<Vec<u8>> = Vec::new();
        let mut cur: Vec<u8> = Vec::new();
        let mut started = false;
        let mut start = 0usize;
        while start < data.len() {
            let end = memchr2(b'\n', data, start)
                .map(|i| i + 1)
                .unwrap_or(data.len());
            let line = &data[start..end];
            if line.starts_with(b"From ") && started {
                raws.push(mem::take(&mut cur));
            } else {
                started = true;
            }
            cur.extend_from_slice(line);
            start = end;
        }
        if !cur.is_empty() {
            raws.push(cur);
        }
        if raws.is_empty() {
            bail!("mbox contains no messages");
        }
        let mut text_payload = format!("mbox: {} messages in {path}\n", raws.len());
        for (i, raw) in raws.iter().enumerate() {
            let (msg_text, _attachments) = parse_message(raw);
            // attachments inside mbox messages stay inline (manifest keeps
            // the mbox a single searchable unit); full MIME recursion is
            // available on single .eml files
            let _ = writeln!(text_payload, "--- message-{i}.eml ---\n{msg_text}");
        }
        Ok(Outcome::Text(text_payload.into_bytes()))
    }
}

/// Single .eml message: text + attachments as members.
#[cfg(feature = "eml")]
pub struct Eml;
#[cfg(feature = "eml")]
impl Adapter for Eml {
    fn name(&self) -> &'static str {
        "eml"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["eml"]
    }
    /// The facts of the message: its headers, and whether it carries
    /// attachments.
    ///
    /// `has.attachments` is reported only when the message really has
    /// attachments. A fact that is always there makes `has:attachments`
    /// true of every message, and a question whose answer is always yes
    /// is not a question.
    fn facts(&self, data: &[u8], _path: &str) -> Vec<Field> {
        let mut out = Vec::new();
        header_facts(data, &mut out);
        let attachments = attachment_count(data);
        if attachments > 0 {
            out.push(Field::new("has.attachments", &attachments.to_string()));
        }
        out
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let (text, attachments) = parse_message(data);
        if text.trim().is_empty() && attachments.is_empty() {
            bail!("empty message");
        }
        if attachments.is_empty() {
            return Ok(Outcome::Text(text.into_bytes()));
        }
        let mut members: Vec<(String, Vec<u8>)> = vec![("message.txt".into(), text.into_bytes())];
        for (i, (name, bytes)) in attachments.into_iter().enumerate() {
            members.push((format!("{i}-{name}"), bytes));
        }
        Ok(Outcome::Members(members))
    }
}

#[cfg(all(test, any(feature = "mbox", feature = "eml")))]
mod tests {
    use super::*;

    /// The value of a fact, as the filter looks it up.
    #[cfg(any(feature = "mbox", feature = "eml"))]
    fn fact_of<'a>(facts: &'a [Field], name: &str) -> Option<&'a str> {
        rgx_core::filter::fact(facts, name)
    }

    #[cfg(feature = "eml")]
    #[test]
    fn eml_plain() {
        let raw = b"From: a@b.c\r\nSubject: ZIRCALOY test\r\n\r\nhello body\r\n";
        let e = Eml;
        match e.extract(raw, "x.eml").unwrap() {
            Outcome::Text(t) => {
                let s = String::from_utf8(t).unwrap();
                assert!(s.contains("ZIRCALOY"), "{s}");
                assert!(s.contains("hello body"), "{s}");
            }
            _ => panic!("expected text"),
        }
    }

    #[cfg(feature = "eml")]
    #[test]
    fn eml_attachment_recurse() {
        let b64 = rgx_core::base64::base64_encode(b"PDFDATA");
        let raw = format!(
            "From: a@b.c\r\nSubject: x\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=BB\r\n\r\n\
             --BB\r\nContent-Type: text/plain\r\n\r\nbody here\r\n\
             --BB\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"r.pdf\"\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n{b64}\r\n--BB--\r\n");
        let e = Eml;
        match e.extract(raw.as_bytes(), "x.eml").unwrap() {
            Outcome::Members(m) => {
                assert_eq!(m.len(), 2);
                let att = m.iter().find(|(n, _)| n.contains("r.pdf")).unwrap();
                assert_eq!(att.1, b"PDFDATA");
            }
            _ => panic!("expected members"),
        }
    }

    #[cfg(feature = "mbox")]
    #[test]
    fn mbox_split() {
        let raw = b"From alice@x Tue Jan  1 00:00:00 2024\nSubject: one\n\nbody1\nFrom bob@x Tue Jan  2 00:00:00 2024\nSubject: two\n\nbody2\n";
        let m = Mbox;
        match m.extract(raw, "a.mbox").unwrap() {
            Outcome::Text(t) => {
                let s = String::from_utf8(t).unwrap();
                assert!(s.contains("mbox: 2 messages"), "{s}");
                assert!(s.contains("body1"), "{s}");
                assert!(s.contains("body2"), "{s}");
            }
            _ => panic!("expected text"),
        }
    }

    #[cfg(feature = "eml")]
    #[test]
    fn eml_facts_report_the_headers() {
        let raw = b"From: admin@example.com\r\nTo: team@example.com\r\n\
                    Subject: calibration run\r\nDate: Tue, 1 Jan 2024 00:00:00 +0000\r\n\
                    \r\nbody\r\n";
        let facts = Eml.facts(raw, "x.eml");
        let from = fact_of(&facts, "mail.from");
        assert!(from == Some("admin@example.com"), "mail.from = {from:?}");
        let to = fact_of(&facts, "mail.to");
        assert!(to == Some("team@example.com"), "mail.to = {to:?}");
        let subject = fact_of(&facts, "mail.subject");
        assert!(
            subject == Some("calibration run"),
            "mail.subject = {subject:?}"
        );
        let date = fact_of(&facts, "mail.date");
        assert!(
            date == Some("Tue, 1 Jan 2024 00:00:00 +0000"),
            "mail.date = {date:?}"
        );
    }

    #[cfg(feature = "eml")]
    #[test]
    fn eml_facts_report_the_whole_address() {
        // The address is the whole of it: a value that stopped at the
        // `@` would answer `mail:from:"admin"` for every message from
        // any domain.
        let raw = b"From: Jane Doe <admin@example.com>\r\nSubject: x\r\n\r\nbody\r\n";
        let facts = Eml.facts(raw, "x.eml");
        let from = fact_of(&facts, "mail.from");
        assert!(from == Some("admin@example.com"), "mail.from = {from:?}");
    }

    #[cfg(feature = "eml")]
    #[test]
    fn eml_facts_report_attachments_only_when_there_are_them() {
        let plain = b"From: admin@example.com\r\nSubject: x\r\n\r\nbody\r\n";
        let facts = Eml.facts(plain, "x.eml");
        let att = fact_of(&facts, "has.attachments");
        assert!(att.is_none(), "has.attachments = {att:?}");
        let ask = |text: &str| {
            rgx_core::filter::Filter::parse(text)
                .expect("the filter parses")
                .matches(&facts)
        };
        assert!(
            !ask("has:attachments"),
            "has:attachments on a plain message"
        );

        let b64 = rgx_core::base64::base64_encode(b"PDFDATA");
        let raw = format!(
            "From: admin@example.com\r\nSubject: x\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=BB\r\n\r\n\
             --BB\r\nContent-Type: text/plain\r\n\r\nbody here\r\n\
             --BB\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"r.pdf\"\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n{b64}\r\n--BB--\r\n");
        let facts = Eml.facts(raw.as_bytes(), "x.eml");
        let att = fact_of(&facts, "has.attachments");
        assert!(att == Some("1"), "has.attachments = {att:?}");
    }

    #[cfg(feature = "eml")]
    #[test]
    fn the_facts_answer_the_filters_that_ask_for_them() {
        let b64 = rgx_core::base64::base64_encode(b"PDFDATA");
        let raw = format!(
            "From: Jane Doe <admin@example.com>\r\nTo: team@example.com\r\n\
             Subject: calibration run\r\nDate: Tue, 1 Jan 2024 00:00:00 +0000\r\n\
             MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=BB\r\n\r\n\
             --BB\r\nContent-Type: text/plain\r\n\r\nbody here\r\n\
             --BB\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"r.pdf\"\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n{b64}\r\n--BB--\r\n");
        let facts = Eml.facts(raw.as_bytes(), "x.eml");
        let ask = |text: &str| {
            rgx_core::filter::Filter::parse(text)
                .expect("the filter parses")
                .matches(&facts)
        };
        assert!(ask("mail:from:\"admin@example.com\""), "mail:from");
        // The value is the whole address, so the domain is in it too.
        assert!(ask("mail:from:\"example.com\""), "mail:from by domain");
        assert!(ask("mail:to:\"team@example.com\""), "mail:to");
        assert!(ask("mail:subject:\"calibration\""), "mail:subject");
        assert!(ask("has:attachments"), "has:attachments");
    }

    #[cfg(feature = "mbox")]
    #[test]
    fn mbox_facts_report_the_first_message_and_the_count() {
        let raw = b"From alice@x Tue Jan  1 00:00:00 2024\n\
                    From: alice@example.com\r\nTo: team@example.com\r\nSubject: one\r\n\
                    Date: Tue, 1 Jan 2024 00:00:00 +0000\r\n\r\nbody1\n\
                    From bob@x Tue Jan  2 00:00:00 2024\n\
                    From: bob@example.com\r\nSubject: two\r\n\r\nbody2\n";
        let facts = Mbox.facts(raw, "a.mbox");
        // The first message's headers: the box has two senders, and one
        // `mail.from` for both of them would be a lie.
        let from = fact_of(&facts, "mail.from");
        assert!(from == Some("alice@example.com"), "mail.from = {from:?}");
        let subject = fact_of(&facts, "mail.subject");
        assert!(subject == Some("one"), "mail.subject = {subject:?}");
        let count = fact_of(&facts, "mail.messages");
        assert!(count == Some("2"), "mail.messages = {count:?}");
    }

    /// A body that declares its charset is decoded in it.
    ///
    /// The bug this holds down: the body was read as UTF-8 whatever it
    /// said, so a latin-1 `0xE9` became U+FFFD and the character was gone
    /// from the answer -- a search for "café" could not find it even
    /// though the byte was in the file.
    #[cfg(any(feature = "mbox", feature = "eml"))]
    #[test]
    fn a_declared_charset_is_honoured() {
        let mut raw =
            b"From: a@b.c\r\nContent-Type: text/plain; charset=ISO-8859-1\r\n\r\n".to_vec();
        raw.extend_from_slice(b"caf\xe9\r\n");
        let (text, _) = parse_message(&raw);
        assert!(text.contains("café"), "{text}");
        assert!(!text.contains('\u{FFFD}'), "a byte became U+FFFD: {text}");
    }

    /// A body that declares no charset still keeps its bytes.
    ///
    /// The lenient reading is Latin-1, which maps every byte to the
    /// codepoint of the same value, so nothing is replaced.
    #[cfg(any(feature = "mbox", feature = "eml"))]
    #[test]
    fn an_undeclared_charset_keeps_every_byte() {
        let mut raw = b"From: a@b.c\r\n\r\n".to_vec();
        raw.extend_from_slice(b"caf\xe9\r\n");
        let (text, _) = parse_message(&raw);
        assert!(text.contains("café"), "{text}");
        assert!(!text.contains('\u{FFFD}'), "a byte became U+FFFD: {text}");
    }

    /// The mbox split must not decode the file before it separates the
    /// messages: a latin-1 message was losing its high bytes at the split,
    /// where no per-message charset could get them back.
    #[cfg(feature = "mbox")]
    #[test]
    fn an_mbox_keeps_the_bytes_of_every_message() {
        let mut raw = b"From alice@x Tue Jan  1 00:00:00 2024\nSubject: one\n\nbody1\n".to_vec();
        raw.extend_from_slice(b"From bob@x Tue Jan  2 00:00:00 2024\nSubject: two\n");
        raw.extend_from_slice(b"Content-Type: text/plain; charset=ISO-8859-1\r\n\r\ncaf\xe9\n");
        let out = match Mbox.extract(&raw, "a.mbox").unwrap() {
            Outcome::Text(t) => String::from_utf8(t).unwrap(),
            _ => panic!("expected text"),
        };
        assert!(out.contains("café"), "{out}");
        assert!(!out.contains('\u{FFFD}'), "a byte became U+FFFD: {out}");
    }

    /// An RFC 2047 encoded-word is decoded: the subject is the most
    /// valuable line in a message and, undecoded, it is a base64 blob.
    #[cfg(any(feature = "mbox", feature = "eml"))]
    #[test]
    fn an_rfc2047_header_is_decoded() {
        // "=?UTF-8?B?...?=" over "Relatório Final"
        let raw = b"From: a@b.c\r\nSubject: =?UTF-8?B?UmVsYXTDs3JpbyBGaW5hbA==?=\r\n\r\nbody\r\n";
        let (text, _) = parse_message(raw);
        assert!(text.contains("Relatório Final"), "{text}");
        assert!(
            !text.contains("=?UTF-8?"),
            "the encoded-word survived: {text}"
        );
    }

    /// The `Q` form, where `_` stands for a space.
    #[cfg(any(feature = "mbox", feature = "eml"))]
    #[test]
    fn an_rfc2047_q_header_is_decoded() {
        let raw = b"From: a@b.c\r\nSubject: =?ISO-8859-1?Q?caf=E9?=\r\n\r\nbody\r\n";
        let (text, _) = parse_message(raw);
        assert!(text.contains("café"), "{text}");
    }

    /// RFC 2047 §6.2: the whitespace between two adjacent encoded-words is
    /// not part of the text.
    #[cfg(any(feature = "mbox", feature = "eml"))]
    #[test]
    fn whitespace_between_adjacent_encoded_words_is_dropped() {
        let raw = b"From: a@b.c\r\nSubject: =?UTF-8?B?UmVsYXTDs3JpbyA=?= =?UTF-8?B?RmluYWw=?=\r\n\r\nbody\r\n";
        let (text, _) = parse_message(raw);
        assert!(text.contains("Relatório Final"), "{text}");
    }

    /// An encoded-word that cannot be read is left exactly as it was: a
    /// header that is a little broken is better than a header that is
    /// broken differently.
    #[cfg(any(feature = "mbox", feature = "eml"))]
    #[test]
    fn an_unreadable_encoded_word_is_left_alone() {
        let raw = b"From: a@b.c\r\nSubject: =?UTF-8?X?not-a-thing?=\r\n\r\nbody\r\n";
        let (text, _) = parse_message(raw);
        assert!(text.contains("=?UTF-8?X?not-a-thing?="), "{text}");
    }

    #[cfg(any(feature = "mbox", feature = "eml"))]
    mod fuzz {
        use super::*;

        #[cfg(feature = "eml")]
        #[test]
        fn eml_never_panics_on_mutation() {
            let raw = b"From: a@b.c\r\nSubject: ZIRCALOY test\r\nMIME-Version: 1.0\r\n\
                        Content-Type: multipart/mixed; boundary=BB\r\n\r\n\
                        --BB\r\nContent-Type: text/plain\r\n\r\nbody\r\n--BB--\r\n"
                .to_vec();
            rgx_core::fuzzkit::assert_never_panics(
                vec![("multipart", raw), ("empty", vec![])],
                1000,
                "eml",
                |data| {
                    let _ = Eml.extract(data, "fuzz.eml");
                },
            );
        }

        #[cfg(feature = "mbox")]
        #[test]
        fn mbox_never_panics_on_mutation() {
            let raw = b"From alice@x Tue Jan  1 00:00:00 2024\nSubject: one\n\nbody1\n".to_vec();
            rgx_core::fuzzkit::assert_never_panics(
                vec![("mbox", raw), ("empty", vec![])],
                800,
                "mbox",
                |data| {
                    let _ = Mbox.extract(data, "fuzz.mbox");
                },
            );
        }

        #[cfg(all(feature = "mbox", feature = "eml"))]
        #[test]
        fn the_facts_never_panic_on_mutation() {
            let eml = b"From: a@b.c\r\nSubject: ZIRCALOY test\r\nMIME-Version: 1.0\r\n\
                        Content-Type: multipart/mixed; boundary=BB\r\n\r\n\
                        --BB\r\nContent-Type: text/plain\r\n\r\nbody\r\n--BB--\r\n"
                .to_vec();
            let mbox =
                b"From alice@x Tue Jan  1 00:00:00 2024\nFrom: a@b.c\nSubject: one\n\nbody1\n"
                    .to_vec();
            rgx_core::fuzzkit::assert_never_panics(
                vec![("eml", eml), ("mbox", mbox), ("empty", vec![])],
                1000,
                "mail-facts",
                |data| {
                    let _ = Eml.facts(data, "fuzz.eml");
                    let _ = Mbox.facts(data, "fuzz.mbox");
                },
            );
        }
    }
}
