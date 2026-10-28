// SPDX-License-Identifier: Apache-2.0

//! Lightweight-markup → text: reStructuredText, org-mode, MediaWiki
//! wikitext, Jupyter notebooks, Textile and troff/groff man pages.
//! Everything pandoc used to cover in-process for grep's sake.
//!
//! A reduced port of the markup readers of the `io` project by Dan Gohman,
//! whose work is used here under Apache-2.0: the structured blocks, outlines
//! and typed errors of `rst`, `org`, `mediawiki`, `ipynb`, `textile` and
//! `man` are the upstream's, and these siblings carry only the flat-text
//! flattening. See `NOTICE`.

use alloc::string::String;
#[allow(unused_imports)]
use alloc::vec::Vec;
use core::str;
use rgx_core::{decline, Result};
use rgx_core::{Adapter, Outcome, Reach};

pub struct Markup;
impl Adapter for Markup {
    fn name(&self) -> &'static str {
        "markup"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &[
            "rst",
            "org",
            "mediawiki",
            "wiki",
            "ipynb",
            "textile",
            "man",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            "md",
            "markdown",
            "gfm",
            "html",
            "htm",
            "xhtml",
            "t2t",
            "fb2",
        ]
    }
    /// Every extension here is plain text that ripgrep reads as it
    /// stands, and every one of these extractors is lossy on it: the
    /// HTML arm drops `<script>`, `<style>` and `<head>` bodies, the
    /// Markdown arm drops front matter, link targets and inline HTML,
    /// the RST arm drops comments and directives. Declaring the reach
    /// keeps the file's own bytes the default answer and leaves this
    /// code reachable under `RGX_ADAPTER_VIEW=render` / `=both`.
    fn reach(&self) -> Reach {
        Reach::Render
    }
    fn extract(&self, data: &[u8], path: &str) -> Result<Outcome> {
        let ext = rgx_core::extension_of(path);
        let text = match &*ext {
            "rst" => rst::extract_text(data),
            "org" => org::extract_text(data),
            "mediawiki" | "wiki" => mediawiki::extract_text(data),
            "ipynb" => ipynb::extract_text(data),
            "textile" => textile::extract_text(data),
            // man pages: .man or numbered sections (.1 … .9)
            "man" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" => man::extract_text(data),
            "md" | "markdown" | "gfm" => markdown::extract_text(data),
            "html" | "htm" | "xhtml" => html::extract_text(data),
            "t2t" => t2t::extract_text(data),
            "fb2" => fb2::extract_text(data),
            _ => decline!("unsupported markup extension: {ext}"),
        };
        let Some(text) = text else {
            decline!("no readable text in {path}")
        };
        Ok(Outcome::Text(text.into_bytes()))
    }
}

/// Collapse runs of blank lines to at most one, trim trailing whitespace.
fn tidy(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut blank = 0usize;
    for line in text.lines() {
        let line = line.trim_end();
        if line.trim().is_empty() {
            blank += 1;
            if blank <= 1 {
                out.push('\n');
            }
            continue;
        }
        blank = 0;
        out.push_str(line);
        out.push('\n');
    }
    // Trimming in place, at both ends: `out.trim().to_string()` copied
    // the whole text a second time right after the buffer was filled
    // once, which on a 50 MB markdown is another 50 MB at the peak, for
    // every one of the eight formats that come through here.
    let lead = out.len() - out.trim_start().len();
    if lead > 0 {
        out.drain(..lead);
    }
    let tail = out.trim_end().len();
    if tail != out.len() {
        out.truncate(tail);
    }
    out
}

// ---------------------------------------------------------------------------
// declared charset
// ---------------------------------------------------------------------------

/// How far into a document the declaration is looked for.
///
/// The HTML5 specification asks for the `<meta charset>` in the first 1024
/// bytes, and the XML prolog is at the very start. 4096 is generous enough
/// for a page with a long comment before its head and short enough that a
/// `charset=` in the body text is not mistaken for a declaration.
const CHARSET_SNIFF_LEN: usize = 4096;

/// The charset a document declares, if it declares one.
///
/// An HTML document says it in `<meta charset="...">` (or in the older
/// `http-equiv` form, where the charset is a parameter of the `content`
/// attribute); an XML document says it in the prolog
/// (`<?xml version="1.0" encoding="..."?>`).
///
/// **Why the declaration is read.** A document that says what its bytes
/// mean and is read as UTF-8 anyway does not get read differently -- it
/// gets *changed*: every byte above 0x7F becomes U+FFFD, the character is
/// gone from the rendering, and a search for it cannot find it. The
/// declaration is the one place the file is allowed to say what it wants.
fn declared_charset(data: &[u8]) -> Option<String> {
    let head = &data[..data.len().min(CHARSET_SNIFF_LEN)];

    // The XML prolog comes first: an XHTML document has one, and it is
    // the authoritative statement.
    if let Some(p) = find_ci(head, 0, b"<?xml") {
        if let Some(v) = attr_value(&head[p..], b"encoding") {
            return Some(v);
        }
    }

    let mut from = 0usize;
    while let Some(p) = find_ci(head, from, b"<meta") {
        let rest = &head[p..];
        let end = crate::find_sub(rest, 0, b">").unwrap_or(rest.len());
        let tag = &rest[..end];
        if let Some(v) = attr_value(tag, b"charset") {
            if !v.is_empty() {
                return Some(v);
            }
        }
        // The older spelling: <meta http-equiv="content-type"
        // content="text/html; charset=iso-8859-1">
        if let Some(content) = attr_value(tag, b"content") {
            if let Some(cs) = find_ci(content.as_bytes(), 0, b"charset=") {
                let v = take_value(&content.as_bytes()[cs + 8..]);
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
        from = p + 5;
        if from >= head.len() {
            break;
        }
    }
    None
}

/// A case-insensitive byte search.
fn find_ci(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || from > hay.len() {
        return None;
    }
    let last = hay.len().checked_sub(needle.len())?;
    let mut i = from;
    while i <= last {
        if hay[i..i + needle.len()]
            .iter()
            .zip(needle)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// The value of an attribute in a tag, if the tag has one.
///
/// The name is matched case-insensitively (HTML attribute names are not
/// case-sensitive) and the value may be quoted with `"` or `'` or bare.
fn attr_value(tag: &[u8], name: &[u8]) -> Option<String> {
    let p = find_ci(tag, 0, name)?;
    let mut i = p + name.len();
    // The name must be a whole attribute: `charset` must not match the
    // tail of `xcharset`.
    if i < tag.len() && (tag[i].is_ascii_alphanumeric() || tag[i] == b'-' || tag[i] == b'_') {
        return None;
    }
    while i < tag.len() && (tag[i] as char).is_whitespace() {
        i += 1;
    }
    if i >= tag.len() || tag[i] != b'=' {
        return None;
    }
    i += 1;
    while i < tag.len() && (tag[i] as char).is_whitespace() {
        i += 1;
    }
    if i >= tag.len() {
        return None;
    }
    let value = if tag[i] == b'"' || tag[i] == b'\'' {
        let quote = tag[i];
        i += 1;
        let start = i;
        while i < tag.len() && tag[i] != quote {
            i += 1;
        }
        &tag[start..i]
    } else {
        let start = i;
        while i < tag.len() && !(tag[i] as char).is_whitespace() && tag[i] != b';' && tag[i] != b'>'
        {
            i += 1;
        }
        &tag[start..i]
    };
    Some(String::from_utf8_lossy(value).into_owned())
}

/// An unquoted attribute value, up to the first space or delimiter.
fn take_value(rest: &[u8]) -> String {
    let end = rest
        .iter()
        .position(|&c| {
            (c as char).is_whitespace() || c == b';' || c == b'>' || c == b'"' || c == b'\''
        })
        .unwrap_or(rest.len());
    String::from_utf8_lossy(&rest[..end]).into_owned()
}

/// Decode a document in the charset it declares.
///
/// A document that declares nothing is left as it is: the caller's own
/// reading applies, and for a text format that is "valid UTF-8, and the
/// invalid bytes marked". Only a document that *says* what its bytes mean
/// is read in that encoding.
fn decode_declared(data: &[u8]) -> Option<Vec<u8>> {
    let cs = declared_charset(data)?;
    rgx_core::charset::decode_named(&cs, data)
}

// ---------------------------------------------------------------------------
// rst
// ---------------------------------------------------------------------------

mod rst {
    use super::{super::find_sub, tidy};
    #[allow(unused_imports)]
    use alloc::string::{String, ToString};
    #[allow(unused_imports)]
    use alloc::vec::Vec;

    pub fn extract_text(data: &[u8]) -> Option<String> {
        let src = String::from_utf8_lossy(data);
        let lines: Vec<&str> = src.lines().collect();
        let mut text = String::new();
        let mut i = 0usize;
        while i < lines.len() {
            let line = lines[i];
            let trimmed = line.trim();
            if trimmed.is_empty() {
                i += 1;
                continue;
            }
            // section title: title + underline (or overline + title + underline)
            if is_adornment(trimmed) {
                i += 1; // also covers transitions (---- alone)
                continue;
            }
            if i + 1 < lines.len() && is_adornment(lines[i + 1].trim()) {
                push(&mut text, inline(trimmed));
                i += 2;
                continue;
            }
            if i + 2 < lines.len()
                && !lines[i + 1].trim().is_empty()
                && is_adornment(lines[i + 2].trim())
            {
                push(&mut text, inline(lines[i + 1].trim()));
                i += 3;
                continue;
            }
            // comment / footnote / citation / directive
            if let Some(rest) = trimmed.strip_prefix(".. ") {
                if let Some(pos) = rest.find("::") {
                    let args = rest[pos + 2..].trim();
                    if !args.is_empty() && !is_target(rest) {
                        push(&mut text, inline(args));
                    }
                    i += 1;
                    while i < lines.len()
                        && (lines[i].starts_with(' ') || lines[i].starts_with('\t'))
                        && !lines[i].trim().is_empty()
                    {
                        i += 1;
                    }
                    continue;
                }
                i += 1;
                continue;
            }
            // list item
            if let Some(item) = list_marker(trimmed) {
                push(&mut text, inline(item));
                i += 1;
                continue;
            }
            // literal block: paragraph ends with ::, body is indented
            if trimmed.ends_with("::") && i + 1 < lines.len() {
                let lead = trimmed.strip_suffix("::").unwrap().trim();
                if !lead.is_empty() {
                    push(&mut text, inline(lead));
                }
                let mut j = i + 1;
                let mut block = String::new();
                let mut min_indent: Option<usize> = None;
                while j < lines.len() && !lines[j].trim().is_empty() {
                    if let Some(p) = lines[j].find(|c: char| !c.is_whitespace()) {
                        min_indent = Some(min_indent.map_or(p, |m: usize| m.min(p)));
                        block.push_str(lines[j]);
                        block.push('\n');
                    }
                    j += 1;
                }
                if !block.is_empty() {
                    let m = min_indent.unwrap_or(0);
                    let dedented: Vec<&str> =
                        block.lines().map(|l| l.get(m..).unwrap_or(l)).collect();
                    push(&mut text, dedented.join("\n"));
                }
                i = j.max(i + 1);
                continue;
            }
            // plain paragraph: join until blank
            let mut para = String::new();
            let start = i;
            while i < lines.len() && !lines[i].trim().is_empty() {
                if i > start
                    && (is_adornment(lines[i].trim()) || list_marker(lines[i].trim()).is_some())
                {
                    break;
                }
                if !para.is_empty() {
                    para.push(' ');
                }
                para.push_str(lines[i].trim());
                i += 1;
            }
            push(&mut text, inline(&para));
        }
        let text = tidy(&text);
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }

    fn push(text: &mut String, s: String) {
        if !s.trim().is_empty() {
            text.push_str(&s);
            text.push('\n');
        }
    }

    fn is_adornment(s: &str) -> bool {
        let bytes = s.as_bytes();
        bytes.len() >= 3
            && matches!(
                bytes[0],
                b'=' | b'-' | b'~' | b'^' | b'"' | b'\'' | b'_' | b'*' | b'+' | b'#' | b'<'
            )
            && bytes[1..].iter().all(|&b| b == bytes[0])
    }

    fn list_marker(s: &str) -> Option<&str> {
        let bytes = s.as_bytes();
        if bytes.len() >= 2 && matches!(bytes[0], b'-' | b'*' | b'+') && bytes[1] == b' ' {
            return Some(s[2..].trim());
        }
        let digit_end = s.find(|c: char| !c.is_ascii_alphanumeric())?;
        let marker = &s[..digit_end];
        if marker.is_empty() {
            return None;
        }
        let rest = &s[digit_end..];
        if (rest.starts_with(". ") || rest.starts_with(") "))
            && marker.chars().all(|c| c.is_ascii_alphanumeric())
        {
            return Some(s[digit_end + 2..].trim());
        }
        None
    }

    fn is_target(rest: &str) -> bool {
        rest.starts_with('_') && rest.ends_with(':')
    }

    fn inline(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let b = s.as_bytes();
        let mut i = 0usize;
        while i < b.len() {
            if b[i..].starts_with(b"``") {
                if let Some(e) = find_sub(b, i + 2, b"``") {
                    out.push_str(&s[i + 2..e]);
                    i = e + 2;
                    continue;
                }
            }
            if b[i..].starts_with(b"**") {
                if let Some(e) = find_sub(b, i + 2, b"**") {
                    out.push_str(&s[i + 2..e]);
                    i = e + 2;
                    continue;
                }
            }
            match b[i] {
                b'*' | b'|' => {
                    let close = b[i];
                    if let Some(p) = find_sub(b, i + 1, &[close]) {
                        let inner = &s[i + 1..p];
                        if !inner.is_empty() && !inner.contains(char::is_whitespace)
                            || inner.len() > 1
                        {
                            out.push_str(inner);
                            i = p + 1;
                            continue;
                        }
                    }
                    out.push(close as char);
                    i += 1;
                }
                b'`' => {
                    if let Some(p) = find_sub(b, i + 1, b"`") {
                        let inner = &s[i + 1..p];
                        let (text, _url) = match inner.rfind(" <") {
                            Some(k) if inner.ends_with('>') => {
                                (&inner[..k], Some(inner[k + 2..inner.len() - 1].to_string()))
                            }
                            _ => (inner, None),
                        };
                        out.push_str(text);
                        i = p + 1;
                        if b.get(i) == Some(&b'_') {
                            i += 1;
                        }
                        continue;
                    }
                    out.push('`');
                    i += 1;
                }
                b'\\' if i + 1 < b.len() => {
                    // char-aware: `i += 1 + len` never lands mid-codepoint
                    let ch = s[i + 1..].chars().next().unwrap_or(' ');
                    out.push(ch);
                    i += 1 + ch.len_utf8();
                }
                _ => {
                    let next = b[i..]
                        .iter()
                        .position(|&c| matches!(c, b'*' | b'`' | b'|' | b'\\'))
                        .map(|p| p + i)
                        .unwrap_or(b.len());
                    if next == i {
                        // terminator byte no earlier arm consumed: emit it
                        let ch = s[i..].chars().next().unwrap_or(' ');
                        out.push(ch);
                        i += ch.len_utf8();
                    } else {
                        out.push_str(&s[i..next]);
                        i = next;
                    }
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// org
// ---------------------------------------------------------------------------

mod org {
    use super::{super::find_sub, tidy};
    #[allow(unused_imports)]
    use alloc::string::{String, ToString};
    #[allow(unused_imports)]
    use alloc::vec::Vec;

    pub fn extract_text(data: &[u8]) -> Option<String> {
        let src = String::from_utf8_lossy(data);
        let mut text = String::new();
        let mut in_block = false;
        let mut in_drawer = false;
        let mut last_was_headline = false;

        for raw in src.lines() {
            let line = raw.trim_end();
            let trimmed = line.trim();

            if trimmed.starts_with("#+BEGIN_") || trimmed.starts_with("#+begin_") {
                in_block = true;
                continue;
            }
            if trimmed.to_uppercase().starts_with("#+END_") {
                in_block = false;
                text.push('\n');
                continue;
            }
            if in_block {
                text.push_str(line);
                text.push('\n');
                continue;
            }

            if trimmed.starts_with(':') && trimmed.ends_with(':') && trimmed.len() > 2 {
                in_drawer = true;
                continue;
            }
            if trimmed.eq_ignore_ascii_case(":END:") {
                in_drawer = false;
                continue;
            }
            if in_drawer {
                continue;
            }

            if trimmed.is_empty() {
                if !last_was_headline {
                    text.push('\n');
                }
                last_was_headline = false;
                continue;
            }
            if trimmed.starts_with("# ") {
                continue;
            }
            if trimmed.len() > 2 && trimmed.starts_with("#+") {
                let body = &trimmed[2..];
                if let Some(colon) = body.find(':') {
                    let key = body[..colon].trim().to_uppercase();
                    let value = body[colon + 1..].trim();
                    if !value.is_empty() {
                        text.push_str(&key.to_lowercase());
                        text.push_str(": ");
                        text.push_str(&inline(value));
                        text.push('\n');
                    }
                }
                continue;
            }
            if trimmed.starts_with('*') {
                let stars = trimmed.bytes().take_while(|&b| b == b'*').count();
                let rest = trimmed[stars..].trim();
                if !rest.is_empty() && stars <= 10 {
                    let title = strip_tags(&strip_todo(rest));
                    text.push('\n');
                    text.push_str(&inline(&title));
                    text.push('\n');
                    last_was_headline = true;
                    continue;
                }
            }
            if let Some(item) = list_text(trimmed) {
                text.push_str(&inline(item));
                text.push('\n');
                continue;
            }
            text.push_str(&inline(trimmed));
            text.push('\n');
        }
        let text = tidy(&text);
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }

    /// Drop a leading TODO/DONE keyword, keep the rest of the title.
    fn strip_todo(rest: &str) -> String {
        let mut words = rest.split_whitespace();
        let first = words.next().unwrap_or("");
        let is_todo = first.chars().all(|c| c.is_ascii_uppercase())
            && !first.contains(char::is_whitespace)
            && (first == "TODO"
                || first == "DONE"
                || first.contains('[')
                || first
                    .chars()
                    .filter(|c| c.is_ascii_uppercase() || *c == '-')
                    .count()
                    == first.len());
        if is_todo {
            words.collect::<Vec<_>>().join(" ")
        } else {
            rest.to_string()
        }
    }

    /// `:tag1:tag2:` trailing tags come off the title.
    fn strip_tags(title: &str) -> String {
        if title.ends_with(':') {
            if let Some(start) = title.rfind(" :") {
                // `get` guards "a :"-shaped titles where the range inverts
                if let Some(blob) = title.get(start + 2..title.len() - 1) {
                    if !blob.is_empty()
                        && blob.bytes().all(|b| {
                            b == b':'
                                || b.is_ascii_alphanumeric()
                                || b == b'_'
                                || b == b'@'
                                || b == b'#'
                        })
                    {
                        return title[..start].to_string();
                    }
                }
            }
        }
        title.to_string()
    }

    fn list_text(s: &str) -> Option<&str> {
        let b = s.as_bytes();
        if b.len() >= 2 && matches!(b[0], b'-' | b'+') && b[1] == b' ' {
            return Some(s[2..].trim());
        }
        let digit_end = s.find(|c: char| !c.is_ascii_digit())?;
        if digit_end == 0 {
            return None;
        }
        let rest = &s[digit_end..];
        if (rest.starts_with(". ") || rest.starts_with(") "))
            && s[..digit_end].chars().all(|c| c.is_ascii_digit())
        {
            return Some(s[digit_end + 2..].trim());
        }
        None
    }

    fn inline(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let b = s.as_bytes();
        let mut i = 0usize;
        while i < b.len() {
            if b[i..].starts_with(b"[[") {
                if let Some(end) = find_sub(b, i + 2, b"]]") {
                    let inner = &s[i + 2..end];
                    let (_url, desc) = match inner.find("][") {
                        Some(k) => (&inner[..k], &inner[k + 2..]),
                        None => (inner, inner),
                    };
                    out.push_str(desc);
                    i = end + 2;
                    continue;
                }
            }
            match b[i] {
                b'*' | b'/' | b'_' | b'=' | b'~' => {
                    let close = b[i];
                    if let Some(p) = find_sub(b, i + 1, &[close]) {
                        let inner = &s[i + 1..p];
                        if !inner.is_empty() && !inner.starts_with(' ') && !inner.ends_with(' ') {
                            out.push_str(inner);
                            i = p + 1;
                            continue;
                        }
                    }
                    out.push(close as char);
                    i += 1;
                }
                b'\\' if i + 1 < b.len() => {
                    // char-aware: `i += 1 + len` never lands mid-codepoint
                    let ch = s[i + 1..].chars().next().unwrap_or(' ');
                    out.push(ch);
                    i += 1 + ch.len_utf8();
                }
                _ => {
                    let next = b[i..]
                        .iter()
                        .position(|&c| matches!(c, b'*' | b'/' | b'_' | b'=' | b'~' | b'\\' | b'['))
                        .map(|p| p + i)
                        .unwrap_or(b.len());
                    if next == i {
                        // a lone `[` (not `[[`) or stray terminator: emit it
                        let ch = s[i..].chars().next().unwrap_or(' ');
                        out.push(ch);
                        i += ch.len_utf8();
                    } else {
                        out.push_str(&s[i..next]);
                        i = next;
                    }
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// mediawiki
// ---------------------------------------------------------------------------

mod mediawiki {
    use super::{super::find_sub, tidy};
    #[allow(unused_imports)]
    use alloc::string::{String, ToString};
    #[allow(unused_imports)]
    use alloc::vec::Vec;

    pub fn extract_text(data: &[u8]) -> Option<String> {
        let src = String::from_utf8_lossy(data);
        let mut text = String::new();
        let mut in_table = false;
        let mut in_template = 0usize;

        for raw in src.lines() {
            let line = raw.trim();
            if line.is_empty() {
                if !in_table {
                    text.push('\n');
                }
                continue;
            }
            if in_template > 0 {
                in_template = template_balance(line, in_template);
                continue;
            }
            if line.starts_with("{{") {
                in_template = template_balance(line, 0);
                continue;
            }
            if line.starts_with("{|") {
                in_table = true;
                continue;
            }
            if line.starts_with("|}") {
                in_table = false;
                text.push('\n');
                continue;
            }
            if in_table {
                if line.starts_with("|-") {
                    text.push('\n');
                    continue;
                }
                let cells = line
                    .trim_start_matches(['|', '!'])
                    .split("||")
                    .flat_map(|c| c.split("!!"))
                    .map(|c| inline(c.trim_start_matches('|').trim()));
                let row: Vec<String> = cells.collect();
                if !row.is_empty() {
                    text.push_str(&row.join(" | "));
                    text.push('\n');
                }
                continue;
            }
            if line.starts_with('=') {
                let eq = line.bytes().take_while(|&b| b == b'=').count();
                let tail = &line[eq..];
                if tail.len() >= eq && tail.ends_with(&"=".repeat(eq)) && (1..=6).contains(&eq) {
                    let title = inline(tail[..tail.len() - eq].trim());
                    if !title.is_empty() {
                        text.push('\n');
                        text.push_str(&title);
                        text.push('\n');
                    }
                    continue;
                }
            }
            if let Some(stripped) = strip_list_marks(line) {
                let t = inline(stripped.trim());
                if !t.is_empty() {
                    text.push_str(&t);
                    text.push('\n');
                }
                continue;
            }
            let t = inline(line);
            if !t.is_empty() {
                text.push_str(&t);
                text.push('\n');
            }
        }
        let text = tidy(&text);
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }

    fn template_balance(line: &str, mut depth: usize) -> usize {
        let b = line.as_bytes();
        let mut i = 0usize;
        while i + 1 < b.len() {
            if b[i..].starts_with(b"{{") {
                depth += 1;
                i += 2;
            } else if b[i..].starts_with(b"}}") {
                depth = depth.saturating_sub(1);
                i += 2;
                if depth == 0 {
                    return 0;
                }
            } else {
                i += 1;
            }
        }
        depth
    }

    fn strip_list_marks(line: &str) -> Option<&str> {
        let b = line.as_bytes();
        let mut i = 0usize;
        while i < b.len() {
            match b[i] {
                b'*' | b'#' | b':' => i += 1,
                b';' => return Some(&line[i + 1..]),
                _ => break,
            }
        }
        if i == 0 || i >= b.len() {
            return None;
        }
        match b[i] {
            b' ' | b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | 0xC0..=0xFF => Some(&line[i..]),
            _ => None,
        }
    }

    fn inline(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let b = s.as_bytes();
        let mut i = 0usize;
        while i < b.len() {
            if b[i..].starts_with(b"<!--") {
                if let Some(e) = find_sub(b, i + 4, b"-->") {
                    i = e + 3;
                    continue;
                }
            }
            if b[i] == b'<' {
                if let Some(e) = find_sub(b, i + 1, b">") {
                    let tag = &s[i + 1..e];
                    // Skip the name's allocating pass and build the
                    // close-tag bytes inline. The name is the
                    // alphanumeric prefix of the tag bytes.
                    let name_end = tag
                        .as_bytes()
                        .iter()
                        .take_while(|&&c| c.is_ascii_alphanumeric())
                        .count();
                    let name = &tag[..name_end];
                    let name_first = name.as_bytes().first().copied();
                    if !name.is_empty()
                        && matches!(name_first, Some(b'A'..=b'Z') | Some(b'a'..=b'z'))
                    {
                        if tag.as_bytes().first() == Some(&b'/') {
                            i = e + 1;
                            continue;
                        }
                        // Build "</name>" into a stack buffer
                        // (max name length for an HTML tag is
                        // unbounded in the spec, but in practice < 64)
                        // and search for it directly. No String
                        // allocation.
                        let mut closing = [0u8; 96];
                        let close_len = name.len() + 3;
                        if close_len <= closing.len() {
                            closing[0] = b'<';
                            closing[1] = b'/';
                            closing[2..2 + name.len()].copy_from_slice(name.as_bytes());
                            closing[2 + name.len()] = b'>';
                            if let Some(ce) = find_sub(b, e + 1, &closing[..close_len]) {
                                i = ce + close_len;
                                continue;
                            }
                        } else {
                            // Long name fallback: fall back to the
                            // old allocating path. Unreachable in
                            // practice but bounds the change.
                            let closing = format!("</{}>", unsafe {
                                core::str::from_utf8_unchecked(name.as_bytes())
                            });
                            if let Some(ce) = find_sub(b, e + 1, closing.as_bytes()) {
                                i = ce + closing.len();
                                continue;
                            }
                        }
                        i = e + 1;
                        continue;
                    }
                }
            }
            if b[i..].starts_with(b"[[") {
                if let Some(e) = find_sub(b, i + 2, b"]]") {
                    let inner = &s[i + 2..e];
                    out.push_str(inner.split('|').next_back().unwrap_or(inner));
                    i = e + 2;
                    continue;
                }
            }
            if b[i] == b'[' && b.get(i + 1) != Some(&b'[') {
                if let Some(e) = find_sub(b, i + 1, b"]") {
                    let inner = &s[i + 1..e];
                    let mut parts = inner.split_whitespace();
                    let url = parts.next().unwrap_or("");
                    let label = parts.collect::<Vec<_>>().join(" ");
                    out.push_str(if label.is_empty() { url } else { &label });
                    i = e + 1;
                    continue;
                }
            }
            if b[i..].starts_with(b"'''") {
                if let Some(e) = find_sub(b, i + 3, b"'''") {
                    out.push_str(&s[i + 3..e]);
                    i = e + 3;
                    continue;
                }
            }
            if b[i..].starts_with(b"''") {
                if let Some(e) = find_sub(b, i + 2, b"''") {
                    out.push_str(&s[i + 2..e]);
                    i = e + 2;
                    continue;
                }
            }
            match b[i] {
                b'&' => {
                    if let Some(semi) = find_sub(b, i + 1, b";") {
                        let ent = &s[i + 1..semi];
                        let decoded = match ent {
                            "amp" => Some('&'),
                            "lt" => Some('<'),
                            "gt" => Some('>'),
                            "quot" => Some('"'),
                            "nbsp" => Some(' '),
                            _ => None,
                        };
                        if let Some(c) = decoded {
                            out.push(c);
                            i = semi + 1;
                            continue;
                        }
                    }
                    out.push('&');
                    i += 1;
                }
                _ => {
                    let next = b[i..]
                        .iter()
                        .position(|&c| matches!(c, b'[' | b']' | b'<' | b'&' | b'\'') || c == b'}')
                        .map(|p| p + i)
                        .unwrap_or(b.len());
                    if next == i {
                        // stray terminator no earlier arm consumed (`<`
                        // without `>`, lone `]`/`'`/`}`, ...): emit it
                        let ch = s[i..].chars().next().unwrap_or(' ');
                        out.push(ch);
                        i += ch.len_utf8();
                    } else {
                        out.push_str(&s[i..next]);
                        i = next;
                    }
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// textile
// ---------------------------------------------------------------------------

mod textile {
    use super::tidy;
    #[allow(unused_imports)]
    use alloc::string::{String, ToString};
    #[allow(unused_imports)]
    use alloc::vec::Vec;

    pub fn extract_text(data: &[u8]) -> Option<String> {
        let src = String::from_utf8_lossy(data);
        let mut text = String::new();
        let mut para = String::new();

        let flush = |text: &mut String, para: &mut String| {
            if !para.trim().is_empty() {
                text.push_str(&inline(para.trim()));
                text.push('\n');
            }
            para.clear();
        };

        for raw in src.lines() {
            let line = raw.trim_end();
            let trimmed = line.trim();
            if trimmed.is_empty() {
                flush(&mut text, &mut para);
                text.push('\n');
                continue;
            }
            if let Some((kind, rest)) = block_signature(trimmed) {
                flush(&mut text, &mut para);
                match kind {
                    "heading" => {
                        text.push('\n');
                        text.push_str(&inline(rest));
                        text.push('\n');
                    }
                    "code" => {
                        text.push_str(rest);
                        text.push('\n');
                    }
                    _ => {
                        text.push_str(&inline(rest));
                        text.push('\n');
                    }
                }
                continue;
            }
            if let Some(rest) = list_marker(trimmed) {
                flush(&mut text, &mut para);
                text.push_str(&inline(rest));
                text.push('\n');
                continue;
            }
            if !para.is_empty() {
                para.push(' ');
            }
            para.push_str(trimmed);
        }
        flush(&mut text, &mut para);
        let text = tidy(&text);
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }

    fn block_signature(s: &str) -> Option<(&'static str, &str)> {
        if let Some(hs) = s.strip_prefix("h") {
            let level = hs.as_bytes().first().copied().unwrap_or(0);
            if (b'1'..=b'6').contains(&level) {
                let rest = hs[1..].trim();
                if let Some(r) = rest.strip_prefix('.') {
                    return Some(("heading", r.trim()));
                }
            }
            return None;
        }
        for (sig, kind) in [
            ("bq.", "quote"),
            ("bc.", "code"),
            ("pre.", "code"),
            ("p.", "paragraph"),
            ("notextile.", "paragraph"),
        ] {
            if let Some(r) = s.strip_prefix(sig) {
                return Some((kind, r.trim()));
            }
        }
        if s.len() > 3 && s.starts_with("###") && s.as_bytes()[3] == b' ' {
            return Some(("heading", s[4..].trim()));
        }
        None
    }

    fn list_marker(s: &str) -> Option<&str> {
        let b = s.as_bytes();
        let mut i = 0usize;
        while i < b.len() && matches!(b[i], b'*' | b'#') {
            i += 1;
        }
        if i == 0 || i >= b.len() || b[i] != b' ' {
            return None;
        }
        Some(s[i + 1..].trim())
    }

    fn inline(s: &str) -> String {
        const SPANS: [(&str, &str); 8] = [
            ("??", "??"),
            ("@", "@"),
            ("%", "%"),
            ("+", "+"),
            ("^", "^"),
            ("~", "~"),
            ("*", "*"),
            ("_", "_"),
        ];
        let mut work = s.to_string();
        for (open, close) in SPANS {
            work = unwrap_span(&work, open, close);
        }
        let b = work.as_bytes();
        let mut out = String::with_capacity(work.len());
        let mut i = 0usize;
        while i < b.len() {
            if b[i] == b'"' {
                if let Some(close) = find_quote(&work, i + 1) {
                    if work.as_bytes().get(close + 1) == Some(&b':') {
                        let url_start = close + 2;
                        let mut url_end = work[url_start..]
                            .find(char::is_whitespace)
                            .map(|p| p + url_start)
                            .unwrap_or(work.len());
                        while url_end > url_start
                            && matches!(
                                work.as_bytes()[url_end - 1],
                                b'.' | b',' | b';' | b':' | b'!' | b'?'
                            )
                        {
                            url_end -= 1;
                        }
                        let url_stop = work[url_end..]
                            .find(char::is_whitespace)
                            .map(|p| p + url_end)
                            .unwrap_or(work.len());
                        out.push_str(&work[i + 1..close]);
                        out.push_str(&work[url_end..url_stop]);
                        i = url_stop;
                        continue;
                    }
                }
            }
            if b[i] == b'!' {
                if let Some(e) = work[i + 1..].find('!').map(|p| p + i + 1) {
                    i = e + 1;
                    continue;
                }
            }
            let ch = work[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
        }
        out
    }

    fn find_quote(s: &str, from: usize) -> Option<usize> {
        let b = s.as_bytes();
        let mut i = from;
        while i < b.len() {
            if b[i] == b'\\' {
                i += 2;
                continue;
            }
            if b[i] == b'"' {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    fn unwrap_span(s: &str, open: &str, close: &str) -> String {
        let ob = open.as_bytes();
        let cb = close.as_bytes();
        let b = s.as_bytes();
        let mut out = String::with_capacity(s.len());
        let mut i = 0usize;
        while i < b.len() {
            if b[i..].starts_with(ob) {
                if let Some(rel) = find_close(s, i + ob.len(), cb) {
                    let inner = &s[i + ob.len()..i + ob.len() + rel];
                    if !inner.is_empty() && !inner.starts_with(' ') && !inner.ends_with(' ') {
                        out.push_str(inner);
                        i += ob.len() + rel + cb.len();
                        continue;
                    }
                }
            }
            let ch = s[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
        }
        out
    }

    fn find_close(s: &str, from: usize, close: &[u8]) -> Option<usize> {
        let b = s.as_bytes();
        let mut i = from;
        while i + close.len() <= b.len() {
            if &b[i..i + close.len()] == close {
                return Some(i - from);
            }
            i += s[i..].chars().next().map_or(1, |c| c.len_utf8());
        }
        None
    }
}

// ---------------------------------------------------------------------------
// man
// ---------------------------------------------------------------------------

mod man {
    use super::tidy;
    #[allow(unused_imports)]
    use alloc::string::{String, ToString};
    #[allow(unused_imports)]
    use alloc::vec::Vec;
    use core::fmt::Write as _;

    pub fn extract_text(data: &[u8]) -> Option<String> {
        let src = String::from_utf8_lossy(data);
        let mut text = String::new();
        let mut para = String::new();
        let mut verbatim = false;
        let mut skip_de_body = false;

        for raw in src.lines() {
            if skip_de_body {
                if raw.starts_with("..") {
                    skip_de_body = false;
                }
                continue;
            }
            let line = raw.trim_end();
            let ctrl = line
                .strip_prefix('.')
                .or_else(|| line.strip_prefix('\''))
                .filter(|_| line.len() >= 2);
            if let Some(rest) = ctrl {
                if rest.starts_with("\\\"") {
                    continue;
                }
                let name_end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
                let name = &rest[..name_end];
                let args = unescape(rest[name_end..].trim());
                match name {
                    "TH" | "th" => {
                        flush(&mut text, &mut para);
                        let mut parts = args.split_whitespace();
                        let title = parts.next().unwrap_or("");
                        let section = parts.next().unwrap_or("");
                        let date = parts.next().unwrap_or("");
                        let extra: Vec<&str> = parts.collect();
                        if !title.is_empty() {
                            let mut t = String::new();
                            if !section.is_empty() {
                                let _ = write!(t, "{title}({section})");
                            } else {
                                t.push_str(title);
                            }
                            if !date.is_empty() {
                                t.push_str(" — ");
                                t.push_str(date);
                            }
                            if !extra.is_empty() {
                                t.push(' ');
                                t.push_str(&extra.join(" "));
                            }
                            text.push_str(&t);
                            text.push('\n');
                        }
                    }
                    "SH" | "sh" => {
                        flush(&mut text, &mut para);
                        text.push_str(&args.to_uppercase());
                        text.push('\n');
                    }
                    "SS" | "ss" => {
                        flush(&mut text, &mut para);
                        text.push_str(&args);
                        text.push('\n');
                    }
                    "PP" | "P" | "LP" | "sp" | "br" => {
                        flush(&mut text, &mut para);
                        if name == "br" {
                            text.push('\n');
                        }
                    }
                    "nf" => {
                        flush(&mut text, &mut para);
                        verbatim = true;
                    }
                    "fi" => {
                        verbatim = false;
                        text.push('\n');
                    }
                    "B" | "I" | "R" | "C" | "BI" | "BR" | "IB" | "IR" | "RB" | "RI" | "SB"
                    | "SM" => {
                        let t = args.split_whitespace().collect::<Vec<_>>().join(" ");
                        if !t.is_empty() {
                            if !para.is_empty() {
                                para.push(' ');
                            }
                            para.push_str(&t);
                        }
                    }
                    "IP" | "TP" => {
                        flush(&mut text, &mut para);
                        if !args.is_empty() {
                            text.push_str(&args);
                            text.push('\n');
                        }
                    }
                    "de" | "am" => {
                        skip_de_body = true;
                    }
                    "so" | "mso" => {}
                    _ => {}
                }
                continue;
            }
            if verbatim {
                text.push_str(line);
                text.push('\n');
                continue;
            }
            if line.trim().is_empty() {
                flush(&mut text, &mut para);
                continue;
            }
            if !para.is_empty() {
                para.push(' ');
            }
            para.push_str(&unescape(line));
        }
        flush(&mut text, &mut para);
        let text = tidy(&text);
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }

    fn flush(text: &mut String, para: &mut String) {
        if !para.trim().is_empty() {
            text.push_str(para.trim());
            text.push('\n');
        }
        para.clear();
    }

    fn unescape(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('-') => out.push('-'),
                Some(' ') => out.push(' '),
                Some('.') => out.push('.'),
                Some('e') => out.push('\\'),
                Some('\\') => out.push('\\'),
                Some('&') => {}
                Some('f') => {
                    let _ = chars.next(); // font select code
                }
                Some('(') => {
                    let a = chars.next().unwrap_or(' ');
                    let b = chars.next().unwrap_or(' ');
                    match (a, b) {
                        ('b', 'u') => out.push('\u{2022}'),
                        ('d', 'e') => out.push('\u{00B0}'),
                        ('t', 'i') => out.push('\u{00D7}'),
                        ('m', 'i') | ('m', 'u') => out.push('\u{00D7}'),
                        ('p', 'l') => out.push('+'),
                        // \(em / \(en keep their two-letter name: greppable
                        (a, b) => {
                            out.push(a);
                            out.push(b);
                        }
                    }
                }
                Some('\'') => {
                    if let Some(base) = chars.next() {
                        out.push(match base {
                            'e' => 'é',
                            'a' => 'á',
                            'i' => 'í',
                            'o' => 'ó',
                            'u' => 'ú',
                            'E' => 'É',
                            'A' => 'Á',
                            'O' => 'Ó',
                            'U' => 'Ú',
                            'n' => 'ñ',
                            'c' => 'ç',
                            other => other,
                        });
                    }
                }
                Some('`') => {
                    if let Some(base) = chars.next() {
                        out.push(match base {
                            'e' => 'è',
                            'a' => 'à',
                            'u' => 'ù',
                            other => other,
                        });
                    }
                }
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// ipynb (mini-JSON cursor, no serde)
// ---------------------------------------------------------------------------

mod ipynb {
    #[allow(unused_imports)]
    use alloc::string::{String, ToString};
    #[allow(unused_imports)]
    use alloc::vec::Vec;

    pub fn extract_text(data: &[u8]) -> Option<String> {
        let mut out = String::new();
        extract_text_into(data, &mut out)?;
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }

    /// Streaming variant of `extract_text`: writes the notebook text
    /// directly into `out` as the JSON cursor advances, skipping the
    /// intermediate `Vec<(String, String, Vec<String>)>` of every
    /// cell the prior path built. Returns `Some(())` on a parsed
    /// notebook and `None` on a JSON error; the caller inspects
    /// `out` for emptiness.
    pub fn extract_text_into(data: &[u8], out: &mut String) -> Option<()> {
        let mut j = JsonCursor { b: data, i: 0 };
        j.skip_ws();
        if j.peek() != Some(b'{') {
            return None;
        }
        let mut found_cells = false;
        let mut had_any_output = false;

        j.expect(b'{')?;
        loop {
            j.skip_ws();
            if j.consume(b'}') {
                break;
            }
            let key = j.parse_string()?;
            j.skip_ws();
            j.expect(b':')?;
            match key.as_str() {
                "cells" => {
                    found_cells = true;
                    stream_cells(&mut j, out, &mut had_any_output);
                }
                "metadata" => {
                    // Kernel metadata lives at the top of the
                    // notebook; we emit "kernel: ..." once if it has a
                    // kernelspec language entry. Allocation is
                    // bounded to the kernel name string -- the rest
                    // is skipped.
                    let mut kernel_name = None;
                    stream_kernel(&mut j, &mut kernel_name);
                    if let Some(k) = kernel_name {
                        out.push_str("kernel: ");
                        out.push_str(&k);
                        out.push_str("\n\n");
                        had_any_output = true;
                    }
                }
                _ => {
                    j.skip_value()?;
                }
            }
            j.skip_ws();
            let _ = j.consume(b',');
        }
        if !found_cells || !had_any_output {
            out.clear();
            return None;
        }
        Some(())
    }

    /// Walk the `cells` array, emitting each cell's text directly into
    /// `out`. Returns no result -- `out` is the output sink.
    fn stream_cells(j: &mut JsonCursor, out: &mut String, had_output: &mut bool) {
        j.skip_ws();
        if !j.consume(b'[') {
            j.skip_value();
            return;
        }
        loop {
            j.skip_ws();
            if j.consume(b']') || j.i >= j.b.len() {
                break;
            }
            if !j.consume(b'{') {
                j.skip_value();
                let _ = j.consume(b',');
                continue;
            }
            let mut ctype = String::new();
            let mut source = String::new();
            let mut outputs_buf = String::new();
            let mut has_outputs = false;
            loop {
                j.skip_ws();
                if j.consume(b'}') {
                    break;
                }
                let Some(key) = j.parse_string() else { break };
                j.skip_ws();
                if j.expect(b':').is_none() {
                    break;
                }
                match key.as_str() {
                    "cell_type" => ctype = j.parse_string().unwrap_or_default(),
                    "source" => source = join_lines(j.parse_string_array()),
                    "outputs" => {
                        // Stream each output into the scratch; if any
                        // output had non-empty text we move the
                        // scratch into the final buffer below.
                        has_outputs = true;
                        stream_outputs(j, &mut outputs_buf);
                    }
                    _ => {
                        if j.skip_value().is_none() {
                            break;
                        }
                    }
                }
                j.skip_ws();
                let _ = j.consume(b',');
            }
            if !ctype.is_empty() {
                out.push_str("# [");
                out.push_str(&ctype);
                out.push_str("]\n");
                if !source.trim().is_empty() {
                    out.push_str(source.trim());
                    out.push('\n');
                }
                if has_outputs && !outputs_buf.is_empty() {
                    out.push_str(&outputs_buf);
                }
                out.push('\n');
                *had_output = true;
            }
            j.skip_ws();
            let _ = j.consume(b',');
        }
    }

    fn stream_kernel(j: &mut JsonCursor, name_out: &mut Option<String>) {
        j.skip_ws();
        if !j.consume(b'{') {
            j.skip_value();
            return;
        }
        loop {
            j.skip_ws();
            if j.consume(b'}') {
                return;
            }
            let Some(key) = j.parse_string() else { return };
            j.skip_ws();
            if j.expect(b':').is_none() {
                return;
            }
            if key == "kernelspec" {
                j.skip_ws();
                if j.consume(b'{') {
                    loop {
                        j.skip_ws();
                        if j.consume(b'}') {
                            return;
                        }
                        let Some(k) = j.parse_string() else { return };
                        j.skip_ws();
                        if j.expect(b':').is_none() {
                            return;
                        }
                        if k == "name" {
                            *name_out = j.parse_string();
                            return;
                        }
                        if j.skip_value().is_none() {
                            return;
                        }
                        j.skip_ws();
                        let _ = j.consume(b',');
                    }
                }
                return;
            }
            if j.skip_value().is_none() {
                return;
            }
            j.skip_ws();
            let _ = j.consume(b',');
        }
    }

    fn stream_outputs(j: &mut JsonCursor, out: &mut String) {
        j.skip_ws();
        if !j.consume(b'[') {
            j.skip_value();
            return;
        }
        loop {
            j.skip_ws();
            if j.consume(b']') || j.i >= j.b.len() {
                break;
            }
            if !j.consume(b'{') {
                j.skip_value();
                let _ = j.consume(b',');
                continue;
            }
            let mut text = String::new();
            let mut traceback = String::new();
            loop {
                j.skip_ws();
                if j.consume(b'}') {
                    break;
                }
                let Some(key) = j.parse_string() else { break };
                j.skip_ws();
                if j.expect(b':').is_none() {
                    break;
                }
                match key.as_str() {
                    "text" => text = join_lines(j.parse_string_array()),
                    "traceback" => traceback = join_lines(j.parse_string_array()),
                    "data" => {
                        // `data` is a vendor-specific structured
                        // blob; skip it -- the printable text and
                        // traceback are the parts users search.
                        j.skip_value();
                    }
                    _ => {
                        if j.skip_value().is_none() {
                            break;
                        }
                    }
                }
                j.skip_ws();
                let _ = j.consume(b',');
            }
            if !text.trim().is_empty() {
                out.push_str("[output]\n");
                out.push_str(text.trim());
                out.push('\n');
            }
            if !traceback.trim().is_empty() {
                out.push_str("[traceback]\n");
                out.push_str(traceback.trim());
                out.push('\n');
            }
            j.skip_ws();
            let _ = j.consume(b',');
        }
    }

    fn join_lines(parts: Vec<String>) -> String {
        let mut s = parts.concat();
        while s.ends_with('\n') {
            s.pop();
        }
        s
    }

    struct JsonCursor<'a> {
        b: &'a [u8],
        i: usize,
    }

    impl<'a> JsonCursor<'a> {
        fn peek(&self) -> Option<u8> {
            self.b.get(self.i).copied()
        }
        fn skip_ws(&mut self) {
            while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
                self.i += 1;
            }
        }
        fn consume(&mut self, c: u8) -> bool {
            self.skip_ws();
            if self.peek() == Some(c) {
                self.i += 1;
                true
            } else {
                false
            }
        }
        fn expect(&mut self, c: u8) -> Option<()> {
            if self.consume(c) {
                Some(())
            } else {
                None
            }
        }
        fn parse_string(&mut self) -> Option<String> {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return None;
            }
            self.i += 1;
            let mut out = String::new();
            while let Some(c) = self.peek() {
                match c {
                    b'"' => {
                        self.i += 1;
                        return Some(out);
                    }
                    b'\\' => {
                        self.i += 1;
                        match self.peek()? {
                            b'"' => out.push('"'),
                            b'\\' => out.push('\\'),
                            b'/' => out.push('/'),
                            b'b' => out.push('\u{0008}'),
                            b'f' => out.push('\u{000C}'),
                            b'n' => out.push('\n'),
                            b'r' => out.push('\r'),
                            b't' => out.push('\t'),
                            b'u' => {
                                let hi = self.hex4()?;
                                if (0xD800..0xDC00).contains(&hi)
                                    && self.b.get(self.i) == Some(&b'\\')
                                    && self.b.get(self.i + 1) == Some(&b'u')
                                {
                                    self.i += 1;
                                    let lo = self.hex4()?;
                                    let cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                                    out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                                } else {
                                    out.push(char::from_u32(hi).unwrap_or('\u{FFFD}'));
                                }
                                continue;
                            }
                            _ => return None,
                        }
                        self.i += 1;
                    }
                    _ => {
                        let len = utf8_len(c);
                        let end = (self.i + len).min(self.b.len());
                        out.push_str(str::from_utf8(&self.b[self.i..end]).unwrap_or("\u{FFFD}"));
                        self.i = end;
                    }
                }
            }
            None
        }
        fn hex4(&mut self) -> Option<u32> {
            // self.i points at 'u'
            let digits = self.b.get(self.i + 1..self.i + 5)?;
            let s = str::from_utf8(digits).ok()?;
            self.i += 5;
            u32::from_str_radix(s, 16).ok()
        }
        fn parse_string_array(&mut self) -> Vec<String> {
            let mut out = Vec::new();
            self.skip_ws();
            if self.peek() == Some(b'"') {
                if let Some(s) = self.parse_string() {
                    out.push(s);
                }
                return out;
            }
            if !self.consume(b'[') {
                let _ = self.skip_value();
                return out;
            }
            loop {
                self.skip_ws();
                if self.consume(b']') || self.i >= self.b.len() {
                    break;
                }
                if let Some(s) = self.parse_string() {
                    out.push(s);
                } else {
                    let _ = self.skip_value();
                }
                self.skip_ws();
                let _ = self.consume(b',');
            }
            out
        }
        fn skip_value(&mut self) -> Option<()> {
            self.skip_ws();
            match self.peek()? {
                b'"' => {
                    self.parse_string()?;
                }
                b'{' => {
                    self.i += 1;
                    loop {
                        self.skip_ws();
                        if self.consume(b'}') {
                            break;
                        }
                        self.parse_string()?;
                        self.skip_ws();
                        self.expect(b':')?;
                        self.skip_value()?;
                        self.skip_ws();
                        let _ = self.consume(b',');
                    }
                }
                b'[' => {
                    self.i += 1;
                    loop {
                        self.skip_ws();
                        if self.consume(b']') {
                            break;
                        }
                        self.skip_value()?;
                        self.skip_ws();
                        let _ = self.consume(b',');
                    }
                }
                b't' => self.i = (self.i + 4).min(self.b.len()),
                b'f' => self.i = (self.i + 5).min(self.b.len()),
                b'n' => self.i = (self.i + 4).min(self.b.len()),
                _ => {
                    // number: [-]digits[.frac][eE..]; a byte matching
                    // nothing is garbage — consume it anyway so callers
                    // looping on skip_value always make progress
                    let start = self.i;
                    while matches!(self.peek(), Some(c) if matches!(c, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'))
                    {
                        self.i += 1;
                    }
                    if self.i == start {
                        self.i += 1;
                    }
                }
            }
            Some(())
        }
    }

    fn utf8_len(first: u8) -> usize {
        if first < 0x80 {
            1
        } else if first < 0xE0 {
            2
        } else if first < 0xF0 {
            3
        } else {
            4
        }
    }
}

// ---------------------------------------------------------------------------
// markdown (md / gfm)
// ---------------------------------------------------------------------------

mod markdown {
    use super::{super::find_sub, tidy};
    #[allow(unused_imports)]
    use alloc::string::{String, ToString};
    #[allow(unused_imports)]
    use alloc::vec::Vec;

    pub fn extract_text(data: &[u8]) -> Option<String> {
        let src = String::from_utf8_lossy(data);
        let lines: Vec<&str> = src.lines().collect();
        let mut text = String::new();
        let mut i = 0usize;

        // YAML frontmatter: --- at line 0, closed by --- or ...
        if lines.first().map(|l| l.trim()) == Some("---") {
            let mut j = 1;
            while j < lines.len() {
                let t = lines[j].trim();
                if t == "---" || t == "..." {
                    i = j + 1;
                    break;
                }
                j += 1;
            }
        }

        while i < lines.len() {
            let line = lines[i];
            let trimmed = line.trim();
            if trimmed.is_empty() {
                i += 1;
                continue;
            }
            if is_fence_open(trimmed) {
                let fence = trimmed.as_bytes()[0];
                let mut body = String::new();
                let mut k = i + 1;
                while k < lines.len() {
                    if is_fence_close(lines[k].trim(), fence) {
                        break;
                    }
                    body.push_str(lines[k]);
                    body.push('\n');
                    k += 1;
                }
                push(&mut text, body.trim_end().to_string());
                i = if k < lines.len() { k + 1 } else { k };
                continue;
            }
            if trimmed.starts_with('#') {
                let hashes = trimmed.bytes().take_while(|&b| b == b'#').count();
                if (1..=6).contains(&hashes) {
                    let rest = trimmed[hashes..].trim();
                    let title = rest.trim_end_matches('#').trim();
                    push(&mut text, inline(title));
                    i += 1;
                    continue;
                }
            }
            if is_thematic_break(trimmed) {
                i += 1;
                continue;
            }
            if is_setext_underline(trimmed) {
                i += 1;
                continue;
            }
            if i + 1 < lines.len() && is_setext_underline(lines[i + 1].trim()) {
                push(&mut text, inline(trimmed));
                i += 2;
                continue;
            }
            if trimmed.starts_with('[') && trimmed.contains("]:") {
                i += 1; // link reference definition
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix('>') {
                push(&mut text, inline(rest.trim_start_matches(' ').trim()));
                i += 1;
                continue;
            }
            if let Some(item) = list_marker(trimmed) {
                push(&mut text, inline(item));
                i += 1;
                continue;
            }
            if line.starts_with("    ") || line.starts_with('\t') {
                let mut body = String::new();
                let mut k = i;
                while k < lines.len()
                    && (lines[k].starts_with("    ")
                        || lines[k].starts_with('\t')
                        || lines[k].trim().is_empty())
                {
                    body.push_str(lines[k].trim_start_matches('\t').trim_start_matches("    "));
                    body.push('\n');
                    k += 1;
                }
                push(&mut text, body.trim_end().to_string());
                i = k;
                continue;
            }
            let mut para = String::new();
            while i < lines.len() && !lines[i].trim().is_empty() {
                let t = lines[i].trim();
                if !para.is_empty()
                    && (is_fence_open(t)
                        || t.starts_with('#')
                        || t.starts_with('>')
                        || is_thematic_break(t)
                        || list_marker(t).is_some()
                        || (t.starts_with('[') && t.contains("]:")))
                {
                    break;
                }
                if !para.is_empty() {
                    para.push(' ');
                }
                para.push_str(t);
                i += 1;
                if i < lines.len() && is_setext_underline(lines[i].trim()) {
                    break;
                }
            }
            push(&mut text, inline(&para));
        }
        let text = tidy(&text);
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }

    fn push(text: &mut String, s: String) {
        if !s.trim().is_empty() {
            text.push_str(&s);
            text.push('\n');
        }
    }

    fn is_fence_open(t: &str) -> bool {
        let b = t.as_bytes();
        b.len() >= 3 && (b[0] == b'`' || b[0] == b'~') && b[..3].iter().all(|&c| c == b[0])
    }

    fn is_fence_close(t: &str, fence: u8) -> bool {
        let b = t.as_bytes();
        !b.is_empty() && b[0] == fence && b.iter().all(|&c| c == fence) && b.len() >= 3
    }

    fn is_setext_underline(t: &str) -> bool {
        let b = t.as_bytes();
        !b.is_empty() && (b[0] == b'=' || b[0] == b'-') && b.iter().all(|&c| c == b[0])
    }

    fn is_thematic_break(t: &str) -> bool {
        let mut core = 0u8;
        let mut count = 0usize;
        for &c in t.as_bytes() {
            if c == b' ' {
                continue;
            }
            if count == 0 {
                if !matches!(c, b'-' | b'*' | b'_') {
                    return false;
                }
                core = c;
                count = 1;
            } else if c == core {
                count += 1;
            } else {
                return false;
            }
        }
        count >= 3
    }

    fn list_marker(s: &str) -> Option<&str> {
        let bytes = s.as_bytes();
        if bytes.len() >= 2 && matches!(bytes[0], b'-' | b'*' | b'+') && bytes[1] == b' ' {
            return Some(s[2..].trim());
        }
        if bytes.len() >= 2 && bytes[0].is_ascii_digit() {
            let digit_end = s.find(|c: char| !c.is_ascii_digit())?;
            let rest = &s[digit_end..];
            if rest.len() >= 2
                && (rest.starts_with(". ") || rest.starts_with(") "))
                && s[..digit_end].chars().all(|c| c.is_ascii_digit())
            {
                return Some(s[digit_end + 2..].trim());
            }
        }
        None
    }

    fn inline(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let b = s.as_bytes();
        let mut i = 0usize;
        'outer: while i < b.len() {
            if b[i] == b'`' {
                let ticks = b[i..].iter().take_while(|&&c| c == b'`').count();
                let marker = &b[i..i + ticks];
                if let Some(rel) = find_sub(b, i + ticks, marker) {
                    out.push_str(s[i + ticks..rel].trim_matches(' '));
                    i = rel + ticks;
                    continue;
                }
                out.push('`');
                i += 1;
                continue;
            }
            if b[i..].starts_with(b"![") {
                if let Some(close) = find_sub(b, i + 2, b"](") {
                    if let Some(end) = find_sub(b, close + 2, b")") {
                        out.push_str(&s[i + 2..close]);
                        i = end + 1;
                        continue;
                    }
                }
            }
            if b[i] == b'[' {
                if let Some(close) = find_sub(b, i + 1, b"]") {
                    let after = close + 1;
                    if b[after..].starts_with(b"(") {
                        if let Some(end) = find_sub(b, after + 1, b")") {
                            out.push_str(&inline(&s[i + 1..close]));
                            i = end + 1;
                            continue;
                        }
                    }
                    if b.get(after) == Some(&b'[') {
                        if let Some(end) = find_sub(b, after + 1, b"]") {
                            out.push_str(&inline(&s[i + 1..close]));
                            i = end + 1;
                            continue;
                        }
                    }
                    out.push('[');
                    out.push_str(&inline(&s[i + 1..close]));
                    out.push(']');
                    i = close + 1;
                    continue;
                }
            }
            if b[i] == b'<' {
                if let Some(end) = find_sub(b, i + 1, b">") {
                    // autolink or raw inline HTML tag: both dropped
                    i = end + 1;
                    continue;
                }
            }
            for delim in ["***", "___", "**", "__", "~~", "*", "_"] {
                let d = delim.as_bytes();
                if b[i..].starts_with(d) {
                    if let Some(rel) = find_sub(b, i + d.len(), d) {
                        let inner = &s[i + d.len()..rel];
                        if !inner.is_empty() && !inner.starts_with(' ') && !inner.ends_with(' ') {
                            out.push_str(&inline(inner));
                            i = rel + d.len();
                            continue 'outer;
                        }
                    }
                }
            }
            match b[i] {
                b'\\' if i + 1 < b.len() => {
                    let ch = s[i + 1..].chars().next().unwrap_or(' ');
                    out.push(ch);
                    i += 1 + ch.len_utf8();
                }
                _ => {
                    let next = b[i..]
                        .iter()
                        .position(|&c| {
                            matches!(c, b'`' | b'!' | b'[' | b'<' | b'*' | b'_' | b'~' | b'\\')
                        })
                        .map(|p| p + i)
                        .unwrap_or(b.len());
                    if next == i {
                        let ch = s[i..].chars().next().unwrap_or(' ');
                        out.push(ch);
                        i += ch.len_utf8();
                    } else {
                        out.push_str(&s[i..next]);
                        i = next;
                    }
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// html (html / htm / xhtml)
// ---------------------------------------------------------------------------

mod html {
    use super::{decode_declared, tidy};
    #[allow(unused_imports)]
    use alloc::string::{String, ToString};
    #[allow(unused_imports)]
    use alloc::vec::Vec;

    /// End tags (and self-closing starts) that end a line.
    fn is_break(name: &[u8]) -> bool {
        matches!(
            name,
            b"p" | b"div"
                | b"li"
                | b"tr"
                | b"td"
                | b"th"
                | b"table"
                | b"section"
                | b"article"
                | b"header"
                | b"footer"
                | b"nav"
                | b"aside"
                | b"ul"
                | b"ol"
                | b"dl"
                | b"dt"
                | b"dd"
                | b"pre"
                | b"blockquote"
                | b"fieldset"
                | b"figcaption"
                | b"figure"
                | b"main"
                | b"h1"
                | b"h2"
                | b"h3"
                | b"h4"
                | b"h5"
                | b"h6"
                | b"title"
                | b"body"
                | b"html"
                | b"form"
        )
    }

    /// Tags whose contents are dropped entirely.
    fn is_skip(name: &[u8]) -> bool {
        matches!(name, b"script" | b"style" | b"head" | b"noscript")
    }

    pub fn extract_text(data: &[u8]) -> Option<String> {
        // A document that declares its charset is read in it, so its
        // accented characters are characters and not U+FFFD.
        let decoded;
        let data = match decode_declared(data) {
            Some(d) => {
                decoded = d;
                decoded.as_slice()
            }
            None => data,
        };
        let mut text_out = String::with_capacity(data.len());
        let mut text = Vec::with_capacity(1024);
        let mut i = 0usize;
        let n = data.len();
        let mut drop_depth = 0usize;
        let mut drop_tag = String::new();

        while i < n {
            if data[i] == b'<' {
                if drop_depth == 0 && !text.is_empty() {
                    push_unescaped(&mut text_out, &text);
                    text.clear();
                } else {
                    text.clear();
                }
                if data[i..].starts_with(b"<!--") {
                    i = mem_find(data, i + 4, b"-->").map(|p| p + 3).unwrap_or(n);
                    continue;
                }
                if i + 1 < n && data[i + 1] == b'!' {
                    if data[i..].starts_with(b"<![CDATA[") {
                        let start = i + 9;
                        let end = mem_find(data, start, b"]]>").unwrap_or(n);
                        if drop_depth == 0 {
                            text.extend_from_slice(&data[start..end]);
                        }
                        i = if end < n { end + 3 } else { n };
                        continue;
                    }
                    i = mem_find(data, i, b">").map(|p| p + 1).unwrap_or(n);
                    continue;
                }
                if i + 1 < n && data[i + 1] == b'?' {
                    i = mem_find(data, i, b"?>").map(|p| p + 2).unwrap_or(n);
                    continue;
                }
                let closing = i + 1 < n && data[i + 1] == b'/';
                let name_start = i + 1 + closing as usize;
                let mut j = name_start;
                while j < n && (data[j].is_ascii_alphanumeric() || data[j] == b'-') {
                    j += 1;
                }
                let name: Vec<u8> = data[name_start..j].to_ascii_lowercase();
                let self_closing = j < n && data[j] == b'/';
                let gt = mem_find(data, j, b">").map(|p| p + 1).unwrap_or(n);

                if drop_depth > 0 {
                    if name == drop_tag.as_bytes() {
                        if closing || self_closing {
                            drop_depth = drop_depth.saturating_sub(1);
                        } else {
                            drop_depth += 1;
                        }
                    }
                    i = gt;
                    continue;
                }
                if closing {
                    if is_break(&name) {
                        text_out.push('\n');
                    }
                } else if matches!(name.as_slice(), b"br" | b"hr") {
                    text_out.push('\n');
                } else if is_skip(&name) && !self_closing {
                    drop_tag = String::from_utf8_lossy(&name).into_owned();
                    drop_depth = 1;
                }
                i = gt;
                continue;
            }
            let next = mem_find(data, i, b"<").unwrap_or(n);
            text.extend_from_slice(&data[i..next]);
            i = next;
        }
        if drop_depth == 0 && !text.is_empty() {
            push_unescaped(&mut text_out, &text);
        }
        let text = tidy(&text_out);
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }

    /// memchr-backed substring search (the office crate has memchr).
    fn mem_find(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
        if from >= hay.len() || needle.is_empty() {
            return None;
        }
        rgx_core::memchr::memmem::find(&hay[from..], needle).map(|p| p + from)
    }

    fn push_unescaped(out: &mut String, raw: &[u8]) {
        let mut i = 0usize;
        while i < raw.len() {
            if raw[i] == b'&' {
                let end = mem_find(raw, i + 1, b";")
                    .map(|p| p.min(i + 32))
                    .unwrap_or(raw.len());
                let ent = &raw[i + 1..end.min(raw.len())];
                let rep = match ent {
                    b"amp" => Some('&'),
                    b"lt" => Some('<'),
                    b"gt" => Some('>'),
                    b"quot" => Some('"'),
                    b"apos" => Some('\''),
                    b"nbsp" => Some(' '),
                    b"mdash" => Some('\u{2014}'),
                    b"ndash" => Some('\u{2013}'),
                    b"hellip" => Some('\u{2026}'),
                    _ if ent.first() == Some(&b'#') => {
                        let s = &ent[1..];
                        let (digits, radix) =
                            if s.first() == Some(&b'x') || s.first() == Some(&b'X') {
                                (&s[1..], 16)
                            } else {
                                (s, 10)
                            };
                        str::from_utf8(digits)
                            .ok()
                            .and_then(|d| u32::from_str_radix(d, radix).ok())
                            .and_then(char::from_u32)
                    }
                    _ => None,
                };
                match rep {
                    Some(c) => {
                        out.push(c);
                        i = (end + 1).min(raw.len());
                    }
                    None => {
                        out.push('&');
                        i += 1;
                    }
                }
            } else {
                let next = raw[i..]
                    .iter()
                    .position(|&c| c == b'&')
                    .map(|p| p + i)
                    .unwrap_or(raw.len());
                out.push_str(&String::from_utf8_lossy(&raw[i..next]));
                i = next;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// t2t (txt2tags)
// ---------------------------------------------------------------------------

mod t2t {
    use super::{super::find_sub, tidy};
    #[allow(unused_imports)]
    use alloc::string::{String, ToString};
    #[allow(unused_imports)]
    use alloc::vec::Vec;

    pub fn extract_text(data: &[u8]) -> Option<String> {
        let src = String::from_utf8_lossy(data);
        let mut text = String::new();
        let mut in_verbatim = false;

        for raw in src.lines() {
            let line = raw.trim_end();
            let trimmed = line.trim();
            if trimmed.is_empty() {
                text.push('\n');
                continue;
            }
            if trimmed.starts_with("```") {
                if in_verbatim {
                    text.push('\n');
                }
                in_verbatim = !in_verbatim;
                continue;
            }
            if in_verbatim {
                text.push_str(line);
                text.push('\n');
                continue;
            }
            if trimmed.starts_with("//") {
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("%!") {
                if let Some((_, value)) = rest.split_once(':') {
                    let value = value.trim();
                    if !value.is_empty() {
                        push(&mut text, inline(value));
                    }
                }
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("% ") {
                push(&mut text, inline(rest.trim()));
                continue;
            }
            if trimmed.starts_with('=') {
                let eq = trimmed.bytes().take_while(|&b| b == b'=').count();
                if (1..=5).contains(&eq) {
                    let rest = trimmed[eq..].trim();
                    let title = rest.trim_end_matches('=').trim();
                    push(&mut text, inline(title));
                    continue;
                }
            }
            if let Some(rest) = list_marker(trimmed) {
                push(&mut text, inline(rest));
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix(':') {
                push(&mut text, inline(rest.trim()));
                continue;
            }
            push(&mut text, inline(trimmed));
        }
        let text = tidy(&text);
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }

    fn push(text: &mut String, s: String) {
        if !s.trim().is_empty() {
            text.push_str(&s);
            text.push('\n');
        }
    }

    fn list_marker(s: &str) -> Option<&str> {
        let b = s.as_bytes();
        if b.len() >= 2 && matches!(b[0], b'-' | b'+') && b[1] == b' ' {
            return Some(s[2..].trim());
        }
        None
    }

    fn inline(s: &str) -> String {
        const MARKUP: [(&str, &str); 6] = [
            ("**", "**"),
            ("//", "//"),
            ("__", "__"),
            ("--", "--"),
            ("`", "`"),
            ("\"", "\""),
        ];
        let mut work = s.to_string();
        for (open, close) in MARKUP {
            work = unwrap_pair(&work, open, close);
        }
        let b = work.as_bytes();
        let mut out = String::with_capacity(work.len());
        let mut i = 0usize;
        while i < b.len() {
            // [[url][label]] link — keep the label
            if b[i..].starts_with(b"[[") {
                if let Some(end) = find_sub(b, i + 2, b"]]") {
                    let inner = &work[i + 2..end];
                    let label = match find_sub(inner.as_bytes(), 0, b"][") {
                        Some(k) => &inner[k + 2..],
                        None => inner,
                    };
                    out.push_str(label);
                    i = end + 2;
                    continue;
                }
            }
            let ch = work[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
        }
        out
    }

    fn unwrap_pair(s: &str, open: &str, close: &str) -> String {
        let ob = open.as_bytes();
        let b = s.as_bytes();
        let mut out = String::with_capacity(s.len());
        let mut i = 0usize;
        while i < b.len() {
            if b[i..].starts_with(ob) {
                if let Some(rel) = find_sub(b, i + ob.len(), close.as_bytes()) {
                    let inner = &s[i + ob.len()..rel];
                    if !inner.is_empty() && !inner.starts_with(' ') && !inner.ends_with(' ') {
                        out.push_str(inner);
                        i = rel + close.len();
                        continue;
                    }
                }
            }
            let ch = s[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
        }
        out
    }
}

// ---------------------------------------------------------------------------
// fb2 (FictionBook 2)
// ---------------------------------------------------------------------------

mod fb2 {
    use super::{decode_declared, tidy};
    #[allow(unused_imports)]
    use alloc::string::{String, ToString};
    #[allow(unused_imports)]
    use alloc::vec::Vec;

    fn is_break(name: &[u8]) -> bool {
        matches!(
            name,
            b"p" | b"v"
                | b"title"
                | b"subtitle"
                | b"stanza"
                | b"text-author"
                | b"date"
                | b"epigraph"
        )
    }

    fn is_skip(name: &[u8]) -> bool {
        matches!(name, b"binary" | b"stylesheet" | b"image" | b"coverpage")
    }

    pub fn extract_text(data: &[u8]) -> Option<String> {
        // FictionBook is XML, and the prolog may say what the bytes are.
        let decoded;
        let data = match decode_declared(data) {
            Some(d) => {
                decoded = d;
                decoded.as_slice()
            }
            None => data,
        };
        let mut text_out = String::with_capacity(data.len() / 4);
        let mut text = Vec::with_capacity(1024);
        let mut i = 0usize;
        let n = data.len();
        let mut skip_depth = 0usize;
        let mut skip_tag = String::new();

        while i < n {
            if data[i] == b'<' {
                if skip_depth == 0 && !text.is_empty() {
                    push_unescaped(&mut text_out, &text);
                    text.clear();
                } else {
                    text.clear();
                }
                if data[i..].starts_with(b"<!--") {
                    i = mem_find(data, i + 4, b"-->").map(|p| p + 3).unwrap_or(n);
                    continue;
                }
                if i + 1 < n && (data[i + 1] == b'!' || data[i + 1] == b'?') {
                    let needle: &[u8] = if data[i + 1] == b'?' { b"?>" } else { b">" };
                    let adv = if data[i + 1] == b'?' { 2 } else { 1 };
                    i = mem_find(data, i, needle).map(|p| p + adv).unwrap_or(n);
                    continue;
                }
                let closing = i + 1 < n && data[i + 1] == b'/';
                let name_start = i + 1 + closing as usize;
                let mut j = name_start;
                while j < n && (data[j].is_ascii_alphanumeric() || data[j] == b'-') {
                    j += 1;
                }
                let name: Vec<u8> = data[name_start..j].to_ascii_lowercase();
                let self_closing = j < n && data[j] == b'/';
                let gt = mem_find(data, j, b">").map(|p| p + 1).unwrap_or(n);

                if skip_depth > 0 {
                    if name == skip_tag.as_bytes() {
                        if closing || self_closing {
                            skip_depth = skip_depth.saturating_sub(1);
                        } else {
                            skip_depth += 1;
                        }
                    }
                    i = gt;
                    continue;
                }
                if closing {
                    if is_break(&name) {
                        text_out.push('\n');
                    }
                } else if is_skip(&name) && !self_closing {
                    skip_tag = String::from_utf8_lossy(&name).into_owned();
                    skip_depth = 1;
                }
                i = gt;
                continue;
            }
            let next = mem_find(data, i, b"<").unwrap_or(n);
            if skip_depth == 0 {
                text.extend_from_slice(&data[i..next]);
            }
            i = next;
        }
        if skip_depth == 0 && !text.is_empty() {
            push_unescaped(&mut text_out, &text);
        }
        let text = tidy(&text_out);
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }

    fn mem_find(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
        if from >= hay.len() || needle.is_empty() {
            return None;
        }
        rgx_core::memchr::memmem::find(&hay[from..], needle).map(|p| p + from)
    }

    fn push_unescaped(out: &mut String, raw: &[u8]) {
        let mut i = 0usize;
        while i < raw.len() {
            if raw[i] == b'&' {
                let end = mem_find(raw, i + 1, b";")
                    .map(|p| p.min(i + 32))
                    .unwrap_or(raw.len());
                let ent = &raw[i + 1..end.min(raw.len())];
                let rep = match ent {
                    b"amp" => Some('&'),
                    b"lt" => Some('<'),
                    b"gt" => Some('>'),
                    b"quot" => Some('"'),
                    b"apos" => Some('\''),
                    b"nbsp" => Some(' '),
                    b"mdash" => Some('\u{2014}'),
                    b"ndash" => Some('\u{2013}'),
                    b"hellip" => Some('\u{2026}'),
                    _ if ent.first() == Some(&b'#') => {
                        let s = &ent[1..];
                        let (digits, radix) =
                            if s.first() == Some(&b'x') || s.first() == Some(&b'X') {
                                (&s[1..], 16)
                            } else {
                                (s, 10)
                            };
                        str::from_utf8(digits)
                            .ok()
                            .and_then(|d| u32::from_str_radix(d, radix).ok())
                            .and_then(char::from_u32)
                    }
                    _ => None,
                };
                match rep {
                    Some(c) => {
                        out.push(c);
                        i = (end + 1).min(raw.len());
                    }
                    None => {
                        out.push('&');
                        i += 1;
                    }
                }
            } else {
                let next = raw[i..]
                    .iter()
                    .position(|&c| c == b'&')
                    .map(|p| p + i)
                    .unwrap_or(raw.len());
                out.push_str(&String::from_utf8_lossy(&raw[i..next]));
                i = next;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn text_of(o: Outcome) -> String {
        match o {
            Outcome::Text(t) => String::from_utf8(t).unwrap(),
            _ => panic!("expected text"),
        }
    }

    const RST: &[u8] = b"ZIRCALOY Report\n===============\n\nThe cladding uses *zircaloy-4* alloy.\nSee the `spec sheet <https://example.invalid/spec>`_.\n\n- first item\n- second ``literal`` item\n\nSteps::\n\n    install the rod\n    torque the cap\n\n.. code-block:: python\n\n    print(\"hello\")\n\n.. this comment must disappear\n\n1. one\n2. two\n";

    const ORG: &[u8] = b"#+TITLE: ZIRCALOY Study\n\n* TODO Sample prep :lab:\nCollect cladding from /reactor 4/ and label it =ZR-4=.\n\n* Results\nSee [[https://example.invalid/data][the data repo]] for raw numbers.\n\n:PROPERTIES:\n:CREATED: 2026-09-01\n:END:\n\n# a comment that must disappear\n\n#+BEGIN_SRC python\nprint(\"zircaloy\")\n#+END_SRC\n";

    const MW: &[u8] = b"= ZIRCALOY =\n\nThe '''cladding''' is ''zircaloy-4''. See [[Zirconium|zirconium metal]]\nand [https://example.invalid/spec the spec].\n\n* item one\n# numbered\n\n{{infobox alloy\n| name = Zircaloy\n| use = cladding\n}}\n\n== Details ==\n{| class=\"wikitable\"\n! Property !! Value\n|-\n| Alloy || Zr-Sn\n|}\n\n<!-- hidden -->\n<ref>citation</ref>\nFinal &amp; last line.\n";

    const TEXTILE: &[u8] = b"h1. ZIRCALOY Notes\n\nThe *cladding* uses _zircaloy-4_. See \"the spec\":https://example.invalid/spec.\n\n* first item\n* second with @monospace@ span\n** nested item\n\nbc. print(\"zircaloy\")\n\nbq. a quoted remark\n";

    const MAN: &[u8] = b".TH ZIRCALOY 1 \"2026-09-26\" \"rgx tools\"\n.SH NAME\nzircaloy \\- cladding inspection tool\n.SH SYNOPSIS\n.B zircaloy\n.RI [ options ]\nfile...\n.TP\n.B \\-t\nset torque\n.SH DESCRIPTION\nThe \\fBcladding\\fR uses zircaloy-4 with \\-SN alloying.\nA second paragraph about \\(em dashes and 300\\(mu C.\n.nf\nverbatim   line\n.fi\n.PP\nFinal line.\n.\\\" a comment\n";

    const IPYNB: &[u8] = br##"{
 "cells": [
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "# ZIRCALOY study\n",
    "Notes about **cladding**."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 3,
   "metadata": {},
   "outputs": [
    {
     "output_type": "stream",
     "name": "stdout",
     "text": [
      "rod torque: 42 Nm\n"
     ]
    },
    {
     "output_type": "execute_result",
     "data": {
      "text/plain": [
       "3.14"
      ],
      "image/png": "iVBOR..."
     },
     "execution_count": 3,
     "metadata": {}
    }
   ],
   "source": [
    "print('rod torque: 42 Nm')\n",
    "3.14"
   ]
  }
 ],
 "metadata": {
  "kernelspec": {
   "display_name": "Python 3",
   "language": "python",
   "name": "python3"
  }
 },
 "nbformat": 4,
 "nbformat_minor": 5
}"##;

    #[test]
    fn rst_flattens_sections_lists_literals() {
        let out = text_of(Markup.extract(RST, "r.rst").unwrap());
        assert!(out.contains("ZIRCALOY Report"), "{out}");
        assert!(out.contains("The cladding uses zircaloy-4 alloy."), "{out}");
        assert!(out.contains("spec sheet"), "{out}");
        assert!(!out.contains("example.invalid"), "url dropped: {out}");
        assert!(out.contains("first item"), "{out}");
        assert!(out.contains("second literal item"), "{out}");
        assert!(out.contains("install the rod"), "{out}");
        assert!(out.contains("print(\"hello\")"), "{out}");
        assert!(!out.contains("comment must disappear"), "{out}");
    }

    #[test]
    fn org_flattens_outline_blocks_links() {
        let out = text_of(Markup.extract(ORG, "n.org").unwrap());
        assert!(out.contains("title: ZIRCALOY Study"), "{out}");
        assert!(out.contains("Sample prep"), "{out}");
        assert!(
            out.contains("Collect cladding from reactor 4 and label it ZR-4."),
            "{out}"
        );
        assert!(out.contains("the data repo"), "{out}");
        assert!(!out.contains("example.invalid"), "url dropped: {out}");
        assert!(!out.contains("CREATED"), "drawer dropped: {out}");
        assert!(!out.contains("comment that must disappear"), "{out}");
        assert!(out.contains("print(\"zircaloy\")"), "{out}");
    }

    #[test]
    fn mediawiki_flattens_templates_tables_links() {
        let out = text_of(Markup.extract(MW, "p.mediawiki").unwrap());
        assert!(out.contains("ZIRCALOY"), "{out}");
        assert!(out.contains("cladding"), "{out}");
        assert!(out.contains("zirconium metal"), "{out}");
        assert!(out.contains("the spec"), "{out}");
        assert!(!out.contains("example.invalid"), "url dropped: {out}");
        assert!(!out.contains("infobox"), "template dropped: {out}");
        assert!(out.contains("Property | Value"), "{out}");
        assert!(out.contains("Alloy | Zr-Sn"), "{out}");
        assert!(!out.contains("hidden"), "{out}");
        assert!(!out.contains("citation"), "ref dropped: {out}");
        assert!(out.contains("Final & last line."), "{out}");
    }

    #[test]
    fn textile_flattens_blocks_inline() {
        let out = text_of(Markup.extract(TEXTILE, "n.textile").unwrap());
        assert!(out.contains("ZIRCALOY Notes"), "{out}");
        assert!(out.contains("The cladding uses zircaloy-4."), "{out}");
        assert!(out.contains("See the spec."), "{out}");
        assert!(!out.contains("example.invalid"), "url dropped: {out}");
        assert!(out.contains("first item"), "{out}");
        assert!(out.contains("second with monospace span"), "{out}");
        assert!(out.contains("nested item"), "{out}");
        assert!(out.contains("print(\"zircaloy\")"), "{out}");
        assert!(out.contains("a quoted remark"), "{out}");
    }

    #[test]
    fn man_flattens_macros_escapes_verbatim() {
        let out = text_of(Markup.extract(MAN, "z.1").unwrap());
        assert!(out.contains("ZIRCALOY(1)"), "{out}");
        assert!(out.contains("NAME"), "{out}");
        assert!(out.contains("zircaloy - cladding inspection tool"), "{out}");
        assert!(out.contains("zircaloy [ options ] file..."), "{out}");
        assert!(out.contains("set torque"), "{out}");
        assert!(
            out.contains("The cladding uses zircaloy-4 with -SN alloying."),
            "{out}"
        );
        assert!(out.contains("em dashes"), "{out}");
        assert!(out.contains("verbatim   line"), "{out}");
        assert!(out.contains("Final line."), "{out}");
        assert!(!out.contains("a comment"), "{out}");
    }

    #[test]
    fn ipynb_flattens_cells_outputs_kernel() {
        let out = text_of(Markup.extract(IPYNB, "n.ipynb").unwrap());
        assert!(out.contains("kernel: python3"), "{out}");
        assert!(out.contains("# [markdown]"), "{out}");
        assert!(out.contains("# [code]"), "{out}");
        assert!(out.contains("[output]"), "{out}");
        assert!(out.contains("print('rod torque: 42 Nm')"), "{out}");
        assert!(out.contains("3.14"), "{out}");
        assert!(!out.contains("iVBOR"), "png dropped: {out}");
    }

    #[test]
    fn rejects_garbage() {
        assert!(Markup.extract(b"", "a.rst").is_err());
        assert!(Markup.extract(b"not json at all", "a.ipynb").is_err());
        assert!(Markup.extract(b"{}", "a.ipynb").is_err());
    }

    const MD: &[u8] = b"---\ntitle: draft\n---\n\n# ZIRCALOY Report\n\nThe cladding uses **zircaloy-4** with *high* strength.\nSee the [spec sheet](https://example.invalid/spec) for details.\n\n```\ninstall the rod\n```\n\n> a quoted remark\n\n- first item\n- second `literal` item\n\nSetext title\n============\n\n1. one\n2. two\n";

    const HTML: &[u8] = br#"<!DOCTYPE html>
<html><head><title>must go</title><style>body{color:red}</style></head>
<body>
<h1>ZIRCALOY Report</h1>
<p>The cladding uses <strong>zircaloy-4</strong> &amp; alloys.<br>
Second line.</p>
<script>var x = 1;</script>
<ul><li>first item</li><li>second item</li></ul>
<!-- a comment -->
<p>Last &lt;paragraph&gt; with &#39;quotes&#x27;.</p>
</body></html>
"#;

    const T2T: &[u8] = b"% ZIRCALOY Study\n\n= ZIRCALOY Notes =\n\nThe cladding uses **zircaloy-4** with //high// strength.\n\n- first item\n- second **bold** item\n+ numbered one\n\n```\nverbatim line one\n```\n\nSee [[https://example.invalid/spec][the spec]] for details.\n\n// this comment must disappear\n";

    const FB2: &[u8] = br#"<?xml version="1.0" encoding="utf-8"?>
<FictionBook>
<description><title-info><book-title>ZIRCALOY Tales</book-title>
<annotation><p>Short stories about cladding.</p></annotation>
</title-info></description>
<body>
<section>
<title><p>Part One</p></title>
<p>The <emphasis>cladding</emphasis> uses zircaloy-4 &amp; alloys.</p>
<section><title><p>Chapter 1</p></title>
<p>First paragraph of chapter one.</p>
<poem><stanza>
<v>The rod goes in</v>
<v>the cap comes tight</v>
</stanza></poem>
</section>
</section>
</body>
<binary id="cover.jpg" content-type="image/jpeg">aGVsbG8=</binary>
</FictionBook>
"#;

    #[test]
    fn markdown_flattens_headings_code_links() {
        let out = text_of(Markup.extract(MD, "r.md").unwrap());
        assert!(out.contains("ZIRCALOY Report"), "{out}");
        assert!(
            out.contains("The cladding uses zircaloy-4 with high strength."),
            "{out}"
        );
        assert!(out.contains("spec sheet"), "{out}");
        assert!(!out.contains("example.invalid"), "url dropped: {out}");
        assert!(out.contains("install the rod"), "{out}");
        assert!(out.contains("a quoted remark"), "{out}");
        assert!(out.contains("first item"), "{out}");
        assert!(out.contains("second literal item"), "{out}");
        assert!(out.contains("Setext title"), "{out}");
        assert!(out.contains("one"), "{out}");
        assert!(!out.contains("title: draft"), "frontmatter skipped: {out}");
    }

    #[test]
    fn html_flattens_tags_scripts_entities() {
        let out = text_of(Markup.extract(HTML, "p.html").unwrap());
        assert!(out.contains("ZIRCALOY Report"), "{out}");
        assert!(
            out.contains("The cladding uses zircaloy-4 & alloys."),
            "{out}"
        );
        assert!(out.contains("Second line."), "{out}");
        assert!(out.contains("first item"), "{out}");
        assert!(out.contains("Last <paragraph> with 'quotes'."), "{out}");
        assert!(!out.contains("must go"), "head dropped: {out}");
        assert!(!out.contains("color:red"), "style dropped: {out}");
        assert!(!out.contains("var x"), "script dropped: {out}");
        assert!(!out.contains("a comment"), "comment dropped: {out}");
    }

    /// A document that declares its charset is read in it.
    ///
    /// The bug this holds down: the page was read as UTF-8 whatever it
    /// said, so a latin-1 `0xE9` became U+FFFD and the character was gone
    /// from the rendering -- a search for "café" could not find it.
    #[test]
    fn an_html_document_is_read_in_the_charset_it_declares() {
        let mut raw =
            b"<html><head><meta charset=\"iso-8859-1\"></head><body><p>caf\xe9</p></body></html>"
                .to_vec();
        raw.push(0);
        let out = text_of(Markup.extract(&raw, "p.html").unwrap());
        assert!(out.contains("café"), "{out}");
        assert!(!out.contains('\u{FFFD}'), "a byte became U+FFFD: {out}");
    }

    /// The older spelling of the same declaration.
    #[test]
    fn an_html_http_equiv_charset_is_honoured() {
        let mut raw = b"<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\"></head><body><p>caf\xe9</p></body></html>".to_vec();
        raw.push(0);
        let out = text_of(Markup.extract(&raw, "p.html").unwrap());
        assert!(out.contains("café"), "{out}");
    }

    /// The XML prolog of an XHTML document.
    #[test]
    fn an_xhtml_prolog_encoding_is_honoured() {
        let mut raw =
            b"<?xml version=\"1.0\" encoding=\"iso-8859-1\"?><html><body><p>caf\xe9</p></body></html>"
                .to_vec();
        raw.push(0);
        let out = text_of(Markup.extract(&raw, "p.xhtml").unwrap());
        assert!(out.contains("café"), "{out}");
    }

    /// A document that declares nothing is not re-read in a guessed
    /// encoding: the caller's own reading applies.
    #[test]
    fn an_html_document_without_a_declaration_is_left_alone() {
        let mut raw = b"<html><body><p>caf\xc3\xa9</p></body></html>".to_vec();
        raw.push(0);
        let out = text_of(Markup.extract(&raw, "p.html").unwrap());
        assert!(out.contains("café"), "{out}");
    }

    #[test]
    fn t2t_flattens_headers_lists_verbatim() {
        let out = text_of(Markup.extract(T2T, "n.t2t").unwrap());
        assert!(out.contains("ZIRCALOY Study"), "{out}");
        assert!(out.contains("ZIRCALOY Notes"), "{out}");
        assert!(
            out.contains("The cladding uses zircaloy-4 with high strength."),
            "{out}"
        );
        assert!(out.contains("first item"), "{out}");
        assert!(out.contains("second bold item"), "{out}");
        assert!(out.contains("numbered one"), "{out}");
        assert!(out.contains("verbatim line one"), "{out}");
        assert!(out.contains("the spec"), "{out}");
        assert!(!out.contains("example.invalid"), "url dropped: {out}");
        assert!(!out.contains("this comment must disappear"), "{out}");
    }

    #[test]
    fn fb2_flattens_sections_poems_skips_binary() {
        let out = text_of(Markup.extract(FB2, "b.fb2").unwrap());
        assert!(out.contains("ZIRCALOY Tales"), "{out}");
        assert!(out.contains("Part One"), "{out}");
        assert!(out.contains("Chapter 1"), "{out}");
        assert!(
            out.contains("The cladding uses zircaloy-4 & alloys."),
            "{out}"
        );
        assert!(out.contains("First paragraph of chapter one."), "{out}");
        assert!(out.contains("The rod goes in"), "{out}");
        assert!(!out.contains("aGVsbG8="), "binary dropped: {out}");
    }

    mod fuzz {
        use super::*;

        #[test]
        fn markup_never_panics_on_mutation() {
            let fixtures: Vec<(&str, Vec<u8>)> = vec![
                ("rst", RST.to_vec()),
                ("org", ORG.to_vec()),
                ("mediawiki", MW.to_vec()),
                ("textile", TEXTILE.to_vec()),
                ("man", MAN.to_vec()),
                ("ipynb", IPYNB.to_vec()),
                ("md", MD.to_vec()),
                ("html", HTML.to_vec()),
                ("t2t", T2T.to_vec()),
                ("fb2", FB2.to_vec()),
                ("empty", vec![]),
            ];
            rgx_core::fuzzkit::assert_never_panics(fixtures, 1200, "markup", |data| {
                for ext in [
                    "rst",
                    "org",
                    "mediawiki",
                    "ipynb",
                    "textile",
                    "man",
                    "md",
                    "gfm",
                    "html",
                    "htm",
                    "xhtml",
                    "t2t",
                    "fb2",
                ] {
                    let _ = Markup.extract(data, &format!("fuzz.{ext}"));
                }
            });
        }
    }
}
