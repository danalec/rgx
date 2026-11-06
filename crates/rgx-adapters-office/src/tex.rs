// SPDX-License-Identifier: Apache-2.0

//! TeX / LaTeX → text (detex-style): drop the preamble, comments and
//! control words, unwrap section titles, skip verbatim environments.
//! Math delimiters are dropped but their content is kept — for grep, the
//! symbols inside math are usually still meaningful.
//!
//! A reduced port of the TeX reader of the `io` project by Dan Gohman,
//! whose work is used here under Apache-2.0: the section outline and the
//! preamble-skipped provenance are the upstream's, and this one carries the
//! flat-text flattening. See `NOTICE`.

use alloc::string::{String, ToString};
use core::str;
use rgx_core::{decline, Result};
use rgx_core::{Adapter, Outcome, Reach};

/// environments whose bodies are code, not prose
const VERBATIM_ENVS: [&str; 4] = ["verbatim", "Verbatim", "lstlisting", "minted"];

/// structural control words whose braced title becomes a text line
const SECTION_WORDS: [&str; 7] = [
    "part",
    "chapter",
    "section",
    "subsection",
    "subsubsection",
    "paragraph",
    "subparagraph",
];

pub fn extract_text(data: &[u8]) -> Result<String> {
    // TeX has no magic bytes; require one of four ASCII tells. The
    // `from_utf8_lossy(data)` path used to copy the whole document
    // into a heap `String` just to test fixed substrings -- the
    // `memchr::memmem` finder skips that.
    if !has_tell(data) {
        decline!("doesn't look like TeX (no documentclass/begin/section)");
    }
    // skip the preamble when there is one: definitions are noise for grep
    let start = find_sub(data, 0, b"\\begin{document}")
        .map(|p| p + b"\\begin{document}".len())
        .unwrap_or(0);
    let mut out = String::with_capacity(data.len() / 2);
    detex(data, start, data.len(), &mut out, 0);
    let text = out.trim().to_string();
    if text.is_empty() {
        decline!("no text content in TeX");
    }
    Ok(text)
}

/// True when `data` looks like TeX: at least one of the four ASCII
/// tells is present. The four substrings are all ASCII so the
/// `memchr::memmem` finder runs straight over the input bytes.
fn has_tell(data: &[u8]) -> bool {
    find_sub(data, 0, b"\\documentclass").is_some()
        || find_sub(data, 0, b"\\begin{").is_some()
        || find_sub(data, 0, b"\\section").is_some()
        || find_sub(data, 0, b"\\chapter").is_some()
}

/// Read a balanced {...} group starting at `i` (which must point at `{`).
/// Returns (content_start, content_end, next_pos_after_closing_brace).
fn read_group(data: &[u8], i: usize) -> Option<(usize, usize, usize)> {
    if data.get(i) != Some(&b'{') {
        return None;
    }
    let mut depth = 0usize;
    let mut j = i;
    while j < data.len() {
        match data[j] {
            b'\\' => j += 2, // escaped brace: not structural
            b'{' => depth += 1,
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some((i + 1, j, j + 1));
                }
            }
            _ => {}
        }
        j += 1;
    }
    None
}

/// Read a control word at `i` (data[i] == '\\', next byte alphabetic):
/// letters, then optional digits/star. Returns (word, next_pos).
fn control_word(data: &[u8], i: usize) -> (&[u8], usize) {
    let mut j = i + 1;
    while j < data.len() && data[j].is_ascii_alphabetic() {
        j += 1;
    }
    let word = &data[i + 1..j];
    while j < data.len() && (data[j].is_ascii_digit() || data[j] == b'*') {
        j += 1;
    }
    (word, j)
}

fn detex(data: &[u8], start: usize, end: usize, out: &mut String, depth: usize) {
    let n = end.min(data.len());
    let mut i = start;
    while i < n {
        match data[i] {
            b'%' => {
                while i < n && data[i] != b'\n' {
                    i += 1;
                }
            }
            b'\\' if i + 1 < n => {
                let c = data[i + 1];
                if c.is_ascii_alphabetic() {
                    let (word, mut j) = control_word(data, i);
                    // one delimiter space after the word is not content
                    if j < n && data[j] == b' ' {
                        j += 1;
                    }
                    if word == b"begin" || word == b"end" {
                        // environment name in braces
                        let mut k = j;
                        while k < n && data[k].is_ascii_whitespace() {
                            k += 1;
                        }
                        if let Some((gs, ge, after)) = read_group(data, k) {
                            let env = str::from_utf8(&data[gs..ge]).unwrap_or("");
                            let verbatim = VERBATIM_ENVS.contains(&env);
                            if word == b"begin" && verbatim {
                                // skip the whole body up to \end{env}
                                let needle = format!("\\end{{{env}}}").into_bytes();
                                if let Some(p) = find_sub(data, after, &needle) {
                                    i = p + needle.len();
                                    continue;
                                }
                                i = n;
                                continue;
                            }
                            out.push('\n');
                            i = after;
                            continue;
                        }
                        out.push('\n');
                        i = j;
                        continue;
                    }
                    if SECTION_WORDS.contains(&str::from_utf8(word).unwrap_or("")) {
                        // optional [short title], then {title}
                        let mut k = j;
                        while k < n && data[k].is_ascii_whitespace() {
                            k += 1;
                        }
                        if data.get(k) == Some(&b'[') {
                            if let Some((_, _, after)) = read_bracket(data, k) {
                                k = after;
                                while k < n && data[k].is_ascii_whitespace() {
                                    k += 1;
                                }
                            }
                        }
                        if depth < 10 {
                            if let Some((gs, ge, after)) = read_group(data, k) {
                                out.push('\n');
                                detex(data, gs, ge, out, depth + 1);
                                out.push('\n');
                                i = after;
                                continue;
                            }
                        }
                        out.push('\n');
                        i = j;
                        continue;
                    }
                    match word {
                        b"par" | b"newline" | b"linebreak" | b"item" | b"bigskip" | b"medskip"
                        | b"smallskip" => out.push('\n'),
                        _ => {}
                    }
                    i = j;
                } else {
                    // control symbol
                    match c {
                        b'%' | b'$' | b'&' | b'#' | b'_' | b'{' | b'}' => {
                            out.push(c as char);
                            i += 2;
                        }
                        b'\\' => {
                            out.push('\n');
                            i += 2;
                        }
                        b'~' => {
                            out.push(' ');
                            i += 2;
                        }
                        b',' | b';' | b' ' | b':' | b'!' => {
                            out.push(' ');
                            i += 2;
                        }
                        _ => i += 2,
                    }
                }
            }
            b'{' | b'}' => i += 1,
            // lone trailing backslash: the guarded control arm above needs
            // i + 1 < n; without this the text-run arm would re-match the
            // same byte forever (it is a "special" char at offset 0)
            b'\\' => i += 1,
            b'$' => i += 1,
            b'~' => {
                out.push(' ');
                i += 1;
            }
            b'\n' => {
                out.push(' ');
                i += 1;
            }
            _ => {
                let next = data[i..n]
                    .iter()
                    .position(|&b| matches!(b, b'%' | b'\\' | b'{' | b'}' | b'$' | b'~' | b'\n'))
                    .map(|p| p + i)
                    .unwrap_or(n);
                out.push_str(&String::from_utf8_lossy(&data[i..next]));
                i = next;
            }
        }
    }
}

/// balanced [...] group (square brackets don't nest in LaTeX optional args)
fn read_bracket(data: &[u8], i: usize) -> Option<(usize, usize, usize)> {
    if data.get(i) != Some(&b'[') {
        return None;
    }
    let mut j = i + 1;
    while j < data.len() {
        match data[j] {
            b'\\' => j += 2,
            b']' => return Some((i + 1, j, j + 1)),
            _ => j += 1,
        }
    }
    None
}

fn find_sub(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from >= hay.len() || needle.is_empty() {
        return None;
    }
    rgx_core::memchr::memmem::find(&hay[from..], needle).map(|p| p + from)
}

pub struct Tex;
impl Adapter for Tex {
    fn name(&self) -> &'static str {
        "tex"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["tex", "latex", "ltx"]
    }
    /// A `.tex` file is plain text ripgrep already reads, and this adapter
    /// drops the preamble, the comments, the control words and the verbatim
    /// bodies — measured over 130 real files, 898 lines against ripgrep's
    /// 11,484, or 7.8%. `rgx '\\begin'` is a query this rendering cannot
    /// answer. See [`Reach::Render`].
    fn reach(&self) -> Reach {
        Reach::Render
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(extract_text(data)?.into_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"
\documentclass{article}
\usepackage{amsmath}
\newcommand{\zirc}{ZIRCALOY}
\begin{document}
\title{Relatório de materiais}
\maketitle
\section{Introdução}
O revestimento de \zirc{} opera a 300\% de carga. % comentário que deve sumir
Fórmula $E = mc^2$ inline.
\subsection{Método \& dados}
\begin{itemize}
\item Primeiro ponto
\item Segundo com escape de \% percentual
\end{itemize}
\end{document}
"#;

    #[test]
    fn strips_preamble_comments_and_control_words() {
        let text = extract_text(DOC.as_bytes()).unwrap();
        assert!(text.contains("Introdução"), "{text}");
        assert!(text.contains("Método & dados"), "{text}");
        assert!(text.contains("E = mc^2"), "{text}");
        assert!(text.contains("Primeiro ponto"), "{text}");
        assert!(text.contains("% percentual"), "{text}");
        assert!(!text.contains("comentário que deve sumir"), "{text}");
        assert!(!text.contains("documentclass"), "{text}");
        assert!(!text.contains("usepackage"), "{text}");
    }

    #[test]
    fn skips_verbatim_environment() {
        let doc = r#"\documentclass{article}
\begin{document}
Texto antes.
\begin{verbatim}
ZIRCALOY_should_not_appear
\end{verbatim}
Texto depois.
\end{document}"#;
        let text = extract_text(doc.as_bytes()).unwrap();
        assert!(text.contains("Texto antes"), "{text}");
        assert!(text.contains("Texto depois"), "{text}");
        assert!(!text.contains("should_not_appear"), "{text}");
    }

    #[test]
    fn rejects_non_tex() {
        assert!(extract_text(b"just plain prose, no tex at all").is_err());
    }

    #[test]
    fn never_panics_on_mutation() {
        rgx_core::fuzzkit::assert_never_panics(
            vec![
                ("doc", DOC.as_bytes().to_vec()),
                ("backslash", b"\\".to_vec()),
                ("empty", vec![]),
            ],
            1500,
            "tex",
            |data| {
                let _ = extract_text(data);
            },
        );
    }
}
