// SPDX-License-Identifier: Apache-2.0

//! The walker: parallel traversal, plus the ignore rules that decide
//! which files rgx ever looks at. Semantics are git's, as implemented
//! by the `ignore` crate — the tool rgx has to agree with, decision
//! for decision. `tests/walk_diff.rs` holds the two implementations
//! against each other; the `ignore` crate stays a dev-dependency solely
//! as that oracle.

use std::cell::OnceCell;
use std::fs::{File, FileType, Metadata};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use crossbeam_deque::{Steal, Stealer, Worker as Deque};

use crate::type_db::TypeDb;

/// Bytes the magic-byte sniffer asks for. 512 gives comfortable
/// headroom over the largest signature the inspect table recognises
/// (~16 bytes, `SQLite format 3\x00`).
const MAGIC_PEEK: usize = 512;

/// Read up to [`MAGIC_PEEK`] bytes from the head of `path` for
/// magic-byte classification. Returns an empty slice on any I/O
/// error, which is the same answer `accepts_with_bytes` gives for a
/// file it could not classify.
fn peek_head(path: &std::path::Path) -> [u8; MAGIC_PEEK] {
    let mut buf = [0u8; MAGIC_PEEK];
    let Ok(mut f) = File::open(path) else {
        return buf;
    };
    let _ = f.read(&mut buf);
    buf
}

/// Entries per pool handover, per thread. Big enough that the mutex
/// is touched once per directory rather than once per file, small
/// enough that a directory with more files than that is still work
/// several threads can share.
const BATCH: usize = 512;

// The ignore-file globs compile to `(?-u)^...$` patterns and run on
// the in-house byte engine, the same way a search pattern does.
// `regex` is kept for one thing only: the `-r` replacement, whose
// `$`-templates wait on the engine finding the leftmost match.
use rgx_core::regex::{ByteRegex, Matcher};

// ---------------------------------------------------------------------------
// type filter
//
// The filter rides alongside the user-glob filter. It sees only
// file entries, not directories — pruning a directory would also
// drop every file under it, and a type predicate by definition has
// nothing to say about a tree. The filter is `None` when the user
// did not pass `-t`/`-T`, which makes the per-entry check a no-op
// for the common case.
//
// The model is ripgrep's. A type is a set of patterns, a file matches
// every type whose patterns its name satisfies, and the *last* type
// the user named that matches the file is the one that decides. So
// `-t js` keeps `lib.min.js` (it is a `.js` file and also a `minified`
// one), and the order of the flags matters: `-t js -T minified` drops
// that file while `-T minified -t js` keeps it.
// ---------------------------------------------------------------------------

/// A type the user named: `-t X` selects it, `-T X` negates it.
#[derive(Clone, Debug)]
pub struct TypeSel {
    /// The name as the user wrote it.
    pub name: String,
    /// Whether the name excludes (`-T`) rather than includes (`-t`).
    pub negate: bool,
}

/// A selection with its type's patterns resolved, so the per-file check
/// is a suffix test and not a walk of the table.
#[derive(Clone, Debug)]
struct ResolvedSel {
    name: String,
    negate: bool,
    patterns: Vec<Box<str>>,
}

/// File-type filter built from the user's `-t`/`-T` flags and any
/// `--type-add`/`--type-clear` edits. Cheap to clone (`TypeDb` is
/// `Clone`), so the walker carries it by `Arc`-style clone in `Ctx`.
#[derive(Clone)]
pub struct TypeFilter {
    db: TypeDb,
    /// The selections in the order the user wrote them.
    selections: Vec<ResolvedSel>,
}

impl TypeFilter {
    /// Build a fresh filter from a `TypeDb` (already cleared and extended
    /// as the user requested) and the selections, in the order the user
    /// wrote them.
    pub fn new(db: TypeDb, selections: Vec<TypeSel>) -> Self {
        let mut resolved = Vec::with_capacity(selections.len());
        for sel in &selections {
            // The canonical name, so an alias and the type it names are
            // the same selection and the magic classifier's names (which
            // are canonical) meet them.
            let name = db.resolve(&sel.name).unwrap_or(&sel.name).to_string();
            let patterns = db
                .patterns_of(&name)
                .unwrap_or(&[])
                .iter()
                .map(|p| p.as_str().into())
                .collect();
            resolved.push(ResolvedSel {
                name,
                negate: sel.negate,
                patterns,
            });
        }
        TypeFilter {
            db,
            selections: resolved,
        }
    }

    /// Borrow the underlying type table (used by `--type-list` and tests).
    pub fn db(&self) -> &TypeDb {
        &self.db
    }

    /// Test a path against the filter. Returns `false` when the file is
    /// excluded; `true` otherwise (including when no filter was configured,
    /// though that case is short-circuited before this is reached).
    #[cfg(test)]
    pub fn accepts(&self, path: &Path) -> bool {
        match lower_basename(path) {
            Some(name) => !self.verdict(&name, None).is_ignore(),
            None => !self.selects(),
        }
    }

    /// Verdict from the file's name alone, or `None` when the name
    /// matches no type at all and the file's first bytes have to be read
    /// to know whether the magic classifier names one.
    pub fn classify_verdict(&self, path: &Path) -> Option<bool> {
        let name = lower_basename(path)?;
        self.db.classify_name(&name)?;
        Some(!self.verdict(&name, None).is_ignore())
    }

    /// Test a file by reading its first few bytes (caller passes the
    /// slice) when the extension was not enough to classify the
    /// file. The byte classifier only kicks in when the
    /// `adapters-inspect` feature is on; without it, an extension-
    /// unclassified file falls back to the include-empty default
    /// (skip when `-t` is set, accept when `-T` alone). Not feature-
    /// gated because `--no-default-features` must build; the method
    /// used to carry `#[cfg(feature = "adapters-inspect")]` while its
    /// call sites did not, so the engine-only build — a CI gate in
    /// its own right — failed to compile.
    pub fn accepts_with_bytes(&self, path: &Path, head: &[u8]) -> bool {
        match lower_basename(path) {
            Some(name) => !self.verdict(&name, Some(head)).is_ignore(),
            None => !self.selects(),
        }
    }

    /// The verdict for a file whose name is `name` and whose first bytes
    /// are `head`.
    ///
    /// The last selection that matches the file decides, and a selection
    /// matches when the file's name satisfies one of the type's patterns.
    /// `head` is only read when the name matched no type at all: a file
    /// whose name says what it is does not need its bytes read to know
    /// what it is.
    fn verdict(&self, name: &str, head: Option<&[u8]>) -> Match {
        let mut verdict = None;
        for sel in &self.selections {
            if sel.matches_name(name) {
                verdict = Some(if sel.negate {
                    Match::Ignore
                } else {
                    Match::Whitelist
                });
            }
        }
        if verdict.is_none() && self.db.classify_name(name).is_none() {
            if let Some(magic) = head.and_then(magic_classify) {
                for sel in &self.selections {
                    if sel.name == magic {
                        verdict = Some(if sel.negate {
                            Match::Ignore
                        } else {
                            Match::Whitelist
                        });
                    }
                }
            }
        }
        verdict.unwrap_or_else(|| {
            // Nothing the user named matched the file. With a selection
            // in hand, the file is not of a type that was asked for, so
            // it is dropped; without one, nothing excludes it.
            if self.selects() {
                Match::Ignore
            } else {
                Match::None
            }
        })
    }

    /// Whether any selection includes rather than excludes.
    fn selects(&self) -> bool {
        self.selections.iter().any(|s| !s.negate)
    }
}

impl ResolvedSel {
    /// Whether the file's name satisfies one of the type's patterns.
    fn matches_name(&self, name: &str) -> bool {
        self.patterns.iter().any(|p| pattern_matches(p, name))
    }
}

/// Whether a table pattern names this file.
///
/// The table keeps the part of ripgrep's glob that follows the star: the
/// type `rust` holds `rs` and the type `minified` holds `min.js`. A
/// pattern names a file when the file's name is the pattern itself
/// (`makefile`) or ends with a dot and the pattern (`lib.min.js`).
fn pattern_matches(pattern: &str, name: &str) -> bool {
    if name == pattern {
        return true;
    }
    name.len() > pattern.len()
        && name.ends_with(pattern)
        && name.as_bytes()[name.len() - pattern.len() - 1] == b'.'
}

/// A file's name, lowercased for the table's patterns.
///
/// The patterns are lowercased, so a name carrying an uppercase ASCII
/// byte is lowercased to meet them. A name with no uppercase is borrowed.
fn lower_basename(path: &Path) -> Option<std::borrow::Cow<'_, str>> {
    let name = path.file_name().and_then(|s| s.to_str())?;
    if name.bytes().any(|b| b.is_ascii_uppercase()) {
        Some(std::borrow::Cow::Owned(name.to_ascii_lowercase()))
    } else {
        Some(std::borrow::Cow::Borrowed(name))
    }
}

/// The type of a file from its first bytes, when its name claims none.
///
/// The magic-byte classifier lives in the `adapters-inspect` crate, and
/// the engine-only build (a CI gate in its own right) has no such
/// crate: there, a file whose name claims no type is a file of no type.
fn magic_classify(head: &[u8]) -> Option<&'static str> {
    #[cfg(feature = "adapters-inspect")]
    {
        rgx_adapters_inspect::magic_classify(head)
    }
    #[cfg(not(feature = "adapters-inspect"))]
    {
        let _ = head;
        None
    }
}

// ---------------------------------------------------------------------------
// globs
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Glob {
    only_dir: bool,
    whitelist: bool,
    absolute: bool,
}

/// A glob whose shape admits a byte comparison instead of a regex
/// run: `*.ext` and `pre*`, the two shapes whose literal part is
/// the basename's. `src/**`, `[abc]*`, `*.[ch]`, `a?b` keep the
/// regex — a shape test that is right 99% of the time is one that
/// lies once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FastShape {
    /// `*.ext` — the name ends with these bytes.
    Suffix,
    /// `pre*` — the name starts with these bytes.
    Prefix,
}

#[derive(Clone)]
struct FastGlob {
    shape: FastShape,
    bytes: Box<[u8]>,
    /// Index into `Globs::all`, so the last-match-wins rule has something to
    /// compare and so the whitelist flag can be read.
    index: u32,
}

/// The basename of a path as the OS spells it: after the last `/` or `\`.
/// No allocation, which is the entire point of this type existing.
fn basename_of(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&b| b == b'/' || b == b'\\') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

/// The globs of one ignore file, in the order they were written: the last
/// one that matches decides.
#[derive(Clone, Default)]
struct Globs {
    all: Vec<Glob>,
    files: Option<std::sync::Arc<Vec<ByteRegex>>>,
    file_of: Vec<u32>,
    dirs: Option<std::sync::Arc<Vec<ByteRegex>>>,
    dir_of: Vec<u32>,
    /// Present only when EVERY file glob is a `*.ext` or a `pre*`.
    fast_files: Option<Arc<Vec<FastGlob>>>,
}

impl Globs {
    fn is_empty(&self) -> bool {
        self.all.is_empty()
    }

    fn matched(&self, cand: &[u8], is_dir: bool) -> Match {
        let mut best: i64 = -1;
        let mut white = false;
        if let Some(set) = &self.files {
            if let Some(i) = last_matching(set, cand) {
                let g = self.file_of[i] as i64;
                best = g;
                white = self.all[g as usize].whitelist;
            }
        }
        if is_dir {
            if let Some(set) = &self.dirs {
                if let Some(i) = last_matching(set, cand) {
                    let g = self.dir_of[i] as i64;
                    if g > best {
                        best = g;
                        white = self.all[g as usize].whitelist;
                    }
                }
            }
        }
        match best {
            -1 => Match::None,
            _ if white => Match::Whitelist,
            _ => Match::Ignore,
        }
    }
}

#[derive(Default)]
struct GlobSetBuilder {
    pats: Vec<String>,
    globs: Vec<Glob>,
    lines: Vec<String>,
    unclosed: bool,
}

/// A glob that could not be compiled.
#[derive(Debug)]
pub struct GlobError {
    glob: String,
    msg: &'static str,
}

impl std::fmt::Display for GlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid glob `{}`: {}", self.glob, self.msg)
    }
}

impl std::error::Error for GlobError {}

impl GlobSetBuilder {
    fn build(&self) -> Globs {
        self.try_build().expect("glob compiled")
    }

    fn try_build(&self) -> Result<Globs, GlobError> {
        let (mut fp, mut fi, mut dp, mut di) = (vec![], vec![], vec![], vec![]);
        for (i, ((pat, line), g)) in self
            .pats
            .iter()
            .zip(&self.lines)
            .zip(&self.globs)
            .enumerate()
        {
            let re = ByteRegex::new(pat.as_bytes()).map_err(|_| GlobError {
                glob: line.clone(),
                msg: "uncompilable",
            })?;
            if g.only_dir {
                dp.push(re);
                di.push(i as u32);
            } else {
                fp.push(re);
                fi.push(i as u32);
            }
        }
        // The fast list is built only when EVERY file glob has one of
        // the two shapes, and it carries the same indices the regex
        // set carries, so `last match wins` and the whitelist flag
        // are decided the same way on both paths. One complicated
        // glob disables it for the set.
        //
        // Classified from `lines` (the glob as the user wrote it),
        // not from `pats` (the compiled regex): a pattern like
        // `*.rs` is `(?-u)^(?:/?|.*/)[^/]*\.rs$` here, and asking
        // whether that has the shape of a suffix is always no.
        let fast_files = if !fp.is_empty() {
            let mut v = Vec::with_capacity(fp.len());
            let mut ok = true;
            for (i, (line, g)) in self.lines.iter().zip(&self.globs).enumerate() {
                if g.only_dir {
                    continue;
                }
                let Some((shape, bytes)) = (!g.absolute).then(|| fast_shape(line)).flatten() else {
                    ok = false;
                    break;
                };
                v.push(FastGlob {
                    shape,
                    bytes: bytes.into_bytes().into_boxed_slice(),
                    index: i as u32,
                });
            }
            ok.then(|| Arc::new(v))
        } else {
            None
        };
        Ok(Globs {
            all: self.globs.clone(),
            files: (!fp.is_empty()).then(|| Arc::new(fp)),
            file_of: fi,
            dirs: (!dp.is_empty()).then(|| Arc::new(dp)),
            dir_of: di,
            fast_files,
        })
    }

    /// One line of a gitignore-style file. A line that will not compile is
    /// dropped, the way a broken glob never took effect.
    fn add_line(&mut self, mut line: &str) -> Result<(), GlobError> {
        if line.starts_with('#') {
            return Ok(());
        }
        if !line.ends_with("\\ ") {
            line = line.trim_end();
        }
        if line.is_empty() {
            return Ok(());
        }
        let mut whitelist = false;
        let mut absolute = false;
        if line.starts_with("\\!") || line.starts_with("\\#") {
            line = &line[1..];
            absolute = line.starts_with('/');
        } else {
            if let Some(rest) = line.strip_prefix('!') {
                whitelist = true;
                line = rest;
            }
            if let Some(rest) = line.strip_prefix('/') {
                line = rest;
                absolute = true;
            }
        }
        let mut only_dir = false;
        if line.ends_with('/') {
            only_dir = true;
            line = &line[..line.len() - 1];
            if line.ends_with('\\') {
                line = &line[..line.len() - 1];
            }
        }
        let mut actual = line.to_string();
        // A pattern with no separator matches at any depth; one
        // with a separator is anchored to the directory holding the
        // ignore file.
        if !absolute && !line.contains('/') && !is_doublestar(&actual) {
            actual = format!("**/{actual}");
        }
        // `foo/**` is everything inside foo, not foo itself.
        if actual.ends_with("/**") {
            actual = format!("{actual}/*");
        }
        let re = glob_regex(&actual, self.unclosed).ok_or_else(|| GlobError {
            glob: line.to_string(),
            msg: "unclosed character class",
        })?;
        self.pats.push(re);
        self.globs.push(Glob {
            only_dir,
            whitelist,
            absolute,
        });
        self.lines.push(line.to_string());
        Ok(())
    }
}

fn is_glob_literal(s: &str) -> bool {
    !s.is_empty()
        && !s
            .bytes()
            .any(|b| matches!(b, b'*' | b'?' | b'[' | b']' | b'{' | b'}' | b'/' | b'\\'))
}

/// The two shapes that admit a byte comparison, or `None` for
/// anything else. A glob is a suffix or prefix shape only if its
/// literal part is the basename's; everything else keeps the regex.
///
/// The leading `**/` that `add_line` prepends to a pattern with no
/// separator is stripped first: a glob of that shape IS a basename
/// shape, and leaving it in made `!~$*` — the office-lock filter,
/// which is in every query — read as an unclassifiable pattern and
/// disabled the fast path for the user's own `-g` alongside it. One
/// glob that looks complicated must not cost every other glob its
/// fast path.
fn fast_shape(pat: &str) -> Option<(FastShape, String)> {
    let pat = pat.strip_prefix("**/").unwrap_or(pat);
    if let Some(rest) = pat.strip_prefix("*.") {
        if is_glob_literal(rest) {
            return Some((FastShape::Suffix, pat[1..].to_string()));
        }
        return None;
    }
    if let Some(pre) = pat.strip_suffix('*') {
        if is_glob_literal(pre) {
            return Some((FastShape::Prefix, pre.to_string()));
        }
        return None;
    }
    None
}

/// The last fast-shape glob that matches, in the same last-wins
/// sense as `last_matching`, and only over the basename.
fn last_matching_fast(set: &[FastGlob], cand: &[u8]) -> Option<u32> {
    let name = basename_of(cand);
    set.iter()
        .rposition(|g| match g.shape {
            FastShape::Suffix => name.ends_with(&g.bytes),
            FastShape::Prefix => name.starts_with(&g.bytes),
        })
        .map(|i| set[i].index)
}

/// The last pattern in the set that matches. Backwards on purpose:
/// an ignore file's last matching line wins.
fn last_matching(set: &[ByteRegex], cand: &[u8]) -> Option<usize> {
    set.iter().rposition(|re| re.is_match_at(cand, 0))
}

fn is_doublestar(s: &str) -> bool {
    s.starts_with("**/") || s == "**"
}

// ---------------------------------------------------------------------------
// glob -> regex
// ---------------------------------------------------------------------------

enum Tok {
    Lit(char),
    Any,
    Star,
    RecPre,
    RecSuf,
    RecZero,
    Class {
        neg: bool,
        ranges: Vec<(char, char)>,
    },
    Alt(Vec<Vec<Tok>>),
}

fn glob_regex(pat: &str, unclosed: bool) -> Option<String> {
    let toks = tokenize(pat, unclosed)?;
    let mut re = String::from("(?-u)^");
    emit(&toks, &mut re);
    re.push('$');
    Some(re)
}

fn emit(toks: &[Tok], re: &mut String) {
    for t in toks {
        match t {
            Tok::Lit(c) => esc(*c, re),
            Tok::Any => re.push_str("[^/]"),
            Tok::Star => re.push_str("[^/]*"),
            Tok::RecPre => re.push_str("(?:/?|.*/)"),
            Tok::RecSuf => re.push_str("/.*"),
            Tok::RecZero => re.push_str("(?:/|/.*/)"),
            Tok::Class { neg, ranges } => {
                re.push('[');
                if *neg {
                    re.push('^');
                }
                for (a, b) in ranges {
                    esc(*a, re);
                    if a != b {
                        re.push('-');
                        esc(*b, re);
                    }
                }
                re.push(']');
            }
            Tok::Alt(parts) => {
                if !parts.is_empty() {
                    re.push_str("(?:");
                    for (i, p) in parts.iter().enumerate() {
                        if i > 0 {
                            re.push('|');
                        }
                        emit(p, re);
                    }
                    re.push(')');
                }
            }
        }
    }
}

/// Bytes, not characters: candidates are byte strings and the
/// pattern is matched with unicode mode off, so anything non-
/// alphanumeric goes out as an explicit byte escape.
fn esc(c: char, re: &mut String) {
    let mut buf = [0u8; 4];
    for b in c.encode_utf8(&mut buf).as_bytes() {
        if b.is_ascii_alphanumeric() {
            re.push(*b as char);
        } else {
            re.push_str(&format!("\\x{b:02x}"));
        }
    }
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
    prev: Option<char>,
    cur: Option<char>,
    branches: Vec<Vec<Tok>>,
    stack: Vec<usize>,
    unclosed: bool,
    unclosed_seen: bool,
}

fn is_sep(c: char) -> bool {
    std::path::is_separator(c)
}

fn tokenize(pat: &str, unclosed: bool) -> Option<Vec<Tok>> {
    let mut p = Parser {
        chars: pat.chars().collect(),
        pos: 0,
        prev: None,
        cur: None,
        branches: vec![vec![]],
        stack: vec![],
        unclosed,
        unclosed_seen: false,
    };
    while let Some(c) = p.bump() {
        match c {
            '?' => p.push(Tok::Any)?,
            '*' => p.star()?,
            '[' if !p.unclosed_seen => p.class()?,
            '{' => {
                p.stack.push(p.branches.len());
                p.branches.push(vec![]);
            }
            '}' => {
                let start = p.stack.pop()?;
                let alts: Vec<Vec<Tok>> = p.branches.drain(start..).collect();
                p.push(Tok::Alt(alts))?;
            }
            ',' if !p.stack.is_empty() => p.branches.push(vec![]),
            ',' => p.push(Tok::Lit(','))?,
            '\\' => {
                let c = p.bump()?;
                p.push(Tok::Lit(c))?
            }
            c => p.push(Tok::Lit(c))?,
        }
    }
    if !p.stack.is_empty() {
        return None;
    }
    p.branches.pop()
}

impl Parser {
    fn bump(&mut self) -> Option<char> {
        self.prev = self.cur;
        self.cur = self.chars.get(self.pos).copied();
        if self.cur.is_some() {
            self.pos += 1;
        }
        self.cur
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn push(&mut self, t: Tok) -> Option<()> {
        self.branches.last_mut()?.push(t);
        Some(())
    }

    fn pop(&mut self) -> Option<Tok> {
        self.branches.last_mut()?.pop()
    }

    fn star(&mut self) -> Option<()> {
        let prev = self.prev;
        if self.peek() != Some('*') {
            return self.push(Tok::Star);
        }
        self.bump();
        if self.branches.last().is_none_or(|b| b.is_empty()) {
            if !self.peek().is_none_or(is_sep) {
                self.push(Tok::Star)?;
                return self.push(Tok::Star);
            }
            self.push(Tok::RecPre)?;
            self.bump();
            return Some(());
        }
        if !prev.is_some_and(is_sep)
            && (self.branches.len() <= 1 || (prev != Some(',') && prev != Some('{')))
        {
            self.push(Tok::Star)?;
            return self.push(Tok::Star);
        }
        let suffix = match self.peek() {
            None => {
                self.bump();
                true
            }
            Some(',') | Some('}') if self.branches.len() >= 2 => true,
            Some(c) if is_sep(c) => {
                self.bump();
                false
            }
            _ => {
                self.push(Tok::Star)?;
                return self.push(Tok::Star);
            }
        };
        match self.pop()? {
            Tok::RecPre => self.push(Tok::RecPre),
            Tok::RecSuf => self.push(Tok::RecSuf),
            _ if suffix => self.push(Tok::RecSuf),
            _ => self.push(Tok::RecZero),
        }
    }

    fn class(&mut self) -> Option<()> {
        let saved: Vec<char> = self.chars.clone();
        let saved_pos = self.pos;
        let saved_prev = self.prev;
        let saved_cur = self.cur;
        let neg = matches!(self.peek(), Some('!') | Some('^'));
        if neg {
            self.bump();
        }
        let mut ranges: Vec<(char, char)> = vec![];
        let mut first = true;
        let mut in_range = false;
        loop {
            let Some(c) = self.bump() else {
                if self.unclosed {
                    // An unterminated `[` is a literal; nothing after
                    // it can start another class.
                    self.chars = saved;
                    self.pos = saved_pos;
                    self.prev = saved_prev;
                    self.cur = saved_cur;
                    self.unclosed_seen = true;
                    return self.push(Tok::Lit('['));
                }
                return None;
            };
            match c {
                ']' if first => {
                    ranges.push((']', ']'));
                    first = false;
                }
                ']' => break,
                '-' if first => {
                    ranges.push(('-', '-'));
                    first = false;
                }
                '-' if in_range => {
                    let r = ranges.last_mut()?;
                    r.1 = c;
                    if r.1 < r.0 {
                        return None;
                    }
                    in_range = false;
                    first = false;
                }
                '-' => in_range = true,
                c => {
                    if in_range {
                        let r = ranges.last_mut()?;
                        r.1 = c;
                        if r.1 < r.0 {
                            return None;
                        }
                    } else {
                        ranges.push((c, c));
                    }
                    in_range = false;
                    first = false;
                }
            }
        }
        if in_range {
            ranges.push(('-', '-'));
        }
        self.push(Tok::Class { neg, ranges })
    }
}

// ---------------------------------------------------------------------------
// ignore files
// ---------------------------------------------------------------------------

/// One ignore file, `.gitignore` syntax.
fn read_globs(path: &Path) -> Globs {
    let Ok(bytes) = std::fs::read(path) else {
        return Globs::default();
    };
    // A byte that is not UTF-8 ends the file, as it does for the
    // oracle.
    let text = match String::from_utf8(bytes) {
        Ok(t) => t,
        Err(e) => {
            let upto = e.utf8_error().valid_up_to();
            String::from_utf8_lossy(&e.into_bytes()[..upto]).into_owned()
        }
    };
    let mut b = GlobSetBuilder {
        unclosed: true,
        ..Default::default()
    };
    for (i, line) in text.lines().enumerate() {
        let line = if i == 0 {
            line.trim_start_matches('\u{feff}')
        } else {
            line
        };
        let _ = b.add_line(line);
    }
    b.build()
}

/// `core.excludesfile` out of a git config file.
fn excludes_from_config(data: &[u8]) -> Option<PathBuf> {
    let text = std::str::from_utf8(data).ok()?;
    for line in text.lines() {
        let Some(rest) = strip_prefix_ci(line.trim_start(), "excludesfile") else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        let v = rest.trim();
        let v = v.strip_prefix('"').unwrap_or(v);
        let v = match v.rfind('"') {
            Some(i) if v[i + 1..].trim().is_empty() => &v[..i],
            _ => v,
        };
        let v = v.trim();
        if v.is_empty() || v.contains(char::is_whitespace) {
            continue;
        }
        return Some(PathBuf::from(expand_tilde(v)));
    }
    None
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let (a, b) = (s.as_bytes(), prefix.as_bytes());
    if a.len() < b.len() || !a[..b.len()].eq_ignore_ascii_case(b) {
        return None;
    }
    Some(&s[b.len()..])
}

static READ_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static READ_PATTERNS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static READ_NANOS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Print the `read_globs` tally on exit. Off unless `RGX_WALK_STATS`
/// is set, and never part of a published timing.
pub fn print_walk_stats() {
    if std::env::var_os("RGX_WALK_STATS").is_none() {
        return;
    }
    use std::sync::atomic::Ordering::Relaxed;
    let calls = READ_CALLS.load(Relaxed);
    let patterns = READ_PATTERNS.load(Relaxed);
    let nanos = READ_NANOS.load(Relaxed);
    eprintln!(
        "rgx walk stats: read_globs {calls} calls, {patterns} patterns, {:.2} ms total, \
         {:.1} us/pattern",
        nanos as f64 / 1e6,
        if patterns > 0 {
            nanos as f64 / 1000.0 / patterns as f64
        } else {
            0.0
        }
    );
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .or_else(|| std::env::var_os("USERPROFILE").filter(|h| !h.is_empty()))
        .map(PathBuf::from)
}

fn expand_tilde(path: &str) -> String {
    match home_dir() {
        Some(h) => path.replace('~', &h.to_string_lossy()),
        None => path.to_string(),
    }
}

fn read_config(p: &Path) -> Option<PathBuf> {
    excludes_from_config(&std::fs::read(p).ok()?)
}

fn xdg_config() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|x| !x.is_empty())
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|h| h.join(".config")))
}

fn global_gitignore_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("GIT_CONFIG_GLOBAL")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .and_then(|p| read_config(&p))
    {
        return Some(p);
    }
    if let Some(p) = home_dir().and_then(|h| read_config(&h.join(".gitconfig"))) {
        return Some(p);
    }
    if let Some(p) = xdg_config().and_then(|x| read_config(&x.join("git/config"))) {
        return Some(p);
    }
    if let Some(p) = std::env::var_os("GIT_CONFIG_SYSTEM")
        .map(PathBuf::from)
        .and_then(|p| read_config(&p))
        .or_else(|| read_config(Path::new("/etc/gitconfig")))
    {
        return Some(p);
    }
    xdg_config().map(|x| x.join("git/ignore"))
}

// ---------------------------------------------------------------------------
// overrides
// ---------------------------------------------------------------------------

/// The verdict of a match. `Whitelist` re-includes, `Ignore` drops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    None,
    Ignore,
    Whitelist,
}

impl Match {
    /// Whether the path is dropped.
    pub fn is_ignore(self) -> bool {
        self == Match::Ignore
    }
}

/// Globs named on the command line. `!` inverts: a bare glob
/// whitelists, a `!` glob ignores, and a file matching no whitelist
/// glob is ignored.
#[derive(Clone, Default)]
pub struct Override {
    globs: Globs,
    includes: usize,
}

impl Override {
    /// A matcher that never matches.
    pub fn empty() -> Override {
        Override::default()
    }

    pub fn is_empty(&self) -> bool {
        self.globs.is_empty()
    }

    /// The verdict for a path as the OS spells it.
    pub fn matched(&self, path: &Path, is_dir: bool) -> Match {
        if self.is_empty() {
            return Match::None;
        }
        // The fast shapes read the basename straight out of the path as the
        // OS spells it, so they skip the separator rewrite below -- a heap
        // allocation per file on Windows -- and produce the same verdict the
        // rewrite would have, because both end in `matched_str`.
        if !is_dir && self.globs.fast_files.is_some() {
            if let Some(s) = path.to_str() {
                return self.matched_str(s.strip_prefix("./").unwrap_or(s), is_dir);
            }
        }
        let s = path.to_string_lossy();
        #[cfg(windows)]
        let s = if s.contains('\\') {
            std::borrow::Cow::Owned(s.replace('\\', "/"))
        } else {
            s
        };
        #[cfg(not(windows))]
        let s = s.into_owned();
        self.matched_str(s.strip_prefix("./").unwrap_or(&s), is_dir)
    }

    /// The verdict for a path already in candidate form: `/` separated, no
    /// leading `./`.
    fn matched_str(&self, path: &str, is_dir: bool) -> Match {
        if self.is_empty() {
            return Match::None;
        }
        // The fast shapes answer the whole question -- a match, no match, and
        // the "no whitelist matched" rule that follows from it -- so this
        // RETURNS rather than falling through to the regex. Falling through
        // runs both, which is what made a glob that matches nothing
        // (`-g 'zzz*'`) cost 1.6x the listing while `-g '*.rs'` cost
        // nothing at all.
        //
        // The inversion is the one below, stated the other way round:
        // `Globs::matched` answers Whitelist for a glob written with `!`,
        // and a `!` glob drops the path here.
        if !is_dir {
            if let Some(fast) = &self.globs.fast_files {
                return match last_matching_fast(fast, path.as_bytes()) {
                    Some(g) if self.globs.all[g as usize].whitelist => Match::Ignore,
                    Some(_) => Match::Whitelist,
                    None if self.includes > 0 => Match::Ignore,
                    None => Match::None,
                };
            }
        }
        let m = match self.globs.matched(path.as_bytes(), is_dir) {
            Match::None => Match::None,
            Match::Ignore => Match::Whitelist,
            Match::Whitelist => Match::Ignore,
        };
        if m == Match::None && self.includes > 0 && !is_dir {
            return Match::Ignore;
        }
        m
    }
}

/// Builds an [`Override`].
pub struct OverrideBuilder {
    b: GlobSetBuilder,
}

impl OverrideBuilder {
    /// Candidates are matched exactly as given, so the root is notional.
    pub fn new<P: AsRef<Path>>(_path: P) -> OverrideBuilder {
        OverrideBuilder {
            b: GlobSetBuilder {
                unclosed: false,
                ..Default::default()
            },
        }
    }

    /// Add one glob; a leading `!` makes it an ignore.
    pub fn add(&mut self, glob: &str) -> Result<&mut OverrideBuilder, GlobError> {
        self.b.add_line(glob)?;
        Ok(self)
    }

    pub fn build(&self) -> Result<Override, GlobError> {
        Ok(Override {
            includes: self.b.globs.iter().filter(|g| !g.whitelist).count(),
            globs: self.b.try_build()?,
        })
    }
}

// ---------------------------------------------------------------------------
// the ignore chain
// ---------------------------------------------------------------------------

/// The path space the rules of the directories above the walk
/// root live in: the oracle rewrites every candidate onto the
/// canonicalized root before consulting them, and the global
/// gitignore onto the working directory.
struct AbsBase {
    canon_root: String,
    root_skip: usize,
}

struct Node {
    parent: Option<Arc<Node>>,
    dir: PathBuf,
    /// One of the directories above the walk root.
    abs: bool,
    has_git: bool,
    any_git: bool,
    /// Bytes to drop off the front of a candidate to make it relative to
    /// this directory.
    skip: usize,
    ignore: Globs,
    git_ignore: Globs,
    git_exclude: Globs,
    absbase: Option<Arc<AbsBase>>,
}

impl Node {
    fn root() -> Arc<Node> {
        Arc::new(Node {
            parent: None,
            dir: PathBuf::new(),
            abs: true,
            has_git: false,
            any_git: false,
            skip: 0,
            ignore: Globs::default(),
            git_ignore: Globs::default(),
            git_exclude: Globs::default(),
            absbase: None,
        })
    }

    /// The kind of file decides before the depth does: a whitelist
    /// in `.ignore` outranks an ignore in a shallower `.gitignore`.
    /// Within one kind the deepest directory wins, and nothing above
    /// the repository root is consulted.
    fn matched_ignore(&self, ctx: &Ctx, cand: &str, is_dir: bool, scratch: &mut String) -> Match {
        let any_git = self.any_git;
        let (mut m_ignore, mut m_gi, mut m_ex) = (Match::None, Match::None, Match::None);
        let mut saw_git = false;
        let mut node = Some(self);
        let mut absolute = false;
        let mut abs_built = false;
        let cand_bytes = cand.as_bytes();
        while let Some(nd) = node {
            let c: &[u8] = if nd.abs {
                absolute = true;
                let a = match self.absbase.as_deref() {
                    Some(a) => a,
                    None => break,
                };
                if !abs_built {
                    // Reuse the caller's buffer rather than
                    // allocating: `absbase` is `Some` whenever any
                    // directory above the walk root has an ignore
                    // file or the machine has a global gitignore,
                    // and `global_gitignore_path` falls back to
                    // `~/.config/git/ignore`, so on most machines
                    // that is every walk and every file in it.
                    scratch.clear();
                    scratch.reserve(a.canon_root.len() + 1 + cand.len());
                    scratch.push_str(&a.canon_root);
                    scratch.push('/');
                    scratch.push_str(&cand[a.root_skip.min(cand.len())..]);
                    abs_built = true;
                }
                // A parent's rules are anchored to the parent's own
                // directory: git matches `dir/.gitignore` against the
                // path *below* `dir`, and an anchored pattern (any
                // pattern with a `/`) can never match a candidate that
                // still carries the absolute prefix above it. The
                // unsliced absolute form is kept for the global
                // gitignore block below, which is anchored to the
                // working directory instead — so `a/*.skip` in the
                // repository root now ignores `foo.skip` when the walk
                // starts inside `a`, the way git and ripgrep answer.
                slice(scratch.as_bytes(), nd.skip)
            } else {
                if absolute {
                    break;
                }
                slice(cand_bytes, nd.skip)
            };
            if m_ignore == Match::None {
                m_ignore = nd.ignore.matched(c, is_dir);
            }
            if any_git && !saw_git && m_gi == Match::None {
                m_gi = nd.git_ignore.matched(c, is_dir);
            }
            if any_git && !saw_git && m_ex == Match::None {
                m_ex = nd.git_exclude.matched(c, is_dir);
            }
            saw_git = saw_git || nd.has_git;
            node = nd.parent.as_deref();
        }
        if m_ignore != Match::None {
            return m_ignore;
        }
        if m_gi != Match::None {
            return m_gi;
        }
        if m_ex != Match::None {
            return m_ex;
        }
        if any_git && !ctx.global.is_empty() {
            let c: &[u8] = if abs_built {
                scratch.as_bytes()
            } else if let Some(a) = self.absbase.as_deref() {
                scratch.clear();
                scratch.reserve(a.canon_root.len() + 1 + cand.len());
                scratch.push_str(&a.canon_root);
                scratch.push('/');
                scratch.push_str(&cand[a.root_skip.min(cand.len())..]);
                scratch.as_bytes()
            } else {
                cand_bytes
            };
            let c = strip_dir(&ctx.cwd_norm, c);
            let m = ctx.global.matched(c, is_dir);
            if m != Match::None {
                return m;
            }
        }
        Match::None
    }
}

fn slice(cand: &[u8], skip: usize) -> &[u8] {
    &cand[skip.min(cand.len())..]
}

fn strip_dir<'a>(dir: &str, cand: &'a [u8]) -> &'a [u8] {
    if dir.is_empty() || dir == "." || !cand.starts_with(dir.as_bytes()) {
        return cand;
    }
    let rest = &cand[dir.len()..];
    match rest.strip_prefix(b"/") {
        Some(r) => r,
        None => rest,
    }
}

// ---------------------------------------------------------------------------
// walking
// ---------------------------------------------------------------------------

/// What the callback says about an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkState {
    /// Keep going.
    Continue,
    /// Stop the whole walk.
    Quit,
}

/// One file or directory seen by the walk.
pub struct DirEntry<'a> {
    path: &'a Path,
    ty: Option<FileType>,
    follow: bool,
    md: OnceCell<io::Result<Metadata>>,
}

impl<'a> DirEntry<'a> {
    /// The path as the OS spells it.
    pub fn path(&self) -> &Path {
        self.path
    }

    /// The file type, or `None` when it could not be read.
    pub fn file_type(&self) -> Option<FileType> {
        self.ty
    }

    /// Metadata, stat'ed once and kept.
    pub fn metadata(&self) -> io::Result<&Metadata> {
        let r = self.md.get_or_init(|| {
            if self.follow {
                std::fs::metadata(self.path)
            } else {
                std::fs::symlink_metadata(self.path)
            }
        });
        match r {
            Ok(m) => Ok(m),
            Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
        }
    }
}

/// Builds a [`WalkParallel`].
pub struct Builder {
    paths: Vec<PathBuf>,
    hidden: bool,
    parents: bool,
    git_ignore: bool,
    git_global: bool,
    git_exclude: bool,
    follow_links: bool,
    max_depth: Option<usize>,
    overrides: Override,
    /// Globs added through [`Builder::add_glob`], kept verbatim so a
    /// second call rebuilds the filter set with the full history
    /// rather than just the latest entry. Compiled into byte regexes
    /// in `build_parallel` and consulted against each file entry's
    /// path relative to the walk root — not the override
    /// mechanism, which sees the absolute path and does not know
    /// what the root was.
    user_globs: Vec<String>,
    /// Type filter (extension-based) and the include/exclude sets,
    /// if any. `None` when no `-t`/`-T` was specified, which makes
    /// the per-entry check a no-op for the common case.
    type_filter: Option<TypeFilter>,
    threads: usize,
    /// Emit in sorted path order, single-threaded. `--sort path`
    /// sets this on the search path: a walk that is already ordered
    /// needs no buffer at the printer at all, which is what keeps the
    /// flag's memory cost proportional to one directory rather than to
    /// every matched file. The listing path does not use it -- that
    /// route sorts through `SortedSink` and stays parallel.
    ordered: bool,
    /// Walk the sorted order backwards (`--sortr path`).
    ordered_reverse: bool,
}

impl Builder {
    pub fn new<P: AsRef<Path>>(path: P) -> Builder {
        Builder {
            paths: vec![path.as_ref().to_path_buf()],
            hidden: true,
            parents: true,
            git_ignore: true,
            git_global: true,
            git_exclude: true,
            follow_links: false,
            max_depth: None,
            overrides: Override::empty(),
            user_globs: Vec::new(),
            type_filter: None,
            threads: 0,
            ordered: false,
            ordered_reverse: false,
        }
    }

    pub fn add<P: AsRef<Path>>(&mut self, path: P) -> &mut Builder {
        self.paths.push(path.as_ref().to_path_buf());
        self
    }

    /// Skip entries whose name starts with `.` and (on Windows)
    /// those with the hidden attribute set.
    pub fn hidden(&mut self, yes: bool) -> &mut Builder {
        self.hidden = yes;
        self
    }

    /// Honour the ignore files of the directories above the walk root.
    pub fn parents(&mut self, yes: bool) -> &mut Builder {
        self.parents = yes;
        self
    }

    pub fn git_ignore(&mut self, yes: bool) -> &mut Builder {
        self.git_ignore = yes;
        self
    }

    pub fn git_global(&mut self, yes: bool) -> &mut Builder {
        self.git_global = yes;
        self
    }

    pub fn git_exclude(&mut self, yes: bool) -> &mut Builder {
        self.git_exclude = yes;
        self
    }

    pub fn follow_links(&mut self, yes: bool) -> &mut Builder {
        self.follow_links = yes;
        self
    }

    pub fn max_depth(&mut self, depth: Option<usize>) -> &mut Builder {
        self.max_depth = depth;
        self
    }

    pub fn overrides(&mut self, o: Override) -> &mut Builder {
        self.overrides = o;
        self
    }

    /// Append one CLI `-g` glob to the file-entry filter. A pattern
    /// that does not compile is dropped the way a broken ignore line
    /// is — the builder keeps what it has.
    pub fn add_glob(&mut self, glob: &str) -> &mut Builder {
        self.user_globs.push(glob.to_string());
        self
    }

    pub fn threads(&mut self, n: usize) -> &mut Builder {
        self.threads = n;
        self
    }

    /// Walk single-threaded, emitting entries in sorted path order.
    ///
    /// The sort key is the `/`-separated candidate with a trailing
    /// separator on directories, so a directory's whole subtree sorts
    /// under its own prefix and a plain `a.txt` sorts before `a/b.txt`
    /// -- byte-wise full-path order, the same comparison
    /// `SortedSink` applies to the listing path. `reverse` walks it
    /// backwards, which is `--sortr path` without buffering. `threads`
    /// is ignored while this is set: an ordered walk with two workers
    /// would interleave the branches again.
    pub fn ordered(&mut self, reverse: bool) -> &mut Builder {
        self.ordered = true;
        self.ordered_reverse = reverse;
        self
    }

    /// Install a file-type filter built from the user's `-t`/`-T`
    /// flags and any `--type-add`/`--type-clear` edits applied so
    /// far. Pass `None` to disable the filter (the default).
    pub fn type_filter(&mut self, f: TypeFilter) -> &mut Builder {
        self.type_filter = Some(f);
        self
    }

    pub fn build_parallel(&self) -> WalkParallel {
        let global = if self.git_global {
            global_gitignore_path()
                .filter(|p| p.is_file())
                .map(|p| read_globs(&p))
                .unwrap_or_default()
        } else {
            Globs::default()
        };
        let user_globs = compile_user_globs(&self.user_globs);
        WalkParallel {
            paths: self.paths.clone(),
            hidden: self.hidden,
            parents: self.parents,
            git_ignore: self.git_ignore,
            git_exclude: self.git_exclude,
            follow_links: self.follow_links,
            max_depth: self.max_depth,
            overrides: Arc::new(self.overrides.clone()),
            user_globs,
            type_filter: self.type_filter.clone(),
            global: Arc::new(global),
            cwd_norm: std::env::current_dir()
                .map(|c| norm(&c))
                .unwrap_or_default(),
            threads: if self.threads > 0 {
                self.threads
            } else {
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(4)
            },
            ordered: self.ordered,
            ordered_reverse: self.ordered_reverse,
        }
    }
}

/// Compile the user `-g` globs into the [`Override`] `run_one`
/// consults. Reuses [`OverrideBuilder::add`] so a pattern that
/// fails to compile is dropped the way a broken ignore line is —
/// the builder keeps what it has, and leading `!` exclusions work
/// the same way they do on the CLI. Wrapped in `Arc` so the per-
/// thread matcher is a clone of the pointer, not of every regex.
fn compile_user_globs(globs: &[String]) -> Option<Arc<Override>> {
    if globs.is_empty() {
        return None;
    }
    let mut b = OverrideBuilder::new(".");
    for g in globs {
        let _ = b.add(g);
    }
    b.build().ok().filter(|o| !o.is_empty()).map(Arc::new)
}

struct Ctx {
    hidden: bool,
    parents: bool,
    git_ignore: bool,
    git_exclude: bool,
    follow_links: bool,
    max_depth: Option<usize>,
    overrides: Arc<Override>,
    user_globs: Option<Arc<Override>>,
    type_filter: Option<TypeFilter>,
    global: Arc<Globs>,
    cwd_norm: String,
}

/// A parallel walk.
pub struct WalkParallel {
    paths: Vec<PathBuf>,
    hidden: bool,
    parents: bool,
    git_ignore: bool,
    git_exclude: bool,
    follow_links: bool,
    max_depth: Option<usize>,
    overrides: Arc<Override>,
    user_globs: Option<Arc<Override>>,
    type_filter: Option<TypeFilter>,
    global: Arc<Globs>,
    cwd_norm: String,
    threads: usize,
    ordered: bool,
    ordered_reverse: bool,
}

impl WalkParallel {
    /// Walk every root, asking `mkf` for a fresh callback per thread.
    pub fn run<F>(&self, mut mkf: F)
    where
        F: FnMut() -> Box<dyn FnMut(&DirEntry<'_>) -> WalkState + Send + 'static> + Send,
    {
        // An ordered walk needs one visitor and no deque: two workers
        // would interleave the branches again and the order would be
        // the pool's, not the path's.
        if self.ordered {
            let mut visit = mkf();
            self.run_ordered(&mut *visit);
            return;
        }
        let mut init: Vec<Vec<Work>> = vec![];
        for p in &self.paths {
            if p == Path::new("-") {
                continue;
            }
            let Ok(md) = std::fs::metadata(p) else {
                continue;
            };
            let (path, norm) = clean(p);
            let skip = offset(&norm);
            // The root's own offset is the byte length at which its
            // path ends plus one for the separator that follows; for
            // every entry beneath the root, slicing `norm` at this
            // offset yields the path relative to the root. The user-
            // glob filter consults exactly that form, which is why
            // `a/*.txt` from the CLI matches `a/file1.txt`
            // regardless of where the root lives on disk.
            let root_skip = skip;
            // A root is a batch of one, and each one is stat'ed up
            // front so that a path that is not there costs nothing.
            init.push(vec![Work {
                path,
                norm,
                skip,
                root_skip,
                ty: Some(md.file_type()),
                follow: false,
                md: None,
                depth: 0,
                ig: Node::root(),
            }]);
        }
        if init.is_empty() {
            return;
        }
        let ctx = Arc::new(Ctx {
            hidden: self.hidden,
            parents: self.parents,
            git_ignore: self.git_ignore,
            git_exclude: self.git_exclude,
            follow_links: self.follow_links,
            max_depth: self.max_depth,
            overrides: Arc::clone(&self.overrides),
            user_globs: self.user_globs.as_ref().map(Arc::clone),
            type_filter: self.type_filter.clone(),
            global: Arc::clone(&self.global),
            cwd_norm: self.cwd_norm.clone(),
        });
        let (pool, workers) = Pool::make(self.threads, init);
        let mut visitors = Vec::with_capacity(self.threads);
        for _ in 0..self.threads {
            visitors.push(mkf());
        }
        let mut workers = workers.into_iter();
        std::thread::scope(|s| {
            for (me, visit) in visitors.into_iter().enumerate() {
                let pool = Arc::clone(&pool);
                let ctx = Arc::clone(&ctx);
                // Each thread owns its own `Worker`. The Stealers live in
                // the shared Pool; the Workers were built in the
                // parent scope so the Stealers could be collected up
                // front, and are now transferred into the spawn
                // closure one by one. (`Worker<T>: Send` but not
                // `Sync` — it has internal `Cell` and raw-pointer
                // fields for its growing buffer, and the chase-lev
                // protocol relies on a single owner.)
                let worker = workers.next().expect("worker");
                s.spawn(move || {
                    let mut visit = visit;
                    while let Some(dir) = pool.take_dir(me, &worker) {
                        // Released on unwind too, or a panicking
                        // callback would leave the other workers
                        // waiting forever.
                        let _active = Active(&pool);
                        for work in dir {
                            if pool.quit() {
                                break;
                            }
                            if run_one(&ctx, &pool, &worker, work, &mut *visit) == WalkState::Quit {
                                pool.stop();
                            }
                        }
                    }
                });
            }
        });
    }

    /// Sorted depth-first walk over every root, one entry at a time.
    ///
    /// The set of files that reaches the visitor is exactly the set the
    /// parallel walk shows -- `accept_child` is shared -- and only the
    /// order differs. Roots are visited in sorted order too, so a
    /// command naming `b` then `a` still emits `a` first.
    fn run_ordered(&self, visit: &mut dyn FnMut(&DirEntry<'_>) -> WalkState) {
        let ctx = Arc::new(Ctx {
            hidden: self.hidden,
            parents: self.parents,
            git_ignore: self.git_ignore,
            git_exclude: self.git_exclude,
            follow_links: self.follow_links,
            max_depth: self.max_depth,
            overrides: Arc::clone(&self.overrides),
            user_globs: self.user_globs.as_ref().map(Arc::clone),
            type_filter: self.type_filter.clone(),
            global: Arc::clone(&self.global),
            cwd_norm: self.cwd_norm.clone(),
        });
        let mut roots: Vec<Work> = Vec::new();
        for p in &self.paths {
            if p == Path::new("-") {
                continue;
            }
            let Ok(md) = std::fs::metadata(p) else {
                continue;
            };
            let (path, norm) = clean(p);
            let skip = offset(&norm);
            roots.push(Work {
                path,
                norm,
                skip,
                root_skip: skip,
                ty: Some(md.file_type()),
                follow: false,
                md: None,
                depth: 0,
                ig: Node::root(),
            });
        }
        roots.sort_by(|a, b| {
            let ka = entry_key(&a.norm, a.ty);
            let kb = entry_key(&b.norm, b.ty);
            if self.ordered_reverse {
                kb.cmp(&ka)
            } else {
                ka.cmp(&kb)
            }
        });
        for w in roots {
            if walk_ordered_dir(&ctx, w, self.ordered_reverse, visit) == WalkState::Quit {
                return;
            }
        }
    }
}

/// One directory of the ordered walk. Visits the entry itself, then
/// its children in sorted order, recursing depth-first.
fn walk_ordered_dir(
    ctx: &Ctx,
    mut work: Work,
    reverse: bool,
    visit: &mut dyn FnMut(&DirEntry<'_>) -> WalkState,
) -> WalkState {
    if !work.ty.is_some_and(|t| t.is_dir()) {
        // A root named on the command line that is a file goes through
        // the same filters `run_one` applies to a file entry.
        if let Some(ug) = ctx.user_globs.as_ref() {
            let relative = work.norm.get(work.root_skip..).unwrap_or("");
            if ug.matched_str(relative, false) == Match::Ignore {
                return WalkState::Continue;
            }
        }
        if work.depth == 0 {
            if let Some(tf) = ctx.type_filter.as_ref() {
                let basename = work
                    .norm
                    .rsplit_once('/')
                    .map(|(_, tail)| tail)
                    .unwrap_or(work.norm.as_str());
                let path = Path::new(basename);
                let ok = match tf.classify_verdict(path) {
                    Some(v) => v,
                    None => tf.accepts_with_bytes(path, &peek_head(&work.path)),
                };
                if !ok {
                    return WalkState::Continue;
                }
            }
        }
        let entry = entry(&mut work);
        return visit(&entry);
    }
    if work.depth == 0 && ctx.parents {
        work.ig = add_parents(ctx, &work);
    }
    let entry = entry(&mut work);
    if visit(&entry) == WalkState::Quit {
        return WalkState::Quit;
    }
    if ctx.max_depth.is_some_and(|m| work.depth >= m) {
        return WalkState::Continue;
    }
    let Ok(rd) = std::fs::read_dir(&work.path) else {
        return WalkState::Continue;
    };
    let want_meta = ctx.hidden;
    let (mut entries, found) = collect(rd, want_meta);
    let node = build_node(ctx, &work.ig, &work, &found);
    let mut scratch = String::with_capacity(work.norm.len() + 64);
    if !work.norm.is_empty() {
        scratch.push_str(&work.norm);
        scratch.push('/');
    }
    let base_len = scratch.len();
    let mut abs_scratch = String::new();
    // The sort key is built from the name and the entry's type only:
    // the parent prefix is identical for every entry here, and the
    // trailing separator on a directory is what orders a subtree
    // against a sibling file. `collect` has already run, so the type
    // is known without a second stat.
    entries.sort_by(|a, b| {
        let ka = entry_key(&a.0, a.1);
        let kb = entry_key(&b.0, b.1);
        if reverse {
            kb.cmp(&ka)
        } else {
            ka.cmp(&kb)
        }
    });
    for (name, ty, md) in entries {
        let child = match accept_child(
            ctx,
            &node,
            &mut work,
            name,
            ty,
            md,
            &mut scratch,
            base_len,
            &mut abs_scratch,
        ) {
            Some(c) => c,
            None => continue,
        };
        if walk_ordered_dir(ctx, child, reverse, visit) == WalkState::Quit {
            return WalkState::Quit;
        }
    }
    WalkState::Continue
}

/// Sort key of one directory entry: `name`, plus a trailing `/` when
/// the entry is a directory.
fn entry_key(name: &str, ty: Option<FileType>) -> String {
    let mut s = String::with_capacity(name.len() + 1);
    s.push_str(name);
    if ty.is_some_and(|t| t.is_dir()) {
        s.push('/');
    }
    s
}

/// Filter one directory entry and build the `Work` for it, or `None`
/// when the entry is rejected.
///
/// Split out of the walk loops so the parallel driver and the
/// ordered single-threaded one share exactly one copy of the
/// acceptance rules -- a filter that drifts between them would make
/// `--sort path` search a different set of files than the default.
/// `scratch` holds the candidate the ignore rules are about to read
/// and `abs_scratch` the absolute form of the same entry; both are
/// caller-owned so the per-entry reuse survives the extraction.
/// `base_len` is the length `scratch` must be restored to after the
/// entry is handled -- the caller appends `name` at that offset.
#[allow(clippy::too_many_arguments)]
fn accept_child(
    ctx: &Ctx,
    node: &Arc<Node>,
    work: &mut Work,
    name: String,
    mut ty: Option<FileType>,
    mut md: Option<Metadata>,
    scratch: &mut String,
    base_len: usize,
    abs_scratch: &mut String,
) -> Option<Work> {
    // `path` is the joined parent/child. Most entries don't follow
    // symlinks, so the join is paid for *after* `skip_entry`
    // accepts the entry: the rejected 19 996 of 20 000 in a flat
    // tree never see a PathBuf allocation. The follow-links arm
    // joins eagerly because `metadata` and the cycle check need
    // a real path, but that branch is off by default and the
    // symlink check filters the rest of the flow.
    let mut follow = false;
    let mut is_dir = ty.is_some_and(|t| t.is_dir());
    // `eager_path` is set ONLY on the follow-links arm, where
    // `metadata` and the cycle check need a real path. The
    // default arm never reads it: `Option<PathBuf>` keeps the
    // same size and avoids the `PathBuf::new()` call entirely.
    let eager_path: Option<PathBuf> = if ctx.follow_links && ty.is_some_and(|t| t.is_symlink()) {
        follow = true;
        let p = work.path.join(&name);
        match std::fs::metadata(&p) {
            Ok(m) => {
                ty = Some(m.file_type());
                is_dir = m.is_dir();
                md = Some(m);
            }
            Err(_) => return None,
        }
        if is_dir && is_loop(node, &p) {
            return None;
        }
        Some(p)
    } else {
        None
    };
    // The `-t`/`-T` filter checks the basename of FILE entries (never
    // directories — pruning a directory would drop every matching file
    // beneath it) before any allocation, so a type that excludes an
    // entire family (e.g. `-T minified` on a tree of mostly vendored
    // JS) pays zero per entry past this point. When the extension path
    // cannot classify the file at all (`None`), defer `peek_head`
    // until after `skip_entry` so hidden and `.gitignore`d files are
    // never opened.
    let mut need_type_peek = false;
    if !is_dir {
        if let Some(tf) = ctx.type_filter.as_ref() {
            match tf.classify_verdict(Path::new(&name)) {
                Some(true) => {}
                Some(false) => return None,
                None => need_type_peek = true,
            }
        }
    }
    // Build the path AFTER `skip_entry` accepts the entry. The
    // follow-links arm already owns one in `eager_path`; reuse
    // it instead of joining twice. The default arm pays the
    // join only for entries that make it past every filter, so
    // the rejected entries in a flat tree never see this. The
    // root arm (work.norm empty) still moves `name` into the
    // candidate and into the join, so the per-entry name clone
    // is gone.
    let (path, norm) = if work.norm.is_empty() {
        if skip_entry(ctx, node, &name, is_dir, &name, md.as_ref(), abs_scratch) {
            return None;
        }
        let p = match eager_path {
            Some(p) => p,
            None => work.path.join(&name),
        };
        (p, name)
    } else {
        scratch.truncate(base_len);
        scratch.push_str(&name);
        if skip_entry(ctx, node, scratch, is_dir, &name, md.as_ref(), abs_scratch) {
            return None;
        }
        // Only allocate the heap copy of the joined path once we know
        // the entry is accepted. `scratch` is a per-thread
        // reusable buffer that is overwritten on the next
        // iteration; without `clone()` here, a `.gitignore`
        // match would still pay for the join just to throw the
        // String away. The hot path is the rejected entries.
        let p = match eager_path {
            Some(p) => p,
            None => work.path.join(&name),
        };
        (p, scratch.clone())
    };
    if need_type_peek {
        if let Some(tf) = ctx.type_filter.as_ref() {
            let basename = norm
                .rsplit_once('/')
                .map(|(_, tail)| tail)
                .unwrap_or(norm.as_str());
            if !tf.accepts_with_bytes(Path::new(basename), &peek_head(&path)) {
                return None;
            }
        }
    }
    let skip = offset(&norm);
    // The root skip is fixed at the walk's start; the
    // descendant never recomputes it, because `Work::skip`
    // (the directory-local offset) is what changes per
    // level. The `add_glob` filter only needs the
    // root-relative slice, so it reads `Work::root_skip`.
    Some(Work {
        path,
        norm,
        skip,
        root_skip: work.root_skip,
        ty,
        follow,
        md,
        depth: work.depth + 1,
        ig: Arc::clone(node),
    })
}

struct Work {
    path: PathBuf,
    norm: String,
    skip: usize,
    /// Offset at which `WORK.norm` becomes the path relative to the
    /// walk root. Set once when the root work item is built and
    /// propagated unchanged to every descendant, so
    /// `WORK.norm[WORK.root_skip..]` always spells the root-relative
    /// form — what the `add_glob` filter matches against.
    /// `Work::skip` is *not* this: it is the offset for the
    /// *current* directory's own path, recomputed per entry.
    root_skip: usize,
    ty: Option<FileType>,
    follow: bool,
    md: Option<Metadata>,
    depth: usize,
    ig: Arc<Node>,
}

fn run_one(
    ctx: &Ctx,
    pool: &Pool,
    worker: &Deque<Vec<Work>>,
    mut work: Work,
    visit: &mut dyn FnMut(&DirEntry<'_>) -> WalkState,
) -> WalkState {
    if !work.ty.is_some_and(|t| t.is_dir()) {
        // File entries that fail every user `-g` glob are dropped
        // here, before the callback sees them. Directories are not
        // filtered: a pattern with a path component like `a/*.txt`
        // cannot match a directory directly, and skipping `a/` would
        // also lose every file beneath. The slice is the path
        // relative to the walk root — `work.root_skip` is set once
        // and never recomputed for descendants — so the absolute
        // prefix a CLI on that path always carries on Windows is
        // invisible to the glob the same way it is invisible to
        // ripgrep's `-g`.
        if let Some(ug) = ctx.user_globs.as_ref() {
            let relative = work.norm.get(work.root_skip..).unwrap_or("");
            if ug.matched_str(relative, false) == Match::Ignore {
                return WalkState::Continue;
            }
        }
        // The `-t`/`-T` filter already ran in `accept_child` for every
        // entry with `depth > 0`; only a file named directly as a walk
        // root (`depth == 0`) still needs the check here.
        if work.depth == 0 {
            if let Some(tf) = ctx.type_filter.as_ref() {
                let basename = work
                    .norm
                    .rsplit_once('/')
                    .map(|(_, tail)| tail)
                    .unwrap_or(work.norm.as_str());
                let path = Path::new(basename);
                let ok = match tf.classify_verdict(path) {
                    Some(v) => v,
                    None => tf.accepts_with_bytes(path, &peek_head(&work.path)),
                };
                if !ok {
                    return WalkState::Continue;
                }
            }
        }
        let entry = entry(&mut work);
        return visit(&entry);
    }
    if work.depth == 0 && ctx.parents {
        work.ig = add_parents(ctx, &work);
    }
    let entry = entry(&mut work);
    if visit(&entry) == WalkState::Quit {
        return WalkState::Quit;
    }
    if ctx.max_depth.is_some_and(|m| work.depth >= m) {
        return WalkState::Continue;
    }
    let Ok(rd) = std::fs::read_dir(&work.path) else {
        return WalkState::Continue;
    };
    // The enumeration already carries the attributes the hidden
    // test needs; stat'ing each path instead measured five times
    // the cost of the walk.
    let want_meta = ctx.hidden;
    let (entries, found) = collect(rd, want_meta);
    let node = build_node(ctx, &work.ig, &work, &found);
    let mut batches: Vec<Vec<Work>> = Vec::new();
    let mut kids = Vec::with_capacity(entries.len().min(BATCH));
    let mut subdirs = Vec::new();
    let mut scratch = String::with_capacity(work.norm.len() + 64);
    if !work.norm.is_empty() {
        scratch.push_str(&work.norm);
        scratch.push('/');
    }
    let base_len = scratch.len();
    // Separate from `scratch`, which holds the candidate that
    // `matched_ignore` is about to read; reusing it would overwrite
    // the input it is matching. This one carries the absolute form,
    // rebuilt once per entry.
    let mut abs_scratch = String::new();
    for (name, ty, md) in entries {
        if pool.quit() {
            return WalkState::Quit;
        }
        // The pool's own quit check sits here rather than mid-entry so
        // the ordered driver can share `accept_child` without also
        // sharing the deque.
        let child = match accept_child(
            ctx,
            &node,
            &mut work,
            name,
            ty,
            md,
            &mut scratch,
            base_len,
            &mut abs_scratch,
        ) {
            Some(c) => c,
            None => continue,
        };
        if child.ty.is_some_and(|t| t.is_dir()) {
            subdirs.push(child);
        } else {
            kids.push(child);
            if kids.len() == BATCH {
                batches.push(std::mem::take(&mut kids));
            }
        }
        if batches.len() >= 32 {
            pool.push_batches(worker, std::mem::take(&mut batches));
        }
    }
    if subdirs.len() > 1 {
        // Multiple subdirectories: branching root. Distribute
        // subdirectories as independent batches so idle workers
        // can steal parallel branches.
        for child in subdirs {
            batches.push(vec![child]);
        }
        if !kids.is_empty() {
            batches.push(kids);
        }
    } else {
        // 0 or 1 subdirectory: keep depth-first order with the
        // directory's files.
        if let Some(child) = subdirs.pop() {
            kids.push(child);
        }
        if !kids.is_empty() {
            batches.push(kids);
        }
    }
    pool.push_batches(worker, batches);
    WalkState::Continue
}

fn entry<'a>(work: &'a mut Work) -> DirEntry<'a> {
    DirEntry {
        path: &work.path,
        ty: work.ty,
        follow: work.follow,
        md: match work.md.take() {
            Some(m) => OnceCell::from(io::Result::Ok(m)),
            None => OnceCell::new(),
        },
    }
}

#[derive(Default, Clone, Copy)]
struct Found {
    ignore: bool,
    git_ignore: bool,
    dot_git: bool,
    jj: bool,
}

/// A directory entry as the consumer of `collect` sees it: name,
/// type, metadata. The path is **not** stored:
/// `std::fs::DirEntry::path()` allocates a fresh `PathBuf` per
/// entry via `self.root.join(...)`, and the entries that survive
/// past the ignore rules are a tiny fraction of a flat tree (4 of
/// 20 000 in the fixture), so paying for a `PathBuf` on the
/// rejected 19 996 is wasted.
type Entry = (String, Option<FileType>, Option<Metadata>);

fn collect(rd: std::fs::ReadDir, want_meta: bool) -> (Vec<Entry>, Found) {
    #[cfg(windows)]
    let _ = want_meta;
    let mut out = vec![];
    let mut found = Found::default();
    for e in rd.flatten() {
        let raw = e.file_name();
        let raw_bytes = raw.as_encoded_bytes();
        if raw_bytes == b".ignore" {
            found.ignore = true;
        } else if raw_bytes == b".gitignore" {
            found.git_ignore = true;
        } else if raw_bytes == b".git" {
            found.dot_git = true;
        } else if raw_bytes == b".jj" {
            found.jj = true;
        }
        let name = match raw.into_string() {
            Ok(s) => s,
            Err(os) => os.to_string_lossy().into_owned(),
        };
        // On Windows, `std::fs::DirEntry::metadata()` constructs the
        // `Metadata` directly from `WIN32_FIND_DATAW` without any
        // filesystem syscall; capturing it here means
        // `DirEntry::metadata()` downstream never pays a
        // `GetFileAttributesExW` syscall per file. On non-Windows
        // platforms, only stat when needed for hidden-attribute
        // testing.
        #[cfg(windows)]
        let md = e.metadata().ok();
        #[cfg(not(windows))]
        let md = match (want_meta, name.starts_with('.')) {
            (true, false) => e.metadata().ok(),
            _ => None,
        };
        out.push((name, e.file_type().ok(), md));
    }
    (out, found)
}

/// The ignore files of one directory, and whether it is a repository root
/// (the git rules only apply inside one).
fn dir_rules(ctx: &Ctx, dir: &Path, found: &Found) -> (Globs, Globs, Globs, bool) {
    let has_git = (ctx.git_ignore || ctx.git_exclude) && (found.dot_git || found.jj);
    let ignore = if found.ignore {
        read_globs(&dir.join(".ignore"))
    } else {
        Globs::default()
    };
    let git_ignore = if ctx.git_ignore && found.git_ignore {
        read_globs(&dir.join(".gitignore"))
    } else {
        Globs::default()
    };
    let git_exclude = if ctx.git_exclude && found.dot_git {
        match git_common_dir(dir) {
            Some(g) => read_globs(&g.join("info").join("exclude")),
            None => Globs::default(),
        }
    } else {
        Globs::default()
    };
    (ignore, git_ignore, git_exclude, has_git)
}

fn build_node(ctx: &Ctx, parent: &Arc<Node>, work: &Work, found: &Found) -> Arc<Node> {
    let (ignore, git_ignore, git_exclude, has_git) = dir_rules(ctx, &work.path, found);
    Arc::new(Node {
        parent: Some(Arc::clone(parent)),
        dir: work.path.clone(),
        abs: false,
        has_git,
        any_git: parent.any_git || has_git,
        skip: work.skip,
        ignore,
        git_ignore,
        git_exclude,
        absbase: parent.absbase.clone(),
    })
}

/// `.git` is a file in a worktree or a submodule: it points elsewhere.
fn git_common_dir(dir: &Path) -> Option<PathBuf> {
    let dot = dir.join(".git");
    if !dot.metadata().ok()?.is_file() {
        return Some(dot);
    }
    let first = std::fs::read_to_string(&dot).ok()?;
    let real = PathBuf::from(first.strip_prefix("gitdir: ")?);
    let commondir = std::fs::read_to_string(real.join("commondir")).ok()?;
    let commondir = commondir.trim();
    if commondir.starts_with('.') {
        Some(real.join(commondir))
    } else {
        Some(PathBuf::from(commondir))
    }
}

/// A symlinked directory that resolves to one of its own ancestors would
/// loop forever; the oracle compares resolved handles up to the walk root.
fn is_loop(node: &Arc<Node>, child: &Path) -> bool {
    let Ok(target) = std::fs::canonicalize(child) else {
        return false;
    };
    let mut n = Some(node.as_ref());
    while let Some(nd) = n {
        if nd.abs {
            break;
        }
        if let Ok(d) = std::fs::canonicalize(&nd.dir) {
            if d == target {
                return true;
            }
        }
        n = nd.parent.as_deref();
    }
    false
}

/// Windows carries a hidden bit that is not in the name;
/// everywhere else the name is the whole of it.
fn hidden_attr(md: Option<&Metadata>) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        md.is_some_and(|m| m.file_attributes() & 0x2 != 0)
    }
    #[cfg(not(windows))]
    {
        let _ = md;
        false
    }
}

/// The rules of every directory above the walk root, applied to candidates
/// rewritten onto the canonicalized root.
fn add_parents(ctx: &Ctx, work: &Work) -> Arc<Node> {
    let Ok(base) = std::fs::canonicalize(&work.path) else {
        return Arc::clone(&work.ig);
    };
    let mut parents = vec![];
    let mut p = base.as_path();
    while let Some(parent) = p.parent() {
        parents.push(parent.to_path_buf());
        p = parent;
    }
    let mut ig = Arc::clone(&work.ig);
    let mut rules = false;
    for dir in parents.into_iter().rev() {
        let ndir = norm(&dir);
        let found = Found {
            ignore: dir.join(".ignore").exists(),
            git_ignore: dir.join(".gitignore").exists(),
            dot_git: dir.join(".git").metadata().is_ok(),
            jj: dir.join(".jj").exists(),
        };
        let (ignore, git_ignore, git_exclude, _) = dir_rules(ctx, &dir, &found);
        // Above the walk root the repository test is bare
        // existence: a `.git` that cannot be opened still ends the
        // search for outer rules.
        let has_git = ctx.git_ignore && (found.dot_git || found.jj);
        rules = rules || !ignore.is_empty() || !git_ignore.is_empty() || !git_exclude.is_empty();
        ig = Arc::new(Node {
            parent: Some(Arc::clone(&ig)),
            dir,
            abs: true,
            has_git,
            any_git: ig.any_git || has_git,
            skip: ndir.len() + 1,
            ignore,
            git_ignore,
            git_exclude,
            absbase: None,
        });
    }
    if !rules && ctx.global.is_empty() {
        return Arc::clone(&work.ig);
    }
    // The deepest absolute node carries the base for the whole
    // chain; every node below it inherits the arc.
    Arc::new(Node {
        parent: ig.parent.clone(),
        dir: ig.dir.clone(),
        abs: true,
        has_git: ig.has_git,
        any_git: ig.any_git,
        skip: ig.skip,
        ignore: ig.ignore.clone(),
        git_ignore: ig.git_ignore.clone(),
        git_exclude: ig.git_exclude.clone(),
        absbase: Some(Arc::new(AbsBase {
            canon_root: norm(&base),
            root_skip: work.skip,
        })),
    })
}

fn skip_entry(
    ctx: &Ctx,
    node: &Arc<Node>,
    cand: &str,
    is_dir: bool,
    name: &str,
    md: Option<&Metadata>,
    scratch: &mut String,
) -> bool {
    // An override that matches is the last word. The ignore files,
    // and the hidden test, never get a say: that is what lets `-g
    // '*.txt'` list a file that `.gitignore` names, which is how `rg
    // --files -g '*.txt'` behaves and what this walker used to
    // refuse. Overrides outrank everything.
    let m = ctx.overrides.matched_str(cand, is_dir);
    if m != Match::None {
        return m == Match::Ignore;
    }
    let m = node.matched_ignore(ctx, cand, is_dir, scratch);
    if m == Match::Ignore {
        return true;
    }
    // A repository's own state is never part of the corpus, whatever
    // the hidden-file policy says: the objects are compressed, the index
    // is a binary, and the directory is routinely larger than the tree
    // it describes. The rule is a directory rule -- a `.gitignore` is a
    // file, and it is read and applied like any other.
    if is_dir && rgx_core::walk_policy::is_vcs_dir(name) {
        return true;
    }
    // A re-include anywhere in the chain keeps the entry even if it
    // is hidden.
    m == Match::None && ctx.hidden && (hidden_attr(md) || name.starts_with('.'))
}

/// Where a directory's own path ends inside the candidate of
/// anything under it: past the path, and past the separator that
/// follows it. The walk root spells its path as the empty string,
/// so it has no separator.
fn offset(norm: &str) -> usize {
    if norm.is_empty() {
        0
    } else {
        norm.len() + 1
    }
}

/// Candidate form: `/` separated, with `.` and empty components
/// folded away so a node's offset is a plain byte count into its
/// children.
fn clean(p: &Path) -> (PathBuf, String) {
    let mut path = PathBuf::new();
    let mut norm = String::new();
    let mut any = false;
    for c in p.components() {
        match c {
            Component::Normal(s) => {
                any = true;
                if !norm.is_empty() {
                    norm.push('/');
                }
                norm.push_str(&s.to_string_lossy());
                path.push(s);
            }
            Component::RootDir => {
                any = true;
                norm.push('/');
                path.push(c.as_os_str());
            }
            Component::Prefix(pre) => {
                any = true;
                norm.push_str(&pre.as_os_str().to_string_lossy().replace('\\', "/"));
                path.push(pre.as_os_str());
            }
            Component::CurDir | Component::ParentDir => {}
        }
    }
    if !any {
        return (PathBuf::from("."), String::new());
    }
    (path, norm)
}

fn norm(p: &Path) -> String {
    let s = p.to_string_lossy();
    #[cfg(windows)]
    let s = s.replace('\\', "/");
    #[cfg(not(windows))]
    let s = s.into_owned();
    s.strip_prefix("./").unwrap_or(&s).to_string()
}

// ---------------------------------------------------------------------------
// the work queue
// ---------------------------------------------------------------------------
//
// Per-worker Chase-Lev deques (one per thread, via `crossbeam-deque::Worker`)
// with FIFO stealing. The owner pushes to the top of its own deque
// and pops from the top (LIFO: the most recently discovered sub-tree
// is the one most likely to be cache-warm and to generate more
// sub-trees); other workers steal from the bottom (FIFO: oldest work,
// the cut that keeps idle threads from chasing the same hot
// directory).
//
// The previous design used one `Mutex<Vec<Vec<Work>>>` plus a `Condvar`
// for all N threads. At `-j32` on the `crates` benchmark that mutex
// was the only contended point in the walk, and the condvar wait when
// the stack ran dry added a context-switch per idle wake-up. With
// one deque per worker the take-side never touches a shared atomic
// unless the local deque is empty, so a busy worker pays zero
// synchronisation. Termination is detected by polling a `pending`
// counter that is bumped on `push_dir` (before the corresponding
// `worker.push`, so a stealer that sees a non-empty target also sees
// a non-zero count) and decremented in the `Active` drop — when
// every deque is empty AND every worker has finished its current
// item, `pending` reaches zero and the polling thread exits.
//
// The work-stealing hot path is lock-free. A condvar is only touched
// on the cold idle path (a worker found nothing to do). 31 idle
// threads spinning on `yield_now` saturated the scheduler at `-j32`
// and slowed the single thread that was actually walking; blocking on
// the condvar when the pool is genuinely drained restores the
// original behaviour where the OS parks the waiters.

struct Pool {
    /// Stealers for each worker (index = worker ID). A stealer is a
    /// `&`-sharable handle to the same memory the owning thread pushes
    /// into; the chase-lev protocol inside `crossbeam-deque` makes the
    /// concurrent push/pop/steal safe.
    stealers: Vec<Stealer<Vec<Work>>>,
    /// Number of work items in flight: contents of every deque plus the
    /// items currently held by an `Active` guard. Bumped on `push_dir`,
    /// decremented on `Active` drop. When a worker finds its own deque
    /// empty and every peer's empty too, a `pending == 0` read means
    /// there is no one left to push -- the system is drained.
    pending: AtomicUsize,
    /// Set on `WalkState::Quit` from a callback; observed by the worker
    /// loop and at the top of every `take_dir` iteration.
    quit: AtomicBool,
    /// Coarse lock that serialises the `pending` check against a
    /// `push_dir` so a thread about to wait cannot miss the wakeup.
    /// Never taken on the work-stealing hot path; only held across a
    /// terminal `pending == 0` read or a `cv.wait`.
    idle: Mutex<()>,
    /// Notified whenever `push_dir` lands work, so an idle worker wakes
    /// up promptly instead of burning the scheduler.
    cv: Condvar,
}

impl Pool {
    /// Build a pool and the per-worker deques. The initial `init`
    /// batches are distributed round-robin across the workers so
    /// the first steal already has a destination, instead of one
    /// worker picking the stack clean while the others wait on the
    /// condvar.
    fn make(threads: usize, init: Vec<Vec<Work>>) -> (Arc<Pool>, Vec<Deque<Vec<Work>>>) {
        let deques: Vec<Deque<Vec<Work>>> = (0..threads).map(|_| Deque::new_lifo()).collect();
        let stealers: Vec<Stealer<Vec<Work>>> = deques.iter().map(|w| w.stealer()).collect();
        let pending = AtomicUsize::new(0);
        for (i, d) in init.into_iter().enumerate() {
            if d.is_empty() {
                continue;
            }
            // Bump `pending` *before* the push: a stealer that loses
            // the race for this batch must still see a non-zero
            // count and not bail out thinking the work is drained.
            pending.fetch_add(1, Ordering::Release);
            deques[i % threads].push(d);
        }
        let pool = Arc::new(Pool {
            stealers,
            pending,
            quit: AtomicBool::new(false),
            idle: Mutex::new(()),
            cv: Condvar::new(),
        });
        (pool, deques)
    }

    fn quit(&self) -> bool {
        self.quit.load(Ordering::Acquire)
    }

    fn stop(&self) {
        self.quit.store(true, Ordering::Release);
        // Wake every idle waiter so a `WalkState::Quit` propagates
        // immediately instead of at the next `push_dir`.
        let _g = self.idle.lock().expect("pool");
        self.cv.notify_all();
    }

    fn push_batches(&self, worker: &Deque<Vec<Work>>, batches: Vec<Vec<Work>>) {
        if batches.is_empty() {
            return;
        }
        let count = batches.len();
        // The `idle` lock here closes the lost-wakeup window: a
        // thread that has already taken the lock and is about to
        // call `cv.wait` will see the bumped `pending` and not block
        // at all, because it re-checks under the lock before waiting.
        let g = self.idle.lock().expect("pool");
        self.pending.fetch_add(count, Ordering::Release);
        for ws in batches {
            worker.push(ws);
        }
        drop(g);
        if count == 1 {
            self.cv.notify_one();
        } else {
            self.cv.notify_all();
        }
    }

    fn take_dir(&self, me: usize, worker: &Deque<Vec<Work>>) -> Option<Vec<Work>> {
        loop {
            if self.quit.load(Ordering::Acquire) {
                return None;
            }
            // Hot path: owner pop (LIFO, no contention), then one round
            // of stealing. The vast majority of `take_dir` calls return
            // here when the worker is busy.
            if let Some(w) = worker.pop() {
                return Some(w);
            }
            if let Some(w) = self.steal(me) {
                return Some(w);
            }
            // Cold path: nothing to do. Take the idle lock so we can
            // read `pending` against any in-flight `push_dir` without
            // missing a wakeup, and so a thread that holds the lock is
            // about to wait is visible to the next `push_dir`.
            let g = self.idle.lock().expect("pool");
            // Re-check under the lock -- work may have arrived between
            // the hot path and the lock acquisition.
            if self.quit.load(Ordering::Acquire) {
                return None;
            }
            if let Some(w) = worker.pop() {
                return Some(w);
            }
            if let Some(w) = self.steal(me) {
                return Some(w);
            }
            if self.pending.load(Ordering::Acquire) == 0 {
                // No one is processing and no one is about to push: the
                // system is drained. (The Active guard is what holds
                // `pending` open during processing, so a zero here
                // really means every worker is between `finish` and
                // `take_dir`.)
                return None;
            }
            // `pending > 0` but our local + every peer's deque is
            // empty. The remaining work is held by an `Active` guard
            // and will land back in some deque when that worker
            // finishes -- or the system will drain to zero, in which
            // case `finish` notifies and we re-check. The condvar
            // parks the thread (no CPU burn) until either happens.
            let _g = self.cv.wait(g).expect("pool");
        }
    }

    fn steal(&self, me: usize) -> Option<Vec<Work>> {
        let n = self.stealers.len();
        if n <= 1 {
            return None;
        }
        let start = random_victim(me, n);
        for i in 0..n {
            let idx = (start + i) % n;
            if idx == me {
                continue;
            }
            // A stealer reports `Retry` when it lost the race for a slot
            // to a concurrent owner pop or another stealer. The slot is
            // still there, so loop until the stealer either wins or the
            // deque reports `Empty`.
            loop {
                match self.stealers[idx].steal() {
                    Steal::Success(w) => return Some(w),
                    Steal::Retry => continue,
                    Steal::Empty => break,
                }
            }
        }
        None
    }

    fn finish(&self) {
        let prev = self.pending.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            // `pending` just hit zero. Every waiter parked on the
            // condvar needs to wake up, re-check the queues, and exit
            // -- otherwise a thread that found `pending > 0` right
            // before we decremented would block forever waiting for a
            // notification that only a `push_dir` produces.
            let _g = self.idle.lock().expect("pool");
            self.cv.notify_all();
        }
    }
}

/// One work item in flight, from this thread's point of view.
struct Active<'a>(&'a Pool);

impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.finish();
    }
}

/// Per-thread pseudo-random starting victim. Seeded from the
/// worker ID on first use and stepped with a single xorshift64*;
/// the goal is to spread steal attempts across peers, not
/// cryptographic strength, so a per-thread `Cell` without any
/// atomic is enough.
fn random_victim(me: usize, n: usize) -> usize {
    debug_assert!(n > 0);
    thread_local! {
        static STATE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }
    STATE.with(|s| {
        let mut x = s.get();
        if x == 0 {
            x = (me as u64)
                .wrapping_add(1)
                .wrapping_mul(0x9E37_79B9_7F4A_7C15);
        }
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        s.set(x);
        (x.wrapping_mul(0x2545_F491_4F6C_DD1D) as usize) % n
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fast shapes are an optimization, so the test is not "does
    /// it match" but "does it match THE SAME as the regex it
    /// replaces". Every case is asserted both ways: through the fast
    /// list and through the regex set, and the two verdicts have to
    /// be identical. A fast path that is right 99% of the time is a
    /// fast path that lies once, in a query, to a user who has no
    /// way to see it.
    fn both_ways(glob: &str, path: &str, is_dir: bool) -> (Match, Match) {
        let mut b = OverrideBuilder::new(".");
        b.add(glob).expect("glob compiles");
        let o = b.build().expect("override builds");
        let fast = o
            .globs
            .fast_files
            .as_ref()
            .map(|f| last_matching_fast(f, path.as_bytes()))
            .is_some();
        let via_fast = match (fast && !is_dir, o.globs.fast_files.as_ref()) {
            (true, Some(f)) => match last_matching_fast(f, path.as_bytes()) {
                Some(g) if o.globs.all[g as usize].whitelist => Match::Ignore,
                Some(_) => Match::Whitelist,
                None if o.includes > 0 => Match::Ignore,
                None => Match::None,
            },
            _ => Match::None,
        };
        let mut o_slow = o;
        o_slow.globs.fast_files = None;
        (via_fast, o_slow.matched_str(path, is_dir))
    }

    #[test]
    fn the_fast_shapes_agree_with_the_regex() {
        for (glob, path) in [
            ("*.rs", "src/main.rs"),
            ("*.rs", r"src\main.rs"),
            ("*.rs", "src/main.txt"),
            ("*.rs", "main.rs"),
            ("*.rs", "a.b.rs"),
            ("*.rs", "rs"),       // a name that is only the extension
            ("*.rs", "Authors"),  // ends with "rs" without a dot
            ("*.rs", "x.rs.bak"), // and one that only contains it
            ("zzz*", "zzz-file.txt"),
            ("zzz*", "file.txt"),
            ("zzz*", "dir/zzz"),
            ("!*.rs", "src/main.rs"),
            ("!~$*", "~$budget.xlsx"),
            ("!~$*", "budget.xlsx"),
        ] {
            let (fast, slow) = both_ways(glob, path, false);
            assert_eq!(
                fast, slow,
                "fast and regex disagree on {glob:?} vs {path:?}"
            );
        }
    }

    /// The shapes that do not qualify must not be silently given one: a
    /// character class, a wildcard, a `**` and a bare literal all keep the
    /// regex, because none of them is a suffix or a prefix of the basename.
    #[test]
    fn only_the_two_shapes_take_the_fast_path() {
        for (glob, want) in [
            ("*.rs", Some(FastShape::Suffix)),
            ("zzz*", Some(FastShape::Prefix)),
            ("**/*.rs", Some(FastShape::Suffix)),
            ("!~$*", Some(FastShape::Prefix)),
            ("*.[ch]", None),
            ("*.{rs,toml}", None),
            ("src/*", None),
            ("/*.rs", None),
            (r"foo\*bar*", None),
            ("src/**", None),
            ("exact.rs", None),
            ("*", None),
            ("a?b", None),
        ] {
            assert_eq!(
                fast_shape(glob).map(|(s, _)| s),
                want,
                "fast_shape({glob:?})"
            );
        }
    }

    /// A set containing one complicated glob loses the fast path for the
    /// whole set, which is the honest outcome: a partially-fast set has to
    /// preserve last-match-wins across both lists, and the regex already
    /// decides that correctly.
    #[test]
    fn one_complicated_glob_disables_the_fast_list() {
        let mut b = OverrideBuilder::new(".");
        b.add("*.rs").unwrap();
        b.add("src/**").unwrap();
        let o = b.build().unwrap();
        assert!(o.globs.fast_files.is_none());

        // A root-anchored glob (`/*.rs`) only matches at the walk root, never
        // against the basename at arbitrary depth, so it must also disable
        // `fast_files`.
        let mut rooted = OverrideBuilder::new(".");
        rooted.add("/*.rs").unwrap();
        let ro = rooted.build().unwrap();
        assert!(ro.globs.fast_files.is_none());
        assert_eq!(ro.matched_str("lib.rs", false), Match::Whitelist);
        assert_eq!(ro.matched_str("src/lib.rs", false), Match::Ignore);
    }

    /// `accepts_with_bytes` is what admits a file the extension classifier
    /// could not name, by looking at its first bytes. It had no test at all --
    /// the other tests in this module are glob fast-paths -- and it is the
    /// function whose `cfg` gate moved, so a change to it would have gone
    /// unnoticed.
    ///
    /// The question is what happens when the extension classifier and the
    /// magic bytes disagree, and what the `-t` include set does to a file
    /// neither of them can name.
    #[test]
    fn accepts_with_bytes_admits_by_magic_when_the_extension_says_nothing() {
        use crate::type_db::TypeDb;
        let f = TypeFilter::new(TypeDb::with_defaults(), Vec::new());

        // An extension the database knows. The call sites check `accepts`
        // first, so the bytes here are never consulted.
        assert!(f.accepts(Path::new("a.txt")));
        assert!(f.accepts_with_bytes(Path::new("a.txt"), b"whatever"));

        // No extension at all, and real PDF magic: the case the method exists
        // for.
        assert!(
            f.accepts_with_bytes(Path::new("mystery"), b"%PDF-1.7\n"),
            "an extensionless file with PDF magic is admitted"
        );
        // Neither name nor magic, and no `-t`: accepted. That is the
        // include-empty default and it is what ripgrep does -- with no type
        // filter, the walk takes everything. It looks like a contradiction
        // next to the line above and is not: the one above was admitted by
        // the magic bytes, this one by having no filter to fail.
        assert!(
            f.accepts_with_bytes(Path::new("mystery"), b"just text"),
            "with no -t, an unrecognised file is still taken"
        );
    }

    /// The `include.is_empty()` fallback is the documented behaviour for an
    /// extension-unclassified file, and it is what `TypeDb::matches` does with
    /// the same file: no `-t` means take everything, `-t` means take only what
    /// the filter names. The two rows below look contradictory until you
    /// notice that the second one has no filter to fail.
    #[test]
    fn accepts_with_bytes_honours_the_include_set_for_an_unnamed_file() {
        use crate::type_db::TypeDb;
        let with_include = TypeFilter::new(
            TypeDb::with_defaults(),
            vec![TypeSel {
                name: "pdf".to_string(),
                negate: false,
            }],
        );
        let without_include = TypeFilter::new(TypeDb::with_defaults(), Vec::new());

        assert!(
            with_include.accepts_with_bytes(Path::new("mystery"), b"%PDF-1.7\n"),
            "-t pdf admits an extensionless file with PDF magic"
        );
        assert!(
            !with_include.accepts_with_bytes(Path::new("mystery"), b"plain text"),
            "-t pdf refuses an extensionless file that is not PDF: the magic \
             bytes are the whole of its case for being here"
        );
        assert!(
            without_include.accepts_with_bytes(Path::new("mystery"), b"plain text"),
            "with no -t, an unrecognised file is still taken"
        );
    }

    /// A file can be several types at once, and ripgrep's rule is that the
    /// last type the user named that matches the file decides.
    ///
    /// `lib.min.js` is a `.js` file and a `minified` one, so `-t
    /// javascript` keeps it and `-t minified` keeps it too. The order of
    /// the flags is what decides between them: `-t javascript -T minified`
    /// drops the file, and `-T minified -t javascript` keeps it.
    #[test]
    fn a_file_matches_every_type_it_satisfies_and_the_last_flag_decides() {
        use crate::type_db::TypeDb;
        let db = TypeDb::with_defaults();
        let sel = |name: &str, negate: bool| TypeSel {
            name: name.to_string(),
            negate,
        };

        let javascript = TypeFilter::new(db.clone(), vec![sel("javascript", false)]);
        assert!(
            javascript.accepts(Path::new("lib.min.js")),
            "-t javascript keeps a .min.js file: it is a .js file"
        );
        assert!(javascript.accepts(Path::new("plain.js")));
        assert!(!javascript.accepts(Path::new("main.rs")));

        let minified = TypeFilter::new(db.clone(), vec![sel("minified", false)]);
        assert!(minified.accepts(Path::new("lib.min.js")));
        assert!(!minified.accepts(Path::new("plain.js")));

        // The exclusion last: it decides.
        let exclude_last = TypeFilter::new(
            db.clone(),
            vec![sel("javascript", false), sel("minified", true)],
        );
        assert!(
            !exclude_last.accepts(Path::new("lib.min.js")),
            "-t javascript -T minified drops the file"
        );
        assert!(exclude_last.accepts(Path::new("plain.js")));

        // The inclusion last: it decides, and the file comes back.
        let include_last =
            TypeFilter::new(db, vec![sel("minified", true), sel("javascript", false)]);
        assert!(
            include_last.accepts(Path::new("lib.min.js")),
            "-T minified -t javascript keeps the file"
        );
    }

    /// A type that is only reachable through a dotted extension still
    /// matches the plain extension underneath: `api.generated.rs` is a
    /// `generated` file *and* a `rust` one.
    #[test]
    fn a_multi_dot_type_does_not_hide_the_extension_underneath() {
        use crate::type_db::TypeDb;
        let db = TypeDb::with_defaults();
        let rust = TypeFilter::new(
            db.clone(),
            vec![TypeSel {
                name: "rust".to_string(),
                negate: false,
            }],
        );
        let generated = TypeFilter::new(
            db,
            vec![TypeSel {
                name: "generated".to_string(),
                negate: false,
            }],
        );
        assert!(
            rust.accepts(Path::new("api.generated.rs")),
            "-t rust keeps a .generated.rs file: it is a .rs file"
        );
        assert!(
            generated.accepts(Path::new("api.generated.rs")),
            "-t generated keeps it too: that is the type it was made for"
        );
    }

    /// The type filter against ripgrep's own matcher.
    ///
    /// The `ignore` crate is the crate ripgrep filters types with, and
    /// its `types::Types` is the oracle: the same rule, the same
    /// order, the last selection that matches a file deciding. The
    /// table is rgx's own, spelled as the globs the oracle takes, so
    /// the two are asked the same question about the same names.
    ///
    /// Every name in the corpus and every combination of flags has to
    /// get the same answer from both.
    #[test]
    fn the_type_filter_agrees_with_the_ignore_crate() {
        use ignore::types::TypesBuilder;

        let db = crate::type_db::TypeDb::with_defaults();
        let names = [
            "lib.min.js",
            "plain.js",
            "main.rs",
            "api.generated.rs",
            "a.txt",
            "Makefile",
            "Dockerfile",
            ".env",
            "x.env",
            "noextension",
            "a.min.css",
            "weird.unknownext",
            "UPPER.RS",
        ];
        let selections: Vec<Vec<(&str, bool)>> = vec![
            vec![],
            vec![("javascript", false)],
            vec![("minified", false)],
            vec![("javascript", false), ("minified", true)],
            vec![("minified", true), ("javascript", false)],
            vec![("rust", false)],
            vec![("rust", false), ("minified", true)],
            vec![("minified", true)],
            vec![("pdf", false)],
            vec![("text", false), ("rust", true)],
        ];

        for sels in &selections {
            let mut builder = TypesBuilder::new();
            // rgx lowercases the name it matches against, and the oracle
            // is asked the same question with the same name: the case
            // rule is rgx's own, and this test is about the rest.
            for name in db.type_names() {
                for pattern in db.patterns_of(name).unwrap_or(&[]) {
                    // rgx's rule: a pattern names a file when the name
                    // is the pattern or ends with a dot and the pattern.
                    // The oracle takes globs, so the rule is spelled as
                    // the two globs that make it up.
                    //
                    // The oracle refuses a type name that is not
                    // alphanumeric (`mpeg-ts`), and no selection below
                    // names such a type.
                    if builder.add(name, &format!("*.{pattern}")).is_err() {
                        break;
                    }
                    let _ = builder.add(name, pattern);
                }
            }
            for (name, negate) in sels {
                if *negate {
                    builder.negate(name);
                } else {
                    builder.select(name);
                }
            }
            let oracle = builder.build().expect("the oracle builds");

            let filter = TypeFilter::new(
                db.clone(),
                sels.iter()
                    .map(|(name, negate)| TypeSel {
                        name: name.to_string(),
                        negate: *negate,
                    })
                    .collect(),
            );

            for name in &names {
                let mine = filter.accepts(Path::new(name));
                let theirs = !oracle
                    .matched(Path::new(&name.to_ascii_lowercase()), false)
                    .is_ignore();
                assert_eq!(mine, theirs, "name {name:?} with the selections {sels:?}");
            }
        }
    }
}
