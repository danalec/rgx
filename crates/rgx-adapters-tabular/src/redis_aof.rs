// SPDX-License-Identifier: Apache-2.0

//! Redis AOF — the append-only command log, in RESP.
//!
//! Where the RDB reader beside it reconstructs a *snapshot*, this reads a
//! *log*: the file is a stream of RESP arrays, one per command, and the
//! searchable content is the commands themselves. That makes it a different
//! job from every other reader in this crate — nothing is being decompressed
//! or unpacked, the bytes are already a sequence of length-prefixed text — so
//! the useful answer is to print the commands with their database selector
//! kept, rather than replay them into a keyspace. A replay would throw away
//! the ordering and the arguments that make a log worth grepping.
//!
//! Two shapes have to be handled, and the second one is the common case.
//! `aof-use-rdb-preamble` defaults to *yes*, so a real `appendonly.aof` opens
//! with an RDB snapshot and the command log starts after it — gating on a
//! leading `*` would refuse the majority of files in the wild. The preamble is
//! rendered too, because a rewrite folds pre-existing keys into it and those
//! keys appear nowhere else. A rewritten file may also end right there, with
//! no log at all, which is a complete AOF and not a failure.
//!
//! Redis 7 also splits the file: a `.manifest` listing a `.base.rdb` plus
//! `.incr.aof` parts. A part *is* the RESP stream and is read as one; the
//! manifest is a container over two formats and is left alone.
//!
//! What is printed: one line per command, `db N` when a `SELECT` changes it,
//! then the verb and its arguments, so a pattern in a key, a value or an
//! option is findable. Payloads that are not UTF-8 are summarised rather than
//! dropped, because a binary value whose only occurrence was the key is a line
//! the reader would otherwise lose.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use rgx_core::bail;
use rgx_core::{decline, Adapter, Outcome, Result};

use crate::databases;

/// Commands in an AOF can be long, and a `SETRANGE` or a big `HMSET` is
/// routinely kilobytes. This is the ceiling on one argument's printed form;
/// past it the value is summarised, not truncated silently.
const MAX_ARG_PRINT: usize = 4096;

/// Cap on printed command lines. An AOF is append-only and a busy instance
/// writes one per command, so an unbounded reader would print a file's worth
/// of history for a single grep. The bound is stated in the output rather than
/// hidden.
const MAX_LINES: usize = 200_000;

/// CRC64, the checksum Redis appends after the RDB EOF opcode when
/// `rdbchecksum yes` — the default. Only ever used as a *checked* skip: the
/// byte past it has to start a RESP array for this to be the boundary.
const RDB_CHECKSUM: usize = 8;

pub struct RedisAof;
impl Adapter for RedisAof {
    fn name(&self) -> &'static str {
        "redis-aof"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["aof"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let mut out = String::new();
        let start;

        if data.get(..5) == Some(b"REDIS".as_slice()) {
            let w = databases::walk_rdb(data)?;
            out.push_str(&w.text);
            if !out.ends_with('\n') {
                out.push('\n');
            }
            match w.eof_at.and_then(|after| log_start(data, after)) {
                Some(at) => start = at,
                None => {
                    // A rewrite that folds every key into the snapshot and
                    // writes no commands after it is a finished AOF. Its
                    // content is the snapshot, so the answer stands; saying so
                    // in the output keeps an empty log from reading as a
                    // failure to find one.
                    let _ = writeln!(
                        out,
                        "[aof: rewrite preamble holds {} keys; no command log follows it]",
                        w.keys
                    );
                    return Ok(Outcome::Text(out.into_bytes()));
                }
            }
        } else if data.first() == Some(&b'*') {
            start = 0;
        } else {
            decline!("not a Redis AOF (neither a RESP array nor an RDB preamble)");
        }

        let mut a = Aof {
            d: data,
            p: start,
            out,
            cmds: 0,
            lines: 0,
            db: None,
            truncated: false,
        };
        a.run();
        // Only an AOF with nothing to say at all is a failure. A preamble that
        // rendered is content, even when no command followed it.
        if a.cmds == 0 && a.out.is_empty() {
            bail!("AOF holds no commands");
        }
        Ok(Outcome::Text(a.out.into_bytes()))
    }
}

/// Where the command log begins after an RDB section that ended at `after`
/// (the offset just past the EOF opcode), or `None` when no log follows.
///
/// Both answers are checked rather than assumed: `rdbchecksum no` puts the
/// log straight after the opcode, `rdbchecksum yes` puts eight CRC64 bytes
/// there, and in each case the byte at the proposed boundary has to be a RESP
/// array header before the offset is believed. Anything else means the file
/// ends with its snapshot.
fn log_start(d: &[u8], after: usize) -> Option<usize> {
    if d.get(after) == Some(&b'*') {
        return Some(after);
    }
    let past_cksum = after.checked_add(RDB_CHECKSUM)?;
    if d.get(past_cksum) == Some(&b'*') {
        return Some(past_cksum);
    }
    None
}

struct Aof<'a> {
    d: &'a [u8],
    p: usize,
    out: String,
    cmds: usize,
    lines: usize,
    /// The current database, once a `SELECT` has said so. Kept so the printed
    /// stream says which keyspace each write belongs to, which is the one
    /// thing a replay-in-your-head reader cannot recover from the file alone.
    db: Option<u32>,
    truncated: bool,
}

impl<'a> Aof<'a> {
    fn run(&mut self) {
        while self.p < self.d.len() {
            if self.lines >= MAX_LINES {
                self.truncated = true;
                break;
            }
            if !self.one_command() {
                break;
            }
        }
        if self.truncated {
            let _ = writeln!(
                self.out,
                "[aof: stopped at {MAX_LINES} printed lines; {} commands read]",
                self.cmds
            );
        } else if self.p < self.d.len() {
            // The walk stops at the first command it cannot read rather than
            // guessing past it, which is right -- but silence is not. A log
            // that ends at `eof after 1 keys` reads like a complete answer,
            // and without this the unread remainder is invisible.
            let _ = writeln!(
                self.out,
                "[aof: stopped at offset {} of {}: {} bytes unread after {} commands]",
                self.p,
                self.d.len(),
                self.d.len() - self.p,
                self.cmds
            );
        }
    }

    /// One RESP array, which is one command. `false` ends the walk: a byte
    /// that is not a command start means the stream is not what we claimed, or
    /// is corrupt, and guessing past it would print the next file's bytes as
    /// this one's commands.
    fn one_command(&mut self) -> bool {
        let start = self.p;
        if self.d.get(self.p) != Some(&b'*') {
            return false;
        }
        self.p += 1;
        let Some(n) = self.line() else { return false };
        let n: i64 = match n.parse() {
            Ok(n) => n,
            Err(_) => return false,
        };
        // `*-1` is the null array and `*-2` a null multi-bulk: Redis writes
        // both for an empty command, and neither carries anything to print.
        // The cursor still moved, so the walk may continue past it.
        if n <= 0 {
            return self.p > start;
        }
        // A file claiming more arguments than it has bytes is a lie about its
        // own size; refusing beats looping on its own word.
        if n as usize > self.d.len() {
            return false;
        }
        let mut args: Vec<&[u8]> = Vec::new();
        for _ in 0..n {
            if self.d.get(self.p) != Some(&b'$') {
                return false;
            }
            self.p += 1;
            let Some(len) = self.line() else { return false };
            let len: usize = match len.parse() {
                Ok(l) => l,
                Err(_) => return false,
            };
            // Checked, because `$` carries an attacker-chosen count: an
            // unchecked `p + len` wraps in release and then slices out of
            // range, and overflows in debug.
            let Some(end) = self.p.checked_add(len) else {
                return false;
            };
            let Some(arg) = self.d.get(self.p..end) else {
                return false;
            };
            self.p = end;
            // The trailing CRLF after the payload. A missing one at the very
            // end of the file is tolerated -- that is a truncated final
            // command, not a reason to invent the next one.
            if self.d.get(self.p..self.p + 2) == Some(b"\r\n") {
                self.p += 2;
            }
            args.push(arg);
        }

        self.cmds += 1;
        self.print(&args);
        true
    }

    /// Read a `...\r\n` terminated line at the cursor. `None` when there is no
    /// terminator left, which is how a truncated file announces itself.
    fn line(&mut self) -> Option<&'a str> {
        let rest = self.d.get(self.p..)?;
        let end = rgx_core::memchr::memmem::find(rest, b"\r\n")?;
        let s = core::str::from_utf8(rest.get(..end)?).ok()?;
        self.p += end + 2;
        Some(s)
    }

    fn print(&mut self, args: &[&[u8]]) {
        let Some(verb) = args.first() else { return };
        let verb_up = String::from_utf8_lossy(verb).to_uppercase();

        if verb_up == "SELECT" {
            // A `SELECT` whose argument is not a number is corrupt; printing a
            // `db` line anyway would invent a keyspace the file never named.
            if let Some(n) = args
                .get(1)
                .and_then(|v| core::str::from_utf8(v).ok())
                .and_then(|v| v.parse::<u32>().ok())
            {
                if self.db != Some(n) {
                    let _ = writeln!(self.out, "db {n}");
                    self.lines += 1;
                    self.db = Some(n);
                }
            }
            return;
        }

        let _ = write!(self.out, "{verb_up}");
        for a in args.get(1..).unwrap_or_default() {
            self.arg(a);
        }
        self.out.push('\n');
        self.lines += 1;
    }

    fn arg(&mut self, a: &[u8]) {
        match as_text(a) {
            Some(s) => {
                let _ = write!(self.out, " {s}");
            }
            None => {
                // A binary value is real content, so it gets a marker a search
                // can still anchor on, plus its length. Printing nothing would
                // shorten the line without saying so.
                let _ = write!(self.out, " <binary {} bytes>", a.len());
            }
        }
    }
}

/// The argument's printed form, or `None` when it is not text at all.
///
/// Valid UTF-8 counts as text: accented values are ordinary and calling one
/// binary would be a lie a grep can see. Only a value that is genuinely not
/// UTF-8 is summarised. The cap lands on a character boundary, because cutting
/// mid-codepoint would fail the validity check above and mislabel a string as
/// binary -- the truncation would manufacture the very label it was avoiding.
fn as_text(a: &[u8]) -> Option<String> {
    let whole = core::str::from_utf8(a).ok()?;
    let mut end = whole.len().min(MAX_ARG_PRINT);
    while !whole.is_char_boundary(end) {
        end -= 1;
    }
    let mut s = String::with_capacity(end);
    for c in whole[..end].chars() {
        match c {
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            c if !c.is_control() => s.push(c),
            // Anything else printable-but-unrenderable (a NUL, a bell) would
            // otherwise vanish from the output without trace.
            c => {
                let _ = write!(s, "\\u{{{:x}}}", c as u32);
            }
        }
    }
    if whole.len() > end {
        s.push_str("...");
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    //! What the reader promises about a command log, stated as properties.
    //!
    //! The reader was written before anything here existed, so these cases
    //! exist to pin the answers that are easy to get wrong rather than to
    //! confirm the happy path: the keyspace a `SELECT` names, what happens to
    //! a value that is not text, and where a walk stops.

    use super::*;
    use rgx_core::Outcome;

    /// One RESP command: the array header, then each argument as a bulk string.
    fn resp(args: &[&[u8]]) -> Vec<u8> {
        let mut v = alloc::format!("*{}\r\n", args.len()).into_bytes();
        for a in args {
            v.extend_from_slice(alloc::format!("${}\r\n", a.len()).as_bytes());
            v.extend_from_slice(a);
            v.extend_from_slice(b"\r\n");
        }
        v
    }

    /// One RDB string key. The length prefix is derived from the bytes rather
    /// than written by hand: the encoding is 6-bit for anything under 64, and
    /// a fixture whose stated length disagrees with its payload fails inside
    /// the string reader, which looks exactly like a defect in the adapter.
    fn rdb_string(key: &[u8], val: &[u8]) -> Vec<u8> {
        assert!(key.len() < 64 && val.len() < 64, "the 6-bit length form");
        let mut v = vec![0u8]; // OP_STRING
        v.push(key.len() as u8);
        v.extend_from_slice(key);
        v.push(val.len() as u8);
        v.extend_from_slice(val);
        v
    }

    /// An AOF that opens with an RDB snapshot, which is what Redis 7 writes by
    /// default (`aof-use-rdb-preamble yes`): `REDIS0011`, `SELECTDB 0`, one
    /// string key, `EOF`, the CRC64 `rdbchecksum yes` appends, then the log.
    fn preamble(log: &[u8]) -> Vec<u8> {
        let mut v = b"REDIS0011".to_vec();
        v.extend_from_slice(&[254, 0]); // OP_SELECTDB, db 0
        v.extend_from_slice(&rdb_string(b"RGXSNAPKEY1", b"RGXSNAPVAL"));
        v.push(255); // OP_EOF
        v.extend_from_slice(&[0u8; 8]); // the checksum
        v.extend_from_slice(log);
        v
    }

    fn text_of(data: &[u8]) -> String {
        match RedisAof.extract(data, "appendonly.aof").expect("extracted") {
            Outcome::Text(t) => String::from_utf8(t).expect("utf-8"),
            Outcome::Members(_) => panic!("expected text, got members"),
            Outcome::Bail(_) => panic!("expected text, got a bail"),
        }
    }

    /// A file that is not an AOF is *declined*, not failed: the caller keeps
    /// the raw bytes and no note appears beside them. Asserting the `Err` is
    /// not enough -- the two differ, and the difference is the whole point.
    #[test]
    fn a_file_that_is_neither_resp_nor_preamble_is_declined_silently() {
        let Err(err) = RedisAof.extract(b"hello, not redis at all", "x.aof") else {
            panic!("a file that is not an AOF produced an answer");
        };
        assert!(err.is_decline(), "expected a decline, got: {err}");
    }

    #[test]
    fn select_prints_the_keyspace_and_set_prints_its_arguments() {
        let mut a = resp(&[b"SELECT", b"3"]);
        a.extend(resp(&[b"SET", b"user:1", b"payload"]));
        let out = text_of(&a);
        assert!(out.contains("db 3"), "{out}");
        assert!(out.contains("SET user:1 payload"), "{out}");
    }

    /// The same `SELECT` twice is one keyspace line, not two: the printed
    /// stream is meant to say which keyspace each *change* belongs to.
    #[test]
    fn a_repeated_select_is_printed_once() {
        let mut a = resp(&[b"SELECT", b"0"]);
        a.extend(resp(&[b"SELECT", b"0"]));
        a.extend(resp(&[b"SET", b"k", b"v"]));
        let out = text_of(&a);
        assert_eq!(out.matches("db 0").count(), 1, "{out}");
    }

    /// A value that is not UTF-8 is content, and the reader says how much of
    /// it there is instead of silently shortening the line.
    #[test]
    fn a_value_that_is_not_utf8_is_summarised_with_its_length() {
        let mut a = resp(&[b"SET", b"blob", &[0xff, 0xfe, 0x00, 0x01]]);
        a.extend(resp(&[b"SET", b"after", b"reachable"]));
        let out = text_of(&a);
        assert!(out.contains("SET blob <binary 4 bytes>"), "{out}");
        // The walk continued past the unreadable value.
        assert!(out.contains("SET after reachable"), "{out}");
    }

    /// UTF-8 is text whatever its width, so an accented value is printed as
    /// itself. Reporting it as binary would be a claim a grep can disprove.
    #[test]
    fn multibyte_utf8_is_text_and_never_binary() {
        let mut a = resp(&[b"SET", b"k", "ação ç ü".as_bytes()]);
        a.extend(resp(&[b"SET", b"emoji", "λ→🔑".as_bytes()]));
        let out = text_of(&a);
        assert!(out.contains("ação ç ü"), "{out}");
        assert!(out.contains("λ→🔑"), "{out}");
        assert!(
            !out.contains("<binary"),
            "a UTF-8 value is not binary: {out}"
        );
    }

    /// A newline inside a value would split one command across two lines and
    /// make the line number a lie; it is escaped instead.
    #[test]
    fn a_value_with_a_newline_stays_on_one_line() {
        let a = resp(&[b"SET", b"k", b"first\nsecond"]);
        let out = text_of(&a);
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(out.contains("first\\nsecond"), "{out}");
    }

    /// The cap lands on a character boundary. Cutting mid-codepoint would fail
    /// the UTF-8 check and get the value mislabelled `<binary ...>`, which is
    /// the exact label the cap was supposed to avoid.
    #[test]
    fn a_capped_value_keeps_its_text_and_its_boundary() {
        let big: Vec<u8> = "€".repeat(MAX_ARG_PRINT).into_bytes();
        let a = resp(&[b"SET", b"k", &big]);
        let out = text_of(&a);
        assert!(out.ends_with("...\n"), "{out}");
        assert!(
            !out.contains("<binary"),
            "a cap must not turn text into binary: {out}"
        );
        assert!(out.contains('€'), "the kept prefix is still text: {out}");
    }

    /// `*-1` and `*-2` are Redis's null forms. They carry nothing to print,
    /// but the cursor still moved, so the walk continues.
    #[test]
    fn a_null_array_is_skipped_without_ending_the_walk() {
        let mut a = b"*-1\r\n".to_vec();
        a.extend(resp(&[b"SET", b"after-null", b"v"]));
        let out = text_of(&a);
        assert!(out.contains("SET after-null v"), "{out}");
    }

    /// A `SELECT` with an argument that is not a number must not invent a
    /// keyspace. Printing `db 0` would assert something the file never said.
    #[test]
    fn a_select_with_a_non_numeric_argument_names_no_keyspace() {
        let mut a = resp(&[b"SELECT", b"nope"]);
        a.extend(resp(&[b"SET", b"k", b"v"]));
        let out = text_of(&a);
        assert!(!out.contains("db "), "invented a keyspace: {out}");
        assert!(out.contains("SET k v"), "{out}");
    }

    /// The length in `$` is attacker-controlled text. An unchecked addition
    /// wraps in release and then slices out of range.
    #[test]
    fn an_argument_length_that_would_overflow_the_cursor_stops_the_walk() {
        let mut a = resp(&[b"SET", b"k", b"v"]);
        a.extend_from_slice(b"*1\r\n$99999999999999999999\r\n");
        let out = text_of(&a);
        assert!(out.contains("SET k v"), "the sound prefix is kept: {out}");
    }

    /// A half-written final command is a truncated append, not a reason to
    /// discard the commands before it.
    #[test]
    fn a_truncated_final_command_keeps_what_came_before() {
        let mut a = resp(&[b"SET", b"first", b"1"]);
        a.extend(resp(&[b"SET", b"second", b"2"]));
        a.extend_from_slice(b"*3\r\n$3\r\nSET\r\n$6\r\nf");
        let out = text_of(&a);
        assert!(out.contains("SET first 1"), "{out}");
        assert!(out.contains("SET second 2"), "{out}");
    }

    /// The preamble's own keys are searchable. A rewrite folds pre-existing
    /// keys into it, so they appear nowhere else in the file.
    #[test]
    fn an_rdb_preamble_is_rendered_next_to_the_command_log() {
        let a = preamble(&resp(&[b"SET", b"live", b"value"]));
        let out = text_of(&a);
        assert!(
            out.contains("RGXSNAPKEY1"),
            "preamble keys must be searchable: {out}"
        );
        assert!(out.contains("RGXSNAPVAL"), "{out}");
        assert!(out.contains("SET live value"), "{out}");
        // The snapshot is db 0 and the log starts in it; the boundary is real,
        // not a byte that happened to be a `*`.
        assert!(out.contains("select db 0"), "{out}");
    }

    /// `rdbchecksum no` leaves nothing between the EOF opcode and the first
    /// command, so the boundary has to be found at the opcode itself.
    #[test]
    fn a_preamble_without_a_checksum_still_finds_the_log() {
        let mut a = preamble(&[]);
        a.truncate(a.len() - 8); // drop the checksum, keep the log's header space
        a.extend_from_slice(&resp(&[b"SET", b"nochecksum", b"v"]));
        let out = text_of(&a);
        assert!(out.contains("SET nochecksum v"), "{out}");
    }

    /// A rewrite that folded every key into the snapshot and then wrote no
    /// commands is a complete AOF. Saying so is better than an empty result
    /// that reads as a failure to find anything.
    #[test]
    fn a_rewrite_preamble_with_no_log_says_the_log_is_absent() {
        let out = text_of(&preamble(&[]));
        assert!(out.contains("no command log follows"), "{out}");
        assert!(out.contains("RGXSNAPKEY1"), "{out}");
    }

    /// The bound is announced rather than applied silently.
    #[test]
    fn a_log_past_the_line_ceiling_says_it_stopped() {
        let mut a = Vec::new();
        for _ in 0..=MAX_LINES {
            a.extend(resp(&[b"SET", b"k", b"v"]));
        }
        let out = text_of(&a);
        assert!(
            out.contains(&alloc::format!("stopped at {MAX_LINES} printed lines")),
            "{out}"
        );
    }

    /// A walk that stops early must say so. This is the case the reader got
    /// wrong first: a log whose `$` header lacks the CRLF after the length
    /// parses as an eleven-byte payload, the walk stops on the very next
    /// argument, and the output ends on a plausible `eof after 1 keys` with
    /// no hint that the rest of the file went unread.
    #[test]
    fn a_walk_that_stops_early_names_the_offset_and_the_remainder() {
        let mut a = resp(&[b"SET", b"first", b"1"]);
        // `*2` then `$3SET` with no CRLF after the length: `$3SET\r\n` reads
        // as a payload of three bytes, and the next `$` is a payload byte.
        a.extend_from_slice(b"*2\r\n$3SET\r\n$6second\r\n");
        let out = text_of(&a);
        assert!(out.contains("SET first 1"), "{out}");
        assert!(out.contains("stopped at offset"), "{out}");
        assert!(out.contains("bytes unread"), "{out}");
        assert!(
            !out.contains("SET second"),
            "nothing may be invented: {out}"
        );
    }

    /// A log that ends exactly on a command boundary is a complete answer and
    /// must not carry the note: the note would train the reader to ignore it.
    #[test]
    fn a_complete_log_carries_no_stop_notice() {
        let mut a = resp(&[b"SET", b"first", b"1"]);
        a.extend(resp(&[b"SET", b"second", b"2"]));
        let out = text_of(&a);
        assert!(!out.contains("stopped at"), "{out}");
        assert!(!out.contains("unread"), "{out}");
    }

    mod fuzz {
        use super::*;

        #[test]
        fn never_panics_on_arbitrary_bytes() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("plain", resp(&[b"SET", b"k", b"v"])),
                    ("preamble", preamble(&resp(&[b"SET", b"k", b"v"]))),
                    ("no-log", preamble(&[])),
                    ("magic-only", b"REDIS0011".to_vec()),
                    ("empty", vec![]),
                ],
                2000,
                "redis-aof",
                |data| {
                    let _ = RedisAof.extract(data, "fuzz.aof");
                },
            );
        }
    }
}
