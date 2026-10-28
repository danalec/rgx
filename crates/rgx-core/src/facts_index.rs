// SPDX-License-Identifier: Apache-2.0

//! The persistent index of a file's facts.
//!
//! **What this is.** A file's facts are the names and values the pipeline
//! knows about it: the path, the extension, the format, the MIME type, the
//! language, and whatever the adapter that answered for it reported —
//! `mail.from`, `exif.gps`, `table.column`. Today they are assembled,
//! tested against `--filter`, and thrown away: the next run assembles them
//! again. That is the filter's own bargain — it is applied per file, the
//! way the pattern is — and it is why a question about a corpus that
//! changes once costs a full extraction pass every time it is asked.
//!
//! **What this changes.** The facts are kept on disk, keyed by the file
//! they belong to, so that a second question about the same corpus is
//! answered from the index instead of from the adapters.
//!
//! **The unit of the index is the path, not the file.** A member of an
//! archive inherits the container's facts, and the container's facts are
//! about the container. The index stores what the pipeline computed for a
//! *path*, and a path is either a real path or a logical member path
//! (`archive.zip!inner.txt`). Both go in, because a query about a member
//! is a query a user can ask and an answer that dropped it would be a
//! silent loss.
//!
//! **What identifies a path here.** The size and the modification time —
//! the same pair the extraction cache keys on (`src/cache.rs`). It is a
//! weaker identity than the cache's content hash, and deliberately so:
//! hashing the content of every file to decide whether the index is stale
//! would cost a full read of the corpus, which is the thing the index
//! exists to avoid. The trade is stated rather than hidden: a file
//! rewritten with the same length and the same modification time keeps its
//! old facts.
//!
//! # The on-disk format
//!
//! **JSON Lines.** One JSON object per line, one line per path:
//!
//! ```text
//! {"path":"a.pdf","size":1024,"mtime":1700000000,"facts":{"mime":"application/pdf"}}
//! ```
//!
//! **Why JSON and not a binary format.** The token index (`.ugi`) is
//! binary because it holds postings, and postings are counted. This one
//! holds names and values that a human reads: `rgx --facts-index` on a
//! directory is supposed to be answerable with `grep`, and an index that
//! cannot be read with the tool the project exists to replace is an
//! index nobody will inspect. The facts are also the export format, so
//! there is one shape rather than two.
//!
//! The `facts` object maps a fact's name to its value. A name that
//! appears twice — two facts with the same name are two chances to match
//! in the filter — cannot be written at all: JSON holds one value per
//! name, and an index that silently kept the last would answer a
//! `--filter` the live walk answers differently. [`FactsIndex::to_jsonl`]
//! refuses the record and names it, so the loss is a refusal rather than
//! a wrong answer.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::djson::{self, Value};
use crate::filter::Field;

/// One path's facts, as the index stores them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The path the facts belong to: a real path, or a logical member path
    /// with `!` between the container and the member.
    pub path: String,
    /// The size of the file in bytes, as it was when the facts were taken.
    pub size: u64,
    /// The modification time of the file, in seconds since the epoch.
    pub mtime: i64,
    /// The facts themselves.
    pub facts: Vec<Field>,
}

impl Record {
    /// A record for `path` with the given facts and no file stamp.
    ///
    /// The stamp is zeroed rather than absent: the index's contract is
    /// that a record says when it was taken, and a caller that has no
    /// stamp to give is saying "at the epoch", which is falsifiable in
    /// the same way any other wrong stamp is.
    pub fn new(path: &str, facts: Vec<Field>) -> Self {
        Record {
            path: path.to_string(),
            size: 0,
            mtime: 0,
            facts,
        }
    }

    /// Whether the file this record describes still looks the same.
    ///
    /// The stamp is the pair the extraction cache keys on: the size and
    /// the modification time. A record whose file no longer matches is
    /// stale, and the caller must not answer from it as if it were
    /// current.
    pub fn is_fresh(&self, size: u64, mtime: i64) -> bool {
        self.size == size && self.mtime == mtime
    }
}

/// The persistent index of a corpus's facts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FactsIndex {
    /// The records, in the order they were read.
    pub records: Vec<Record>,
}

impl FactsIndex {
    /// An empty index.
    pub fn new() -> Self {
        FactsIndex {
            records: Vec::new(),
        }
    }

    /// The record for `path`, when the index has one.
    pub fn get(&self, path: &str) -> Option<&Record> {
        self.records.iter().find(|r| r.path == path)
    }

    /// Whether the index holds a record for `path` that is still fresh.
    ///
    /// Both halves matter: the record has to exist, and the file it
    /// describes has to still be the file it was taken from.
    pub fn is_fresh(&self, path: &str, size: u64, mtime: i64) -> bool {
        self.get(path)
            .map(|r| r.is_fresh(size, mtime))
            .unwrap_or(false)
    }

    /// The index as JSON Lines: one object per line, one line per record.
    ///
    /// The order is the order of the records, so a query that reads the
    /// file back gets the same order it was written in.
    ///
    /// A record holding the same fact name twice is refused: the JSON
    /// object holds one value per name, and the reader would keep the
    /// last — an index that answers a `--filter` differently from the
    /// live walk is worse than one that says it cannot be written.
    pub fn to_jsonl(&self) -> Result<String, String> {
        let mut out = String::new();
        for rec in &self.records {
            out.push_str("{\"path\":");
            out.push_str(&quote(&rec.path));
            out.push_str(",\"size\":");
            out.push_str(&rec.size.to_string());
            out.push_str(",\"mtime\":");
            out.push_str(&rec.mtime.to_string());
            out.push_str(",\"facts\":{");
            let mut first = true;
            let mut seen: Vec<&str> = Vec::new();
            for fact in &rec.facts {
                if seen.contains(&fact.name.as_str()) {
                    return Err(alloc::format!(
                        "record {} holds the fact {:?} twice, and one JSON \
                         object cannot hold two values for one name",
                        rec.path,
                        fact.name
                    ));
                }
                seen.push(&fact.name);
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&quote(&fact.name));
                out.push(':');
                out.push_str(&quote(&fact.value));
            }
            out.push_str("}}\n");
        }
        Ok(out)
    }

    /// Read an index back from JSON Lines.
    ///
    /// Returns the line number and the reason for the first line that
    /// does not parse. A line that is not an object, or that is missing
    /// `path`, is an error rather than a skipped line: a truncated index
    /// that answers for the lines it could read is an index that lies
    /// about the corpus.
    pub fn from_jsonl(text: &str) -> Result<FactsIndex, String> {
        let mut records = Vec::new();
        for (n, line) in text.lines().enumerate() {
            let lineno = n + 1;
            if line.trim().is_empty() {
                continue;
            }
            let arena = djson::parse(line)
                .map_err(|e| alloc::format!("line {lineno}: invalid JSON: {e}"))?;
            let root = arena.root();
            let path = match root.get(&arena, "path").and_then(|v| v.as_str(&arena)) {
                Some(p) => p.to_string(),
                None => return Err(alloc::format!("line {lineno}: no \"path\"")),
            };
            let size = match root.get(&arena, "size").and_then(|v| v.as_u64()) {
                Some(s) => s,
                None => return Err(alloc::format!("line {lineno}: no \"size\"")),
            };
            let mtime = match root.get(&arena, "mtime").and_then(|v| v.as_i64()) {
                Some(m) => m,
                None => return Err(alloc::format!("line {lineno}: no \"mtime\"")),
            };
            let facts_value = root
                .get(&arena, "facts")
                .ok_or_else(|| alloc::format!("line {lineno}: no \"facts\""))?;
            let obj = match facts_value {
                Value::Object(idx) => idx,
                _ => return Err(alloc::format!("line {lineno}: \"facts\" is not an object")),
            };
            let mut facts = Vec::new();
            for (key_idx, value) in arena.object_iter(obj) {
                let key = arena.get_string(key_idx).to_string();
                let text = match value.as_str(&arena) {
                    Some(t) => t.to_string(),
                    None => {
                        return Err(alloc::format!(
                            "line {lineno}: fact {key:?} is not a string"
                        ))
                    }
                };
                facts.push(Field {
                    name: key,
                    value: text,
                });
            }
            records.push(Record {
                path,
                size,
                mtime,
                facts,
            });
        }
        Ok(FactsIndex { records })
    }
}

/// A JSON string, quoted and escaped.
fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u");
                let code = c as u32;
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.push(HEX[((code >> 12) & 0xf) as usize] as char);
                out.push(HEX[((code >> 8) & 0xf) as usize] as char);
                out.push(HEX[((code >> 4) & 0xf) as usize] as char);
                out.push(HEX[(code & 0xf) as usize] as char);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The facts of one record, as the filter's predicates see them.
///
/// A convenience for the query path: the index holds them in the order
/// they were read, and a predicate does not care about the order, but
/// the order is kept anyway because a fact's name is what a predicate
/// names and a file that has two of the same name is a file with two
/// chances to match.
pub fn facts_of(record: &Record) -> &[Field] {
    &record.facts
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn record(path: &str, size: u64) -> Record {
        let mut r = Record::new(
            path,
            vec![
                Field::new("format", "pdf"),
                Field::new("mime", "application/pdf"),
            ],
        );
        r.size = size;
        r.mtime = 1_700_000_000;
        r
    }

    #[test]
    fn round_trip_keeps_the_records() {
        let mut idx = FactsIndex::new();
        idx.records.push(record("a.pdf", 10));
        idx.records.push(record("dir/b.zip!inner.txt", 20));
        let text = idx.to_jsonl().expect("writes");
        let back = FactsIndex::from_jsonl(&text).expect("round-trip");
        assert_eq!(back, idx);
    }

    #[test]
    fn an_empty_index_round_trips() {
        let idx = FactsIndex::new();
        assert_eq!(idx.to_jsonl().expect("writes"), "");
        let back = FactsIndex::from_jsonl(&idx.to_jsonl().expect("writes")).expect("round-trip");
        assert!(back.records.is_empty());
    }

    #[test]
    fn a_value_with_a_quote_survives_the_round_trip() {
        let mut r = Record::new("a.txt", vec![Field::new("note", "he said \"hi\"")]);
        r.size = 1;
        r.mtime = 2;
        let mut idx = FactsIndex::new();
        idx.records.push(r);
        let back = FactsIndex::from_jsonl(&idx.to_jsonl().expect("writes")).expect("round-trip");
        assert_eq!(back.records[0].facts[0].value, "he said \"hi\"");
    }

    #[test]
    fn a_value_with_a_newline_survives_the_round_trip() {
        let mut r = Record::new("a.txt", vec![Field::new("note", "one\ntwo")]);
        r.size = 1;
        r.mtime = 2;
        let mut idx = FactsIndex::new();
        idx.records.push(r);
        let text = idx.to_jsonl().expect("writes");
        assert_eq!(text.lines().count(), 1);
        let back = FactsIndex::from_jsonl(&text).expect("round-trip");
        assert_eq!(back.records[0].facts[0].value, "one\ntwo");
    }

    #[test]
    fn a_record_with_one_fact_name_twice_is_refused() {
        // Two facts with the same name are two chances to match in the
        // live filter, and one JSON object holds one value per name: the
        // writer refuses the record rather than keeping the last value
        // and answering a filter the walk answers differently.
        let mut r = Record::new(
            "a.pdf",
            vec![Field::new("author", "ana"), Field::new("author", "bo")],
        );
        r.size = 1;
        r.mtime = 2;
        let mut idx = FactsIndex::new();
        idx.records.push(r);
        let err = idx.to_jsonl().expect_err("the duplicate must be refused");
        assert!(err.contains("a.pdf"), "{err}");
        assert!(err.contains("author"), "{err}");
    }

    #[test]
    fn a_line_that_is_not_an_object_is_an_error() {
        let err = FactsIndex::from_jsonl("[1,2,3]").expect_err("must fail");
        assert!(err.contains("path"), "{err}");
    }

    #[test]
    fn a_line_without_a_path_is_an_error() {
        let err = FactsIndex::from_jsonl("{\"size\":1}").expect_err("must fail");
        assert!(err.contains("path"), "{err}");
    }

    #[test]
    fn a_line_that_is_not_json_names_the_line() {
        let good = "{\"path\":\"a\",\"size\":1,\"mtime\":0,\"facts\":{}}";
        let err = FactsIndex::from_jsonl(&format!("{good}\nnot json")).expect_err("must fail");
        assert!(err.contains("line 2"), "{err}");
    }

    #[test]
    fn a_stamp_that_moved_is_not_fresh() {
        let r = record("a.pdf", 10);
        assert!(r.is_fresh(10, 1_700_000_000));
        assert!(!r.is_fresh(11, 1_700_000_000));
        assert!(!r.is_fresh(10, 1_700_000_001));
    }

    #[test]
    fn a_record_with_no_stamp_matches_only_a_file_from_the_epoch() {
        // A record built without a stamp says "at the epoch", and that is
        // falsifiable in the same way any other stamp is. It matches a
        // file whose own stamp is the epoch -- a file that was never
        // really written -- and nothing else.
        let r = Record::new("a.pdf", vec![]);
        assert!(r.is_fresh(0, 0));
        assert!(!r.is_fresh(100, 1_700_000_000));
        assert!(!r.is_fresh(0, 1_700_000_000));
    }
}
