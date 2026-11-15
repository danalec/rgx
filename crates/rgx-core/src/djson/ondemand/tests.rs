// SPDX-License-Identifier: Apache-2.0

//! Differential oracle: the lazy walk against the Arena parser.
//!
//! The two walks share the Stage-1 scanner and nothing else. This
//! suite holds them against each other on the axes the consumers can
//! observe: which documents are JSON at all (reject parity), what a
//! lookup returns (value parity, including duplicate-key semantics),
//! what order an object's keys come out in (the intern-rank order the
//! `BTreeMap` produces), and what the serialiser emits (byte parity).
//! A disagreement here is exactly the class of bug a lazy parser
//! ships silently.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::Ondemand;
use crate::djson::parser::{parse, to_string};
use crate::djson::value::Value as ArenaValue;

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// Full lazy walk: root consumed, everything validated, trailing
/// content checked. Returns Err exactly when the walk rejects.
fn lazy_accepts(doc: &str) -> bool {
    let Ok(mut od) = Ondemand::new(doc) else {
        return false;
    };
    let Ok(root) = od.root() else {
        return false;
    };
    if root.skip().is_err() {
        return false;
    }
    od.finish().is_ok()
}

fn arena_accepts(doc: &str) -> bool {
    parse(doc).is_ok()
}

/// The object's keys in Arena iteration order (intern-rank).
fn arena_keys_in_order(doc: &str) -> Vec<String> {
    let arena = parse(doc).expect("arena parses");
    let root = arena.root();
    let ArenaValue::Object(idx) = root else {
        panic!("root is not an object");
    };
    arena
        .object_iter(idx)
        .map(|(k, _)| arena.get_string(k).to_string())
        .collect()
}

/// The object's keys as the lazy walk sees them, deduped last-wins and
/// sorted by first-appearance rank -- the order an adapter must emit
/// to byte-match the Arena parser.
fn lazy_keys_in_arena_order(doc: &str) -> Vec<String> {
    let mut od = Ondemand::new(doc).expect("lazy opens");
    let mut collected: Vec<String> = Vec::new();
    od.root()
        .expect("root")
        .object_entries(|k, v| {
            v.skip()?;
            let name = k.into_owned();
            if let Some(slot) = collected.iter_mut().find(|e| **e == name) {
                *slot = name;
            } else {
                collected.push(name);
            }
            Ok(true)
        })
        .expect("entries");
    let keys: Vec<&str> = collected.iter().map(|s| s.as_str()).collect();
    let ranks = od.first_string_positions(&keys);
    let mut order: Vec<usize> = (0..collected.len()).collect();
    order.sort_by_key(|&i| ranks[i]);
    order.into_iter().map(|i| collected[i].clone()).collect()
}

fn lazy_compact(doc: &str) -> String {
    let mut od = Ondemand::new(doc).expect("lazy opens");
    let s = od
        .root()
        .expect("root")
        .to_compact_string()
        .expect("compact");
    od.finish().expect("no trailing");
    s
}

/// The lazy lookup of `key` serialised, for comparison against the
/// Arena's `object_get` + `to_string`. `None` = key absent.
fn lazy_find_compact(doc: &str, key: &str) -> Option<String> {
    let mut od = Ondemand::new(doc).expect("lazy opens");
    let mut out: Option<String> = None;
    let found = od
        .root()
        .expect("root")
        .find_key(key, |v| {
            out = Some(v.to_compact_string()?);
            Ok(())
        })
        .expect("find");
    found.then_some(out).flatten()
}

fn arena_find_compact(doc: &str, key: &str) -> Option<String> {
    let arena = parse(doc).expect("arena parses");
    let v = arena.root().get(&arena, key)?;
    Some(to_string(v, &arena))
}

// ---------------------------------------------------------------------
// Reject parity: which documents are JSON at all
// ---------------------------------------------------------------------

#[test]
fn the_two_walks_reject_the_same_documents() {
    let bad: &[&str] = &[
        "",
        "   ",
        "{",
        "[",
        "{\"a\"",
        "{\"a\":}",
        "{\"a\" 1}",
        "{\"a\": 1 \"b\": 2}",
        "{\"a\": 1,}",
        "[1,]",
        "[1 2]",
        "[1,,2]",
        "\"unterminated",
        "{\"a\": \"bad \\q escape\"}",
        "{\"a\": \"dangling \\",
        "{\"a\": \"\\u12\"}",
        "{\"a\": \"\\uD800\"}",
        "{\"a\": \"\\uD800x\"}",
        "{\"a\": \"\\uDC00\"}",
        "{\"a\": 01}",
        "{\"a\": 1.}",
        "{\"a\": .1}",
        "{\"a\": +1}",
        "{\"a\": 1e}",
        "{\"a\": True}",
        "{\"a\": Null}",
        "{\"a\": tru}",
        "{\"a\": nul}",
        "{\"a\": nulll}",
        "tru",
        "nulll",
        "{} {}",
        "[] []",
        "12 34",
        "\"ok\" \"extra\"",
        "01",
        "1.",
    ];
    for doc in bad {
        assert!(!arena_accepts(doc), "arena accepted {doc:?}");
        assert!(!lazy_accepts(doc), "lazy accepted {doc:?}");
    }

    // A literal that overflows to infinity is out of range for both.
    assert!(!arena_accepts("1e999"));
    assert!(!lazy_accepts("1e999"));

    let good: &[&str] = &[
        "null",
        "true",
        "false",
        "0",
        "-0",
        "-0.0",
        "[]",
        "{}",
        "  {\"a\": [1, 2, {\"b\": \"c\"}]}  ",
        "{\"\\u0041\": \"\\ud83d\\ude00\"}",
        "[[[[[[[[[[1]]]]]]]]]]",
    ];
    for doc in good {
        assert_eq!(
            arena_accepts(doc),
            lazy_accepts(doc),
            "acceptance diverged on {doc:?}"
        );
        assert!(lazy_accepts(doc), "lazy rejected {doc:?}");
    }
}

#[test]
fn raw_control_characters_in_strings_are_rejected_by_both() {
    let doc = "{\"a\": \"tab\there\"}"; // a literal tab inside a string
    assert!(!arena_accepts(doc));
    assert!(!lazy_accepts(doc));
}

#[test]
fn nesting_depth_agrees_at_the_boundary() {
    let deep = |n: usize| {
        let mut s = String::new();
        for _ in 0..n {
            s.push('[');
        }
        for _ in 0..n {
            s.push(']');
        }
        s
    };
    // The check runs on openers: 128 levels are accepted, 129 are not.
    assert_eq!(arena_accepts(&deep(128)), lazy_accepts(&deep(128)));
    assert!(arena_accepts(&deep(128)));
    assert_eq!(arena_accepts(&deep(129)), lazy_accepts(&deep(129)));
    assert!(!arena_accepts(&deep(129)));
}

#[test]
fn the_walk_validates_values_the_consumer_never_reads() {
    // The garbage sits under "b"; a consumer that only ever asks about
    // "a" must still see the document rejected, exactly as `parse`
    // rejects it. Validation runs once, at `root`.
    let doc = "{\"a\": 1, \"b\": 01}";
    assert!(!arena_accepts(doc));
    let mut od = Ondemand::new(doc).expect("opens");
    assert!(od.root().is_err(), "untouched garbage went unvalidated");
}

// ---------------------------------------------------------------------
// Value parity
// ---------------------------------------------------------------------

#[test]
fn scalar_values_round_trip_identically() {
    let docs: &[&str] = &[
        "null",
        "true",
        "false",
        "0",
        "-0",
        "3.5",
        "1e3",
        "1E-2",
        "12345678901234567890",
        "\"\"",
        "\"plain\"",
        "\"with \\\"quotes\\\"\"",
        "\"escapes \\\" \\\\ \\/ \\b \\f \\n \\r \\t\"",
        "\"unicode \\u0041\\u00e9\\u20ac\"",
        "\"emoji \\ud83d\\ude00 surrogate pair\"",
        "\"héllo wörld\"",
        "[]",
        "{}",
        "[1, [2, [3]]]",
        "{\"a\": {\"b\": {\"c\": [1, 2, 3]}}}",
    ];
    for doc in docs {
        let arena = parse(doc).expect("arena parses");
        let want = to_string(arena.root(), &arena);
        let got = lazy_compact(doc);
        assert_eq!(got, want, "compact serialisation diverged on {doc:?}");
    }
}

#[test]
fn find_key_returns_the_last_duplicate_like_object_get() {
    let doc = "{\"k\": {\"v\": 1}, \"x\": 9, \"k\": {\"v\": 2}}";
    assert_eq!(
        lazy_find_compact(doc, "k").as_deref(),
        arena_find_compact(doc, "k").as_deref()
    );
    assert_eq!(lazy_find_compact(doc, "k").as_deref(), Some("{\"v\":2}"));

    // Duplicate keys spelled differently but decoding equal.
    let doc = "{\"a\": 1, \"\\u0061\": 2}";
    assert_eq!(
        lazy_find_compact(doc, "a").as_deref(),
        arena_find_compact(doc, "a").as_deref()
    );
    assert_eq!(lazy_find_compact(doc, "a").as_deref(), Some("2"));

    // An escaped key is looked up by decoded content.
    let doc = "{\"a\\u0062\": 7}";
    assert_eq!(lazy_find_compact(doc, "ab").as_deref(), Some("7"));
    assert_eq!(
        lazy_find_compact(doc, "ab").as_deref(),
        arena_find_compact(doc, "ab").as_deref()
    );

    // Absent keys agree.
    assert_eq!(lazy_find_compact(doc, "zz"), None);
    assert_eq!(arena_find_compact(doc, "zz"), None);

    // A lookup on a non-object root is `None`, not an error, on both
    // sides -- the GLB adapter relies on it for a JSON chunk that
    // parses as an array or a scalar.
    assert_eq!(lazy_find_compact("[1, 2]", "a"), None);
    assert_eq!(arena_find_compact("[1, 2]", "a"), None);
    assert_eq!(lazy_find_compact("42", "a"), None);
    assert_eq!(arena_find_compact("42", "a"), None);
}

#[test]
fn lookup_type_mismatches_are_none_not_errors() {
    let doc = "{\"s\": \"text\", \"n\": 1, \"b\": true, \"o\": {}, \"arr\": []}";
    // as_str on a non-string: Ok(None), matching Arena's Option.
    let mut od = Ondemand::new(doc).unwrap();
    let mut kinds = Vec::new();
    od.root()
        .unwrap()
        .object_entries(|k, v| {
            let s = v.as_str()?;
            kinds.push(format!("{}:{}", k, s.is_some()));
            Ok(true)
        })
        .unwrap();
    assert_eq!(
        kinds,
        ["s:true", "n:false", "b:false", "o:false", "arr:false"]
    );

    // as_u64 on non-numbers and on non-integer numbers is None.
    let doc = "{\"a\": [1, \"x\", 2.5, true, 3]}";
    let mut od = Ondemand::new(doc).unwrap();
    let mut nums = Vec::new();
    od.root()
        .unwrap()
        .find_key("a", |arr| {
            arr.array_items(|_, item| {
                nums.push(item.as_u64()?);
                Ok(true)
            })
        })
        .unwrap();
    assert_eq!(nums, [Some(1), None, None, None, Some(3)]);
}

#[test]
fn array_items_agree_with_the_arena() {
    let doc = "{\"shape\": [4096, 1024, 0, 17], \"other\": 1}";
    let arena = parse(doc).unwrap();
    let want: Vec<Option<u64>> = {
        let arr = arena
            .root()
            .get(&arena, "shape")
            .unwrap()
            .as_array(&arena)
            .unwrap();
        arr.iter().map(|v| v.as_u64()).collect()
    };
    let mut od = Ondemand::new(doc).unwrap();
    let mut got = Vec::new();
    od.root()
        .unwrap()
        .find_key("shape", |arr| {
            arr.array_items(|_, item| {
                got.push(item.as_u64()?);
                Ok(true)
            })
        })
        .unwrap();
    assert_eq!(got, want);
}

#[test]
fn raw_returns_the_exact_source_bytes() {
    let doc = "{ \"a\" :  [1, 2] , \"b\": \"x\" }";
    let mut od = Ondemand::new(doc).unwrap();
    let mut raws = Vec::new();
    od.root()
        .unwrap()
        .object_entries(|_, v| {
            raws.push(String::from(v.raw()?));
            Ok(true)
        })
        .unwrap();
    assert_eq!(raws, ["[1, 2]", "\"x\""]);
}

// ---------------------------------------------------------------------
// Order parity: the intern-rank quirk, reproduced exactly
// ---------------------------------------------------------------------

#[test]
fn key_order_is_intern_rank_not_source_order() {
    // "x" is interned as a nested key before "a" appears, so the
    // Arena's BTreeMap emits b, x, a -- not the source order b, a, x.
    let doc = "{\"b\": {\"x\": 1}, \"a\": 2, \"x\": 3}";
    assert_eq!(arena_keys_in_order(doc), ["b", "x", "a"]);
    assert_eq!(lazy_keys_in_arena_order(doc), ["b", "x", "a"]);

    // A value string counts as an occurrence too: "k" is interned as
    // the value 1's neighbourhood before the root key "j".
    let doc = "{\"m\": {\"k\": 1}, \"j\": 2, \"k\": 3}";
    assert_eq!(arena_keys_in_order(doc), ["m", "k", "j"]);
    assert_eq!(lazy_keys_in_arena_order(doc), ["m", "k", "j"]);

    // The boring case stays boring.
    let doc = "{\"one\": 1, \"two\": 2, \"three\": 3}";
    assert_eq!(arena_keys_in_order(doc), ["one", "two", "three"]);
    assert_eq!(lazy_keys_in_arena_order(doc), ["one", "two", "three"]);
}

#[test]
fn compact_serialisation_reproduces_rank_order_and_dedupe() {
    let doc = "{\"b\": {\"x\": 1}, \"a\": 2, \"x\": 3}";
    let arena = parse(doc).unwrap();
    let want = to_string(arena.root(), &arena);
    assert_eq!(want, "{\"b\":{\"x\":1},\"x\":3,\"a\":2}");
    assert_eq!(lazy_compact(doc), want);

    // Duplicate keys collapse to the last value, at the first key's
    // rank.
    let doc = "{\"z\": 1, \"a\": 2, \"z\": 3}";
    let arena = parse(doc).unwrap();
    let want = to_string(arena.root(), &arena);
    assert_eq!(lazy_compact(doc), want);

    // Nested objects get the same treatment at every level.
    let doc = "{\"o\": {\"inner\": 1, \"x\": 2, \"inner\": 3}, \"a\": 0}";
    let arena = parse(doc).unwrap();
    let want = to_string(arena.root(), &arena);
    assert_eq!(lazy_compact(doc), want);
}

// ---------------------------------------------------------------------
// Never panic on arbitrary bytes
// ---------------------------------------------------------------------

#[cfg(feature = "std")]
#[test]
fn the_lazy_walk_never_panics_on_mutation() {
    let corpus: Vec<(&str, Vec<u8>)> = vec![
        (
            "valid-object",
            b"{\"a\": [1, \"two\", {\"b\": null}], \"c\": 3.5}".to_vec(),
        ),
        (
            "valid-string",
            b"\"esc \\u0041 \\ud83d\\ude00 \\\" \\\\\"".to_vec(),
        ),
        ("valid-num", b"-12.5e+7".to_vec()),
        ("truncated", b"{\"a\": [1, 2".to_vec()),
        ("garbage", b"\x00\x01\x02{\"a\"".to_vec()),
    ];
    crate::fuzzkit::assert_never_panics(corpus, 1500, "ondemand", |data| {
        if let Ok(text) = core::str::from_utf8(data) {
            if let Ok(mut od) = Ondemand::new(text) {
                if let Ok(root) = od.root() {
                    let _ = root.to_compact_string();
                }
                let _ = od.finish();
            }
        }
    });
}
