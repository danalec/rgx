// SPDX-License-Identifier: Apache-2.0

//! End-to-end check for the adapter-failure note.
//!
//! `rgx_core::process` renders an adapter failure into the searchable
//! corpus with `format!("{e:#}")` and keeps the first line. If the
//! replacement `Error`'s alternate Display collapsed to the plain form,
//! whatever `.context(..)` added would vanish — and nothing else in the
//! test suite would notice, because no test previously drove this path at
//! all.
//!
//! ## The note is an extra unit, not a replacement
//!
//! This arm used to push the note and stop there, and the comment above it
//! claimed that was "keep the corpus searchable". It was the opposite. Every
//! extractor declines with `bail!`, `bail!` arrives at `process` as `Err`
//! rather than as `Outcome::Bail`, and so a file an adapter merely found
//! nothing in — a PNG with no EXIF, a PEM the x509 walker cannot parse, a
//! `.tex` without `\documentclass` — lost its bytes entirely. rgx then
//! printed nothing for a file ripgrep reads: the same strict-subset property
//! the rendering adapters had, reached through a different door, and it cost
//! 14,251 lines across 1,387 of the 4,881 claimed files in the registry
//! corpus.
//!
//! The note therefore sits *beside* the file's own bytes and both are
//! searched. It still says what happened, and a corpus where a file the walk
//! found cannot be searched at all is less searchable than a corpus with no
//! adapter in it — which is the opposite of what the adapters are for.

use rgx_core::{Adapter, Context, Ctx, Outcome, Registry};

struct Boom;
impl Adapter for Boom {
    fn name(&self) -> &'static str {
        "boom"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["boom"]
    }
    fn extract(&self, _data: &[u8], _path: &str) -> rgx_core::Result<Outcome> {
        // a real chain: an inner cause under a context message
        let inner: std::io::Result<()> = Err(std::io::Error::other("disk on fire"));
        inner.context("while reading the header")?;
        Ok(Outcome::Text(b"unreachable".to_vec()))
    }
}

#[test]
fn adapter_failure_note_keeps_the_context_message() {
    let reg = Registry::new(vec![Box::new(Boom)]);
    let ctx = Ctx::default();
    let mut out = Vec::new();
    rgx_core::process(&reg, "x.boom", b"payload", 0, &ctx, &mut out);

    let note = out
        .iter()
        .find(|f| f.via == "boom")
        .map(|f| String::from_utf8_lossy(&f.bytes).into_owned())
        .expect("the failing adapter must still produce a record");

    assert!(
        note.starts_with("[rgx: adapter 'boom' failed: "),
        "unexpected note shape: {note}"
    );
    // The context message is the outermost link, so it is what
    // `.lines().next()` keeps. Under anyhow it was identical, because
    // `{e:#}` rendered "while reading the header: disk on fire".
    assert!(
        note.contains("while reading the header"),
        "the context message must survive: {note}"
    );
    // and the inner cause must appear in the chain, not be dropped
    assert!(
        note.contains("disk on fire"),
        "the cause must be in the chain: {note}"
    );
    // the note is a single line
    assert_eq!(
        note.trim_end().lines().count(),
        1,
        "note must be one line: {note}"
    );
}

/// The half of the contract the note used to break: the file survives it.
///
/// The payload is searched as itself, so a pattern that lives in the file is
/// a line rgx reports, and a pattern that matches the note is a line rgx
/// reports *as well* — the note is a second unit, not a substitute. This is
/// the shape that took 1,387 claimed files out of the corpus.
#[test]
fn a_failed_adapter_does_not_take_the_file_out_of_the_corpus() {
    let reg = Registry::new(vec![Box::new(Boom)]);
    let ctx = Ctx::default();
    let mut out = Vec::new();
    rgx_core::process(
        &reg,
        "x.boom",
        b"the payload is still here\n",
        0,
        &ctx,
        &mut out,
    );

    assert!(
        out.iter()
            .any(|f| f.via == "boom" && f.bytes.starts_with(b"[rgx: adapter")),
        "the note must still be there:\n{out:?}"
    );
    let raw = out
        .iter()
        .find(|f| f.via == "raw")
        .unwrap_or_else(|| panic!("the file's own bytes must survive the note:\n{out:?}"));
    assert_eq!(
        raw.bytes, b"the payload is still here\n",
        "the raw unit must be the file, byte for byte"
    );
    // both units carry the same path: they are two views of one file, and the
    // searcher reads both, so nothing in the file becomes unreachable
    assert_eq!(out[0].path, out[1].path, "{out:?}");
}
