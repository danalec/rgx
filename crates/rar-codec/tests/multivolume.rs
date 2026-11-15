// SPDX-License-Identifier: Apache-2.0

//! Multivolume (split) RAR5 reassembly against a real RARLAB archive.
//!
//! `src/read.rs` has synthetic volume tests for both RAR formats; these are
//! the ones that hold `open_multi` down against bytes `Rar.exe` actually
//! wrote, because the split logic is all index bookkeeping — exactly the kind
//! of code that passes on a fixture built to match the implementation.
//!
//! What it would fail to catch: a reassembly that concatenates the right
//! chunks in the wrong order, or adopts a per-volume packed CRC where the
//! closing volume carries the whole-file one. The expected bytes are the
//! source text files, so both show up as a CRC or length mismatch.

use rar_codec::{Archive, Error};

/// Five volumes of one archive: `Rar.exe a -ma5 -m3 -v1k -ep1`.
const VOLUMES: [&[u8]; 5] = [
    include_bytes!("../testdata/rar/rar5-mv.part01.rar"),
    include_bytes!("../testdata/rar/rar5-mv.part02.rar"),
    include_bytes!("../testdata/rar/rar5-mv.part03.rar"),
    include_bytes!("../testdata/rar/rar5-mv.part04.rar"),
    include_bytes!("../testdata/rar/rar5-mv.part05.rar"),
];

const NOTE: &[u8] = include_bytes!("../testdata/rar/rar5-note.expected");
const BODY: &[u8] = include_bytes!("../testdata/rar/rar5-body.expected");

fn open_all() -> Archive<'static> {
    Archive::open_multi(&VOLUMES).expect("the five volumes are one complete set")
}

#[test]
fn a_real_five_volume_set_reassembles_to_the_source_bytes() {
    let a = open_all();
    assert!(
        a.multivolume,
        "the main header must carry the RAR5 volume flag"
    );
    assert_eq!(a.entries().len(), 2, "two files, not one per volume");

    let note = a
        .entries()
        .iter()
        .find(|e| e.name == "note.txt")
        .expect("note.txt, which fits in volume 1");
    assert_eq!(a.extract(note).unwrap(), NOTE);

    // The one that was chopped: its packed area is four chunks in four
    // volumes, and its declared unpacked size is the whole file.
    let body = a
        .entries()
        .iter()
        .find(|e| e.name == "body.txt")
        .expect("body.txt, split across volumes");
    assert!(
        !body.split_before && !body.split_after,
        "reassembled, so neither"
    );
    // The four chunks really were concatenated: a 20 KB member packed
    // across 1 KB volumes still compresses, so the reassembled packed area
    // is smaller than the output it decodes to. If the chunks were dropped
    // or truncated the two numbers would converge.
    assert!(
        (body.packed_size as usize) < BODY.len(),
        "packed {} should be well under unpacked {}",
        body.packed_size,
        BODY.len()
    );
    assert_eq!(a.extract(body).unwrap(), BODY);
}

#[test]
fn a_lone_volume_reports_the_entry_as_spanning_volumes() {
    // Not "it decoded the first 1 KB and called it a day": the entry is
    // marked as continuing, and extracting it is an explicit refusal.
    let a = Archive::open(VOLUMES[1]).expect("a volume is a parseable archive");
    assert!(a.multivolume);
    let body = a
        .entries()
        .iter()
        .find(|e| e.name == "body.txt")
        .expect("volume 2 repeats the file header for the continuation");
    assert!(body.split_before);
    assert!(matches!(a.extract(body), Err(Error::Unsupported(_))));
}

#[test]
fn a_missing_volume_is_truncated_not_a_short_read() {
    // Dropping the last volume leaves the file header still claiming to
    // continue. A decoder that returned the bytes it had would be
    // indistinguishable from success, so this has to be an error.
    let short = &VOLUMES[..4];
    assert!(matches!(Archive::open_multi(short), Err(Error::Truncated)));
}

#[test]
fn volumes_out_of_order_are_rejected() {
    let mut shuffled = VOLUMES;
    shuffled.swap(0, 3);
    assert!(matches!(
        Archive::open_multi(&shuffled),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn one_volume_alone_is_an_incomplete_set_not_a_short_read() {
    // `open_multi`'s doc says "passing a single slice is equivalent to
    // `open`". It is not quite: it also refuses a volume whose entries still
    // claim to continue, because a set that needs a volume it was not given
    // has to be an error rather than a silently short file. `open` itself
    // does no such check, which is the difference the two assertions below
    // pin down.
    let lone = Archive::open(VOLUMES[0]).expect("a volume is a parseable archive");
    assert!(lone.entries().iter().any(|e| e.split_after));
    let note = lone
        .entries()
        .iter()
        .find(|e| e.name == "note.txt")
        .expect("note.txt, whole inside volume 1");
    assert_eq!(lone.extract(note).unwrap(), NOTE);

    assert!(matches!(
        Archive::open_multi(&VOLUMES[..1]),
        Err(Error::Truncated)
    ));
}
