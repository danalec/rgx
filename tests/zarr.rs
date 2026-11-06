// SPDX-License-Identifier: Apache-2.0
//! The Zarr array, end to end: the real binary over a real array.
//!
//! **A Zarr array is a directory.** The manifest in it is a dotfile, and
//! the values live in the chunks beside it, compressed, in a format that
//! says nothing about what it holds. This is the only format in the tree
//! whose answer depends on files other than the one rgx was pointed at,
//! and it is also the only one whose manifest is a dotfile -- which is
//! why the hidden files are read by default.
//!
//! The array is written here rather than copied from the tree, so the
//! test says what it means: the bytes on disk are a Zarr array, and rgx
//! reads the numbers out of it.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

fn rgx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rgx"))
}

/// A temporary directory for one array.
///
/// The directory is one of this run's own: `common::scratch` owns the rule
/// its name follows, and the rule is written down there.
fn temp() -> PathBuf {
    common::scratch("zarr")
}

/// Write a Zarr array: the manifest, and the chunks with the values
/// zlib-compressed the way `numcodecs` compresses them.
fn array(dir: &Path, shape: [usize; 2], chunks: [usize; 2], values: &[f64]) {
    let manifest = format!(
        "{{\n    \"zarr_format\": 2,\n    \"shape\": [{s0}, {s1}],\n    \"chunks\": [{c0}, {c1}],\n    \"dtype\": \"<f8\",\n    \"compressor\": {{\"id\": \"zlib\", \"level\": 1}},\n    \"fill_value\": 0,\n    \"order\": \"C\",\n    \"filters\": null\n}}\n",
        s0 = shape[0],
        s1 = shape[1],
        c0 = chunks[0],
        c1 = chunks[1]
    );
    std::fs::write(dir.join(".zarray"), manifest).unwrap();

    for ci in 0..shape[0].div_ceil(chunks[0]) {
        for cj in 0..shape[1].div_ceil(chunks[1]) {
            let mut raw = Vec::new();
            for i in 0..chunks[0] {
                for j in 0..chunks[1] {
                    let row = ci * chunks[0] + i;
                    let col = cj * chunks[1] + j;
                    let v = values[row * shape[1] + col];
                    raw.extend_from_slice(&v.to_le_bytes());
                }
            }
            let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
            enc.write_all(&raw).unwrap();
            let blob = enc.finish().unwrap();
            std::fs::write(dir.join(format!("{ci}.{cj}")), blob).unwrap();
        }
    }
}

/// The lines rgx prints for a needle over a tree, and whether it matched.
/// The exit status is 1 when there is no match, which is rg's answer and
/// not a failure.
fn found(dir: &Path, args: &[&str], needle: &str) -> (String, bool) {
    let out = rgx()
        .args(args)
        .arg("-a")
        .arg(needle)
        .arg(dir)
        .output()
        .expect("rgx runs");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.success(),
    )
}

/// One array, the same in every test: four rows of four.
fn array4() -> (PathBuf, Vec<f64>) {
    let dir = temp();
    let values: Vec<f64> = (0..16).map(|i| i as f64).collect();
    array(&dir, [4, 4], [2, 2], &values);
    (dir, values)
}

#[test]
fn the_values_of_a_zarr_array_are_searchable() {
    let (dir, _) = array4();
    let (out, matched) = found(&dir, &[], "4.0");
    assert!(matched, "{out}");
    assert!(out.contains("chunk 0.0: 0.0 1.0 4.0 5.0"), "{out}");
    assert!(out.contains("chunk 1.1: 10.0 11.0 14.0 15.0"), "{out}");
}

#[test]
fn the_manifest_is_still_there_to_be_searched() {
    let (dir, _) = array4();
    // rgx is a superset of ripgrep: the JSON in the manifest is still
    // there, under the values.
    let (out, matched) = found(&dir, &[], "zarr_format");
    assert!(matched, "{out}");
    assert!(out.contains("\"zarr_format\": 2"), "{out}");
}

#[test]
fn the_manifest_is_a_dotfile_and_the_default_reads_it() {
    let (dir, _) = array4();
    // By default the hidden files are read, so the array is read.
    let (out, matched) = found(&dir, &[], "chunk 0.0");
    assert!(matched, "{out}");
    assert!(out.contains(".zarray"), "{out}");
    // And `--no-hidden` puts ripgrep's behaviour back, which takes the
    // manifest -- and with it the array -- out of the search.
    let (out, matched) = found(&dir, &["--no-hidden"], "chunk 0.0");
    assert!(!matched, "{out}");
    assert!(!out.contains(".zarray"), "{out}");
}

#[test]
fn the_array_can_be_named_by_its_facts() {
    let (dir, _) = array4();
    let (out, matched) = found(&dir, &["--filter", "zarr.compressor:zlib"], "chunk 1.1");
    assert!(matched, "{out}");
    assert!(out.contains("chunk 1.1"), "{out}");
    // A filter that names a fact nobody reports is false, not an error.
    let (out, matched) = found(&dir, &["--filter", "zarr.compressor:blosc"], "chunk 1.1");
    assert!(!matched, "{out}");
}
