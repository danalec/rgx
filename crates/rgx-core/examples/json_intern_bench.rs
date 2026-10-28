// SPDX-License-Identifier: Apache-2.0

//! Times the JSON arena's string interning on a document with many distinct
//! keys -- the path where the `no_std` build used to scan the whole string
//! table for every string, and where it is now a lookup.
//!
//! The two configurations are the two builds of the same crate, on the same
//! machine, on the same document:
//!
//! ```text
//! cargo run --release --example json_intern_bench -p rgx-core
//! cargo run --release --example json_intern_bench -p rgx-core --no-default-features
//! ```
//!
//! Three phases, because "the parse" and "the index" are different
//! questions: `parse` is the whole document (the scan, the object map, the
//! numbers), `intern` is the shadow alone, and `floats` is the document
//! whose numbers the two configurations parse with different parsers.

use std::time::Instant;

use rgx_core::djson::value::Arena;

/// A document with `n` distinct keys, each with an integer value.
fn document(n: usize) -> String {
    let mut doc = String::with_capacity(n * 24);
    doc.push('{');
    for i in 0..n {
        if i > 0 {
            doc.push(',');
        }
        doc.push_str("\"key_");
        doc.push_str(&format!("{i:06}"));
        doc.push_str("\":");
        doc.push_str(&i.to_string());
    }
    doc.push('}');
    doc
}

/// A document with `n` distinct keys, each with a decimal value.
fn float_document(n: usize) -> String {
    let mut doc = String::with_capacity(n * 40);
    doc.push('{');
    for i in 0..n {
        if i > 0 {
            doc.push(',');
        }
        doc.push_str("\"key_");
        doc.push_str(&format!("{i:06}"));
        doc.push_str("\":-");
        doc.push_str(&format!("{i}.5"));
        doc.push_str("125");
    }
    doc.push('}');
    doc
}

/// The best of nine runs of `f`, in milliseconds.
fn best_of_nine(mut f: impl FnMut() -> f64) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..9 {
        let secs = f();
        if secs < best {
            best = secs;
        }
    }
    best * 1_000.0
}

/// The time to parse `doc`, in milliseconds.
fn parse_ms(doc: &str) -> f64 {
    best_of_nine(|| {
        let start = Instant::now();
        let arena = rgx_core::djson::parse(doc).expect("the document parses");
        let elapsed = start.elapsed().as_secs_f64();
        std::hint::black_box(&arena);
        elapsed
    })
}

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000);

    let doc = document(n);
    let floats = float_document(n);

    // One parse to warm the allocator; the timed one is the second.
    let arena = rgx_core::djson::parse(&doc).expect("the document parses");
    let strings = arena.strings().len();

    let parse = parse_ms(&doc);
    let float_parse = parse_ms(&floats);

    // The shadow alone: the same number of distinct strings, interned into
    // an arena that never holds an object or a number.
    let keys: Vec<String> = (0..n).map(|i| format!("key_{i:06}")).collect();
    let intern = best_of_nine(|| {
        let mut arena = Arena::new();
        let start = Instant::now();
        for k in &keys {
            arena.intern(k.clone());
        }
        let elapsed = start.elapsed().as_secs_f64();
        std::hint::black_box(&arena);
        elapsed
    });

    println!(
        "keys={n} interned={strings} parse={parse:.3} ms floats={float_parse:.3} ms \
         intern={intern:.3} ms"
    );

    // The two number parsers, side by side: this crate's own decimal parser
    // and the standard library's. The `std` configuration parses with the
    // second one, the `no_std` configuration with the first.
    let numbers: Vec<String> = (0..n).map(|i| format!("-{i}.5125")).collect();
    let own = best_of_nine(|| {
        let start = Instant::now();
        for number in &numbers {
            let value = rgx_core::parse_decimal(number).expect("the number parses");
            std::hint::black_box(value);
        }
        start.elapsed().as_secs_f64()
    });
    let library = best_of_nine(|| {
        let start = Instant::now();
        for number in &numbers {
            let value: f64 = number.parse().expect("the number parses");
            std::hint::black_box(value);
        }
        start.elapsed().as_secs_f64()
    });
    println!("numbers={n} own={own:.3} ms library={library:.3} ms");
}
