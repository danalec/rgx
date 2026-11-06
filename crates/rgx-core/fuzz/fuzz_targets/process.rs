// SPDX-License-Identifier: Apache-2.0

//! Coverage-guided fuzzing of the full adapter pipeline.
//!
//! libFuzzer steers arbitrary bytes through every registered adapter by
//! rotating the claimed extension (first bytes of input pick it), so deep
//! parser states unreachable by the deterministic mutator get explored.
//! Panics, index-out-of-bounds and hangs are the failure modes under test —
//! `process` must never propagate them.
//!
//! Run:  cargo +nightly fuzz run process -- -max_total_time=300

#![no_main]

use libfuzzer_sys::fuzz_target;

/// Every adapter the fuzz target drives, in one place.
///
/// The registry and the extension list are built from THIS list, so there is
/// no second copy to drift: adding an adapter here puts it in both.
fn adapters() -> Vec<Box<dyn rgx_core::Adapter>> {
    let mut v: Vec<Box<dyn rgx_core::Adapter>> = Vec::new();
    v.extend(rgx_adapters_archive::adapters());
    v.extend(rgx_adapters_office::adapters());
    v.extend(rgx_adapters_threed::adapters());
    v.extend(rgx_adapters_llm::adapters());
    v.extend(rgx_adapters_media::adapters());
    v.extend(rgx_adapters_tabular::adapters());
    v.extend(rgx_adapters_docs::adapters());
    v.extend(rgx_adapters_mail::adapters());
    v.extend(rgx_adapters_inspect::adapters());
    v.extend(rgx_adapters_pdf::adapters());
    v
}

/// The registry, and every extension it can reach, out of ONE build.
///
/// The two used to be two hand-written lists that agreed by hand. They did
/// not: the extension list named 206 extensions and the registry reached
/// 443, so a fifth of the parsers were never driven by the fuzzer at all --
/// and the fuzzer is the only thing in the tree that drives the parsers
/// with bytes no fixture ever produces. A list kept beside the code is a
/// list that goes stale, and nothing in the build notices: the same lesson
/// `tests/crate_readmes.rs` writes down for the adapter READMEs ("a copy of
/// the list in the test would drift exactly the way the README does, and
/// two wrong copies agreeing would look like a pass").
///
/// So the list is derived. The extension strings are `&'static str`, so they
/// outlive the adapters that declared them: the boxes can go when the
/// vector does.
fn parts() -> (&'static rgx_core::Registry, &'static [&'static str]) {
    static PARTS: std::sync::OnceLock<(rgx_core::Registry, Vec<&'static str>)> =
        std::sync::OnceLock::new();
    PARTS.get_or_init(|| {
        let v = adapters();
        let mut exts: Vec<&'static str> =
            v.iter().flat_map(|a| a.extensions().iter().copied()).collect();
        exts.sort_unstable();
        exts.dedup();
        (rgx_core::Registry::new(v), exts)
    });
    let (reg, exts) = PARTS.get().expect("the registry is built above");
    (reg, exts.as_slice())
}

fn registry() -> &'static rgx_core::Registry {
    parts().0
}

fn extensions() -> &'static [&'static str] {
    &parts().1
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let ctx = rgx_core::Ctx {
        max_depth: 4,
        max_members: 256,
        max_file_size: 1 << 20,
        filter: None,
        facts_sink: None,
    };
    // rotate extensions across runs: byte 0 picks, rest is the payload
    let exts = extensions();
    let ext = exts[data[0] as usize % exts.len()];
    let path = format!("fuzz/sample.{ext}");
    let mut out = Vec::new();
    rgx_core::process(registry(), &path, &data[1..], 0, &ctx, &mut out);
    // touch the output so unit extraction isn't dead-stripped
    std::hint::black_box(out.len());
});
