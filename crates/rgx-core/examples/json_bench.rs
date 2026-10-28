// SPDX-License-Identifier: Apache-2.0

//! Where does a JSON parse spend its time, and what does materialising
//! the document cost?
//!
//! The lazy-parsing work in `djson` is only worth doing if the Arena
//! build (Stage 2 + materialisation) is a real fraction of what the
//! adapters spend. This decomposes one adapter-shaped run per corpus
//! into: Stage 1 scan, full parse into an Arena, the consumer walk the
//! adapters actually do, and the serialisation the GLB/Keras paths pay.
//! Every phase also reports the bytes it allocated, counted by a
//! `#[global_allocator]` wrapper — "materialisation" has two prices,
//! time and memory, and the lazy walker must win on both to exist.
//!
//! Output gate, same spirit as `bench-status.sh`: a phase only reports
//! if its consumer output is non-empty and identical across rounds, and
//! `to_string` round-trips through `parse`. A phase whose output moved
//! would be timing the wrong work.
//!
//! ```text
//! cargo run --release -p rgx-core --example json_bench
//! ```

use std::alloc::{GlobalAlloc, Layout, System};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use rgx_core::djson::json_scan;
use rgx_core::djson::ondemand::Ondemand;
use rgx_core::djson::{parse, to_string, to_string_pretty, Arena, Value};

// ---------------------------------------------------------------------
// Counting allocator
// ---------------------------------------------------------------------

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static TOTAL: AtomicUsize = AtomicUsize::new(0);

fn record_add(size: usize) {
    let now = CURRENT.fetch_add(size, Ordering::Relaxed) + size;
    PEAK.fetch_max(now, Ordering::Relaxed);
    TOTAL.fetch_add(size, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            record_add(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Snapshot the counters; the phase's report is the delta of the two.
struct AllocSnap {
    total: usize,
    peak_live: usize,
}

fn alloc_snap() -> AllocSnap {
    let base = CURRENT.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    AllocSnap {
        total: TOTAL.load(Ordering::Relaxed),
        peak_live: base,
    }
}

impl AllocSnap {
    /// (bytes allocated in total, extra bytes live at the peak)
    fn delta(&self) -> (usize, usize) {
        (
            TOTAL.load(Ordering::Relaxed).saturating_sub(self.total),
            PEAK.load(Ordering::Relaxed).saturating_sub(self.peak_live),
        )
    }
}

// ---------------------------------------------------------------------
// Corpora: generated, but shaped like what the adapters see
// ---------------------------------------------------------------------

/// glTF 2.0 as the GLB JSON chunk carries it: named nodes/meshes and
/// the numeric-heavy accessor/bufferView tail the adapter discards.
fn gltf_like() -> String {
    let mut out = String::new();
    out.push_str(
        r#"{"asset":{"version":"2.0","generator":"rgx json_bench"},"scene":0,
"scenes":[{"name":"Scene","nodes":["#,
    );
    for i in 0..2000 {
        if i > 0 {
            out.push(',');
        }
        write!(out, "{i}").unwrap();
    }
    out.push_str("]}],\"nodes\":[");
    for i in 0..2000 {
        if i > 0 {
            out.push(',');
        }
        write!(
            out,
            "{{\"name\":\"Node {i}\",\"mesh\":{i},\"translation\":[{a}.25,-{b}.5,{c}.75],\
\"rotation\":[0.0,0.0,0.0,1.0],\"children\":[{j}]}}",
            a = i % 100,
            b = i % 57,
            c = i % 31,
            j = (i + 1) % 2000
        )
        .unwrap();
    }
    out.push_str("],\"meshes\":[");
    for i in 0..2000 {
        if i > 0 {
            out.push(',');
        }
        write!(
            out,
            "{{\"name\":\"Mesh {i}\",\"primitives\":\
[{{\"attributes\":{{\"POSITION\":{i}}},\"indices\":{i},\"material\":{i}}}]}}",
            i = i
        )
        .unwrap();
    }
    out.push_str("],\"materials\":[");
    for i in 0..500 {
        if i > 0 {
            out.push(',');
        }
        write!(
            out,
            "{{\"name\":\"Material {i}\",\"pbrMetallicRoughness\":\
{{\"baseColorFactor\":[0.5,0.5,0.5,1.0],\"metallicFactor\":0.1,\"roughnessFactor\":0.9}}}}",
            i = i
        )
        .unwrap();
    }
    out.push_str("],\"accessors\":[");
    for i in 0..4000 {
        if i > 0 {
            out.push(',');
        }
        write!(
            out,
            "{{\"bufferView\":{i},\"componentType\":5126,\"count\":{c},\"type\":\"VEC3\",\
\"min\":[-1.5,-2.5,-3.5],\"max\":[1.5,2.5,3.5]}}",
            i = i,
            c = (i % 97) + 3
        )
        .unwrap();
    }
    out.push_str("],\"bufferViews\":[");
    for i in 0..4000 {
        if i > 0 {
            out.push(',');
        }
        write!(
            out,
            "{{\"buffer\":0,\"byteOffset\":{o},\"byteLength\":{l}}}",
            o = i * 64,
            l = 64
        )
        .unwrap();
    }
    out.push_str("],\"buffers\":[{\"byteLength\":262144}]}");
    out
}

/// safetensors header as the adapter sees it: one entry per tensor with
/// dtype/shape/data_offsets, plus a `__metadata__` tail. This is the
/// shape where the parser builds thousands of objects to read three
/// fields per object.
fn safetensors_like() -> String {
    let mut out = String::new();
    out.push_str("{\"__metadata__\":{");
    for i in 0..40 {
        if i > 0 {
            out.push(',');
        }
        write!(
            out,
            "\"meta_key_{i}\":\"meta value number {i} for the run\""
        )
        .unwrap();
    }
    out.push_str("},");
    for i in 0..20_000 {
        if i > 0 {
            out.push(',');
        }
        write!(
            out,
            "\"model.layers.{l}.blocks.{i}.{p}_proj.{w}\":\
{{\"dtype\":\"F32\",\"shape\":[{a},{b}],\"data_offsets\":[{o},{e}]}}",
            l = i % 80,
            i = i,
            p = ["q", "k", "v", "o"][i % 4],
            w = ["weight", "bias"][i % 2],
            a = 4096,
            b = 1024 + (i % 7),
            o = i * 16_777_216,
            e = (i + 1) * 16_777_216
        )
        .unwrap();
    }
    out.push('}');
    out
}

/// A tokenizer.json-shaped document: a large vocab map (key -> id) and
/// an added-tokens array of objects.
fn tokenizer_like() -> String {
    let mut out = String::new();
    out.push_str("{\"model\":{\"type\":\"BPE\",\"vocab\":{");
    for i in 0..60_000 {
        if i > 0 {
            out.push(',');
        }
        write!(out, "\"tok{i}\":{i}").unwrap();
    }
    out.push_str("}},\"added_tokens\":[");
    for i in 0..8000 {
        if i > 0 {
            out.push(',');
        }
        write!(
            out,
            "{{\"id\":{i},\"content\":\"added token number {i}\",\"special\":false}}",
            i = i
        )
        .unwrap();
    }
    out.push_str("]}");
    out
}

/// A Keras-style config, minified: small, deeply nested, mostly strings.
fn config_minified() -> String {
    let mut out = String::new();
    out.push_str(
        "{\"class_name\":\"Functional\",\"config\":{\"name\":\"zircaloy_net\",\"layers\":[",
    );
    for i in 0..200 {
        if i > 0 {
            out.push(',');
        }
        write!(
            out,
            "{{\"class_name\":\"Dense\",\"config\":{{\"name\":\"dense_{i}\",\"units\":{u},\
\"activation\":\"relu\",\"use_bias\":true,\"dtype\":\"float32\"}}}}",
            i = i,
            u = 32 + (i % 9) * 64
        )
        .unwrap();
    }
    out.push_str(
        "],\"input_layers\":[[\"input_1\",0,0]],\"output_layers\":[[\"dense_199\",0,0]]}}",
    );
    out
}

// ---------------------------------------------------------------------
// Consumer walks: exactly what the adapters do with the Arena
// ---------------------------------------------------------------------

/// The safetensors adapter's walk: root keys, `__metadata__` k:v lines,
/// then per tensor dtype + shape.
fn consume_safetensors(root: Value, arena: &Arena) -> String {
    let mut out = String::new();
    if let Some(meta_v) = root.get(arena, "__metadata__") {
        if let Some(meta) = meta_v.as_object(arena) {
            for (k_idx, v) in meta.iter() {
                let k = arena.get_string(*k_idx);
                let val_text = v.as_str(arena).unwrap_or("?");
                let _ = writeln!(out, "{k}: {val_text}");
            }
        }
    }
    if let Some(obj) = root.as_object(arena) {
        for (k_idx, t) in obj.iter() {
            let name = arena.get_string(*k_idx);
            if name == "__metadata__" {
                continue;
            }
            let dtype = t
                .get(arena, "dtype")
                .and_then(|d| d.as_str(arena))
                .unwrap_or("?");
            let shape = t.get(arena, "shape").and_then(|s| s.as_array(arena));
            let _ = write!(out, "tensor {name}: dtype={dtype} shape=[");
            if let Some(a) = shape {
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        let _ = write!(out, "x");
                    }
                    match v.as_u64() {
                        Some(u) => {
                            let _ = write!(out, "{u}");
                        }
                        None => {
                            let _ = write!(out, "?");
                        }
                    }
                }
            }
            let _ = writeln!(out, "]");
        }
    }
    out
}

/// The threed adapter's walk: a fixed key list, `name` of each item,
/// and the `asset` subtree re-serialised.
fn consume_threed(root: Value, arena: &Arena) -> String {
    let mut out = String::new();
    for key in ["scenes", "nodes", "meshes", "materials", "skins", "images"] {
        if let Some(arr) = root.get(arena, key).and_then(|v| v.as_array(arena)) {
            let _ = writeln!(out, "{key}: {}", arr.len());
            for item in arr {
                if let Some(name) = item.get(arena, "name").and_then(|n| n.as_str(arena)) {
                    let _ = writeln!(out, "  {key}[..]: {name}");
                }
            }
        }
    }
    if let Some(asset) = root.get(arena, "asset") {
        let _ = writeln!(out, "asset: {}", to_string(asset, arena));
    }
    out
}

// ---------------------------------------------------------------------
// Lazy consumer walks: the same questions, answered without an Arena
// ---------------------------------------------------------------------

/// The safetensors adapter's questions over the lazy cursor: root
/// keys, `__metadata__` strings, per tensor dtype + shape.
fn lazy_safetensors(text: &str) -> String {
    let mut doc = Ondemand::new(text).expect("opens");
    let mut tensors = 0u64;
    let mut meta = 0u64;
    let mut shape_dims = 0u64;
    let root = doc.root().expect("root");
    root.object_entries(|k, mut v| {
        if k.as_ref() == "__metadata__" {
            if v.is_object().expect("kind") {
                v.object_entries(|_, mv| {
                    let _ = mv.as_str()?;
                    meta += 1;
                    Ok(true)
                })
                .expect("meta");
            } else {
                v.skip().expect("meta");
            }
            return Ok(true);
        }
        let _name = k;
        if v.is_object().expect("kind") {
            v.object_entries(|tk, mut tv| {
                match tk.as_ref() {
                    "dtype" => {
                        let _ = tv.as_str()?;
                    }
                    "shape" if tv.is_array().expect("kind") => {
                        tv.array_items(|_, item| {
                            let _ = item.as_u64()?;
                            shape_dims += 1;
                            Ok(true)
                        })
                        .expect("shape");
                    }
                    _ => {}
                }
                Ok(true)
            })
            .expect("tensor");
        } else {
            v.skip().expect("tensor");
        }
        tensors += 1;
        Ok(true)
    })
    .expect("entries");
    doc.finish().expect("no trailing");
    format!("tensors {tensors} meta {meta} dims {shape_dims}")
}

/// The threed adapter's questions over the lazy cursor: the fixed key
/// lists with names, plus the `asset` fragment re-serialised.
fn lazy_threed(text: &str) -> String {
    let mut doc = Ondemand::new(text).expect("opens");
    let mut counts = [0u64; 6];
    let mut names = 0u64;
    let mut asset = String::new();
    const KEYS: [&str; 6] = ["scenes", "nodes", "meshes", "materials", "skins", "images"];
    let root = doc.root().expect("root");
    root.object_entries(|k, mut v| {
        if k.as_ref() == "asset" {
            asset = v.to_compact_string().expect("asset");
            return Ok(true);
        }
        if let Some(slot) = KEYS.iter().position(|&key| key == k.as_ref()) {
            if v.is_array().expect("kind") {
                v.array_items(|_, item| {
                    counts[slot] += 1;
                    let mut found = None;
                    item.find_key("name", |n| {
                        found = n.as_str()?;
                        Ok(())
                    })
                    .expect("name");
                    if found.is_some() {
                        names += 1;
                    }
                    Ok(true)
                })
                .expect("items");
            }
        }
        Ok(true)
    })
    .expect("entries");
    doc.finish().expect("no trailing");
    format!("counts {counts:?} names {names} asset {asset}")
}

// ---------------------------------------------------------------------
// Phase runner: best of 7, allocation from one extra run
// ---------------------------------------------------------------------

fn bench<F>(label: &str, n: usize, mut f: F)
where
    F: FnMut() -> (u64, String),
{
    const ROUNDS: usize = 7;

    // The output gate: every round must produce the same answer.
    let (first_sig, first_out) = f();
    assert!(!first_out.is_empty(), "{label}: empty consumer output");

    let mut lo = f64::MAX;
    for _ in 0..ROUNDS {
        let t = Instant::now();
        let (sig, out) = f();
        lo = lo.min(t.elapsed().as_secs_f64());
        assert_eq!(sig, first_sig, "{label}: output moved between rounds");
        assert_eq!(out, first_out, "{label}: output text moved between rounds");
    }

    // One untimed run for the allocation delta.
    let snap = alloc_snap();
    let _ = f();
    let (allocated, peak_extra) = snap.delta();

    let ms = lo * 1000.0;
    let gbs = (n as f64 / 1e9) / lo;
    let mb = allocated as f64 / 1e6;
    let mb_peak = peak_extra as f64 / 1e6;
    println!(
        "{label:<28} {ms:8.2} ms  {gbs:6.2} GB/s  alloc {mb:7.1} MB  peak-live {mb_peak:7.1} MB"
    );
}

fn main() {
    let corpora: [(&str, String); 4] = [
        ("gltf", gltf_like()),
        ("safetensors", safetensors_like()),
        ("tokenizer", tokenizer_like()),
        ("config", config_minified()),
    ];

    for (name, text) in &corpora {
        let n = text.len();
        println!("\n== {name}: {n} bytes ==");

        // Round-trip gate before any timing: the corpus must parse, its
        // serialisation must reparse, and the serialisation must still
        // BE the document — a collapsed output would round-trip happily
        // and make every number below a lie (that is how `to_string`
        // once measured 150 GB/s on a 2 MB corpus).
        let arena0 = parse(text).expect("corpus parses");
        let compact = to_string(arena0.root(), &arena0);
        println!("   compact output: {} bytes", compact.len());
        assert!(
            compact.len() > n / 2,
            "compact serialisation collapsed: {} bytes out of {} in",
            compact.len(),
            n
        );
        parse(&compact).expect("compact round-trip");
        drop(arena0);

        // Stage 1 alone.
        bench("scan (stage 1)", n, || {
            let idx = json_scan::scan(text.as_bytes());
            (idx.structural.count_ones() as u64, "ok".to_string())
        });

        // Full parse: Stage 1 + Stage 2 + arena materialisation.
        bench("parse (arena)", n, || {
            let a = parse(text).expect("parses");
            let sig = a.strings().len() as u64;
            (sig, format!("{sig}"))
        });

        // Serialisation only, over a pre-parsed arena.
        {
            let a = parse(text).expect("parses");
            bench("to_string (compact)", n, || {
                let s = to_string(a.root(), &a);
                let sig = s.len() as u64;
                (sig, s)
            });
            bench("to_string_pretty", n, || {
                let s = to_string_pretty(a.root(), &a);
                let sig = s.len() as u64;
                (sig, s)
            });
        }

        // The adapter-shaped end-to-end walks. Each runs only where its
        // consumer has real content: an all-misses walk would time the
        // wrong work and its output gate is legitimately empty.
        if name == &"safetensors" || name == &"tokenizer" {
            bench("adapter safetensors", n, || {
                let a = parse(text).expect("parses");
                let out = consume_safetensors(a.root(), &a);
                let sig = out.len() as u64;
                (sig, out)
            });
        }
        if name == &"gltf" {
            bench("adapter threed", n, || {
                let a = parse(text).expect("parses");
                let out = consume_threed(a.root(), &a);
                let sig = out.len() as u64;
                (sig, out)
            });
        }

        // The lazy counterpart of the same walks: validate everything,
        // materialise only what the consumer reads.
        bench("ondemand skip (validate)", n, || {
            let mut od = Ondemand::new(text).expect("opens");
            od.root().expect("root").skip().expect("valid");
            od.finish().expect("no trailing");
            (1, String::from("ok"))
        });
        if name == &"safetensors" || name == &"tokenizer" {
            bench("ondemand safetensors", n, || {
                let out = lazy_safetensors(text);
                let sig = out.len() as u64;
                (sig, out)
            });
        }
        if name == &"gltf" {
            bench("ondemand threed", n, || {
                let out = lazy_threed(text);
                let sig = out.len() as u64;
                (sig, out)
            });
        }
    }

    println!(
        "\nread: 'parse (arena)' minus 'scan' is Stage 2 + materialisation;\n\
         'adapter X' minus 'parse' is the walk the consumer pays on top;\n\
         'ondemand X' is the same questions with no Arena at all."
    );
}
