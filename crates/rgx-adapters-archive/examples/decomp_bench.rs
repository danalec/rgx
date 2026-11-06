// SPDX-License-Identifier: Apache-2.0

//! Decode throughput of the in-house codecs, on real corpora, min of N.
//!
//! ```text
//! cargo run --release -p rgx-adapters-archive --example decomp_bench -- <file>... [--rounds N] [--check <plain>]
//! ```
//!
//! One row per input: compressed size, decoded size, the MINIMUM of the
//! timed rounds, and MB/s of decoded output. `--check` decodes once more
//! and compares byte-for-byte against the plain file -- a bench that
//! measures the wrong answer is a fast bench, so the check runs before
//! any timing is printed.
//!
//! For `.zst` the libzstd reference is timed in the same process (the
//! `zstd` crate is this crate's dev-dependency): same bytes, same rounds,
//! and the ratio is the honest headroom. The other formats have their
//! references in the shell (`zstd`/`xz`/`7z`/`bzip2` CLIs), not here.

use std::hint::black_box;
use std::time::Instant;

use rgx_adapters_archive::brotli::BrotliDecoder;
use rgx_adapters_archive::lz4::Lz4Decoder;
use rgx_adapters_archive::sevenz::SevenzArchive;

const UNLIMITED: u64 = u64::MAX;

fn main() {
    let mut files: Vec<String> = Vec::new();
    let mut rounds = 5usize;
    let mut check: Option<String> = None;
    let mut dump: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--rounds" => {
                rounds = args.next().and_then(|v| v.parse().ok()).unwrap_or(5);
            }
            "--check" => check = args.next(),
            "--dump" => dump = args.next(),
            _ => files.push(a),
        }
    }
    if files.is_empty() {
        eprintln!(
            "usage: decomp_bench <file.(zst|xz|bz2|br|7z|lz4)>... [--rounds N] [--check <plain>]"
        );
        std::process::exit(2);
    }
    let plain: Option<Vec<u8>> = check.map(|p| std::fs::read(p).expect("read --check"));
    if rounds < 3 {
        rounds = 3;
    }

    for f in files {
        let data = std::fs::read(&f).unwrap_or_else(|e| panic!("read {f}: {e}"));
        let ext = f.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        let dec = |data: &[u8]| -> Vec<u8> {
            match &*ext {
                "zst" | "zstd" => {
                    rgx_core::compress::zstd::ZstdDecoder::new()
                        .decode_bounded(data, UNLIMITED)
                        .expect("zstd decode")
                        .bytes
                }
                "xz" => {
                    rgx_core::compress::xz::XzReader::decompress_bounded(data, UNLIMITED)
                        .expect("xz decode")
                        .bytes
                }
                "bz2" => {
                    rgx_core::compress::bzip2::Bzip2Decoder::new()
                        .decode_bounded(data, UNLIMITED)
                        .expect("bzip2 decode")
                        .bytes
                }
                "br" => {
                    BrotliDecoder::new()
                        .decode_bounded(data, UNLIMITED)
                        .expect("brotli decode")
                        .bytes
                }
                "7z" => {
                    let arc = SevenzArchive::parse(data).expect("7z parse");
                    arc.extract(0).expect("7z extract")
                }
                "lz4" => {
                    Lz4Decoder::new()
                        .decode_auto_bounded(data, UNLIMITED)
                        .expect("lz4 decode")
                        .bytes
                }
                other => panic!("unknown extension .{other}"),
            }
        };

        let out = dec(&data);
        if let Some(d) = &dump {
            std::fs::write(d, &out).expect("write --dump");
        }
        if let Some(p) = &plain {
            assert_eq!(
                out.len(),
                p.len(),
                "{f}: decoded {} bytes, plain is {}",
                out.len(),
                p.len()
            );
            let first_bad = out.iter().zip(p.iter()).position(|(a, b)| a != b);
            assert!(first_bad.is_none(), "{f}: first mismatch at {first_bad:?}");
        }
        let mib = out.len() as f64 / (1024.0 * 1024.0);

        let mut best = f64::INFINITY;
        for _ in 0..rounds {
            let t = Instant::now();
            let o = dec(&data);
            let got = black_box(o.len());
            let _ = got;
            let ms = t.elapsed().as_secs_f64() * 1000.0;
            if ms < best {
                best = ms;
            }
        }
        println!(
            "{f:<44} {ext:<4} {:>8.1} MB -> {:>7.1} MB   {:>8.1} ms   {:>7.1} MB/s",
            data.len() as f64 / (1024.0 * 1024.0),
            mib,
            best,
            mib / (best / 1000.0),
        );

        // The in-process libzstd reference, same rounds, same bytes.
        if ext == "zst" || ext == "zstd" {
            let mut best = f64::INFINITY;
            for _ in 0..rounds {
                let t = Instant::now();
                let o = zstd::stream::decode_all(&data[..]).expect("libzstd");
                let _ = black_box(o.len());
                let ms = t.elapsed().as_secs_f64() * 1000.0;
                if ms < best {
                    best = ms;
                }
            }
            println!(
                "{:<44} libzstd (zstd crate)            {:>8.1} ms   {:>7.1} MB/s",
                "",
                best,
                mib / (best / 1000.0),
            );
        }
    }
}
