// SPDX-License-Identifier: Apache-2.0

use std::process::{Command, Stdio};
use std::time::Instant;

fn run(args: &[&str]) -> f64 {
    let mut cmd = Command::new("target/release/rgx.exe");
    cmd.args(args);
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    let t = Instant::now();
    let _ = cmd.output();
    t.elapsed().as_secs_f64() * 1e3
}

fn stat(args: &[&str]) -> (f64, f64, f64, f64) {
    let mut v = Vec::new();
    for _ in 0..9 {
        v.push(run(args));
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let min = v[0];
    let med = v[v.len() / 2];
    let max = *v.last().unwrap();
    (min, med, max, v[1])
}

fn main() {
    let walks = ["-j", "32", "--files", "-g", "!testdata", "-g", "!*.bin", "-g", "!*.gz", "crates"];
    let fulls = ["-j", "32", "-c", "fn main", "-g", "!testdata", "-g", "!*.bin", "-g", "!*.gz", "crates"];
    let helps = ["--version"];

    println!("rgx walk-vs-search phase measurement (Rust-side Instant, Stdio::null)");
    println!("rounds: 9, +2 warmup discarded by sort; report min,med,max\n");

    for (label, args) in [("walk  --files (no read, no search, no format)", &walks[..]),
                          ("full  -c fn main (everything)", &fulls[..]),
                          ("bench --version (process spawn only)", &helps[..])] {
        let mut samples = Vec::new();
        for _ in 0..2 { let _ = run(args); }
        let (mn, md, mx, mn2) = stat(args);
        samples.push(mn); samples.push(md); samples.push(mx); samples.push(mn2);
        let sorted_str = samples.iter().map(|x| format!("{x:.1}")).collect::<Vec<_>>().join(", ");
        println!("  {label:<48}  min={mn:7.2}  med={md:7.2}  max={mx:7.2}  (sorted: [{sorted_str}])");
    }
    println!();
    println!("Implication: walk_ms vs full_ms = stage above walk. full_ms - walk_ms is");
    println!("read+search+format overhead (the in-house engine dominates that).");
}
