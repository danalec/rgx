// SPDX-License-Identifier: Apache-2.0

use rgx_core::regex::ByteRegex;

fn main() {
    for pat in [
        "fn main",
        "e[0-9]",
        "pub fn",
        "(pub|fn) [a-z]+",
        "let mut",
        "foo.*bar",
        "error",
        "pub fn",
        "yes|no",
    ] {
        let re = ByteRegex::new(pat.as_bytes()).unwrap();
        println!("=== {pat} ===");
        for a in re.anchor_info() {
            println!("  {a:?}");
        }
    }
}
