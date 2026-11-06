// SPDX-License-Identifier: Apache-2.0

//! Print what the JSON parser does with a battery of awkward inputs.
//!
//! A review wants to see behavior, not to infer it from the source: the
//! interesting cases here are the ones where "does it parse" and "what did
//! it produce" are different questions, which is how the two serializer
//! bugs in this module stayed invisible for as long as they did.
//!
//! ```text
//! cargo run --release -p rgx-core --example json_probe
//! ```

use rgx_core::djson::{parse, to_string, to_string_pretty, Arena, Value};

fn show(input: &str) {
    match parse(input) {
        Ok(arena) => {
            let root = arena.root();
            let compact = to_string(root, &arena);
            let round = parse(&compact);
            let reprints = match &round {
                Ok(r) => to_string(r.root(), r) == compact,
                Err(_) => false,
            };
            let pretty = to_string_pretty(root, &arena);
            let pretty_parses = parse(&pretty).is_ok();
            println!(
                "{:<44} -> {:<34} compact={:<34} reparse={} pretty_ok={}",
                esc(input),
                kind(&arena, root),
                esc(&compact),
                if reprints { "yes" } else { "NO" },
                if pretty_parses { "yes" } else { "NO" }
            );
        }
        Err(e) => println!("{:<44} -> ERR {}", esc(input), e),
    }
}

fn kind(arena: &Arena, v: Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => format!("bool {b}"),
        Value::Number(n) => format!("number {n}"),
        Value::String(idx) => {
            let s = arena.get_string(idx);
            format!("string {:?}", trunc(s))
        }
        Value::Array(idx) => format!("array[{}]", arena.get_array(idx).len()),
        Value::Object(idx) => format!("object{{{}}}", arena.get_object(idx).len()),
    }
}

fn trunc(s: &str) -> String {
    let t: String = s.chars().take(18).collect();
    if s.chars().count() > 18 {
        format!("{t}...")
    } else {
        t
    }
}

fn esc(s: &str) -> String {
    use core::fmt::Write as _;
    let mut o = String::new();
    for c in s.chars() {
        match c {
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            '"' => o.push_str("\\\""),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o
}

fn main() {
    println!("== numbers ==");
    for n in [
        "0",
        "-0",
        "1",
        "-1",
        "1.0",
        "1e2",
        "1E2",
        "1e+2",
        "1e-2",
        "0.1",
        "0.0000001",
        "1e400",
        "-1e400",
        "9007199254740993",
        "18446744073709551615",
        "18446744073709551616",
        "-9223372036854775808",
        "-9223372036854775809",
        "1.7976931348623157e308",
        "5e-324",
        "01",
        "+1",
        ".5",
        "5.",
        "Infinity",
        "NaN",
        "1_000",
    ] {
        show(n);
    }

    println!("\n== strings ==");
    for s in [
        r#""""#,
        r#""a""#,
        r#""\"""#,
        r#""\\""#,
        r#""\/""#,
        r#""\b\f\n\r\t""#,
        r#""\u0041""#,
        r#""\u00e9""#,
        r#""\uD83C\uDFAF""#,
        r#""\uD83C""#,
        r#""\uDFAF""#,
        r#""\uDEAD""#,
        r#""\q""#,
        r#""\x41""#,
        r#""café 🎯""#,
        "\"raw\ttab\"",
    ] {
        show(s);
    }

    println!("\n== structure ==");
    for s in [
        "{}",
        "[]",
        "[1,2,3]",
        r#"{"a":1,"a":2}"#,
        r#"{"a\"b":1}"#,
        r#"{"":1}"#,
        r#"{"a":1,}"#,
        "[1,]",
        "[1 2]",
        "  1  ",
        "1 2",
        "",
        "   ",
        "nul",
        "tru",
        "[",
        "]",
        r#"{"a"}"#,
        r#"{"a":}"#,
        r#"{,}"#,
    ] {
        show(s);
    }

    println!("\n== depth ==");
    for d in [1, 127, 128, 129, 200] {
        show(&format!("{}1{}", "[".repeat(d), "]".repeat(d)));
    }

    println!("\n== keys that need escaping on the way out ==");
    for s in [
        r#"{"a\"b":1}"#,
        r#"{"a\\b":1}"#,
        r#"{"a\nb":1}"#,
        r#"{"é":1}"#,
        r#"{"🎯":1}"#,
        r#"{"":1}"#,
    ] {
        show(s);
    }
}
