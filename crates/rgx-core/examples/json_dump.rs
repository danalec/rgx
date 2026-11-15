// SPDX-License-Identifier: Apache-2.0

//! Differential JSON dump for rgx, byte-identical to the canonical
//! line. A run exposes the parser by reading a JSON file from
//! argv[1] and writing one canonical line to stdout.
//!
//! Format (one line, byte 0x1F between tokens):
//!   OK <canonical dump>    accepted
//!   NO <error category>    rejected
//!
//! Canonical dump is document-order:
//!   O{ O} A[ A]   container delimiters
//!   K<key> S<str> string keys and string values (decoded UTF-8)
//!   N<number>     numbers, in their original source bytes
//!   T F Z         booleans and null
//!
//! Both sides emit the same byte content for the same input.  Numbers
//! carry their original spelling from the source through the walk, so
//! 1e3 stays 1e3 (it is parsed as F64, but the dump prints the source).
//!
//! Strict-mode pre-checks (leading zero, plus sign, control char in
//! string, lone surrogate, numeric overflow, trailing comma) match
//! rgx's parser behaviour and run before the parser, so the same
//! NO <category> is reported for inputs a permissive tokenizer would
//! accept.

use std::collections::BTreeSet;
use std::io::Write;
use std::process::ExitCode;

use rgx_core::djson::{parse, Arena, Number, Value};

const US: u8 = 0x1F;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 {
        // Single-path mode.
        process_one(&args[1]);
    } else {
        // Batch mode: paths are read from stdin, one per line.
        let stdin = std::io::stdin();
        let mut line = String::new();
        while stdin.read_line(&mut line).unwrap_or(0) > 0 {
            let p = line.trim().to_string();
            if !p.is_empty() {
                process_one(&p);
            }
            line.clear();
        }
    }
    ExitCode::SUCCESS
}

fn process_one(path: &str) {
    let src = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            println!("NO IO_ERROR");
            eprintln!("{path}: {e}");
            return;
        }
    };
    let mut out = Vec::with_capacity(src.len() * 2);
    if let Some(cat) = pre_check(&src) {
        out.extend_from_slice(b"NO ");
        out.extend_from_slice(cat.as_bytes());
        out.push(b'\n');
    } else {
        let s = match std::str::from_utf8(&src) {
            Ok(s) => s,
            Err(_) => {
                out.extend_from_slice(b"NO UTF8\n");
                let _ = std::io::stdout().write_all(&out);
                return;
            }
        };
        match parse(s) {
            Ok(arena) => {
                let mut cursor = 0usize;
                walk_value(&src, &mut cursor, &arena, arena.root(), &mut out);
                out.push(b'\n');
            }
            Err(e) => {
                out.extend_from_slice(b"NO ");
                out.extend_from_slice(category_from_msg(&e.message).as_bytes());
                out.push(b'\n');
            }
        }
    }
    let _ = std::io::stdout().write_all(&out);
}

// ---- walker -----------------------------------------------------------

fn walk_value(src: &[u8], cursor: &mut usize, arena: &Arena, v: Value, out: &mut Vec<u8>) {
    skip_ws(src, cursor);
    match v {
        Value::Null => {
            *cursor += 4;
            out.push(b'Z');
            out.push(US);
        }
        Value::Bool(true) => {
            *cursor += 4;
            out.push(b'T');
            out.push(US);
        }
        Value::Bool(false) => {
            *cursor += 5;
            out.push(b'F');
            out.push(US);
        }
        Value::Number(_) => {
            let start = *cursor;
            advance_number(src, cursor);
            out.push(b'N');
            out.extend_from_slice(&src[start..*cursor]);
            out.push(US);
        }
        Value::String(idx) => {
            // Advance the cursor past the source string literal so the
            // walker stays in lockstep with the byte stream.  The
            // string content is taken from the parsed Value, which is
            // already the decoded UTF-8, so the dump emits the same
            // bytes the canonical line uses.
            skip_string_literal(src, cursor);
            out.push(b'S');
            push_escaped(arena.get_string(idx), out);
            out.push(US);
        }
        Value::Array(idx) => {
            let items = arena.get_array(idx);
            debug_assert_eq!(src[*cursor], b'[');
            *cursor += 1;
            out.push(b'A');
            out.push(b'[');
            out.push(US);
            skip_ws(src, cursor);
            if src.get(*cursor) == Some(&b']') {
                *cursor += 1;
            } else {
                let mut i = 0;
                while i < items.len() {
                    skip_ws(src, cursor);
                    walk_value(src, cursor, arena, items[i], out);
                    i += 1;
                    skip_ws(src, cursor);
                    if src.get(*cursor) == Some(&b']') {
                        *cursor += 1;
                        break;
                    }
                    debug_assert_eq!(src[*cursor], b',');
                    *cursor += 1;
                }
            }
            out.push(b'A');
            out.push(b']');
            out.push(US);
        }
        Value::Object(obj_idx) => {
            debug_assert_eq!(src[*cursor], b'{');
            *cursor += 1;
            out.push(b'O');
            out.push(b'{');
            out.push(US);
            skip_ws(src, cursor);
            if src.get(*cursor) == Some(&b'}') {
                *cursor += 1;
            } else {
                // Walk the source in document order, decoding each
                // key as we go.  The decoded key text is matched
                // against the arena's string table; the matching
                // intern index gives us the parsed value.  We use the
                // source range only to advance the cursor.
                // Duplicates within a scope are dropped on both
                // sides, so the dumps agree byte-for-byte.
                let mut seen: BTreeSet<String> = BTreeSet::new();
                let mut first = true;
                loop {
                    skip_ws(src, cursor);
                    if src.get(*cursor) != Some(&b'}') && src.get(*cursor).is_none() {
                        // Out of source -- the walk was somehow longer
                        // than the actual document; give up rather than
                        // panic on a slice index past the end.
                        break;
                    }
                    if src.get(*cursor) == Some(&b'}') {
                        *cursor += 1;
                        break;
                    }
                    if !first {
                        skip_ws(src, cursor);
                        if src.get(*cursor) != Some(&b',') {
                            // Malformed: stop rather than read a bogus
                            // comma (which would push the source past end).
                            break;
                        }
                        *cursor += 1;
                        skip_ws(src, cursor);
                    }
                    first = false;
                    let (kstart, kend) = read_string_range(src, cursor);
                    skip_ws(src, cursor);
                    if src.get(*cursor) != Some(&b':') {
                        break;
                    }
                    *cursor += 1;
                    let key_decoded = decode_string(&src[kstart..kend]);
                    if !seen.insert(key_decoded.clone()) {
                        // Duplicate key -- the arena's BTreeMap keeps
                        // only the LAST value, but we want a value
                        // walk that advances the cursor.  Skip the
                        // value bytes for this occurrence.
                        skip_value_range(src, cursor);
                        continue;
                    }
                    if let Some(value) = arena.object_get(obj_idx, &key_decoded) {
                        out.push(b'K');
                        push_escaped(&key_decoded, out);
                        out.push(US);
                        walk_value(src, cursor, arena, value, out);
                    }
                }
            }
            out.push(b'O');
            out.push(b'}');
            out.push(US);
        }
    }
}

fn skip_ws(src: &[u8], cursor: &mut usize) {
    while let Some(&b) = src.get(*cursor) {
        if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
            *cursor += 1;
        } else {
            break;
        }
    }
}

fn skip_value_range(src: &[u8], cursor: &mut usize) {
    skip_ws(src, cursor);
    if *cursor >= src.len() {
        return;
    }
    match src[*cursor] {
        b'{' => {
            *cursor += 1;
            let mut depth = 1;
            while *cursor < src.len() && depth > 0 {
                match src[*cursor] {
                    b'{' | b'[' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            *cursor += 1;
                            break;
                        }
                    }
                    b'"' => {
                        *cursor += 1;
                        while *cursor < src.len() && src[*cursor] != b'"' {
                            if src[*cursor] == b'\\' {
                                *cursor += 1;
                            }
                            *cursor += 1;
                        }
                    }
                    _ => {}
                }
                *cursor += 1;
            }
        }
        b'[' => {
            *cursor += 1;
            let mut depth = 1;
            while *cursor < src.len() && depth > 0 {
                match src[*cursor] {
                    b'[' | b'{' => depth += 1,
                    b']' => {
                        depth -= 1;
                        if depth == 0 {
                            *cursor += 1;
                            break;
                        }
                    }
                    b'"' => {
                        *cursor += 1;
                        while *cursor < src.len() && src[*cursor] != b'"' {
                            if src[*cursor] == b'\\' {
                                *cursor += 1;
                            }
                            *cursor += 1;
                        }
                    }
                    _ => {}
                }
                *cursor += 1;
            }
        }
        b'"' => {
            *cursor += 1;
            while *cursor < src.len() && src[*cursor] != b'"' {
                if src[*cursor] == b'\\' {
                    *cursor += 1;
                }
                *cursor += 1;
            }
            if *cursor < src.len() {
                *cursor += 1;
            }
        }
        _ => {
            while *cursor < src.len() {
                let b = src[*cursor];
                if b == b','
                    || b == b'}'
                    || b == b']'
                    || b == b' '
                    || b == b'\t'
                    || b == b'\n'
                    || b == b'\r'
                {
                    break;
                }
                *cursor += 1;
            }
        }
    }
    skip_ws(src, cursor);
    // Skip optional trailing comma.
    if *cursor < src.len() && src[*cursor] == b',' {
        *cursor += 1;
    }
}

fn advance_number(src: &[u8], cursor: &mut usize) {
    let mut i = *cursor;
    if i < src.len() && src[i] == b'-' {
        i += 1;
    }
    while i < src.len() {
        let b = src[i];
        if b.is_ascii_digit() || b == b'.' || b == b'e' || b == b'E' || b == b'+' || b == b'-' {
            i += 1;
        } else {
            break;
        }
    }
    *cursor = i;
}

fn skip_string_literal(src: &[u8], cursor: &mut usize) {
    debug_assert_eq!(src[*cursor], b'"');
    *cursor += 1;
    while *cursor < src.len() {
        let b = src[*cursor];
        if b == b'\\' {
            *cursor += 2;
        } else if b == b'"' {
            *cursor += 1;
            return;
        } else {
            *cursor += 1;
        }
    }
}

fn read_string_range(src: &[u8], cursor: &mut usize) -> (usize, usize) {
    debug_assert_eq!(src[*cursor], b'"');
    *cursor += 1;
    let start = *cursor;
    while *cursor < src.len() {
        let b = src[*cursor];
        if b == b'\\' {
            *cursor += 2;
        } else if b == b'"' {
            let end = *cursor;
            *cursor += 1;
            return (start, end);
        } else {
            *cursor += 1;
        }
    }
    (start, *cursor)
}

fn decode_string(span: &[u8]) -> String {
    let mut out = String::with_capacity(span.len());
    let bytes = span;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'"' => {
                    out.push('"');
                    i += 2;
                }
                b'\\' => {
                    out.push('\\');
                    i += 2;
                }
                b'/' => {
                    out.push('/');
                    i += 2;
                }
                b'b' => {
                    out.push('\u{0008}');
                    i += 2;
                }
                b'f' => {
                    out.push('\u{000C}');
                    i += 2;
                }
                b'n' => {
                    out.push('\n');
                    i += 2;
                }
                b'r' => {
                    out.push('\r');
                    i += 2;
                }
                b't' => {
                    out.push('\t');
                    i += 2;
                }
                b'u' => {
                    if i + 6 <= bytes.len() {
                        let cp = match u32::from_str_radix(
                            std::str::from_utf8(&bytes[i + 2..i + 6]).unwrap_or(""),
                            16,
                        ) {
                            Ok(v) => v,
                            Err(_) => {
                                out.push('?');
                                i += 6;
                                continue;
                            }
                        };
                        if (0xD800..=0xDBFF).contains(&cp)
                            && i + 12 <= bytes.len()
                            && bytes[i + 6] == b'\\'
                            && bytes[i + 7] == b'u'
                        {
                            let lo = u32::from_str_radix(
                                std::str::from_utf8(&bytes[i + 8..i + 12]).unwrap_or(""),
                                16,
                            )
                            .unwrap_or(0);
                            let full = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            if let Some(c) = char::from_u32(full) {
                                out.push(c);
                            } else {
                                out.push('\u{FFFD}');
                            }
                            i += 12;
                        } else if let Some(c) = char::from_u32(cp) {
                            out.push(c);
                            i += 6;
                        } else {
                            out.push('\u{FFFD}');
                            i += 6;
                        }
                    } else {
                        out.push('?');
                        i = bytes.len();
                    }
                }
                other => {
                    out.push(other as char);
                    i += 2;
                }
            }
        } else {
            let s = std::str::from_utf8(&bytes[i..i + 1]).unwrap_or("?");
            out.push_str(s);
            i += 1;
        }
    }
    out
}

fn push_escaped(s: &str, out: &mut Vec<u8>) {
    // Walk the string and emit each char's UTF-8 bytes.  Lone
    // surrogates are decoded to the replacement character so the
    // canonical line agrees byte-for-byte with the input's well-formed
    // pairs.
    let bytes = s.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut chars = s.chars().peekable();
    for c in chars.by_ref() {
        let len = c.len_utf8();
        let pos = i;
        if c == '"' {
            out.extend_from_slice(&bytes[start..pos]);
            out.extend_from_slice(b"\\\"");
            start = pos + len;
        } else if c == '\\' {
            out.extend_from_slice(&bytes[start..pos]);
            out.extend_from_slice(b"\\\\");
            start = pos + len;
        } else if c == '\n' {
            out.extend_from_slice(&bytes[start..pos]);
            out.extend_from_slice(b"\\n");
            start = pos + len;
        } else if c == '\r' {
            out.extend_from_slice(&bytes[start..pos]);
            out.extend_from_slice(b"\\r");
            start = pos + len;
        } else if c == '\t' {
            out.extend_from_slice(&bytes[start..pos]);
            out.extend_from_slice(b"\\t");
            start = pos + len;
        } else if c == '\u{0008}' {
            out.extend_from_slice(&bytes[start..pos]);
            out.extend_from_slice(b"\\b");
            start = pos + len;
        } else if c == '\u{000C}' {
            out.extend_from_slice(&bytes[start..pos]);
            out.extend_from_slice(b"\\f");
            start = pos + len;
        } else if (c as u32) < 0x20 {
            out.extend_from_slice(&bytes[start..pos]);
            out.extend_from_slice(b"\\u00");
            let hex = b"0123456789abcdef";
            let cp = c as u32;
            out.push(hex[((cp >> 4) & 0xF) as usize]);
            out.push(hex[(cp & 0xF) as usize]);
            start = pos + len;
        }
        i = pos + len;
    }
    out.extend_from_slice(&bytes[start..]);
}

// ---- pre-checks --------------------------------------------------------

fn pre_check(src: &[u8]) -> Option<&'static str> {
    if let Some(c) = trailing_comma(src) {
        return Some(c);
    }
    if let Some(c) = leading_zero(src) {
        return Some(c);
    }
    if let Some(c) = numeric_overflow(src) {
        return Some(c);
    }
    if let Some(c) = invalid_ctrl_char(src) {
        return Some(c);
    }
    if let Some(c) = unpaired_surrogate(src) {
        return Some(c);
    }
    None
}

fn is_digit(b: u8) -> bool {
    b.is_ascii_digit()
}
fn is_number_cont(b: u8) -> bool {
    is_digit(b) || b == b'.' || b == b'e' || b == b'E' || b == b'+' || b == b'-'
}

fn skip_string_range(src: &[u8], mut i: usize) -> usize {
    if i >= src.len() || src[i] != b'"' {
        return i;
    }
    i += 1;
    while i < src.len() {
        let b = src[i];
        if b == b'\\' {
            i += 2;
            continue;
        }
        if b == b'"' {
            return i + 1;
        }
        i += 1;
    }
    i
}

fn trailing_comma(src: &[u8]) -> Option<&'static str> {
    let mut i = 0;
    while i < src.len() && (src[i] == b' ' || src[i] == b'\t' || src[i] == b'\n' || src[i] == b'\r')
    {
        i += 1;
    }
    if i >= src.len() {
        return None;
    }
    let b = src[i];
    if b == b'[' {
        i += 1;
        walk_array(src, i)
    } else if b == b'{' {
        i += 1;
        walk_object(src, i)
    } else {
        None
    }
}

fn walk_array(src: &[u8], mut i: usize) -> Option<&'static str> {
    loop {
        while i < src.len()
            && (src[i] == b' ' || src[i] == b'\t' || src[i] == b'\n' || src[i] == b'\r')
        {
            i += 1;
        }
        if i >= src.len() {
            return None;
        }
        let b = src[i];
        if b == b']' {
            return None;
        }
        if b == b'}' {
            return None;
        }
        if b == b',' {
            let mut j = i + 1;
            while j < src.len()
                && (src[j] == b' ' || src[j] == b'\t' || src[j] == b'\n' || src[j] == b'\r')
            {
                j += 1;
            }
            if j < src.len() && src[j] == b']' {
                return Some("TRAILING_COMMA");
            }
            i = skip_value(src, i + 1);
            continue;
        }
        if b == b'[' {
            i += 1;
            let r = walk_array(src, i);
            if r.is_some() {
                return r;
            }
            i = skip_container_full(src, i, b']');
            continue;
        }
        if b == b'{' {
            i += 1;
            let r = walk_object(src, i);
            if r.is_some() {
                return r;
            }
            i = skip_container_full(src, i, b'}');
            continue;
        }
        if b == b'"' {
            i = skip_string_range(src, i);
            continue;
        }
        i = skip_value(src, i);
    }
}

fn walk_object(src: &[u8], mut i: usize) -> Option<&'static str> {
    loop {
        while i < src.len()
            && (src[i] == b' ' || src[i] == b'\t' || src[i] == b'\n' || src[i] == b'\r')
        {
            i += 1;
        }
        if i >= src.len() {
            return None;
        }
        let b = src[i];
        if b == b'}' {
            return None;
        }
        if b == b']' {
            return None;
        }
        if b == b',' {
            let mut j = i + 1;
            while j < src.len()
                && (src[j] == b' ' || src[j] == b'\t' || src[j] == b'\n' || src[j] == b'\r')
            {
                j += 1;
            }
            if j < src.len() && src[j] == b'}' {
                return Some("TRAILING_COMMA");
            }
            i = j;
            continue;
        }
        if b == b'"' {
            i = skip_string_range(src, i);
            // Expect `:`, advance.
            while i < src.len()
                && (src[i] == b' ' || src[i] == b'\t' || src[i] == b'\n' || src[i] == b'\r')
            {
                i += 1;
            }
            if i < src.len() && src[i] == b':' {
                i += 1;
            }
            while i < src.len()
                && (src[i] == b' ' || src[i] == b'\t' || src[i] == b'\n' || src[i] == b'\r')
            {
                i += 1;
            }
            // Recurse into nested arrays/objects for trailing-comma
            // detection.
            if i < src.len() && src[i] == b'[' {
                i += 1;
                let r = walk_array(src, i);
                if r.is_some() {
                    return r;
                }
                i = skip_container_full(src, i, b']');
            } else if i < src.len() && src[i] == b'{' {
                i += 1;
                let r = walk_object(src, i);
                if r.is_some() {
                    return r;
                }
                i = skip_container_full(src, i, b'}');
            } else {
                i = skip_value(src, i);
            }
            // After the value, a comma followed by close `}` is a
            // trailing comma.
            while i < src.len()
                && (src[i] == b' ' || src[i] == b'\t' || src[i] == b'\n' || src[i] == b'\r')
            {
                i += 1;
            }
            if i < src.len() && src[i] == b',' {
                let mut j = i + 1;
                while j < src.len()
                    && (src[j] == b' ' || src[j] == b'\t' || src[j] == b'\n' || src[j] == b'\r')
                {
                    j += 1;
                }
                if j < src.len() && src[j] == b'}' {
                    return Some("TRAILING_COMMA");
                }
                i = j;
                continue;
            }
            continue;
        }
        if b == b'[' {
            i += 1;
            let r = walk_array(src, i);
            if r.is_some() {
                return r;
            }
            i = skip_container_full(src, i, b']');
            continue;
        }
        if b == b'{' {
            i += 1;
            let r = walk_object(src, i);
            if r.is_some() {
                return r;
            }
            i = skip_container_full(src, i, b'}');
            continue;
        }
        i = skip_value(src, i);
    }
}

fn skip_value(src: &[u8], mut i: usize) -> usize {
    while i < src.len() {
        let b = src[i];
        if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
            i += 1;
            continue;
        }
        if b == b'"' {
            return skip_string_range(src, i);
        }
        if b == b'[' {
            return skip_container_full(src, i + 1, b']');
        }
        if b == b'{' {
            return skip_container_full(src, i + 1, b'}');
        }
        if b == b']' || b == b'}' || b == b',' {
            return i;
        }
        if b == b'-' || is_digit(b) {
            while i < src.len() && is_number_cont(src[i]) {
                i += 1;
            }
            return i;
        }
        // true / false / null
        while i < src.len() && !matches!(src[i], b',' | b']' | b'}' | b' ' | b'\t' | b'\n' | b'\r')
        {
            i += 1;
        }
        return i;
    }
    i
}

fn skip_container_full(src: &[u8], mut i: usize, close: u8) -> usize {
    let other_close = if close == b'}' { b']' } else { b'}' };
    loop {
        while i < src.len()
            && (src[i] == b' ' || src[i] == b'\t' || src[i] == b'\n' || src[i] == b'\r')
        {
            i += 1;
        }
        if i >= src.len() {
            return i;
        }
        if src[i] == close {
            return i + 1;
        }
        if src[i] == other_close {
            return i;
        }
        i = skip_value(src, i);
        while i < src.len()
            && (src[i] == b' ' || src[i] == b'\t' || src[i] == b'\n' || src[i] == b'\r')
        {
            i += 1;
        }
        if i < src.len() && src[i] == b',' {
            i += 1;
        }
    }
}

fn leading_zero(src: &[u8]) -> Option<&'static str> {
    let mut i = 0;
    while i < src.len() {
        let c = src[i];
        if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
            i += 1;
            continue;
        }
        if c == b'"' {
            i = skip_string_range(src, i);
            continue;
        }
        if c == b'-' || is_digit(c) {
            if c == b'-' {
                i += 1;
                if i >= src.len() {
                    return None;
                }
                let c2 = src[i];
                if c2 == b'0' && i + 1 < src.len() && is_digit(src[i + 1]) {
                    return Some("LEADING_ZERO");
                }
            } else if c == b'0' && i + 1 < src.len() && is_digit(src[i + 1]) {
                return Some("LEADING_ZERO");
            }
            while i < src.len() && is_number_cont(src[i]) {
                i += 1;
            }
            continue;
        }
        if c == b'+' && i + 1 < src.len() && is_digit(src[i + 1]) {
            return Some("NUMERIC_PLUS");
        }
        i += 1;
    }
    None
}

fn numeric_overflow(src: &[u8]) -> Option<&'static str> {
    let mut i = 0;
    while i < src.len() {
        let c = src[i];
        if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
            i += 1;
            continue;
        }
        if c == b'"' {
            i = skip_string_range(src, i);
            continue;
        }
        if c == b'-' || is_digit(c) || c == b'+' {
            let start = i;
            if c == b'+' {
                i += 1;
                if i >= src.len() {
                    return None;
                }
            }
            while i < src.len() && is_number_cont(src[i]) {
                i += 1;
            }
            if i > start {
                if let Some(v) = std::str::from_utf8(&src[start..i])
                    .ok()
                    .and_then(|s| s.parse::<f64>().ok())
                {
                    if !v.is_finite() {
                        return Some("NUMERIC_OVERFLOW");
                    }
                }
            }
            continue;
        }
        i += 1;
    }
    None
}

fn invalid_ctrl_char(src: &[u8]) -> Option<&'static str> {
    let mut i = 0;
    while i < src.len() {
        if src[i] != b'"' {
            i += 1;
            continue;
        }
        let after = skip_string_range(src, i);
        if after >= src.len() || src[after - 1] != b'"' {
            return None;
        }
        let close = after - 1;
        let mut j = i + 1;
        while j < close {
            let c = src[j];
            if c == b'\\' {
                j += 2;
                continue;
            }
            if c < 0x20 {
                return Some("INVALID_CTRL_CHAR");
            }
            j += 1;
        }
        i = after;
    }
    None
}

fn unpaired_surrogate(src: &[u8]) -> Option<&'static str> {
    let mut i = 0;
    while i < src.len() {
        if src[i] != b'"' {
            i += 1;
            continue;
        }
        i += 1;
        let mut pending_low = 0u8;
        while i < src.len() {
            let c = src[i];
            if c == b'\\' && i + 1 < src.len() && src[i + 1] == b'u' && i + 6 <= src.len() {
                let cp = match hex4(&src[i + 2..i + 6]) {
                    Some(v) => v,
                    None => {
                        i += 6;
                        continue;
                    }
                };
                if (0xD800..=0xDBFF).contains(&cp) {
                    if pending_low == 1 {
                        return Some("UNPAIRED_SURROGATE");
                    }
                    pending_low = 1;
                } else if (0xDC00..=0xDFFF).contains(&cp) {
                    if pending_low != 1 {
                        return Some("UNPAIRED_SURROGATE");
                    }
                    pending_low = 0;
                } else {
                    pending_low = 0;
                }
                i += 6;
                continue;
            }
            if c == b'"' {
                break;
            }
            i += 1;
        }
        i = skip_string_range(src, i);
    }
    None
}

fn hex4(s: &[u8]) -> Option<u32> {
    let mut v = 0u32;
    for &b in s {
        let d = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };
        v = (v << 4) | d as u32;
    }
    Some(v)
}

fn category_from_msg(msg: &str) -> &'static str {
    if msg.starts_with("Leading zero") {
        "LEADING_ZERO"
    } else if msg.starts_with("Nesting too deep") {
        "DEPTH"
    } else if msg.starts_with("Unexpected end of input") {
        "EMPTY"
    } else if msg.starts_with("Unexpected content after JSON value") {
        "TRAILING"
    } else if msg.starts_with("Unterminated string") {
        "UNTERMINATED_STRING"
    } else if msg.starts_with("Unterminated escape") {
        "UNTERMINATED_ESCAPE"
    } else if msg.starts_with("Incomplete unicode")
        || msg.starts_with("Invalid unicode")
        || msg.starts_with("Invalid hex")
    {
        "INVALID_UNICODE_ESCAPE"
    } else if msg.starts_with("Invalid high surrogate")
        || msg.starts_with("Invalid low surrogate")
        || msg.starts_with("Invalid surrogate")
        || msg.starts_with("Expected low surrogate")
    {
        "UNPAIRED_SURROGATE"
    } else if msg.starts_with("Unescaped control") {
        "INVALID_CTRL_CHAR"
    } else if msg.starts_with("Invalid escape") {
        "INVALID_ESCAPE"
    } else if msg.starts_with("Number out of range") {
        "NUMERIC_OVERFLOW"
    } else if msg.starts_with("Invalid number")
        || msg.starts_with("Incomplete number")
        || msg.starts_with("Expected digits")
    {
        "INVALID_NUMBER"
    } else if msg.starts_with("Expected ',' or ']'")
        || msg.starts_with("Expected ',' or '}'")
        || msg.starts_with("Expected '")
        || msg.starts_with("Unexpected character")
    {
        "EXPECTED_VALUE"
    } else {
        "PARSE_ERROR"
    }
}

// `Number` is referenced for the public API; the walker pulls the source
// bytes directly so the type is not used at runtime.
#[allow(dead_code)]
fn _pin_number(_: &Number) {}
