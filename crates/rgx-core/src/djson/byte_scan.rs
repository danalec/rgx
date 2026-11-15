// SPDX-License-Identifier: Apache-2.0

//! Byte-walking helpers shared by stream parsing and raw_value extraction.
//! No `Value`, no `Arena` -- just byte-level JSON scanning.
//!
//! The functions here were previously duplicated between
//! [`super::stream`] and [`super::raw_value`]; extracting them into a
//! shared module lets both call sites reuse the same byte-level
//! boundary detector. Semantics match the streaming walk: leading
//! whitespace is consumed, trailing whitespace is consumed (the stream
//! parser needs the next document's start position; raw_value drops
//! it), and the value is bounded by bracket matching, string-escape
//! skipping, and the small JSON number grammar.

/// Skip the value starting at `i` in `bytes` and return the position
/// just past it. Returns `None` if the value is incomplete.
pub(super) fn skip_one_value(bytes: &[u8], mut i: usize) -> Option<usize> {
    if i >= bytes.len() {
        return None;
    }
    match bytes[i] {
        b'{' | b'[' => {
            i += 1;
            let mut depth = 1;
            while i < bytes.len() && depth > 0 {
                let b = bytes[i];
                if b == b'"' {
                    i += 1;
                    while i < bytes.len() {
                        match bytes[i] {
                            b'\\' => {
                                i += 2;
                                continue;
                            }
                            b'"' => {
                                i += 1;
                                break;
                            }
                            _ => {
                                i += 1;
                            }
                        }
                    }
                    if i > bytes.len() || (i == bytes.len() && bytes[i - 1] != b'"') {
                        return None;
                    }
                } else if b == b'{' || b == b'[' {
                    depth += 1;
                    i += 1;
                } else if b == b'}' || b == b']' {
                    depth -= 1;
                    i += 1;
                } else {
                    i += 1;
                }
            }
            if depth != 0 {
                return None;
            }
            Some(i)
        }
        b'"' => {
            i += 1;
            while i < bytes.len() {
                match bytes[i] {
                    b'\\' => {
                        i += 2;
                        continue;
                    }
                    b'"' => return Some(i + 1),
                    _ => {
                        i += 1;
                    }
                }
            }
            None
        }
        b'-' | b'0'..=b'9' => {
            i += 1;
            while i < bytes.len()
                && matches!(bytes[i], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
            {
                i += 1;
            }
            Some(i)
        }
        b't' => {
            if bytes.get(i..i + 4) == Some(b"true") {
                Some(i + 4)
            } else {
                None
            }
        }
        b'f' => {
            if bytes.get(i..i + 5) == Some(b"false") {
                Some(i + 5)
            } else {
                None
            }
        }
        b'n' => {
            if bytes.get(i..i + 4) == Some(b"null") {
                Some(i + 4)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Find the end position of the first complete JSON value starting at
/// the beginning of `bytes`, skipping leading and trailing whitespace.
pub(super) fn find_document_end(bytes: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    i = skip_one_value(bytes, i)?;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    Some(i)
}
