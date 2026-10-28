// SPDX-License-Identifier: Apache-2.0

//! Codec error type.
//!
//! Independent reimplementation. The API contract (these variants and this
//! `Result` alias) is what the rest of rgx binds to; the body is written
//! fresh from RARLAB's published RAR 5.0 archive format specification
//! (`technote.htm`), not from any upstream implementation.

use core::fmt;

/// Everything the codec can refuse is recoverable and named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The buffer ended before a complete structure could be read.
    Truncated,
    /// Missing or wrong `Rar!` signature.
    BadMagic,
    /// Structurally invalid header: a vint that will not terminate, a size
    /// that overflows its field, a record shorter than its own length word.
    Malformed(&'static str),
    /// A CRC32 check failed. The payload names which one.
    BadCrc(&'static str),
    /// The archive uses a feature this codec does not implement: encrypted
    /// payload, PPMd filters, arbitrary RAR VM filter programs, or the RAR
    /// 7.x compression algorithm.
    Unsupported(&'static str),
}

pub type Result<T> = core::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated => write!(f, "truncated RAR archive"),
            Error::BadMagic => write!(f, "not a RAR archive"),
            Error::Malformed(what) => write!(f, "malformed RAR structure: {what}"),
            Error::BadCrc(what) => write!(f, "CRC mismatch: {what}"),
            Error::Unsupported(what) => write!(f, "unsupported RAR feature: {what}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
