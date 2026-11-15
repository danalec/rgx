// SPDX-License-Identifier: Apache-2.0

//! What a `.br` can be, or cannot be, decoded into.

/// A decode that stopped. Every variant names a field of RFC 7932, so the
/// message says which one the stream got wrong rather than only that it
/// did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The stream ended in the middle of a field.
    Truncated,
    /// Padding bits that the format requires to be zero were not.
    Padding,
    /// A prefix code that no bit pattern reaches.
    Code,
    /// A prefix code that is not a prefix code: over- or under-subscribed,
    /// or a repeat count that overruns its alphabet.
    CodeLength,
    /// A simple prefix code naming a symbol outside its alphabet, or the
    /// same symbol twice.
    Symbol,
    /// A reserved bit set, or a window size the format does not have.
    Reserved,
    /// A field with a value the format does not allow: a distance that
    /// resolves to zero, a block type past its category, a transform id
    /// above 120.
    Range,
    /// A meta-block that would produce more bytes than it declared.
    Overflow,
    /// The output cap stopped the decode. Not a defect in the stream, and
    /// the only variant that is not an error at all.
    Budget,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::Truncated => "truncated brotli stream",
            Error::Padding => "non-zero padding bits in a brotli stream",
            Error::Code => "brotli prefix code has an unreachable code",
            Error::CodeLength => "malformed brotli prefix code",
            Error::Symbol => "brotli simple prefix code names a symbol out of range",
            Error::Reserved => "reserved bit set in a brotli stream",
            Error::Range => "value out of range for the brotli format",
            Error::Overflow => "brotli meta-block longer than it declared",
            Error::Budget => "byte budget",
        })
    }
}

pub type Result<T> = core::result::Result<T, Error>;
