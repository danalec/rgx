// SPDX-License-Identifier: Apache-2.0

//! Compression error types.

use alloc::string::String;
use core::fmt;

/// Compression error type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompressError {
    /// Invalid compressed data format.
    InvalidFormat(&'static str),
    /// Corrupted data detected during decompression.
    CorruptedData(&'static str),
    /// Unexpected end of input.
    UnexpectedEof,
    /// Output buffer too small.
    BufferTooSmall,
    /// Invalid compression level.
    InvalidLevel(u8),
    /// CRC mismatch.
    CrcMismatch { expected: u32, actual: u32 },
    /// Unsupported feature.
    Unsupported(&'static str),
    /// Unsupported format (dynamic message).
    UnsupportedFormat(String),
    /// Decompression failed (dynamic message).
    DecompressionFailed(String),
    /// Internal error.
    InternalError(&'static str),
}

impl fmt::Display for CompressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat(msg) => write!(f, "invalid format: {msg}"),
            Self::CorruptedData(msg) => write!(f, "corrupted data: {msg}"),
            Self::UnexpectedEof => write!(f, "unexpected end of input"),
            Self::BufferTooSmall => write!(f, "output buffer too small"),
            Self::InvalidLevel(level) => write!(f, "invalid compression level: {level}"),
            Self::CrcMismatch { expected, actual } => {
                write!(
                    f,
                    "CRC mismatch: expected {expected:#08x}, got {actual:#08x}"
                )
            }
            Self::Unsupported(msg) => write!(f, "unsupported: {msg}"),
            Self::UnsupportedFormat(msg) => write!(f, "unsupported format: {msg}"),
            Self::DecompressionFailed(msg) => write!(f, "decompression failed: {msg}"),
            Self::InternalError(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CompressError {}

/// Result type for compression operations.
pub type CompressResult<T> = core::result::Result<T, CompressError>;
