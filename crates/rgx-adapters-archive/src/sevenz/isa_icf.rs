// SPDX-License-Identifier: Apache-2.0

//! Stand-in for the `isa-l_icf` encoder the vendored 7-Zip sources import.
//!
//! **This is not ISA-L.** It is an Intel library with an x86-64 assembly core,
//! not a dependency of this crate, and linking it would make every build here
//! non-portable. What the feature needs is narrower: a type that takes a level
//! and returns a DEFLATE stream. So this wraps [`super::deflate::DeflateEncoder`]
//! and produces byte-identical output to it — `encode_fast` gains correctness
//! and a buildable path, not speed.
//!
//! If real acceleration is wanted, this is the seam where it goes: the two
//! methods below are the whole surface the vendored code calls.

use alloc::vec::Vec;

use super::deflate::DeflateEncoder;

/// DEFLATE encoder behind the ISA-L-shaped name the vendored sources use.
pub struct IsalDeflateEncoder {
    inner: DeflateEncoder,
}

impl IsalDeflateEncoder {
    /// An encoder at `level`, where ISA-L accepts 0-3.
    pub fn with_level(level: u8) -> Self {
        Self {
            inner: DeflateEncoder::with_level(level),
        }
    }

    /// Encode `data` as a raw DEFLATE stream.
    pub fn encode(&mut self, data: &[u8]) -> Vec<u8> {
        self.inner.encode(data)
    }
}
