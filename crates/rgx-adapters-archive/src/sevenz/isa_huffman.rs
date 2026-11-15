// SPDX-License-Identifier: Apache-2.0

//! `CompressionLevel` under the `isa_huffman` name the vendored sources use.
//!
//! The vendored `sevenz/deflate.rs` imports
//! `super::isa_huffman::CompressionLevel` behind the `isa-huffman` feature
//! (`deflate.rs:25`). The import has no other use in the file, so this module
//! exists to satisfy it rather than to serve a caller — see
//! [`super::isa_icf`] for the encoder itself.
//!
//! ISA-L's scale is 0-3 where DEFLATE's is 0-9, so the mapping is
//! `[isa_huffman::CompressionLevel]` → [`super::deflate::CompressionLevel`]
//! the way the vendored code expects.

/// ISA-L's four compression levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompressionLevel {
    /// No compression.
    None = 0,
    /// Fast.
    Level1 = 1,
    /// Faster still.
    Level2 = 2,
    /// The fastest compressing setting.
    #[default]
    Level3 = 3,
}

impl From<CompressionLevel> for u8 {
    fn from(level: CompressionLevel) -> Self {
        level as u8
    }
}
