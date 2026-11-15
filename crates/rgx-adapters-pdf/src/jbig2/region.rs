// SPDX-License-Identifier: Apache-2.0

//! The region segment information field (ITU-T T.88 §7.4.1).
//!
//! Every region segment's data part opens with the same seventeen bytes: the
//! size and position of the bitmap it carries, and the operator that merges
//! it into the page.

/// The region segment information field.
pub struct RegionInfo {
    /// Width of the bitmap in pixels.
    pub width: u32,
    /// Height of the bitmap in pixels.
    pub height: u32,
    /// Horizontal offset from the page's left edge.
    pub x: u32,
    /// Vertical offset from the page's top edge.
    pub y: u32,
    /// The external combination operator (T.88 §7.4.1.5).
    pub comb_operator: u8,
}

impl RegionInfo {
    /// The field's length in bytes.
    pub const LENGTH: usize = 17;

    /// Parse the field at the start of `data`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::LENGTH {
            return None;
        }
        let be = |i: usize| u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        Some(RegionInfo {
            width: be(0),
            height: be(4),
            x: be(8),
            y: be(12),
            comb_operator: data[16] & 0x07,
        })
    }
}
