// SPDX-License-Identifier: Apache-2.0

//! The .xz container: stream/block/index framing in [`container`] and
//! the CRC-64 check type in [`crc64`]. Both are independent
//! reimplementations of the published format, written from the xz
//! container specification and the CRC-64/XZ parameters rather than
//! from any implementation's source.

pub mod container;
pub mod crc64;

pub use container::XzReader;
