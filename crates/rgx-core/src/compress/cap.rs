// SPDX-License-Identifier: Apache-2.0

//! The ceiling on how many bytes one decode may emit.
//!
//! rgx's own bomb guard, not derived from any third-party implementation.
//! Every bounded decode here counts bytes as they are emitted. Decoding first
//! and measuring afterwards costs exactly what a compression bomb was built to
//! cost.

use alloc::vec::Vec;

/// No cap: more bytes than any decode will emit in one process.
pub const UNLIMITED: u64 = u64::MAX;

/// Bytes one decode may still emit, counted as it emits them.
#[derive(Clone, Copy, Debug)]
pub struct OutputCap {
    /// Bytes the cap will allow before it stops the decode.
    limit: u64,
    /// Bytes the decode has already emitted.
    used: u64,
    /// True once the cap has refused a byte.
    capped: bool,
}

impl OutputCap {
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            used: 0,
            capped: false,
        }
    }

    pub fn unlimited() -> Self {
        Self::new(UNLIMITED)
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    pub fn used(&self) -> u64 {
        self.used
    }

    /// True once the cap has refused something.
    pub fn capped(&self) -> bool {
        self.capped
    }

    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    /// Move the ceiling, keeping what has already been counted counted.
    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    /// Count `n` more emitted bytes. False means the cap is spent, and
    /// nothing was counted.
    pub fn take(&mut self, n: u64) -> bool {
        match self.used.checked_add(n) {
            Some(used) if used <= self.limit => {
                self.used = used;
                true
            }
            _ => {
                self.capped = true;
                false
            }
        }
    }

    /// Whether `n` more bytes would fit, without counting them.
    pub fn fits(&self, n: u64) -> bool {
        self.used.saturating_add(n) <= self.limit
    }
}

impl Default for OutputCap {
    fn default() -> Self {
        Self::unlimited()
    }
}

/// The payload of a bounded decode.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bounded {
    /// What the decode emitted. A prefix of the real payload when
    /// `capped`, and unverified: a decoder that stops early cannot have
    /// checked the checksum that covers the bytes it did not see.
    pub bytes: Vec<u8>,
    /// What the container said it would contain. `None` where the format
    /// has none, or where the value is known to be a lie (gzip's ISIZE is
    /// the size modulo 2^32).
    pub declared: Option<u64>,
    /// The cap, echoed so the caller does not have to carry it alongside.
    pub limit: u64,
    /// True when the cap stopped the decode before the stream ended.
    pub capped: bool,
}

impl Bounded {
    /// A decode that ran to the end of the stream under its cap.
    pub fn complete(bytes: Vec<u8>, declared: Option<u64>, limit: u64) -> Self {
        Self {
            bytes,
            declared,
            limit,
            capped: false,
        }
    }

    /// A decode the cap stopped, carrying the bytes it did emit.
    pub fn stopped(bytes: Vec<u8>, declared: Option<u64>, limit: u64) -> Self {
        Self {
            bytes,
            declared,
            limit,
            capped: true,
        }
    }
}
