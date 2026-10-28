// SPDX-License-Identifier: Apache-2.0

//! A bi-level bitmap: one byte per pixel, `1` = black, `0` = white.
//!
//! T.88 numbers a pixel 1 when it is black and 0 when it is white, and that
//! is the numbering used throughout this decoder. The gray-scale conversion
//! the PDF path needs happens once, at the boundary.

use alloc::vec;
use alloc::vec::Vec;

/// A bi-level bitmap.
#[derive(Clone)]
pub struct Bitmap {
    pub width: u32,
    pub height: u32,
    /// Row-major, `width * height` bytes: `1` = black, `0` = white.
    pub pixels: Vec<u8>,
}

impl Bitmap {
    /// A blank (all white) bitmap of the given size.
    pub fn new(width: u32, height: u32) -> Self {
        let len = (width as usize).saturating_mul(height as usize);
        Self {
            width,
            height,
            pixels: vec![0; len],
        }
    }

    /// The value of the pixel at `(x, y)`, or 0 when it is outside the bitmap.
    ///
    /// T.88 §6.2.5.2: "All pixels lying outside the bounds of the actual
    /// bitmap have the value 0."
    #[inline]
    pub fn get(&self, x: i64, y: i64) -> u8 {
        if x < 0 || y < 0 || x >= self.width as i64 || y >= self.height as i64 {
            return 0;
        }
        self.pixels[y as usize * self.width as usize + x as usize]
    }

    /// Set the pixel at `(x, y)`. Out-of-range coordinates are ignored.
    #[inline]
    pub fn set(&mut self, x: i64, y: i64, value: u8) {
        if x < 0 || y < 0 || x >= self.width as i64 || y >= self.height as i64 {
            return;
        }
        self.pixels[y as usize * self.width as usize + x as usize] = value;
    }

    /// Copy the row above `y` into row `y`.
    ///
    /// The copy is within one buffer, so the rows are split rather than
    /// borrowed twice: the destination row starts after the source row, and
    /// the two cannot overlap.
    pub fn copy_row_above(&mut self, y: u32) {
        if y == 0 || y >= self.height {
            return;
        }
        let w = self.width as usize;
        let to = y as usize * w;
        let from = to - w;
        let (head, tail) = self.pixels.split_at_mut(to);
        tail[..w].copy_from_slice(&head[from..from + w]);
    }

    /// Draw `other` onto this bitmap at `(x, y)`, combining the pixels with
    /// the operator `op` (T.88 §7.4.1.5): 0 = OR, 1 = AND, 2 = XOR,
    /// 3 = XNOR, 4 = REPLACE.
    ///
    /// The part of `other` that falls outside this bitmap is ignored.
    pub fn combine(&mut self, other: &Bitmap, x: i64, y: i64, op: u8) {
        for oy in 0..other.height as i64 {
            for ox in 0..other.width as i64 {
                let px = x + ox;
                let py = y + oy;
                if px < 0 || py < 0 || px >= self.width as i64 || py >= self.height as i64 {
                    continue;
                }
                let old = self.get(px, py);
                let new = other.get(ox, oy);
                let value = match op {
                    1 => old & new,
                    2 => old ^ new,
                    3 => 1 - (old ^ new),
                    4 => new,
                    _ => old | new,
                };
                self.set(px, py, value);
            }
        }
    }
}
