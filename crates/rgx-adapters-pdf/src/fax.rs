// SPDX-License-Identifier: Apache-2.0

//! ITU-T T.4 (Group 3) and T.6 (Group 4) decoding, in the shape a PDF
//! `/CCITTFaxDecode` stream carries them.
//!
//! A CCITT scan is not a bitmap, it is a run-length program against the
//! *previous row*: a 2D code says "this row's changing element sits at the
//! reference line's element `b1`, shifted by this much", and the reader has
//! to have tracked the previous row's changing elements to place it. Getting
//! the reference line wrong does not produce garbage, it produces a plausible
//! image that is shifted, and a shifted scan OCRs to noise rather than
//! failing loudly.
//!
//! Every entry point here is total: a malformed, truncated or empty stream
//! answers `None`. Half a scan is not a scan, and an OCR engine handed one
//! reports a bad image rather than a bad page.

extern crate alloc;

use alloc::vec::Vec;

/// ITU-T T.4 (Group 3) and T.6 (Group 4), as PDF's `/CCITTFaxDecode`
/// carries them.
pub struct FaxParams {
    /// `/K`: 0 is Group 4, -1 is Group 3, and any positive value is the
    /// number of 1D-encoded rows in that many 2D rows (mixed coding).
    pub k: i64,
    /// `/Columns` — pixels per row.
    pub columns: u32,
    /// `/Rows` — rows in the image. `0` or absent means "until the data
    /// runs out", which real files do use.
    pub rows: u32,
    /// `/BlackIs1` — whether a 1 bit means black. PDF's default is `false`.
    pub black_is_1: bool,
    /// `/EncodedByteAlign` — pad each 1D row to a byte boundary.
    pub byte_align: bool,
}

/// The answer to "can this PDF afford a grayscale image at all".
///
/// A `/Rows` of zero over a short stream is unbounded on paper, so without
/// this the row count would be whatever the bit budget allowed — and at one
/// byte per pixel an attacker-chosen `/Columns` turns a kilobyte stream into
/// a gigabyte allocation. This is the same refusal `OutputCap` makes for a
/// decompression bomb, applied to an image the container only *claims* is
/// large.
const MAX_PIXELS: u64 = 64 * 1024 * 1024;

/// `(bits, len, run)` — a code's value, its width in bits, and the run
/// length it stands for.
///
/// Written out one entry per line rather than packed, because these tables
/// *are* the standard: a typo here is a silent misdecode that still renders a
/// plausible page, and the way to keep one out is to make every digit
/// readable and checkable against ITU-T T.4 Tables 2, 3 and 4.
type Code = (u32, u32, u32);

/// Longest code in the MH and 2D sets. Black make-up codes reach 13 bits, and
/// 14 gives the matcher a definite place to stop on a byte of fill bits,
/// which match nothing.
const MAX_CODE_BITS: u32 = 14;

/// T.4 Table 2 — white terminating run lengths 0..=63.
const WHITE_TERMINATING: &[Code] = &[
    (0b0011_0101, 8, 0),
    (0b000111, 6, 1),
    (0b0111, 4, 2),
    (0b1000, 4, 3),
    (0b1011, 4, 4),
    (0b1100, 4, 5),
    (0b1110, 4, 6),
    (0b1111, 4, 7),
    (0b10011, 5, 8),
    (0b10100, 5, 9),
    (0b00111, 5, 10),
    (0b01000, 5, 11),
    (0b00_1000, 6, 12),
    (0b00_0011, 6, 13),
    (0b110100, 6, 14),
    (0b110101, 6, 15),
    (0b101010, 6, 16),
    (0b101011, 6, 17),
    (0b010_0111, 7, 18),
    (0b000_1100, 7, 19),
    (0b000_1000, 7, 20),
    (0b001_0111, 7, 21),
    (0b000_0011, 7, 22),
    (0b000_0100, 7, 23),
    (0b010_1000, 7, 24),
    (0b010_1011, 7, 25),
    (0b001_0011, 7, 26),
    (0b010_0100, 7, 27),
    (0b001_1000, 7, 28),
    (0b0000_0010, 8, 29),
    (0b0000_0011, 8, 30),
    (0b0001_1010, 8, 31),
    (0b0001_1011, 8, 32),
    (0b0001_0010, 8, 33),
    (0b0001_0011, 8, 34),
    (0b0001_0100, 8, 35),
    (0b0001_0101, 8, 36),
    (0b0001_0110, 8, 37),
    (0b0001_0111, 8, 38),
    (0b0010_1000, 8, 39),
    (0b0010_1001, 8, 40),
    (0b0010_1010, 8, 41),
    (0b0010_1011, 8, 42),
    (0b0010_1100, 8, 43),
    (0b0010_1101, 8, 44),
    (0b0000_0100, 8, 45),
    (0b0000_0101, 8, 46),
    (0b0000_1010, 8, 47),
    (0b0000_1011, 8, 48),
    (0b0101_0010, 8, 49),
    (0b0101_0011, 8, 50),
    (0b0101_0100, 8, 51),
    (0b0101_0101, 8, 52),
    (0b0010_0100, 8, 53),
    (0b0010_0101, 8, 54),
    (0b0101_1000, 8, 55),
    (0b0101_1001, 8, 56),
    (0b0101_1010, 8, 57),
    (0b0101_1011, 8, 58),
    (0b0100_1010, 8, 59),
    (0b0100_1011, 8, 60),
    (0b0011_0010, 8, 61),
    (0b0011_0011, 8, 62),
    (0b0011_0100, 8, 63),
];

/// T.4 Table 2 (make-up) — white runs 64..=1728, plus the extended make-up
/// codes 1792..=2560 that T.4 shares with the 2D horizontal mode.
///
/// 2560 exists because `1728 + 63 + 63` is the widest run one make-up-plus-
/// terminating pair can express, and a document can hold a wider one.
const WHITE_MAKEUP: &[Code] = &[
    (0b11011, 5, 64),
    (0b10010, 5, 128),
    (0b010111, 6, 192),
    (0b0110111, 7, 256),
    (0b0011_0110, 8, 320),
    (0b0011_0111, 8, 384),
    (0b0110_0100, 8, 448),
    (0b0110_0101, 8, 512),
    (0b0110_1000, 8, 576),
    (0b0110_0111, 8, 640),
    (0b011000, 6, 1664),
    (0b0_1100_1100, 9, 704),
    (0b0_1100_1101, 9, 768),
    (0b0_1101_0010, 9, 832),
    (0b0_1101_0011, 9, 896),
    (0b0_1101_0100, 9, 960),
    (0b0_1101_0101, 9, 1024),
    (0b0_1101_0110, 9, 1088),
    (0b0_1101_0111, 9, 1152),
    (0b0_1101_1000, 9, 1216),
    (0b0_1101_1001, 9, 1280),
    (0b0_1101_1010, 9, 1344),
    (0b0_1101_1011, 9, 1408),
    (0b0_1001_1000, 9, 1472),
    (0b0_1001_1001, 9, 1536),
    (0b0_1001_1010, 9, 1600),
    (0b0_1001_1011, 9, 1728),
    (0b000_0000_1000, 11, 1792),
    (0b000_0000_1100, 11, 1856),
    (0b000_0000_1101, 11, 1920),
    (0b0000_0001_0010, 12, 1984),
    (0b0000_0001_0011, 12, 2048),
    (0b0000_0001_0100, 12, 2112),
    (0b0000_0001_0101, 12, 2176),
    (0b0000_0001_0110, 12, 2240),
    (0b0000_0001_0111, 12, 2304),
    (0b0000_0001_1100, 12, 2368),
    (0b0000_0001_1101, 12, 2432),
    (0b0000_0001_1110, 12, 2500),
    (0b0000_0001_1111, 12, 2560),
];

/// T.4 Table 3 — black terminating run lengths 0..=63.
const BLACK_TERMINATING: &[Code] = &[
    (0b00_0011_0111, 10, 0),
    (0b010, 3, 1),
    (0b11, 2, 2),
    (0b10, 2, 3),
    (0b011, 3, 4),
    (0b0011, 4, 5),
    (0b0010, 4, 6),
    (0b00011, 5, 7),
    (0b000101, 6, 8),
    (0b000100, 6, 9),
    (0b000_0100, 7, 10),
    (0b000_0101, 7, 11),
    (0b000_0111, 7, 12),
    (0b0000_0100, 8, 13),
    (0b0000_0111, 8, 14),
    (0b0_0001_1000, 9, 15),
    (0b00_0001_0111, 10, 16),
    (0b00_0001_1000, 10, 17),
    (0b00_0000_1000, 10, 18),
    (0b000_0110_0111, 11, 19),
    (0b000_0110_1000, 11, 20),
    (0b000_0110_1100, 11, 21),
    (0b000_0011_0111, 11, 22),
    (0b000_0010_1000, 11, 23),
    (0b000_0001_0111, 11, 24),
    (0b000_0001_1000, 11, 25),
    (0b0000_1100_1010, 12, 26),
    (0b0000_1100_1011, 12, 27),
    (0b0000_1100_1100, 12, 28),
    (0b0000_1100_1101, 12, 29),
    (0b0000_0110_1000, 12, 30),
    (0b0000_0110_1001, 12, 31),
    (0b0000_0110_1010, 12, 32),
    (0b0000_0110_1011, 12, 33),
    (0b0000_1101_0010, 12, 34),
    (0b0000_1101_0011, 12, 35),
    (0b0000_1101_0100, 12, 36),
    (0b0000_1101_0101, 12, 37),
    (0b0000_1101_0110, 12, 38),
    (0b0000_1101_0111, 12, 39),
    (0b0000_0110_1100, 12, 40),
    (0b0000_0110_1101, 12, 41),
    (0b0000_1101_1010, 12, 42),
    (0b0000_1101_1011, 12, 43),
    (0b0000_0101_0100, 12, 44),
    (0b0000_0101_0101, 12, 45),
    (0b0000_0101_0110, 12, 46),
    (0b0000_0101_0111, 12, 47),
    (0b0000_0110_0100, 12, 48),
    (0b0000_0110_0101, 12, 49),
    (0b0000_0101_0010, 12, 50),
    (0b0000_0101_0011, 12, 51),
    (0b0000_0010_0100, 12, 52),
    (0b0000_0011_0111, 12, 53),
    (0b0000_0011_1000, 12, 54),
    (0b0000_0010_0111, 12, 55),
    (0b0000_0010_1000, 12, 56),
    (0b0000_0101_1000, 12, 57),
    (0b0000_0101_1001, 12, 58),
    (0b0000_0010_1011, 12, 59),
    (0b0000_0010_1100, 12, 60),
    (0b0000_0101_1010, 12, 61),
    (0b0000_0110_0110, 12, 62),
    (0b0000_0110_0111, 12, 63),
];

/// T.4 Table 3 (make-up) — black runs 64..=1728, plus the extended make-up
/// codes 1792..=2448.
const BLACK_MAKEUP: &[Code] = &[
    (0b00_0000_1111, 10, 64),
    (0b0000_1100_1000, 12, 128),
    (0b0000_1100_1001, 12, 192),
    (0b0000_0101_1011, 12, 256),
    (0b0000_0011_0011, 12, 320),
    (0b0000_0011_0100, 12, 384),
    (0b0000_0011_0101, 12, 448),
    (0b0_0000_0110_1100, 13, 512),
    (0b0_0000_0110_1101, 13, 576),
    (0b0_0000_0100_1010, 13, 640),
    (0b0_0000_0100_1011, 13, 704),
    (0b0_0000_0100_1100, 13, 768),
    (0b0_0000_0100_1101, 13, 832),
    (0b0_0000_0111_0010, 13, 896),
    (0b0_0000_0111_0011, 13, 960),
    (0b0_0000_0111_0100, 13, 1024),
    (0b0_0000_0111_0101, 13, 1088),
    (0b0_0000_0111_0110, 13, 1152),
    (0b0_0000_0111_0111, 13, 1216),
    (0b0_0000_0101_0010, 13, 1280),
    (0b0_0000_0101_0011, 13, 1344),
    (0b0_0000_0101_0100, 13, 1408),
    (0b0_0000_0101_0101, 13, 1472),
    (0b0_0000_0101_1010, 13, 1536),
    (0b0_0000_0101_1011, 13, 1600),
    (0b0_0000_0110_0100, 13, 1664),
    (0b0_0000_0110_0101, 13, 1728),
    (0b000_0000_1000, 11, 1792),
    (0b000_0000_1001, 11, 1856),
    (0b000_0000_1010, 11, 1920),
    (0b000_0000_1011, 11, 1984),
    (0b000_0000_1100, 11, 2048),
    (0b000_0000_1101, 11, 2112),
    (0b000_0000_1110, 11, 2176),
    (0b000_0000_1111, 11, 2240),
    (0b000_0000_0100, 11, 2304),
    (0b000_0000_0101, 11, 2368),
    (0b000_0000_0110, 11, 2432),
    (0b000_0000_0111, 11, 2448),
];

/// T.4 Table 4 — the 2D mode codes, as a prefix-free decision tree.
///
/// The set is `1`, `011`, `010`, `001`, `0001`, `000011`, `000010`,
/// `0000011`, `0000010` and the extension `0000001xxx`, and the tree has to
/// split them at every prefix or one shadows another: `00001` opens the two
/// 6-bit verticals while `00000` opens the three 7/8-bit ones.
///
/// `Vertical` carries `a1 - b1`, because that is what a VR/VL code *is*: the
/// element on the coding line is placed at the reference line's element `b1`
/// shifted by this much. The decoder cannot recover the shift from the coding
/// line it is still building — a pass may have moved `a0` past an element
/// that row has not reached — so discarding the sign here is what turns a
/// correct decode into a shifted one. And the sign is not a convention:
/// Table 1/T.6 names `VR` the mode that puts `a1` to the *right* of `b1` and
/// `VL` the one that puts it to the left.
enum Mode {
    Pass,
    Horizontal,
    Vertical(i32),
}

/// What sits at the current bit position. T.4 writes an `EOL` before every
/// line it codes 1D; both standards define `EOFB` at the end of a block.
#[derive(PartialEq, Eq)]
enum Mark {
    Eol,
    Eofb,
}

const EOL: u32 = 0b0000_0000_0001;
const EOFB: u32 = 0b0000_0000_0001_0000_0000_0001;

/// Decode a fax stream into 8-bit grayscale, one byte per pixel, row-major,
/// `0` = black and `255` = white. Returns `None` rather than a partial image:
/// half a scan is not a scan, and an OCR engine handed one reports a bad
/// image rather than a bad page.
pub fn decode_fax(data: &[u8], p: &FaxParams) -> Option<Vec<u8>> {
    if p.columns == 0 || data.is_empty() {
        return None;
    }
    let columns = p.columns as u64;
    // A `/Rows` of zero means "as many as the data holds", so the ceiling has
    // to come from the allocation limit rather than from the header.
    let declared = if p.rows == 0 {
        (MAX_PIXELS / columns).min(u32::MAX as u64) as u32
    } else {
        p.rows
    };
    if declared as u64 * columns > MAX_PIXELS {
        return None;
    }

    let mut d = Decoder::new(data, p);
    let mut out: Vec<u8> = Vec::new();
    let mut done: u32 = 0;
    while done < declared {
        // `EOFB` is a block terminator, not a failure: it is how a T.4 stream
        // says the page ended, and the rows before it are whole. The encoder
        // saying so is a different thing from the data running out, and the
        // difference is what tells a short page from a truncated file.
        if d.take_mark() == Some(Mark::Eofb) {
            break;
        }
        // T.4 with a positive K codes the first row of each group 1D and the
        // rest 2D; a negative K codes every row 1D; T.6 codes every row 2D.
        let one_d = if p.k < 0 {
            true
        } else if p.k > 0 {
            done.is_multiple_of(p.k as u32)
        } else {
            false
        };
        if !d.row(one_d) {
            // The data ran out or a row could not be decoded. A declared
            // `/Rows` is a promise about the image, so a row that stops short
            // of it means the file does not hold what it claims — and half a
            // scan reads as a bad image rather than a bad page. With no
            // declared count the rows that did decode are the image.
            return if p.rows == 0 && done > 0 {
                Some(out)
            } else {
                None
            };
        }
        out.extend_from_slice(&d.row_buf);
        done += 1;
    }
    if done == 0 {
        return None;
    }
    Some(out)
}

/// `ref_ce` is the previous row's changing elements and is this decoder's
/// reference line. An empty list is the imaginary all-white line T.4 starts a
/// page from, which is why `Vec::new()` is the correct initial state and not
/// a placeholder.
struct Decoder<'a> {
    bits: BitReader<'a>,
    columns: u32,
    byte_align: bool,
    /// Gray level a run taken from the **white** code table carries.
    white: u8,
    /// Gray level a run taken from the **black** code table carries.
    black: u8,
    row_buf: Vec<u8>,
    ref_ce: Vec<u32>,
    cur_ce: Vec<u32>,
}

impl<'a> Decoder<'a> {
    fn new(data: &'a [u8], p: &FaxParams) -> Self {
        // The two code tables name a run by its *bit value*, not by its ink:
        // the white table is the run of 0 bits, the black table the run of 1
        // bits, which is the fax convention the tables are written in.
        // `/BlackIs1` is then the flag that says which of the two values is
        // ink — so with the default `false`, where 0 is black, the white
        // table paints black. libtiff's Group 3 and Group 4 writers and its
        // own reader agree on this for a `PHOTOMETRIC_MINISBLACK` bilevel
        // image, and the output of every PDF the shape matches.
        //
        // Getting it backwards does not look like a mistake: it is the same
        // page with its ink and its ground exchanged.
        let (white, black) = if p.black_is_1 { (255, 0) } else { (0, 255) };
        Self {
            bits: BitReader { data, pos: 0 },
            columns: p.columns,
            byte_align: p.byte_align,
            white,
            black,
            row_buf: Vec::new(),
            ref_ce: Vec::new(),
            cur_ce: Vec::new(),
        }
    }

    /// Consume an `EOL` (`000000000001`) or an `EOFB` (two of them) if one
    /// is next. `EOFB` is tested first because it starts with `EOL`.
    fn take_mark(&mut self) -> Option<Mark> {
        if self.bits.peek(24) == Some(EOFB) {
            self.bits.advance(24);
            Some(Mark::Eofb)
        } else if self.bits.peek(12) == Some(EOL) {
            self.bits.advance(12);
            Some(Mark::Eol)
        } else {
            None
        }
    }

    /// Decode one row into `row_buf`, then promote it to the reference line.
    ///
    /// `false` means the row stopped short — out of bits or an undecodable
    /// code — and the caller decides whether that is a refused image or the
    /// end of a `/Rows`-less one.
    fn row(&mut self, one_d: bool) -> bool {
        self.row_buf.clear();
        self.row_buf.resize(self.columns as usize, self.white);
        self.cur_ce.clear();
        let ok = if one_d { self.row_1d() } else { self.row_2d() };
        if self.byte_align {
            self.bits.align();
        }
        if ok {
            // The next row's reference line is this one; keeping both vectors
            // and swapping lets each row reuse the other's allocation.
            let old = core::mem::take(&mut self.ref_ce);
            self.ref_ce = core::mem::take(&mut self.cur_ce);
            self.cur_ce = old;
        }
        ok
    }

    /// A one-dimensionally coded row: MH run lengths, white then black, over
    /// and over until the row is full.
    fn row_1d(&mut self) -> bool {
        let mut a0: u32 = 0;
        loop {
            if a0 >= self.columns {
                return true;
            }
            let before = a0;
            let white_run = match self.read_run(true) {
                Some(n) => n,
                None => return false,
            };
            let black_run = match self.read_run(false) {
                Some(n) => n,
                None => return false,
            };
            let w_end = a0.saturating_add(white_run).min(self.columns);
            let b_end = w_end.saturating_add(black_run).min(self.columns);
            self.paint(a0, w_end, true);
            self.paint(w_end, b_end, false);
            // A zero-length run is legal and records *no* changing element,
            // because nothing changed. Only a black pixel between `a0` and
            // `b_end` makes `w_end` and `b_end` elements of this row, and
            // getting that wrong moves every later row's reference line.
            if b_end > w_end || w_end > a0 {
                self.note_changing(w_end);
                if b_end > w_end {
                    self.note_changing(b_end);
                }
            }
            a0 = b_end;
            // Two zero-length runs leave `a0` where it was, and a stream that
            // never advances is an infinite loop rather than a decode.
            if a0 == before {
                return false;
            }
        }
    }

    /// A two-dimensionally coded row: each code places one changing element
    /// of this row relative to the previous one, or walks past the
    /// reference's elements without placing any.
    ///
    /// The mode code is read first and *then* acted on. Testing `b2 < a1`
    /// before the code would be the encoder's rule, not the decoder's: `a1`
    /// is an element of the row being built, and after a pass it can be
    /// further right than the decoder can yet know.
    fn row_2d(&mut self) -> bool {
        let mut a0: u32 = 0;
        // T.6 2.2.5.1 puts the first a0 of a line *before* the first picture
        // element and codes the first run as `a0a1 - 1`. Folding that `-1`
        // into the arithmetic is what lets the position start at 0, but the
        // reference lookup must still see the virtual position: the
        // reference line's element at 0 is to the right of it, and treating
        // it as not-there costs the line its first b1 and every vertical on
        // it after that.
        let mut virtual_a0 = true;
        // Colour of the run starting at `a0`. T.4's a0 is a virtual element
        // just left of the row and white; a vertical code flips it, and a
        // pass and a horizontal leave it alone.
        let mut a0_white = true;
        loop {
            if a0 >= self.columns {
                return true;
            }
            let after = if virtual_a0 { -1 } else { a0 as i64 };
            match self.read_mode() {
                Some(Mode::Pass) => {
                    // The coding line has no changing element before the
                    // next one, so the reference has to be walked forward by
                    // hand. The colour does *not* flip: `b2` sits inside the
                    // run already being painted, and flipping there inverts
                    // the rest of the line while still rendering a plausible
                    // page.
                    let b1_idx = changing_index(&self.ref_ce, after, a0_white);
                    // T.6 2.2.5.2: a b1 or b2 that is not detected sits on the
                    // imaginary changing element just after the reference
                    // line's last actual element, which is the line's width.
                    let b2 = self.ref_ce.get(b1_idx + 1).copied().unwrap_or(self.columns);
                    self.paint(a0, b2, a0_white);
                    a0 = b2;
                }
                Some(Mode::Vertical(delta)) => {
                    let b1 = changing_at(&self.ref_ce, after, a0_white).unwrap_or(self.columns);
                    let a1 = shift(b1, delta, self.columns);
                    self.paint(a0, a1, a0_white);
                    self.note_changing(a1);
                    a0 = a1;
                    a0_white = !a0_white;
                }
                Some(Mode::Horizontal) => {
                    // The first run has `a0`'s own colour, which is why the
                    // very first row starts by reading the *white* table.
                    let r1 = match self.read_run(a0_white) {
                        Some(n) => n,
                        None => return false,
                    };
                    let r2 = match self.read_run(!a0_white) {
                        Some(n) => n,
                        None => return false,
                    };
                    let mid = a0.saturating_add(r1).min(self.columns);
                    let end = mid.saturating_add(r2).min(self.columns);
                    self.paint(a0, mid, a0_white);
                    self.paint(mid, end, !a0_white);
                    // A first run of length zero still changes the colour at
                    // `a0` itself, and that element is what every later row's
                    // reference line is built from — leave it out and the
                    // parity that gives each element its colour is off by one
                    // for the rest of the page.
                    if mid > a0 || end > mid {
                        self.note_changing(mid);
                        if end > mid {
                            self.note_changing(end);
                        }
                    }
                    a0 = end;
                }
                None => return false,
            }
            // The imaginary a0 only covers the first mode of the line; from
            // here on a0 is a real picture element and the reference lookup
            // is the ordinary strict one.
            virtual_a0 = false;
        }
    }

    /// Record a changing element at `at`, unless one is already recorded
    /// there and unless it falls past the row. The parity of the list is what
    /// gives each element its colour, so a duplicate or an out-of-row entry
    /// silently re-colours every element after it.
    fn note_changing(&mut self, at: u32) {
        if at < self.columns && self.cur_ce.last().copied() != Some(at) {
            self.cur_ce.push(at);
        }
    }

    fn paint(&mut self, from: u32, to: u32, is_white: bool) {
        let lo = (from as usize).min(self.columns as usize);
        let hi = (to as usize).min(self.columns as usize);
        if lo < hi {
            let v = if is_white { self.white } else { self.black };
            self.row_buf[lo..hi].fill(v);
        }
    }

    /// One MH run: make-up codes until a terminating code ends it.
    fn read_run(&mut self, is_white: bool) -> Option<u32> {
        let (term, makeup) = tables(is_white);
        let mut total: u32 = 0;
        loop {
            if let Some(run) = self.read_code(term) {
                return Some(total.saturating_add(run));
            }
            // `read_code` consumes nothing when it finds no match, and the
            // two tables are prefix-free against each other, so the make-up
            // table is tried over the same bits.
            let extra = self.read_code(makeup)?;
            total = total.saturating_add(extra);
            // T.4 caps a run at 2560; a longer chain is a decoding error,
            // not a run, and letting it grow would size a `paint` from a
            // number the stream chose.
            if total > 2560 {
                return None;
            }
        }
    }

    /// T.4 Table 4, walked as the prefix tree it is.
    fn read_mode(&mut self) -> Option<Mode> {
        if self.bits.bit()? == 1 {
            return Some(Mode::Vertical(0)); // 1       V0
        }
        if self.bits.bit()? == 1 {
            return Some(if self.bits.bit()? == 1 {
                Mode::Vertical(1) // 011      VR1
            } else {
                Mode::Vertical(-1) // 010      VL1
            });
        }
        if self.bits.bit()? == 1 {
            return Some(Mode::Horizontal); // 001
        }
        if self.bits.bit()? == 1 {
            return Some(Mode::Pass); // 0001
        }
        // `00001` opens the two six-bit verticals and `00000` the two
        // seven-bit ones, so the tree splits here and not one level down —
        // read one bit too few and `000010` is mistaken for the start of
        // `0000010`, which turns a VL2 into a decode failure.
        if self.bits.bit()? == 1 {
            return Some(if self.bits.bit()? == 1 {
                Mode::Vertical(2) // 000011   VR2
            } else {
                Mode::Vertical(-2) // 000010   VL2
            });
        }
        // `000001` is the prefix both seven-bit verticals share, and the
        // seventh bit is what tells them apart: `0000011` is VR3 and
        // `0000010` is VL3. Split the tree a level earlier and both are
        // refused while `0000001xxx` — the extension — reads as a vertical.
        if self.bits.bit()? == 1 {
            return Some(if self.bits.bit()? == 1 {
                Mode::Vertical(3) // 0000011  VR3
            } else {
                Mode::Vertical(-3) // 0000010  VL3
            });
        }
        // `0000001xxx` is T.4's 2D extension — an EOL, which belongs at a
        // row boundary and not inside one, so a row that reaches it stopped
        // short. Nothing else leads anywhere from here.
        None
    }

    /// Match one code, widening one bit at a time.
    ///
    /// The tables are prefix-free, so the first width that matches is the
    /// only one that can — which is why the scan can stop instead of
    /// backtracking. A byte of fill bits matches nothing within
    /// `MAX_CODE_BITS` and ends the stream as a decode failure.
    fn read_code(&mut self, table: &[Code]) -> Option<u32> {
        let mut len: u32 = 0;
        loop {
            len += 1;
            if len > MAX_CODE_BITS {
                return None;
            }
            let bits = self.bits.peek(len)?;
            for &(code, code_len, run) in table {
                if code_len == len && code == bits {
                    self.bits.advance(len);
                    return Some(run);
                }
            }
        }
    }
}

fn tables(is_white: bool) -> (&'static [Code], &'static [Code]) {
    if is_white {
        (WHITE_TERMINATING, WHITE_MAKEUP)
    } else {
        (BLACK_TERMINATING, BLACK_MAKEUP)
    }
}

/// Place the coding line's changing element at the reference's, shifted by a
/// vertical code's signed distance.
///
/// `b1` is the reference line's element, and a vertical code's whole meaning
/// is `a1 = b1 + d`. The result is a picture element of the coding line, so it
/// cannot be past the last one: a vertical that would put it there is the
/// encoder closing the line, and the closing element is the width.
fn shift(b1: u32, delta: i32, width: u32) -> u32 {
    let shifted = if delta < 0 {
        b1.saturating_sub(delta.unsigned_abs())
    } else {
        b1.saturating_add(delta as u32)
    };
    shifted.min(width)
}

/// The index in `ce` of the first changing element right of `after` that
/// begins a run of the requested colour, or `ce.len()` when there is none.
///
/// `after` is `-1` for the imaginary a0 that opens a line, whose position is
/// before the first picture element: the reference line's element at 0 is to
/// the right of it, and treating it as not-there costs the line its first b1.
///
/// `want_black` is the colour *opposite* to the caller's, because T.4 defines
/// `b1` as the first reference element of opposite colour to `a0` — and an
/// element that begins black is exactly one the reference line is leaving
/// white at. Changing elements strictly alternate and the list always starts
/// with a transition *to* black, so an even index begins black; the colour
/// filter is not redundant bookkeeping, because on a reference line that is
/// black at `after` the next element to the right begins *white*, and
/// handing that one to a vertical code's comparison as if it began black
/// shifts every mode on the line.
fn changing_index(ce: &[u32], after: i64, want_black: bool) -> usize {
    let mut i = 0;
    while i < ce.len() {
        if (ce[i] as i64) > after {
            break;
        }
        i += 1;
    }
    if i < ce.len() && (i % 2 == 0) != want_black {
        i += 1;
    }
    i
}

/// The reference line's element `b1`, or `None` when the reference line has no
/// changing element to the right of `after` of the colour the caller wants.
///
/// The caller is the one that knows what a missing `b1` means: T.6 2.2.5.2
/// puts it on the imaginary changing element just after the reference line's
/// last actual element, which is the line's width.
fn changing_at(ce: &[u32], after: i64, want_black: bool) -> Option<u32> {
    ce.get(changing_index(ce, after, want_black)).copied()
}

/// MSB-first bit reader.
///
/// MSB first is the norm and is taken as given rather than detected: PDF has
/// no fill-order flag for `/CCITTFaxDecode`, so the only way a producer
/// writes the other order is to be non-conforming, and guessing would mean
/// decoding twice and returning whichever produced something.
struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BitReader<'a> {
    fn peek(&self, n: u32) -> Option<u32> {
        let avail = self.data.len().saturating_mul(8).saturating_sub(self.pos);
        if avail < n as usize {
            return None;
        }
        let mut v = 0u32;
        for k in 0..n as usize {
            let at = self.pos + k;
            v = (v << 1) | ((self.data[at >> 3] >> (7 - (at & 7))) & 1) as u32;
        }
        Some(v)
    }

    fn advance(&mut self, n: u32) {
        self.pos = (self.pos + n as usize).min(self.data.len().saturating_mul(8));
    }

    fn bits(&mut self, n: u32) -> Option<u32> {
        let v = self.peek(n)?;
        self.advance(n);
        Some(v)
    }

    fn bit(&mut self) -> Option<u32> {
        self.bits(1)
    }

    /// `/EncodedByteAlign`: the next row starts on the next byte boundary.
    /// Left unaligned, those fill bits are read as the head of the next code,
    /// and the reader then walks off into a code that does not exist.
    fn align(&mut self) {
        let slack = self.pos % 8;
        if slack != 0 {
            self.advance(8 - slack as u32);
        }
    }
}
#[cfg(all(test, feature = "pdf"))]
mod tests {
    //! What each coding mode must decode to.
    //!
    //! The streams here are spelled out as literal bit strings rather than
    //! encoded through the tables under test, because a table that is wrong
    //! in a self-consistent way — a mistyped run *and* a mistyped code —
    //! would cancel out against an encoder built from the same mistyped table
    //! and leave a green suite over a decoder that misreads real fax. The
    //! table-driven tests that do exist are therefore separate ones, holding
    //! the structural properties a literal stream cannot: that no code
    //! shadows another, and that every advertised run reads back as itself.

    use super::*;

    /// A run taken from the **white** code table is the image's 0 bits, and
    /// `/BlackIs1 false` — PDF's default — makes a 0 bit black. Every
    /// expectation below is written against these two names rather than
    /// against 0 and 255, because the polarity is the one thing here a
    /// misreading cannot make obvious: the page is the same page with its
    /// ink and its ground exchanged.
    const TABLE_WHITE: u8 = 0;
    const TABLE_BLACK: u8 = 255;

    const EOL_BITS: &str = "000000000001";
    const EOFB_BITS: &str = "000000000001000000000001";
    const V0: &str = "1";
    /// Table 1/T.6: `VR2` puts `a1` to the *right* of `b1` by two, `VL2` to
    /// the left. The two are different code words and they are not
    /// interchangeable — a stream built with one and read with the other
    /// puts the element on the wrong side of the reference.
    const VR2: &str = "000011";
    const VL2: &str = "000010";
    const PASS: &str = "0001";
    const HORIZONTAL: &str = "001";
    const WHITE_0: &str = "00110101";
    const WHITE_2: &str = "0111";
    const WHITE_4: &str = "1011";
    const WHITE_8: &str = "10011";
    const WHITE_10: &str = "00111";
    const WHITE_13: &str = "000011";
    const WHITE_64: &str = "11011";
    const BLACK_0: &str = "0000110111";
    const BLACK_2: &str = "11";
    const BLACK_3: &str = "10";
    const BLACK_4: &str = "011";

    struct Stream {
        bytes: Vec<u8>,
        nbits: u32,
    }

    impl Stream {
        fn new() -> Self {
            Self {
                bytes: Vec::new(),
                nbits: 0,
            }
        }

        fn bit(&mut self, one: bool) {
            if self.nbits.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if one {
                let last = self.bytes.len() - 1;
                self.bytes[last] |= 1 << (7 - self.nbits % 8);
            }
            self.nbits += 1;
        }

        /// A code written out as a literal bit string.
        fn code(&mut self, literal: &str) {
            for c in literal.chars() {
                match c {
                    '0' => self.bit(false),
                    '1' => self.bit(true),
                    _ => panic!("{literal} is not a bit string"),
                }
            }
        }

        fn code_bits(&mut self, value: u32, len: u32) {
            for k in (0..len).rev() {
                self.bit((value >> k) & 1 == 1);
            }
        }

        /// The zero fill `/EncodedByteAlign` makes an encoder emit between
        /// rows, written here so the test stream is what the flag claims.
        fn pad_to_byte(&mut self) {
            while !self.nbits.is_multiple_of(8) {
                self.bit(false);
            }
        }

        /// Emit the table entry that stands for exactly `n` pixels.
        fn entry_for(&mut self, table: &[Code], n: u32) {
            let (code, len, _) = table
                .iter()
                .find(|(_, _, run)| *run == n)
                .copied()
                .unwrap_or_else(|| panic!("no code for {n}"));
            self.code_bits(code, len);
        }

        /// One MH run of `n` pixels, through the tables the decoder reads.
        fn run(&mut self, is_white: bool, n: u32) {
            let (term, makeup) = tables(is_white);
            let mut left = n;
            while left >= 64 {
                let (_, _, run) = makeup
                    .iter()
                    .filter(|(_, _, run)| *run <= left)
                    .max_by_key(|(_, _, run)| *run)
                    .copied()
                    .unwrap_or_else(|| panic!("no make-up code for {left}"));
                self.entry_for(makeup, run);
                left -= run;
            }
            self.entry_for(term, left);
        }

        fn finish(self) -> Vec<u8> {
            self.bytes
        }
    }

    fn g4(columns: u32, rows: u32) -> FaxParams {
        FaxParams {
            k: 0,
            columns,
            rows,
            black_is_1: false,
            byte_align: false,
        }
    }

    fn g3(columns: u32, rows: u32) -> FaxParams {
        FaxParams {
            k: -1,
            columns,
            rows,
            black_is_1: false,
            byte_align: false,
        }
    }

    /// Decode and split into rows, so a failure reads as "which row, which
    /// pixel" rather than as two long byte strings.
    fn rows_of(data: &[u8], p: &FaxParams) -> Vec<Vec<u8>> {
        let img = decode_fax(data, p).expect("the stream decodes");
        assert_eq!(
            img.len(),
            (p.rows as usize) * (p.columns as usize),
            "one byte per pixel"
        );
        img.chunks(p.columns as usize).map(<[u8]>::to_vec).collect()
    }

    #[test]
    fn a_run_from_the_white_table_is_the_images_zero_bits() {
        // The whole polarity of the module in one row: `/BlackIs1 false`,
        // so a white-table run — the image's 0 bits — is black.
        let mut s = Stream::new();
        s.code(EOL_BITS);
        s.code(WHITE_4);
        s.code(BLACK_3);
        s.code(WHITE_10);
        s.code(BLACK_0);
        s.code(EOFB_BITS);
        let want: Vec<u8> = [TABLE_WHITE; 4]
            .into_iter()
            .chain([TABLE_BLACK; 3])
            .chain([TABLE_WHITE; 10])
            .collect();
        assert_eq!(rows_of(&s.finish(), &g3(17, 1)), [want]);
    }

    #[test]
    fn black_is_1_inverts_the_gray_levels_and_moves_no_pixel() {
        let mut s = Stream::new();
        s.code(EOL_BITS);
        s.code(WHITE_4);
        s.code(BLACK_3);
        s.code(WHITE_10);
        s.code(BLACK_0);
        s.code(EOFB_BITS);
        let data = s.finish();

        let normal = decode_fax(&data, &g3(17, 1)).expect("decodes");
        let inverted = decode_fax(
            &data,
            &FaxParams {
                black_is_1: true,
                ..g3(17, 1)
            },
        )
        .expect("decodes");
        assert_eq!(inverted.len(), normal.len());
        for (a, b) in normal.iter().zip(&inverted) {
            assert_eq!(a + b, 255, "one table and one ink, same pixel");
        }
        assert_ne!(normal, inverted, "the flag must change something");
    }

    #[test]
    fn an_all_white_page_decodes_to_every_zero_bit() {
        let mut s = Stream::new();
        s.code(EOL_BITS);
        s.code(WHITE_64);
        s.code(WHITE_0);
        s.code(BLACK_0);
        s.code(EOFB_BITS);
        assert_eq!(rows_of(&s.finish(), &g3(64, 1)), [[TABLE_WHITE; 64]]);
    }

    #[test]
    fn a_make_up_code_and_a_terminating_code_add_up_to_one_run() {
        // 64 + 13 = 77: the case where the two tables are joined wrongly,
        // since each half is a perfectly good code alone.
        let mut s = Stream::new();
        s.code(EOL_BITS);
        s.code(WHITE_64);
        s.code(WHITE_13);
        s.code(BLACK_0);
        s.code(EOFB_BITS);
        assert_eq!(rows_of(&s.finish(), &g3(77, 1)), [[TABLE_WHITE; 77]]);
    }

    #[test]
    fn a_horizontal_mode_row_reads_two_run_lengths_of_opposite_tables() {
        let mut s = Stream::new();
        s.code(HORIZONTAL);
        s.code(WHITE_4);
        s.code(BLACK_4);
        s.code(WHITE_0);
        s.code(BLACK_0);
        s.code(EOFB_BITS);
        let want: Vec<u8> = [TABLE_WHITE; 4]
            .into_iter()
            .chain([TABLE_BLACK; 4])
            .collect();
        assert_eq!(rows_of(&s.finish(), &g4(8, 1)), [want]);
    }

    #[test]
    fn a_vertical_zero_mode_places_the_coding_line_on_the_reference_line() {
        // Two identical rows of one black run: the second row is V0 on the
        // left of the run and V0 on its right, both landing on the reference
        // line's elements. A reference line off by one element puts the
        // second row's ink somewhere else entirely, and still renders.
        let mut s = Stream::new();
        for row in 0..2 {
            if row == 0 {
                s.code(HORIZONTAL);
                s.code(WHITE_2);
                s.code(BLACK_2);
                s.code(HORIZONTAL);
                s.code(WHITE_2);
                s.code(BLACK_0);
            } else {
                s.code(V0);
                s.code(V0);
                s.code(HORIZONTAL);
                s.code(WHITE_2);
                s.code(BLACK_0);
            }
        }
        s.code(EOFB_BITS);
        let want: Vec<u8> = [TABLE_WHITE; 2]
            .into_iter()
            .chain([TABLE_BLACK; 2])
            .chain([TABLE_WHITE; 2])
            .collect();
        assert_eq!(rows_of(&s.finish(), &g4(6, 2)), [want.clone(), want]);
    }

    #[test]
    fn a_vertical_two_mode_shifts_the_coding_line_right_of_the_reference_line() {
        let mut s = Stream::new();
        s.code(HORIZONTAL);
        s.code(WHITE_2);
        s.code(BLACK_2);
        s.code(HORIZONTAL);
        s.code(WHITE_4);
        s.code(BLACK_0);
        // Reference is black at [2,4); VR2 puts this row's element at 2 + 2.
        s.code(VR2);
        s.code(HORIZONTAL);
        s.code(BLACK_2);
        s.code(WHITE_2);
        s.code(EOFB_BITS);
        let first: Vec<u8> = [TABLE_WHITE; 2]
            .into_iter()
            .chain([TABLE_BLACK; 2])
            .chain([TABLE_WHITE; 4])
            .collect();
        let second: Vec<u8> = [TABLE_WHITE; 4]
            .into_iter()
            .chain([TABLE_BLACK; 2])
            .chain([TABLE_WHITE; 2])
            .collect();
        assert_eq!(rows_of(&s.finish(), &g4(8, 2)), [first, second]);
    }

    #[test]
    fn a_vertical_two_mode_shifts_the_coding_line_left_of_the_reference_line() {
        let mut s = Stream::new();
        s.code(HORIZONTAL);
        s.code(WHITE_2);
        s.code(BLACK_2);
        s.code(HORIZONTAL);
        s.code(WHITE_4);
        s.code(BLACK_0);
        // Reference is black at [2,4); VL2 puts this row's element at 2 - 2,
        // which is 0 — the coding line starts black. The mirror of the VR2
        // case, and the only thing that tells the two code words apart.
        s.code(VL2);
        s.code(HORIZONTAL);
        s.code(BLACK_4);
        s.code(WHITE_4);
        s.code(EOFB_BITS);
        let first: Vec<u8> = [TABLE_WHITE; 2]
            .into_iter()
            .chain([TABLE_BLACK; 2])
            .chain([TABLE_WHITE; 4])
            .collect();
        let second: Vec<u8> = [TABLE_BLACK; 4]
            .into_iter()
            .chain([TABLE_WHITE; 4])
            .collect();
        assert_eq!(rows_of(&s.finish(), &g4(8, 2)), [first, second]);
    }

    #[test]
    fn a_pass_mode_row_walks_past_both_reference_elements_before_it() {
        // Reference: black at [2,4) and [6,8), so elements 2, 4, 6, 8.
        // Coding: white to 8, then black at [8,10). The first pass carries a0
        // from 0 to 4 and the second from 4 to 8; without them the row needs
        // horizontals the encoder never sent.
        let mut s = Stream::new();
        s.code(HORIZONTAL);
        s.code(WHITE_2);
        s.code(BLACK_2);
        s.code(HORIZONTAL);
        s.code(WHITE_2);
        s.code(BLACK_2);
        s.code(HORIZONTAL);
        s.code(WHITE_2);
        s.code(BLACK_0);
        s.code(PASS);
        s.code(PASS);
        s.code(HORIZONTAL);
        s.code(WHITE_0);
        s.code(BLACK_2);
        s.code(EOFB_BITS);
        let reference: Vec<u8> = [TABLE_WHITE; 2]
            .into_iter()
            .chain([TABLE_BLACK; 2])
            .chain([TABLE_WHITE; 2])
            .chain([TABLE_BLACK; 2])
            .chain([TABLE_WHITE; 2])
            .collect();
        let coding: Vec<u8> = [TABLE_WHITE; 8]
            .into_iter()
            .chain([TABLE_BLACK; 2])
            .collect();
        assert_eq!(rows_of(&s.finish(), &g4(10, 2)), [reference, coding]);
    }

    #[test]
    fn a_k_factor_of_two_codes_every_other_row_one_dimensionally() {
        let p = FaxParams {
            k: 2,
            columns: 8,
            rows: 4,
            black_is_1: false,
            byte_align: false,
        };
        let mut s = Stream::new();
        for row in 0..4u32 {
            match row {
                0 | 2 => {
                    s.code(EOL_BITS);
                    s.code(WHITE_4);
                    s.code(BLACK_4);
                }
                // Each 2D row reads the 1D row above it as its reference: the
                // first shifts it right by two, the second lands back on it.
                // A K factor applied to the wrong rows fails on the first
                // one-dimensionally coded row, not on the second.
                1 => {
                    s.code(VR2);
                    s.code(HORIZONTAL);
                    s.code(BLACK_2);
                    s.code(WHITE_0);
                }
                _ => {
                    s.code(V0);
                    s.code(HORIZONTAL);
                    s.code(BLACK_2);
                    s.code(HORIZONTAL);
                    s.code(WHITE_2);
                    s.code(BLACK_0);
                }
            }
        }
        s.code(EOFB_BITS);
        let banded: Vec<u8> = [TABLE_WHITE; 4]
            .into_iter()
            .chain([TABLE_BLACK; 4])
            .collect();
        let shifted: Vec<u8> = [TABLE_WHITE; 6]
            .into_iter()
            .chain([TABLE_BLACK; 2])
            .collect();
        let settled: Vec<u8> = [TABLE_WHITE; 4]
            .into_iter()
            .chain([TABLE_BLACK; 2])
            .chain([TABLE_WHITE; 2])
            .collect();
        assert_eq!(
            rows_of(&s.finish(), &p),
            [banded.clone(), shifted, banded, settled]
        );
    }

    #[test]
    fn encoded_byte_align_moves_the_second_row_onto_a_byte_boundary() {
        // The first row's runs are chosen to land on 25 bits, so the seven
        // zero fill bits it leaves behind decide whether the reader finds the
        // second row's EOL. Unaligned, it walks into that EOL and on into a
        // code that does not exist.
        let mut s = Stream::new();
        s.code(EOL_BITS);
        s.run(true, 3);
        s.run(false, 1);
        s.run(true, 2);
        s.run(false, 2);
        s.pad_to_byte();
        s.code(EOL_BITS);
        s.run(true, 4);
        s.run(false, 4);
        s.run(true, 0);
        s.run(false, 0);
        s.code(EOFB_BITS);
        let data = s.finish();

        let aligned = decode_fax(
            &data,
            &FaxParams {
                byte_align: true,
                ..g3(8, 2)
            },
        )
        .expect("the aligned reading decodes");
        let first: Vec<u8> = [TABLE_WHITE; 3]
            .into_iter()
            .chain([TABLE_BLACK; 1])
            .chain([TABLE_WHITE; 2])
            .chain([TABLE_BLACK; 2])
            .collect();
        let second: Vec<u8> = [TABLE_WHITE; 4]
            .into_iter()
            .chain([TABLE_BLACK; 4])
            .collect();
        assert_eq!(aligned, [first, second].concat());

        assert!(
            decode_fax(&data, &g3(8, 2)).is_none(),
            "the unaligned reading of the same bytes is not a valid stream"
        );
    }

    #[test]
    fn a_block_ending_code_stops_the_decode_at_the_rows_already_read() {
        // `/Rows 3` is a lie the block terminator contradicts, and the
        // terminator is the honest word: the row before it is whole.
        let mut s = Stream::new();
        s.code(HORIZONTAL);
        s.code(WHITE_4);
        s.code(BLACK_0);
        s.code(EOFB_BITS);
        assert_eq!(decode_fax(&s.finish(), &g4(4, 3)).map(|v| v.len()), Some(4));
    }

    #[test]
    fn a_row_count_of_zero_decodes_until_the_block_ends() {
        let mut s = Stream::new();
        s.code(HORIZONTAL);
        s.code(WHITE_4);
        s.code(BLACK_2);
        s.code(HORIZONTAL);
        s.code(WHITE_2);
        s.code(BLACK_0);
        s.code(V0);
        s.code(V0);
        s.code(HORIZONTAL);
        s.code(WHITE_2);
        s.code(BLACK_0);
        s.code(EOFB_BITS);
        let p = g4(8, 0);
        let img = decode_fax(&s.finish(), &p).expect("decodes");
        assert_eq!(img.len(), 16, "two rows of eight pixels");
        let banded: Vec<u8> = [TABLE_WHITE; 4]
            .into_iter()
            .chain([TABLE_BLACK; 2])
            .chain([TABLE_WHITE; 2])
            .collect();
        assert_eq!(&img[..8], &banded[..]);
        assert_eq!(&img[8..], &banded[..]);
    }

    #[test]
    fn a_stream_that_stops_mid_row_is_refused_rather_than_handed_over_half_scanned() {
        let mut s = Stream::new();
        for _ in 0..2 {
            s.code(HORIZONTAL);
            s.code(WHITE_4);
            s.code(BLACK_0);
        }
        let full = s.finish();
        // Three bytes hold row 0 and the first two codes of row 1; the black
        // run that finishes row 1 is not there.
        assert_eq!(full.len(), 5);
        assert!(decode_fax(&full[..3], &g4(4, 2)).is_none());
        assert_eq!(decode_fax(&full, &g4(4, 2)).map(|v| v.len()), Some(8));
    }

    #[test]
    fn an_empty_stream_decodes_to_nothing_rather_than_to_an_empty_page() {
        assert!(decode_fax(b"", &g4(8, 1)).is_none());
        assert!(decode_fax(b"", &g4(8, 0)).is_none());
    }

    #[test]
    fn a_run_that_overruns_the_row_ends_the_row_without_panicking_or_looping() {
        // Black 72 into an 8-wide row. The decoder clamps, finishes the row
        // and stops; what it must not do is paint past the row or read the
        // same run for ever.
        let mut s = Stream::new();
        s.code(EOL_BITS);
        s.code(WHITE_0);
        s.code("0000001111"); // black make-up 64
        s.code("000101"); // black terminating 8
        s.code(EOFB_BITS);
        let img = decode_fax(&s.finish(), &g3(8, 1)).expect("decodes");
        // The white run is empty, so the row opens on the black run that
        // runs past the end of it: pixel 0 is black too.
        assert_eq!(img, [TABLE_BLACK; 8]);
    }

    #[test]
    fn every_prefix_of_a_two_dimensional_stream_returns_none_instead_of_panicking() {
        // A real-shaped stream cut at every byte length. Each prefix is
        // either a shorter valid image or `None`; what is held down is the
        // absence of a panic and of a wrongly-sized image, which is what a
        // truncated scan in a real PDF looks like.
        let full = pass_mode_stream();
        assert_eq!(decode_fax(&full, &g4(10, 2)).map(|v| v.len()), Some(20));

        for cut in 0..=full.len() {
            for rows in [0u32, 1, 2] {
                let p = g4(10, rows);
                if let Some(img) = decode_fax(&full[..cut], &p) {
                    assert_eq!(img.len() % 10, 0, "prefix of {cut} bytes");
                    assert!(!img.is_empty(), "prefix of {cut} bytes");
                }
            }
        }
    }

    /// Two Group 4 rows over a reference line of four changing elements,
    /// with every 2D mode the decoder implements: three horizontal segments
    /// on row 0, then two passes and a horizontal on row 1.
    fn pass_mode_stream() -> Vec<u8> {
        let mut s = Stream::new();
        s.code(HORIZONTAL);
        s.code(WHITE_2);
        s.code(BLACK_2);
        s.code(HORIZONTAL);
        s.code(WHITE_2);
        s.code(BLACK_2);
        s.code(HORIZONTAL);
        s.code(WHITE_2);
        s.code(BLACK_0);
        s.code(PASS);
        s.code(PASS);
        s.code(HORIZONTAL);
        s.code(WHITE_0);
        s.code(BLACK_2);
        s.code(EOFB_BITS);
        s.finish()
    }

    #[test]
    fn a_bit_flip_anywhere_never_produces_a_panic() {
        let full = pass_mode_stream();
        for byte in 0..full.len() {
            for bit in 0..8u32 {
                let mut m = full.clone();
                m[byte] ^= 1 << bit;
                for p in [g4(10, 0), g4(10, 2), g3(10, 2)] {
                    if let Some(img) = decode_fax(&m, &p) {
                        assert_eq!(img.len() % 10, 0);
                    }
                }
            }
        }
    }

    #[test]
    fn an_undecodable_byte_string_never_produces_a_panic() {
        let mut x: u32 = 0x1234_5678;
        for _ in 0..512 {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let len = (x >> 16) as usize % 24;
            let data: Vec<u8> = (0..len)
                .map(|i| ((x >> ((i % 4) * 8)) as u8) ^ (i as u8).wrapping_mul(31))
                .collect();
            for p in [g4(16, 0), g4(16, 4), g3(16, 4)] {
                if let Some(img) = decode_fax(&data, &p) {
                    assert_eq!(img.len() % 16, 0);
                }
            }
        }
    }

    #[test]
    fn an_image_the_container_only_claims_is_huge_is_refused() {
        let mut s = Stream::new();
        s.code(HORIZONTAL);
        s.code(WHITE_8);
        s.code(BLACK_0);
        s.code(EOFB_BITS);
        // 60000 x 4000 is 240 megapixels of gray, from a nine-byte stream.
        assert!(decode_fax(&s.finish(), &g4(60_000, 4_000)).is_none());
    }

    #[test]
    fn the_run_length_tables_shadow_no_code_of_their_own() {
        // Two codes in one colour's set that can both match the same bits
        // would make a run length depend on table order, and the standard's
        // tables are prefix-free across *both* tables precisely so that a
        // make-up code can be looked for after a terminating one misses.
        for is_white in [true, false] {
            let (term, makeup) = tables(is_white);
            let all: Vec<Code> = term.iter().chain(makeup.iter()).copied().collect();
            for (i, &(bits_a, len_a, run_a)) in all.iter().enumerate() {
                for &(bits_b, len_b, run_b) in all.iter().skip(i + 1) {
                    assert_ne!(
                        (bits_a, len_a),
                        (bits_b, len_b),
                        "runs {run_a} and {run_b} share one code"
                    );
                    let (short, short_len, long, long_len) = if len_a < len_b {
                        (bits_a, len_a, bits_b, len_b)
                    } else {
                        (bits_b, len_b, bits_a, len_a)
                    };
                    if short_len != long_len {
                        assert_ne!(
                            short,
                            long >> (long_len - short_len),
                            "runs {run_a} ({bits_a}, len {len_a}) and {run_b} ({bits_b}, len {len_b})"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn every_terminating_code_stands_for_the_run_it_advertises() {
        // A code that is shadowed by a shorter one, or whose width does not
        // match its value, reads back as some *other* run. This walks every
        // terminating code in both colours through a whole one-dimensional
        // row, so the row's pixel count is the run the code claims.
        for is_white in [true, false] {
            let (term, _) = tables(is_white);
            for &(_, _, run) in term {
                let columns = run + 4;
                let mut pairs: [(u32, u32); 2] = if is_white {
                    [(run, 0), (columns - run, 0)]
                } else {
                    [(0, run), (columns - run, 0)]
                };
                // Two zero-length runs in a row are not a run at all — no
                // encoder emits them, and a decoder that loops on them never
                // finishes — so the leading one goes.
                if pairs[0] == (0, 0) {
                    pairs[0] = pairs[1];
                }
                let mut s = Stream::new();
                s.code(EOL_BITS);
                for (w, b) in pairs {
                    s.run(true, w);
                    s.run(false, b);
                }
                s.code(EOFB_BITS);
                let img = decode_fax(&s.finish(), &g3(columns, 1)).expect("decodes");
                let ink = if is_white { TABLE_WHITE } else { TABLE_BLACK };
                assert!(
                    img[..run as usize].iter().all(|&v| v == ink),
                    "run {run} is not the run the code advertises"
                );
                assert!(
                    img[run as usize..].iter().all(|&v| v == TABLE_WHITE),
                    "run {run} painted past its own length"
                );
            }
        }
    }

    #[test]
    fn every_make_up_code_stands_for_the_run_it_advertises() {
        for is_white in [true, false] {
            let (_, makeup) = tables(is_white);
            for &(_, _, run) in makeup {
                let mut s = Stream::new();
                s.code(EOL_BITS);
                if is_white {
                    s.entry_for(makeup, run);
                    s.code(WHITE_0);
                    s.code(BLACK_0);
                } else {
                    s.code(WHITE_0);
                    s.entry_for(makeup, run);
                    s.code(BLACK_0);
                }
                s.code(EOFB_BITS);
                let img = decode_fax(&s.finish(), &g3(run, 1))
                    .unwrap_or_else(|| panic!("make-up {run} decodes"));
                let ink = if is_white { TABLE_WHITE } else { TABLE_BLACK };
                assert_eq!(img.len(), run as usize, "make-up {run}");
                assert!(img.iter().all(|&v| v == ink), "make-up {run}");
            }
        }
    }

    /// The decoder is a byte-slice parser over a stream that says nothing
    /// about its own length, so the mutation floor is the only thing between
    /// a corrupt scan and a panic. The corpus is the two real streams — a
    /// Group 4 one and a Group 3 one — because a decoder that never sees a
    /// well-formed scan cannot be shown to survive a malformed one.
    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let corpus: Vec<(&'static str, Vec<u8>)> = vec![
            ("g4", include_bytes!("../testdata/fax_g4.strip").to_vec()),
            ("g3", include_bytes!("../testdata/fax_g3.strip").to_vec()),
            ("zeros", vec![0u8; 512]),
            ("ones", vec![0xff; 512]),
        ];
        let g4 = FaxParams {
            k: 0,
            columns: 1720,
            rows: 280,
            black_is_1: false,
            byte_align: false,
        };
        let g3 = FaxParams {
            k: -1,
            columns: 800,
            rows: 200,
            black_is_1: false,
            byte_align: false,
        };
        rgx_core::fuzzkit::assert_never_panics(corpus, 200, "fax", move |data| {
            let _ = decode_fax(data, &g4);
            let _ = decode_fax(data, &g3);
        });
    }
}
