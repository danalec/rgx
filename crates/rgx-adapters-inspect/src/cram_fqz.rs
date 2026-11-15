// SPDX-License-Identifier: Apache-2.0

//! The FQZComp quality codec of CRAM 3.1.
//!
//! The codec is the one the CRAM 3.0 and 3.1 specifications point at for the
//! quality values of a slice: the "CRAM codec specification" of the hts-specs
//! repository, section 6 ("FQZComp"), describes the frame, and the reference
//! implementation of that codec, the htscodecs library, is what writes the
//! frames the tests carry.
//!
//! The frame holds the number of quality values, the global parameters, the
//! parameter blocks and then the entropy-coded values themselves. The
//! qualities of a record are coded against a context that mixes the quality
//! before, the position in the record, the number of quality changes so far
//! and the selector of the record, so that a record of similar qualities
//! costs less than one that changes often.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::cram_arith::{Model, RangeCoder, Reader};

/// The version of the codec this reader speaks.
///
/// The frame carries the version in its second byte, and the reference
/// implementation refuses anything but this one.
const VERSION: u8 = 5;

/// The number of quality contexts.
///
/// The context of a quality value is sixteen bits wide, so there are this
/// many contexts and each of them has a model of its own.
const CTX_SIZE: usize = 1 << 16;

/// The largest a decoded block may be.
///
/// The size comes from the frame itself, so a corrupt one could ask for a
/// gigabyte before it is refused. The ceiling is the same one the other
/// decompressors of this crate use.
const MAX_OUTPUT: usize = 32 << 20;

/// The bits of the global flags byte.
#[cfg(feature = "cram")]
mod gflag {
    /// The frame carries more than one parameter block.
    pub const MULTI_PARAM: u8 = 0x01;
    /// The frame carries the table that maps a selector to a parameter block.
    pub const HAVE_STAB: u8 = 0x02;
    /// The frame says, per record, whether the qualities are stored reversed.
    pub const DO_REV: u8 = 0x04;
}

/// The bits of a parameter block's flags byte.
#[cfg(feature = "cram")]
mod pflag {
    /// The record may be a copy of the one before it.
    pub const DO_DEDUP: u8 = 0x02;
    /// Every record of this block has the same length.
    pub const DO_LEN: u8 = 0x04;
    /// The record is chosen by the selector.
    pub const DO_SEL: u8 = 0x08;
    /// The block carries the map from the model's symbols to the qualities.
    pub const HAVE_QMAP: u8 = 0x10;
    /// The block carries the table of the position context.
    pub const HAVE_PTAB: u8 = 0x20;
    /// The block carries the table of the delta context.
    pub const HAVE_DTAB: u8 = 0x40;
    /// The block carries the table of the quality context.
    pub const HAVE_QTAB: u8 = 0x80;
}

/// One parameter block: the context a record starts in, and the tables and
/// sub-contexts its qualities are coded against.
#[cfg(feature = "cram")]
struct Param {
    /// The context the first quality of a record is coded in.
    context: u16,
    /// The block's flags.
    pflags: u8,
    /// The number of symbols the block's map holds.
    max_sym: u8,
    /// The mask of the quality sub-context.
    qmask: u32,
    /// The shift of the quality sub-context.
    qshift: u8,
    /// Where the quality sub-context sits in the context.
    qloc: u8,
    /// Where the selector sits in the context.
    sloc: u8,
    /// Where the position context sits in the context.
    ploc: u8,
    /// Where the delta context sits in the context.
    dloc: u8,
    /// The map from the model's symbols to the qualities.
    qmap: [u8; 256],
    /// The table of the quality sub-context.
    qtab: [u8; 256],
    /// The table of the position context.
    ptab: [u16; 1024],
    /// The table of the delta context.
    dtab: [u16; 256],
}

/// The models of the contexts whose high byte is one: one per low byte.
#[cfg(feature = "cram")]
type Bucket = Box<[Option<Box<Model>>; 256]>;

/// The quality models, one per context.
///
/// The context is sixteen bits wide, so the models are held in two levels:
/// the high byte picks the bucket and the low byte the model in it. A frame
/// touches few buckets, so the memory goes to the contexts it uses and not
/// to the sixty-five thousand the width of the context allows.
#[cfg(feature = "cram")]
struct Quality {
    /// The buckets of models, the high byte of the context picking one.
    buckets: Vec<Option<Bucket>>,
    /// The number of symbols each model holds.
    num_sym: usize,
}

#[cfg(feature = "cram")]
impl Quality {
    /// The models of a frame, each with `num_sym` symbols.
    fn new(num_sym: usize) -> Self {
        Self {
            buckets: Vec::new(),
            num_sym,
        }
    }

    /// The model of a context, made when the context is first used.
    fn model(&mut self, ctx: usize) -> &mut Model {
        let num_sym = self.num_sym;
        let high = ctx >> 8;
        let low = ctx & 0xff;
        if self.buckets.len() <= high {
            self.buckets.resize_with(high + 1, || None);
        }
        let bucket =
            self.buckets[high].get_or_insert_with(|| Box::new(core::array::from_fn(|_| None)));
        bucket[low]
            .get_or_insert_with(|| Box::new(Model::new(num_sym)))
            .as_mut()
    }
}

/// Reads one parameter block.
///
/// The block is the context the records start in, the flags that say what the
/// block carries, and then the tables: the map from the model's symbols to
/// the qualities, and the tables of the quality, position and delta
/// sub-contexts.
#[cfg(feature = "cram")]
fn read_param(reader: &mut Reader<'_>) -> Option<Param> {
    let context = u16::from(reader.byte()?) | (u16::from(reader.byte()?) << 8);
    let pflags = reader.byte()?;
    let max_sym = reader.byte()?;

    // The sizes and the places of the sub-contexts: the first byte of each
    // pair holds the high nibble and the second the low one.
    let q = reader.byte()?;
    let qbits = q >> 4;
    let qshift = q & 0x0f;
    let q = reader.byte()?;
    let qloc = q >> 4;
    let sloc = q & 0x0f;
    let q = reader.byte()?;
    let ploc = q >> 4;
    let dloc = q & 0x0f;

    let mut qmap = [0u8; 256];
    let mut qtab = [0u8; 256];
    let mut ptab = [0u16; 1024];
    let mut dtab = [0u16; 256];

    if pflags & pflag::HAVE_QMAP != 0 {
        // The map holds one quality for each symbol the model may produce.
        for map in qmap.iter_mut().take(usize::from(max_sym)) {
            *map = reader.byte()?;
        }
    } else {
        // Without a map the symbol is the quality.
        for (value, map) in qmap.iter_mut().enumerate() {
            *map = value as u8;
        }
    }

    // The table of the quality sub-context is only read when the block has a
    // quality sub-context at all: with no bits to it, the table is of no use
    // to anyone, and the frame does not carry it.
    if qbits != 0 {
        if pflags & pflag::HAVE_QTAB != 0 {
            let table = read_array(reader, 256)?;
            for (value, tab) in qtab.iter_mut().enumerate() {
                *tab = table[value] as u8;
            }
        } else {
            for (value, tab) in qtab.iter_mut().enumerate() {
                *tab = value as u8;
            }
        }
    } else {
        for (value, tab) in qtab.iter_mut().enumerate() {
            *tab = value as u8;
        }
    }

    if pflags & pflag::HAVE_PTAB != 0 {
        let table = read_array(reader, 1024)?;
        ptab.copy_from_slice(&table);
    }

    if pflags & pflag::HAVE_DTAB != 0 {
        let table = read_array(reader, 256)?;
        dtab.copy_from_slice(&table);
    }

    Some(Param {
        context,
        pflags,
        max_sym,
        qmask: (1u32 << qbits) - 1,
        qshift,
        qloc,
        sloc,
        ploc,
        dloc,
        qmap,
        qtab,
        ptab,
        dtab,
    })
}

/// Reads a table of the specification's run-length encoding.
///
/// The table is a list of run lengths: the first says how many times the
/// value zero appears, the next how many times the value one appears, and so
/// on. A run of more than 255 is broken into a series of 255s and the
/// remainder, and a run that repeats the run before it is followed by the
/// count of the copies that come with it.
#[cfg(feature = "cram")]
fn read_array(reader: &mut Reader<'_>, size: usize) -> Option<Vec<u16>> {
    let size = size.min(1024);

    // The first level of the encoding: the run lengths themselves.
    let mut runs = [0u8; 1024];
    let mut count = 0usize;
    let mut total = 0usize;
    let mut last: i32 = -1;
    loop {
        if total >= size {
            break;
        }
        let run = i32::from(reader.byte()?);
        runs[count] = run as u8;
        count += 1;
        total += run as usize;
        if run == last {
            // The run repeats the one before it: the next byte says how many
            // copies come with it.
            let copies = usize::from(reader.byte()?);
            total += run as usize * copies;
            let mut copies = copies;
            while copies > 0 && total <= size && count < 1024 {
                runs[count] = run as u8;
                count += 1;
                copies -= 1;
            }
        }
        if count >= 1024 {
            return None;
        }
        last = run;
    }

    // The second level: the runs are expanded into the values they hold. A
    // run of 255 says that the value runs on into the next one, so the parts
    // are added up until a part is not 255.
    let mut table = vec![0u16; size];
    let mut at = 0usize;
    let mut part = 0usize;
    let mut value = 0usize;
    while at < size {
        if part >= count {
            return None;
        }
        let mut run = 0usize;
        loop {
            let piece = usize::from(runs[part]);
            part += 1;
            run += piece;
            if piece != 255 || part >= count {
                break;
            }
        }
        if runs[part - 1] == 255 {
            // The last run of the table says the value runs on, but there is
            // no run to add to it.
            return None;
        }
        while run > 0 && at < size {
            table[at] = value as u16;
            at += 1;
            run -= 1;
        }
        value += 1;
    }

    Some(table)
}

/// Decodes one FQZComp block into the quality values it carries.
///
/// `None` when the frame is not one this reader can decode: a version it does
/// not speak, a frame that ends before the values it says it holds, a
/// parameter block that asks for a selector the frame does not have, a
/// record that does not fit in the frame, or a value the model produces that
/// the block's map does not hold.
#[cfg(feature = "cram")]
pub(crate) fn decode(block: &[u8]) -> Option<Vec<u8>> {
    let mut reader = Reader::new(block);

    // The number of quality values the frame carries.
    let total = usize::try_from(reader.uint7()?).ok()?;
    if total > MAX_OUTPUT {
        return None;
    }

    // The global parameters.
    let version = reader.byte()?;
    if version != VERSION {
        return None;
    }
    let gflags = reader.byte()?;
    let nparam = if gflags & gflag::MULTI_PARAM != 0 {
        usize::from(reader.byte()?)
    } else {
        1
    };
    if nparam == 0 {
        return None;
    }
    // The number of selector values: the parameter blocks themselves when
    // there is more than one, and the frame's own byte when the frame carries
    // the table that maps a selector to a parameter block.
    let mut max_sel = if nparam > 1 { nparam } else { 0 };
    let mut stab = [0u16; 256];
    if gflags & gflag::HAVE_STAB != 0 {
        max_sel = usize::from(reader.byte()?);
        let table = read_array(&mut reader, 256)?;
        stab.copy_from_slice(&table);
    }

    // The parameter blocks. The largest symbol of the frame is the largest
    // of the blocks: the models of the qualities are shared by all of them.
    let mut params = Vec::with_capacity(nparam);
    let mut max_sym = 0usize;
    for _ in 0..nparam {
        let param = read_param(&mut reader)?;
        if param.pflags & pflag::DO_SEL != 0 && max_sel == 0 {
            // The block asks for a selector the frame does not have.
            return None;
        }
        max_sym = max_sym.max(usize::from(param.max_sym));
        params.push(param);
    }

    // The models: the qualities, the four bytes of a record's length, the
    // duplication flag, the reversal flag and the selector.
    let mut quality = Quality::new(max_sym + 1);
    let mut lengths = [
        Model::new(256),
        Model::new(256),
        Model::new(256),
        Model::new(256),
    ];
    let mut dup = Model::new(2);
    let mut rev = Model::new(2);
    let mut selectors = if max_sel > 0 {
        Some(Model::new(max_sel + 1))
    } else {
        None
    };

    let mut coder = RangeCoder::new(&mut reader)?;
    let mut out = vec![0u8; total];
    let mut at = 0usize;

    // What the frame keeps from one record to the next.
    let mut first = true;
    let mut last_len = 0u32;
    let mut param = 0usize;
    let mut selector = 0u8;

    // What a record keeps of its own.
    let mut remaining = 0u32;
    let mut delta = 0u32;
    let mut previous = 0u8;
    let mut qctx = 0u32;
    let mut ctx = 0usize;

    // The reversal, per record.
    let mut reversed: Vec<bool> = Vec::new();
    let mut record_len: Vec<u32> = Vec::new();

    while at < total {
        if remaining == 0 {
            // A new record. The selector comes first, and it is the block of
            // the record before that says whether there is one.
            let before = &params[param];
            let sel = if before.pflags & pflag::DO_SEL != 0 {
                selectors.as_mut()?.decode(&mut coder)?
            } else {
                0
            };
            selector = sel;

            // The selector picks the block of this record, either as it is or
            // through the frame's table.
            let index = if gflags & gflag::HAVE_STAB != 0 {
                usize::from(stab[usize::from(sel).min(255)])
            } else {
                usize::from(sel)
            };
            if index >= nparam {
                return None;
            }
            param = index;
            let block = &params[param];

            // The length of the record. The frame carries it unless every
            // record of the block has the same length, and the first record
            // always carries its own.
            let len = if block.pflags & pflag::DO_LEN == 0 || first {
                let len = u32::from(lengths[0].decode(&mut coder)?)
                    | (u32::from(lengths[1].decode(&mut coder)?) << 8)
                    | (u32::from(lengths[2].decode(&mut coder)?) << 16)
                    | (u32::from(lengths[3].decode(&mut coder)?) << 24);
                first = false;
                last_len = len;
                len
            } else {
                last_len
            };
            if len == 0 || len as usize > total - at {
                return None;
            }

            // The reversal flag.
            if gflags & gflag::DO_REV != 0 {
                reversed.push(rev.decode(&mut coder)? != 0);
                record_len.push(len);
            }

            // The duplication flag: the record is a copy of the one before it.
            if block.pflags & pflag::DO_DEDUP != 0 && dup.decode(&mut coder)? != 0 {
                let len = len as usize;
                if len > at {
                    return None;
                }
                out.copy_within(at - len..at, at);
                at += len;
                continue;
            }

            remaining = len;
            delta = 0;
            previous = 0;
            qctx = 0;
            ctx = usize::from(block.context);
        }

        // One quality value, and the context the next one is coded in.
        let block = &params[param];
        let q = quality.model(ctx).decode(&mut coder)?;

        let mut next = u32::from(block.context);
        qctx = qctx
            .wrapping_shl(u32::from(block.qshift))
            .wrapping_add(u32::from(block.qtab[usize::from(q)]));
        next = next.wrapping_add((qctx & block.qmask).wrapping_shl(u32::from(block.qloc)));
        next = next.wrapping_add(u32::from(block.ptab[remaining.min(1023) as usize]) << block.ploc);
        next = next.wrapping_add(u32::from(block.dtab[delta.min(255) as usize]) << block.dloc);
        next = next.wrapping_add(u32::from(selector) << block.sloc);
        delta += u32::from(previous != q);
        previous = q;
        remaining -= 1;
        ctx = (next & (CTX_SIZE as u32 - 1)) as usize;

        // The quality itself: the map says which quality the symbol stands
        // for, and without a map the symbol is the quality.
        let value = if block.pflags & pflag::HAVE_QMAP != 0 {
            let symbol = usize::from(q);
            if symbol >= usize::from(block.max_sym) {
                // The model produced a symbol the map does not hold.
                return None;
            }
            block.qmap[symbol]
        } else {
            q
        };
        out[at] = value;
        at += 1;
    }

    // The records the frame says are stored backwards are put back the right
    // way round.
    if gflags & gflag::DO_REV != 0 {
        let mut start = 0usize;
        for (rec, flag) in reversed.iter().enumerate() {
            let len = record_len[rec] as usize;
            if *flag {
                out[start..start + len].reverse();
            }
            start += len;
        }
    }

    Some(out)
}

/// The frame of the codec specification's own example: twenty quality
/// values, all of them the letter I.
///
/// Written by the reference implementation on the box with
/// `printf 'IIIIIIIIIIIIIIIIIIII' > /tmp/fqzref/work/a.in` and
/// `fqzref2 /tmp/fqzref/work/a.in /tmp/fqzref/work/a.frame
/// /tmp/fqzref/work/a.dec 20 0 auto`, the driver that takes the record
/// lengths, the per-record flags and the mode of the global parameters.
/// The reference decodes the frame back to twenty quality values of 'I'.
#[cfg(all(test, feature = "cram"))]
pub(crate) const SPECIFICATION: &[u8] = &[
    0x14, 0x05, 0x02, 0x03, 0xff, 0x01, 0x00, 0x00, 0x7e, 0x01, 0x22, 0x0d, 0xaf, 0x49, 0x20, 0x20,
    0x01, 0xff, 0xff, 0x01, 0xa3, 0x02, 0x06, 0x0a, 0xee, 0x00, 0xc4, 0xff, 0xff, 0xe9, 0x00, 0x00,
    0x00, 0x00,
];

/// A frame of three reads of different lengths: thirty, twenty-five and
/// forty quality values.
///
/// Written by the reference implementation on the box with
/// `fqzref2 /tmp/fqzref/work/b.in /tmp/fqzref/work/b.frame
/// /tmp/fqzref/work/b.dec 30,25,40 0,0,0 auto`, over a file of ninety-five
/// quality values. The reference decodes the frame back to the same
/// ninety-five values, in records of thirty, twenty-five and forty.
#[cfg(all(test, feature = "cram"))]
pub(crate) const READS: &[u8] = &[
    0x5f, 0x05, 0x02, 0x03, 0xff, 0x01, 0x00, 0x00, 0x6a, 0x79, 0x55, 0x0d, 0xaf, 0x04, 0x04, 0x05,
    0xff, 0xff, 0x01, 0xe7, 0x02, 0x06, 0x0a, 0xee, 0x00, 0xc7, 0x7f, 0xff, 0xdf, 0x13, 0x1a, 0xb3,
    0xc1, 0xca, 0xf8, 0xce, 0xee, 0x8d, 0x8f, 0x15, 0x68, 0xbf, 0x3f, 0x0f, 0xcd, 0xd3, 0x91, 0xf9,
    0x07, 0xf7, 0xbd, 0x7e, 0x89, 0xf8, 0xa6, 0x85, 0x86, 0xea, 0xea, 0x0a, 0xa7, 0xb5, 0xed, 0x54,
    0x65, 0x2b, 0xbe, 0xb9, 0x62, 0x9c, 0x01, 0xce, 0xbf, 0x3b, 0x27, 0x46, 0xfb, 0x50, 0xc8, 0x7b,
    0xa0, 0xa6, 0xe8, 0xb2, 0x41, 0x35, 0x22, 0x4c, 0x45, 0x2a, 0x7a, 0x09, 0xe5, 0x1c, 0x74, 0x0c,
    0x9c, 0x29, 0x29, 0xa9, 0x65, 0x44, 0x7c, 0x02, 0x5c, 0xe3, 0x1f, 0x62, 0xe6, 0x4c, 0x47, 0xbc,
    0xa2, 0x00,
];

/// A frame whose qualities hold every value from the exclamation mark to
/// the tilde, twice over: the block carries a map of ninety-four
/// qualities, so the model codes symbols and not the qualities.
///
/// Written by the reference implementation on the box with
/// `fqzref2 /tmp/fqzref/work/c.in /tmp/fqzref/work/c.frame
/// /tmp/fqzref/work/c.dec 188 0 auto`, over a file of the values from
/// 33 to 126 twice over. The reference decodes the frame back to the same
/// one hundred and eighty-eight values.
#[cfg(all(test, feature = "cram"))]
pub(crate) const MANY_VALUES: &[u8] = &[
    0x81, 0x3c, 0x05, 0x00, 0x00, 0x00, 0x66, 0x7e, 0x55, 0x0d, 0xaf, 0x20, 0x20, 0x05, 0xff, 0xff,
    0x01, 0x23, 0x02, 0x06, 0x0a, 0xee, 0x00, 0xbb, 0xff, 0xff, 0x44, 0x21, 0x88, 0x28, 0x97, 0xb9,
    0xf9, 0x4e, 0xb3, 0xa7, 0xd9, 0x21, 0xf5, 0xdf, 0x18, 0xa9, 0x89, 0xcc, 0xf8, 0xdf, 0xba, 0xbc,
    0xaa, 0xd3, 0xfe, 0x28, 0xbb, 0xbb, 0xca, 0xfa, 0x92, 0x48, 0xec, 0x0e, 0xdb, 0xd9, 0x5a, 0xa5,
    0xe3, 0x63, 0x22, 0x06, 0x8a, 0x7a, 0xf9, 0x59, 0x07, 0x23, 0x7e, 0xe0, 0xba, 0x76, 0x72, 0x77,
    0xc5, 0xa8, 0x88, 0x00, 0x97, 0xf9, 0x7d, 0xd4, 0x91, 0x07, 0xa6, 0x8a, 0x18, 0x82, 0x86, 0x1a,
    0x04, 0x4a, 0xd8, 0x05, 0x5d, 0x5d, 0xbf, 0x4f, 0x0c, 0x8f, 0xeb, 0x99, 0x22, 0xa7, 0x9f, 0x4c,
    0x71, 0x72, 0xea, 0x55, 0x65, 0x38, 0x32, 0xf6, 0xfc, 0x14, 0x05, 0x2b, 0x00, 0xed, 0x2c, 0x14,
    0xe8, 0x7a, 0xc4, 0x6e, 0xd6, 0xba, 0x59, 0x93, 0xdf, 0xc9, 0xa2, 0x83, 0x00, 0xfa, 0x64, 0x19,
    0xe9, 0xd7, 0x49, 0x82, 0x09, 0xcb, 0x36, 0xfe, 0xac, 0xed, 0xd3, 0x82, 0xd4, 0x00, 0x38, 0xc7,
    0x0c, 0x89, 0x1e, 0xdc, 0x98, 0x6d, 0x58, 0xba, 0xd5, 0x8d, 0xfa, 0x7a, 0x9c, 0x33, 0x0a, 0xb5,
    0x38, 0x3b, 0xa9, 0xde, 0x96, 0x16, 0x10, 0xd5, 0xce, 0x46, 0x49, 0x32, 0xdc, 0xb0, 0x1b, 0x31,
    0x28, 0x40, 0x00,
];

/// A frame whose qualities are stored the other way round: the frame says
/// so, and the reader has to put them back.
///
/// Written by the reference implementation on the box with
/// `fqzref2 /tmp/fqzref/work/d.in /tmp/fqzref/work/d.frame
/// /tmp/fqzref/work/d.dec 20 r auto`, over a file of twenty quality
/// values, the flag 'r' marking the record as reversed. The reference
/// decodes the frame back to the same twenty values.
#[cfg(all(test, feature = "cram"))]
pub(crate) const REVERSED: &[u8] = &[
    0x14, 0x05, 0x06, 0x03, 0xff, 0x01, 0x00, 0x00, 0x6e, 0x54, 0x55, 0x0d, 0xaf, 0x02, 0x02, 0x05,
    0xff, 0xff, 0x01, 0xf5, 0x02, 0x06, 0x0a, 0xee, 0x00, 0xc4, 0xff, 0xff, 0xe9, 0x2f, 0xff, 0x6a,
    0x7f, 0x37, 0x2b, 0xe1, 0xce, 0xdf, 0x24, 0xb1, 0xb3, 0xa7, 0x46, 0xa7, 0x5c, 0xa4, 0x9d, 0x76,
    0x00,
];

/// A frame of two parameter blocks with the table that maps a selector to
/// one of them: the first record is coded against the first block and
/// the second against the second.
///
/// Written by the reference implementation on the box with
/// `fqzref2 /tmp/fqzref/work/e.in /tmp/fqzref/work/e.frame
/// /tmp/fqzref/work/e.dec 20,20 0,2 multi`, the mode 'multi' building the
/// global parameters by hand: two parameter blocks and the table that
/// maps the selectors to them. The reference decodes the frame back to
/// the same forty values.
#[cfg(all(test, feature = "cram"))]
pub(crate) const TWO_BLOCKS: &[u8] = &[
    0x28, 0x05, 0x03, 0x02, 0x04, 0x02, 0xfe, 0x00, 0x00, 0x08, 0xff, 0x42, 0x08, 0xce, 0x00, 0x10,
    0x08, 0xff, 0x42, 0x08, 0xce, 0x00, 0x03, 0xff, 0xff, 0xfc, 0x0d, 0x0d, 0x0c, 0xff, 0xc8, 0xf1,
    0x4b, 0x9a, 0x73, 0xfe, 0xdd, 0x04, 0x30, 0x24, 0x42, 0x50, 0x35, 0xd7, 0x48, 0x84,
];

/// A frame of two parameter blocks without the table: the selector is the
/// number of the block.
///
/// Written by the reference implementation on the box with
/// `fqzref2 /tmp/fqzref/work/f.in /tmp/fqzref/work/f.frame
/// /tmp/fqzref/work/f.dec 20,20 0,1 multi-nostab`, the mode 'multi-nostab'
/// building two parameter blocks and no table. The reference decodes the
/// frame back to the same forty values.
#[cfg(all(test, feature = "cram"))]
pub(crate) const TWO_BLOCKS_NO_TABLE: &[u8] = &[
    0x28, 0x05, 0x01, 0x02, 0x00, 0x00, 0x08, 0xff, 0x42, 0x08, 0xce, 0x00, 0x10, 0x08, 0xff, 0x42,
    0x08, 0xce, 0x00, 0x06, 0xaa, 0xaa, 0xa4, 0x15, 0xc0, 0x6a, 0xff, 0xa4, 0x3d, 0x02, 0x7b, 0x58,
    0x3b, 0xe6, 0xf6, 0x66, 0x50, 0x6c, 0xf4, 0x5e, 0x51, 0x83, 0x36,
];

/// A frame whose second record is a copy of the first: the frame says so
/// with the duplication flag, and the reader has to copy the qualities
/// instead of coding them again.
///
/// Written by the reference implementation on the box with
/// `fqzref2 /tmp/fqzref/work/g.in /tmp/fqzref/work/g.frame
/// /tmp/fqzref/work/g.dec 20,20 0,0 dedup`, the mode 'dedup' asking for
/// the duplication flag. The reference decodes the frame back to the same
/// forty values.
#[cfg(all(test, feature = "cram"))]
pub(crate) const DUPLICATED: &[u8] = &[
    0x28, 0x05, 0x00, 0x00, 0x00, 0x02, 0xff, 0x42, 0x08, 0xce, 0x00, 0x13, 0xff, 0xff, 0xec, 0x2c,
    0x2c, 0x2b, 0x4a, 0x2e, 0xf3, 0xc4, 0xd3, 0x5d, 0x34, 0xc8, 0x00,
];

/// A frame of a read longer than 255 quality values, so the number of
/// values needs more than one byte.
///
/// Written by the reference implementation on the box with
/// `fqzref2 /tmp/fqzref/work/h.in /tmp/fqzref/work/h.frame
/// /tmp/fqzref/work/h.dec 300 0 auto`, over a file of three hundred
/// quality values. The reference decodes the frame back to the same three
/// hundred values.
#[cfg(all(test, feature = "cram"))]
pub(crate) const LONG_READ: &[u8] = &[
    0x82, 0x2c, 0x05, 0x02, 0x03, 0xff, 0x01, 0x00, 0x00, 0x7e, 0x01, 0x22, 0x0d, 0xaf, 0x5a, 0x20,
    0x20, 0x01, 0xff, 0xff, 0x01, 0xa3, 0x02, 0x06, 0x0a, 0xee, 0x00, 0xcb, 0x00, 0x3f, 0xd0, 0xff,
    0x00, 0x00, 0x00, 0x00,
];

#[cfg(all(test, feature = "cram"))]
mod tests {
    use super::*;

    /// The frame of the codec specification's own example decodes back to the
    /// qualities it was written from.
    #[test]
    fn the_frame_of_the_specification_decodes() {
        assert_eq!(
            decode(SPECIFICATION).as_deref(),
            Some(&b"IIIIIIIIIIIIIIIIIIII"[..]),
            "the frame of the specification is not decoded"
        );
    }

    /// A frame of three reads of different lengths decodes back to the
    /// qualities it was written from: the frame carries the length of every
    /// record, and the reader has to start a new record on each of them.
    #[test]
    fn a_frame_of_reads_of_different_lengths_decodes() {
        let mut want =
            b"Hello, world! This is a quality string with some variety in it. ".repeat(2);
        want.truncate(95);
        assert_eq!(
            decode(READS).as_deref(),
            Some(&want[..]),
            "the frame of reads of different lengths is not decoded"
        );
    }

    /// A frame whose qualities hold many distinct values decodes back to the
    /// qualities it was written from: the block carries a map, so the model
    /// codes symbols and the map says which quality each of them stands for.
    #[test]
    fn a_frame_of_many_distinct_values_decodes() {
        let want: Vec<u8> = (0x21u8..=0x7e).chain(0x21u8..=0x7e).collect();
        assert_eq!(
            decode(MANY_VALUES).as_deref(),
            Some(&want[..]),
            "the frame of many distinct values is not decoded"
        );
    }

    /// A frame whose qualities are stored the other way round decodes back to
    /// the qualities it was written from.
    #[test]
    fn a_frame_of_reversed_qualities_decodes() {
        assert_eq!(
            decode(REVERSED).as_deref(),
            Some(&b"ABCDEFGHIJKLMNOPQRST"[..]),
            "the frame of reversed qualities is not decoded"
        );
    }

    /// A frame of two parameter blocks and the table that maps a selector to
    /// one of them decodes back to the qualities it was written from.
    #[test]
    fn a_frame_of_two_parameter_blocks_decodes() {
        let want = b"AAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBB";
        assert_eq!(
            decode(TWO_BLOCKS).as_deref(),
            Some(&want[..]),
            "the frame of two parameter blocks is not decoded"
        );
    }

    /// A frame of two parameter blocks without the table decodes back to the
    /// qualities it was written from: the selector is the number of the
    /// block.
    #[test]
    fn a_frame_of_two_parameter_blocks_without_a_table_decodes() {
        let want = b"AAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBB";
        assert_eq!(
            decode(TWO_BLOCKS_NO_TABLE).as_deref(),
            Some(&want[..]),
            "the frame of two parameter blocks without a table is not decoded"
        );
    }

    /// A frame whose second record is a copy of the first decodes back to
    /// the qualities it was written from.
    #[test]
    fn a_frame_of_a_duplicated_record_decodes() {
        let want = b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        assert_eq!(
            decode(DUPLICATED).as_deref(),
            Some(&want[..]),
            "the frame of a duplicated record is not decoded"
        );
    }

    /// A frame of a read longer than 255 quality values decodes back to the
    /// qualities it was written from: the number of values needs more than
    /// one byte, and the length of the record needs more than one too.
    #[test]
    fn a_frame_of_a_long_read_decodes() {
        let want = vec![b'Z'; 300];
        assert_eq!(
            decode(LONG_READ).as_deref(),
            Some(&want[..]),
            "the frame of a long read is not decoded"
        );
    }

    /// A frame this reader cannot decode is refused, not guessed at: a
    /// version it does not speak, a frame that ends early, a frame with no
    /// parameter block at all, and a block that asks for a selector the frame
    /// does not have.
    #[test]
    fn a_frame_that_is_not_one_this_reader_can_decode_is_refused() {
        // A version this reader does not speak.
        let mut frame = SPECIFICATION.to_vec();
        frame[1] = 0x04;
        assert!(decode(&frame).is_none(), "the version of 4 was not refused");

        // A frame that ends before the parameters it says it holds.
        assert!(
            decode(&SPECIFICATION[..10]).is_none(),
            "the frame that ends early was not refused"
        );

        // A frame that says it has no parameter block at all.
        let frame = [0x01, 0x05, 0x01, 0x00];
        assert!(
            decode(&frame).is_none(),
            "the frame without a parameter block was not refused"
        );

        // A block that asks for a selector the frame does not have: the
        // frame has one parameter block and no table.
        let frame = [0x01, 0x05, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00];
        assert!(
            decode(&frame).is_none(),
            "the block that asks for a selector was not refused"
        );
    }
}
