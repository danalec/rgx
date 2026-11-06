// SPDX-License-Identifier: Apache-2.0

//! The rANS Nx16 block codec of CRAM 3.1.
//!
//! The codec is the range-coder variant of Asymmetric Numeral Systems, in
//! the shape CRAM 3.1 gave it: the frame carries a flag byte, the
//! uncompressed length and, depending on the flags, the meta-data of the
//! run-length and bit-packing transforms. The entropy coder is a 16-bit
//! rANS with four or thirty-two interleaved states, in order 0 or order 1,
//! and a striped frame holds several frames of the same shape.
//!
//! The pseudocode this follows is the "CRAM codec specification" version
//! 3.1 of the hts-specs repository, sections 3 to 3.7. The frames the
//! tests carry were written by the reference implementation of that codec,
//! the htscodecs library, and not by this reader.
//!
//! What this reader refuses, by name:
//!
//! - The reserved flag bit, the second one: the specification reserves it
//!   for a future order and does not say what it would mean.
//! - A frame whose length is not stored and that no caller has given the
//!   length of.
//! - An order-1 table scaled to a number of bits other than ten or
//!   twelve: the specification permits those two only.
//! - A pack map of no symbols or of more than sixteen: the specification
//!   permits one to sixteen.
//! - A frequency table that does not fill the range of a state exactly:
//!   the state would carry a value the table does not cover.
//! - A state below the lower bound of the range, 0x8000.
//! - A striped frame with no stream, or with a stream of no bytes.
//! - A frame that ends before the bytes it says it holds.

use alloc::vec;
use alloc::vec::Vec;

/// The largest a decoded block may be.
///
/// The size comes from the frame itself, so a corrupt one could ask for a
/// gigabyte before it is refused. The ceiling is the same one the other
/// decompressors of this crate use.
const MAX_OUTPUT: usize = 32 << 20;

/// The range of a state in the order-0 codec: twelve bits wide.
const TOTAL_0: u32 = 4096;

/// The lower bound of a state.
///
/// The specification changes the lower bound of the CRAM 3.0 codec from
/// 0x100 to 0x8000, and the renormalisation reads two bytes at a time
/// instead of one.
const LOWER_BOUND: u32 = 0x8000;

/// The flag bits of the frame.
#[cfg(feature = "cram")]
const ORDER: u8 = 0x01;
#[cfg(feature = "cram")]
const RESERVED: u8 = 0x02;
#[cfg(feature = "cram")]
const N32: u8 = 0x04;
#[cfg(feature = "cram")]
const STRIPE: u8 = 0x08;
#[cfg(feature = "cram")]
const NOSIZE: u8 = 0x10;
#[cfg(feature = "cram")]
const CAT: u8 = 0x20;
#[cfg(feature = "cram")]
const RLE: u8 = 0x40;
#[cfg(feature = "cram")]
const PACK: u8 = 0x80;

/// A byte reader over a frame.
#[cfg(feature = "cram")]
struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

#[cfg(feature = "cram")]
impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    fn byte(&mut self) -> Option<u8> {
        let b = *self.data.get(self.at)?;
        self.at += 1;
        Some(b)
    }

    /// The next `n` bytes.
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let bytes = self.data.get(self.at..end)?;
        self.at = end;
        Some(bytes)
    }

    /// The bytes that are left.
    fn remaining(&self) -> usize {
        self.data.len() - self.at
    }

    fn u16le(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        Some(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32le(&mut self) -> Option<u32> {
        let bytes = self.take(4)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// The 7-bit integer: seven bits per byte, the most significant group
    /// first, the top bit set on every byte but the last.
    fn uint7(&mut self) -> Option<u32> {
        let mut rest = &self.data[self.at..];
        let value = read_uint7(&mut rest)?;
        self.at += self.data.len() - self.at - rest.len();
        Some(value)
    }
}

/// The 7-bit integer of a slice.
///
/// Seven bits per byte, the most significant group first, the top bit set
/// on every byte but the last. Five bytes carry thirty-five bits, and a
/// number this reader cannot hold is refused.
#[cfg(feature = "cram")]
fn read_uint7(bytes: &mut &[u8]) -> Option<u32> {
    let mut value: u64 = 0;
    for _ in 0..5 {
        let b = *bytes.first()?;
        *bytes = &bytes[1..];
        value = (value << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return u32::try_from(value).ok();
        }
    }
    None
}

/// One frequency table: the symbols it holds, their frequencies, and the
/// cumulative frequency each of them starts at.
#[cfg(feature = "cram")]
#[derive(Clone)]
struct Table {
    /// The symbol of each entry, in ascending order.
    symbol: Vec<u8>,
    /// The frequency of each entry.
    freq: Vec<u32>,
    /// The cumulative frequency before each entry.
    base: Vec<u32>,
    /// The total of the frequencies: the range of a state.
    total: u32,
}

#[cfg(feature = "cram")]
impl Table {
    /// The entry a cumulative frequency belongs to.
    ///
    /// `None` when the frequency is outside the range of the table, which
    /// happens when the state carries a value the table does not cover.
    fn find(&self, c: u32) -> Option<usize> {
        if c >= self.total {
            return None;
        }
        // The entries are sorted, so a binary search finds the one.
        let mut lo = 0usize;
        let mut hi = self.symbol.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.base[mid] <= c {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo.checked_sub(1)
    }
}

/// The symbols of an alphabet, in ascending order.
///
/// The list is run-length encoded: after the second of two consecutive
/// symbols a counter says how many more symbols follow without being
/// written.
#[cfg(feature = "cram")]
fn read_alphabet(reader: &mut Reader<'_>) -> Option<Vec<u8>> {
    let mut symbols = Vec::new();
    let mut symbol = reader.byte()?;
    let mut run: u32 = 0;
    loop {
        symbols.push(symbol);
        if run > 0 {
            run -= 1;
            symbol = symbol.checked_add(1)?;
        } else {
            let next = reader.byte()?;
            if symbol < 255 && next == symbol + 1 {
                // The run starts: the symbol just read is the first of it,
                // and the counter says how many follow it. The symbol 255
                // is never followed by a run: the counter would be the
                // end of the list.
                symbol = next;
                run = u32::from(reader.byte()?);
            } else {
                symbol = next;
            }
        }
        if symbol == 0 {
            break;
        }
    }
    Some(symbols)
}

/// Build a table from the frequencies of the symbols of an alphabet.
///
/// The frequencies are scaled up to the range of a state, and a table that
/// does not fill the range exactly is refused: the state would carry a
/// value the table does not cover.
#[cfg(feature = "cram")]
fn build_table(alphabet: &[u8], freq: &[u32], total: u32, range: u32) -> Option<Table> {
    if total == 0 || total > range {
        return None;
    }
    // The normalisation of the specification: the frequencies are doubled
    // until they add up to the range.
    let mut shift = 0u32;
    while (total << shift) < range {
        shift += 1;
    }
    let mut table = Table {
        symbol: Vec::with_capacity(alphabet.len()),
        freq: Vec::with_capacity(alphabet.len()),
        base: Vec::with_capacity(alphabet.len()),
        total: 0,
    };
    let mut x = 0u32;
    for (i, &symbol) in alphabet.iter().enumerate() {
        let f = freq[i] << shift;
        if f == 0 {
            continue;
        }
        if f > range - x {
            return None;
        }
        table.symbol.push(symbol);
        table.freq.push(f);
        table.base.push(x);
        x += f;
    }
    if x != range {
        return None;
    }
    table.total = x;
    Some(table)
}

/// The order-0 frequency table.
///
/// The table is the list of the symbols of the alphabet and their
/// frequencies, and the frequencies are scaled up to the range of a
/// state.
#[cfg(feature = "cram")]
fn read_table0(reader: &mut Reader<'_>) -> Option<Table> {
    let alphabet = read_alphabet(reader)?;
    let mut freq = Vec::with_capacity(alphabet.len());
    let mut total: u32 = 0;
    for _ in &alphabet {
        let f = reader.uint7()?;
        freq.push(f);
        total += f;
    }
    build_table(&alphabet, &freq, total, TOTAL_0)
}

/// The states of the entropy coder: one 32-bit word each, little-endian.
///
/// A state below the lower bound of the range is refused: the reference
/// implementation refuses one too.
#[cfg(feature = "cram")]
fn read_states(reader: &mut Reader<'_>, n: usize) -> Option<Vec<u32>> {
    let mut states = Vec::with_capacity(n);
    for _ in 0..n {
        let state = reader.u32le()?;
        if state < LOWER_BOUND {
            return None;
        }
        states.push(state);
    }
    Some(states)
}

/// The next state, from the symbol and the state.
#[cfg(feature = "cram")]
fn advance(state: u32, freq: u32, base: u32, bits: u32) -> u32 {
    freq * (state >> bits) + (state & ((1 << bits) - 1)) - base
}

/// Renormalise the state, reading two bytes when it is short of the range.
///
/// The 16-bit renormalisation of the specification reads the bytes in one
/// step, where the 8-bit one of CRAM 3.0 read them in a loop.
#[cfg(feature = "cram")]
fn renorm(reader: &mut Reader<'_>, mut state: u32) -> Option<u32> {
    if state < LOWER_BOUND {
        state = (state << 16) | u32::from(reader.u16le()?);
    }
    Some(state)
}

/// Decode an order-0 entropy coded stream.
///
/// The states are interleaved: the byte at the index `i` is decoded by the
/// state `i mod n`.
#[cfg(feature = "cram")]
fn decode_order0(reader: &mut Reader<'_>, n: usize, len: usize) -> Option<Vec<u8>> {
    let table = read_table0(reader)?;
    let mut states = read_states(reader, n)?;
    let mut out = vec![0u8; len];
    for (i, byte) in out.iter_mut().enumerate() {
        let j = i % n;
        let c = states[j] & (TOTAL_0 - 1);
        let entry = table.find(c)?;
        *byte = table.symbol[entry];
        states[j] = advance(states[j], table.freq[entry], table.base[entry], 12);
        states[j] = renorm(reader, states[j])?;
    }
    Some(out)
}

/// The order-1 frequency tables: one per context byte.
#[cfg(feature = "cram")]
struct Tables1 {
    /// The number of bits the frequencies of a context are scaled to.
    bits: u32,
    /// The table of each context, at the slot of the context's byte value.
    tables: Vec<Option<Table>>,
}

/// Read the order-1 frequency tables.
///
/// The first byte of the tables says how many bits the frequencies are
/// scaled to, in its top nibble, and whether the tables are compressed, in
/// its bottom bit. Compressed tables are an order-0 stream of their own,
/// with four states whatever the frame asks for.
#[cfg(feature = "cram")]
fn read_tables1(reader: &mut Reader<'_>) -> Option<Tables1> {
    let header = reader.byte()?;
    let bits = u32::from(header >> 4);
    if bits != 10 && bits != 12 {
        // The specification permits ten and twelve bits only.
        return None;
    }
    if header & 1 != 0 {
        let plain_len = reader.uint7()? as usize;
        let packed_len = reader.uint7()? as usize;
        if plain_len > MAX_OUTPUT {
            return None;
        }
        let packed = reader.take(packed_len)?;
        let plain = decode_order0(&mut Reader::new(packed), 4, plain_len)?;
        let mut inner = Reader::new(&plain);
        Some(Tables1 {
            bits,
            tables: read_tables1_body(&mut inner, bits)?,
        })
    } else {
        Some(Tables1 {
            bits,
            tables: read_tables1_body(reader, bits)?,
        })
    }
}

/// Read the order-1 tables from the source of the frequencies.
///
/// The alphabet is the list of the symbols used in any context, and each
/// context of that list carries a frequency for each of them. A frequency
/// of zero is followed by a counter that says how many more zeros follow
/// without being written.
#[cfg(feature = "cram")]
fn read_tables1_body(reader: &mut Reader<'_>, bits: u32) -> Option<Vec<Option<Table>>> {
    let alphabet = read_alphabet(reader)?;
    let range = 1u32 << bits;
    let mut tables: Vec<Option<Table>> = vec![None; 256];
    for &context in &alphabet {
        let mut freq = Vec::with_capacity(alphabet.len());
        let mut total: u32 = 0;
        let mut run: u32 = 0;
        for _ in &alphabet {
            if run > 0 {
                run -= 1;
                freq.push(0);
                continue;
            }
            let f = reader.uint7()?;
            if f == 0 {
                run = u32::from(reader.byte()?);
            }
            freq.push(f);
            total += f;
        }
        if total == 0 {
            // The context has no table: the reference implementation
            // answers for it with no symbol at all.
            continue;
        }
        tables[usize::from(context)] = Some(build_table(&alphabet, &freq, total, range)?);
    }
    Some(tables)
}

/// Decode an order-1 entropy coded stream.
///
/// The states work on distinct regions of the data: the state `j` decodes
/// the bytes from `j * len / n` onwards, and the last state finishes the
/// data when it is not a multiple of `n`.
#[cfg(feature = "cram")]
fn decode_order1(reader: &mut Reader<'_>, n: usize, len: usize) -> Option<Vec<u8>> {
    let tables = read_tables1(reader)?;
    let mut states = read_states(reader, n)?;
    let mut last = vec![0u8; n];
    let mut out = vec![0u8; len];
    let region = len / n;
    let mut i = 0usize;
    while i < region {
        for j in 0..n {
            let context = usize::from(last[j]);
            let table = tables.tables[context].as_ref()?;
            let c = states[j] & ((1 << tables.bits) - 1);
            let entry = table.find(c)?;
            let symbol = table.symbol[entry];
            out[i + j * region] = symbol;
            states[j] = advance(states[j], table.freq[entry], table.base[entry], tables.bits);
            states[j] = renorm(reader, states[j])?;
            last[j] = symbol;
        }
        i += 1;
    }
    // The data that is not a multiple of the number of states: the last
    // state finishes it, as the specification says it does.
    let mut k = region * n;
    while k < len {
        let j = n - 1;
        let context = usize::from(last[j]);
        let table = tables.tables[context].as_ref()?;
        let c = states[j] & ((1 << tables.bits) - 1);
        let entry = table.find(c)?;
        let symbol = table.symbol[entry];
        out[k] = symbol;
        states[j] = advance(states[j], table.freq[entry], table.base[entry], tables.bits);
        states[j] = renorm(reader, states[j])?;
        last[j] = symbol;
        k += 1;
    }
    Some(out)
}

/// The meta-data of the run-length transform.
#[cfg(feature = "cram")]
struct RleMeta {
    /// The length of the data before the runs are expanded.
    len: usize,
    /// The symbols that have a run length.
    symbols: [bool; 256],
    /// The run lengths, as the specification's 7-bit integers.
    runs: Vec<u8>,
}

/// Read the meta-data of the run-length transform.
///
/// The first number is the size of the meta-data times two, and its bottom
/// bit says whether the meta-data is stored as it is or compressed. The
/// second number is the length of the data before the runs are expanded.
/// The meta-data itself starts with the count of the symbols that have a
/// run length, followed by those symbols, followed by the run lengths.
#[cfg(feature = "cram")]
fn read_rle_meta(reader: &mut Reader<'_>, n: usize) -> Option<RleMeta> {
    let meta_len = reader.uint7()? as usize;
    let len = reader.uint7()? as usize;
    let meta = if meta_len & 1 != 0 {
        // The meta-data is stored as it is.
        reader.take(meta_len / 2)?.to_vec()
    } else {
        // The meta-data is an order-0 stream of its own, with the same
        // number of states as the frame.
        let packed_len = reader.uint7()? as usize;
        let packed = reader.take(packed_len)?;
        decode_order0(&mut Reader::new(packed), n, meta_len / 2)?
    };
    let count = usize::from(*meta.first()?);
    // A count of zero means that every symbol has a run length.
    let count = if count == 0 { 256 } else { count };
    if meta.len() < 1 + count {
        return None;
    }
    let mut symbols = [false; 256];
    for &symbol in &meta[1..1 + count] {
        symbols[usize::from(symbol)] = true;
    }
    Some(RleMeta {
        len,
        symbols,
        runs: meta[1 + count..].to_vec(),
    })
}

/// Expand the runs of the data.
///
/// The literals that have a run length are followed by the length of the
/// run: the number of times the literal is repeated after itself.
#[cfg(feature = "cram")]
fn expand_runs(data: &[u8], meta: &RleMeta, limit: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut runs = meta.runs.as_slice();
    for &literal in data {
        if meta.symbols[usize::from(literal)] {
            let run = read_uint7(&mut runs)? as usize;
            if out.len() + run + 1 > limit {
                return None;
            }
            out.resize(out.len() + run + 1, literal);
        } else {
            if out.len() + 1 > limit {
                return None;
            }
            out.push(literal);
        }
    }
    Some(out)
}

/// The meta-data of the bit-packing transform.
#[cfg(feature = "cram")]
struct PackMeta {
    /// The number of distinct symbols.
    count: u8,
    /// The map from the packed value to the symbol.
    map: [u8; 16],
    /// The length of the packed data.
    len: usize,
}

/// Read the meta-data of the bit-packing transform.
///
/// The meta-data starts with the number of distinct symbols, followed by
/// the map from the packed value to the symbol, followed by the length of
/// the packed data.
#[cfg(feature = "cram")]
fn read_pack_meta(reader: &mut Reader<'_>) -> Option<PackMeta> {
    let count = reader.byte()?;
    if !(1..=16).contains(&count) {
        // The specification permits one to sixteen symbols: with more they
        // do not fit in a byte, and with none there is nothing to pack.
        return None;
    }
    let mut map = [0u8; 16];
    for slot in map.iter_mut().take(usize::from(count)) {
        *slot = reader.byte()?;
    }
    let len = reader.uint7()? as usize;
    Some(PackMeta { count, map, len })
}

/// Unpack the data.
///
/// The symbols are packed from the lowest bits up: with two symbols each
/// takes one bit, with four each takes two and with sixteen each takes
/// four.
#[cfg(feature = "cram")]
fn unpack(data: &[u8], meta: &PackMeta, len: usize) -> Option<Vec<u8>> {
    if meta.count == 1 {
        // Every symbol is the same: the data carries no symbol at all.
        return Some(vec![meta.map[0]; len]);
    }
    let bits = if meta.count <= 2 {
        1
    } else if meta.count <= 4 {
        2
    } else {
        4
    };
    let per_byte = 8 / bits;
    if len.div_ceil(per_byte) > data.len() {
        return None;
    }
    let mask = (1u8 << bits) - 1;
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        let byte = data[i / per_byte];
        let value = (byte >> ((i % per_byte) * bits)) & mask;
        out.push(meta.map[usize::from(value)]);
    }
    Some(out)
}

/// The length of the uncompressed data.
#[cfg(feature = "cram")]
fn read_len(reader: &mut Reader<'_>) -> Option<usize> {
    let len = reader.uint7()? as usize;
    if len > MAX_OUTPUT {
        return None;
    }
    Some(len)
}

/// Decode a striped frame: `n` interleaved streams, each a frame of its
/// own.
///
/// The streams are the columns of the transposed data: the byte at the
/// index `i` of the stream `j` is the byte at the index `i * n + j` of the
/// whole.
#[cfg(feature = "cram")]
fn decode_stripe(reader: &mut Reader<'_>, len: usize, depth: usize) -> Option<Vec<u8>> {
    // A sub-stream of a stripe may itself claim the stripe flag, and each
    // nesting level costs four bytes of the block: unbounded, a small
    // crafted block nests until the stack goes. Stripes do not
    // legitimately nest at all, so the depth bound is generous.
    if depth > 8 {
        return None;
    }
    let n = usize::from(reader.byte()?);
    if n < 1 {
        // There is at least one stream.
        return None;
    }
    let mut lengths = Vec::with_capacity(n);
    let mut total = 0usize;
    for _ in 0..n {
        let length = reader.uint7()? as usize;
        if length == 0 {
            return None;
        }
        total = total.checked_add(length)?;
        lengths.push(length);
    }
    if total > reader.remaining() {
        return None;
    }
    let mut streams = Vec::with_capacity(n);
    for (j, &length) in lengths.iter().enumerate() {
        let bytes = reader.take(length)?;
        // The length of a stream is not stored in it: the length of the
        // whole says how long each one is.
        let ulen = len / n + usize::from((len % n) > j);
        streams.push(decode_frame(
            &mut Reader::new(bytes),
            Some(ulen),
            depth + 1,
        )?);
    }
    let mut out = vec![0u8; len];
    for (j, stream) in streams.iter().enumerate() {
        for (i, &byte) in stream.iter().enumerate() {
            out[i * n + j] = byte;
        }
    }
    Some(out)
}

/// Decode a frame.
///
/// The `expected` length is the length of the data when the frame does not
/// carry it, which is the case of the streams of a striped frame.
#[cfg(feature = "cram")]
fn decode_frame(reader: &mut Reader<'_>, expected: Option<usize>, depth: usize) -> Option<Vec<u8>> {
    let flags = reader.byte()?;
    if flags & RESERVED != 0 {
        // The specification reserves the bit for a future order and does
        // not say what it would mean.
        return None;
    }
    let len = if flags & STRIPE != 0 {
        // A striped frame always carries the length of the whole stream.
        read_len(reader)?
    } else if flags & NOSIZE != 0 {
        // The frame does not carry the length: only the caller knows it.
        expected?
    } else {
        read_len(reader)?
    };
    if let Some(want) = expected {
        if want != len {
            return None;
        }
    }
    if flags & STRIPE != 0 {
        return decode_stripe(reader, len, depth);
    }

    let n = if flags & N32 != 0 { 32 } else { 4 };
    // The meta-data of the transforms: the pack map first, then the run
    // lengths, as the specification lists them.
    let pack = if flags & PACK != 0 {
        Some(read_pack_meta(reader)?)
    } else {
        None
    };
    let rle = if flags & RLE != 0 {
        Some(read_rle_meta(reader, n)?)
    } else {
        None
    };
    // The data the entropy decoder produces is not longer than the data it
    // comes from.
    let source_len = match &pack {
        Some(meta) => meta.len,
        None => len,
    };
    if source_len > len {
        return None;
    }
    if let Some(meta) = &rle {
        if meta.len > source_len {
            return None;
        }
    }
    let data_len = match &rle {
        Some(meta) => meta.len,
        None => source_len,
    };
    let data = if flags & CAT != 0 {
        // The data is stored as it is.
        reader.take(data_len)?.to_vec()
    } else if flags & ORDER != 0 {
        decode_order1(reader, n, data_len)?
    } else {
        decode_order0(reader, n, data_len)?
    };
    // The transforms are applied in the order the specification gives: the
    // runs first, then the unpack.
    let expanded = match &rle {
        Some(meta) => expand_runs(&data, meta, len)?,
        None => data,
    };
    match &pack {
        Some(meta) => unpack(&expanded, meta, len),
        None => Some(expanded),
    }
}

/// Decode a rANS Nx16 block.
///
/// The block's bytes are the codec's own frame: the flag byte, the
/// uncompressed length, the meta-data of the transforms the flags ask for
/// and the entropy coded bytes.
///
/// `None` when the frame is not one this reader can decode: a flag the
/// specification does not define, a size that does not match the frame, a
/// table whose frequencies do not fill the range of a state, a frame that
/// ends before the bytes it says it holds, or a transform this reader
/// refuses.
#[cfg(feature = "cram")]
pub(crate) fn decode(block: &[u8]) -> Option<Vec<u8>> {
    let mut reader = Reader::new(block);
    decode_frame(&mut reader, None, 0)
}
/// The frame of "abracadabra" four times and a "d", with order 0, written
/// by the reference implementation of the codec.
///
/// The frame is the flag byte, the length, the symbol list, the
/// frequencies, the four states and the encoded bytes. The symbol list is
/// the one of the specification's own example: the symbols 'a', 'b', 'c',
/// 'd' and 'r', and the run-length counter after 'b' says that 'c' and
/// 'd' follow without being written.
#[cfg(all(test, feature = "cram"))]
pub(crate) const ORDER0: &[u8] = &[
    0x00, 0x2d, 0x61, 0x62, 0x02, 0x72, 0x00, 0x1e, 0x0b, 0x05, 0x07, 0x0b, 0xe9, 0xd1, 0x9d, 0x01,
    0x92, 0x79, 0x31, 0x00, 0x56, 0x4f, 0x2c, 0x00, 0x48, 0x35, 0x2d, 0x00, 0x00, 0xf6, 0x00, 0xd5,
    0x00, 0x5d, 0xc0, 0xe9,
];

/// The frame of a run of DNA with order 1, written by the reference
/// implementation of the codec.
///
/// The order-1 frame carries a table per context: the context is the byte
/// before the one being decoded.
#[cfg(all(test, feature = "cram"))]
pub(crate) const ORDER1: &[u8] = &[
    0x01, 0x66, 0xa0, 0x00, 0x41, 0x43, 0x47, 0x4e, 0x54, 0x00, 0x00, 0x00, 0x02, 0x01, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x01, 0x1e, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x1d, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x02, 0x01, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x1c, 0x00, 0x00, 0x01, 0x01, 0x02, 0x40, 0xfc, 0x1b, 0x00, 0x60, 0xd3, 0x5f, 0x0c, 0x80,
    0xb0, 0x0a, 0x00, 0xe0, 0x0a, 0x1a, 0x00, 0x80, 0x03, 0xef, 0x0b, 0x20, 0xfc,
];

/// The frame of a run of every byte value with order 1, written by the
/// reference implementation of the codec.
///
/// Every byte is the successor of the byte before it, so the frame has a
/// table of 256 contexts of one symbol each. The table is over a thousand
/// bytes and the reference implementation compresses it with the order-0
/// codec of its own.
#[cfg(all(test, feature = "cram"))]
pub(crate) const ORDER1_TABLE: &[u8] = &[
    0x01, 0xa8, 0x00, 0xa1, 0x89, 0x7f, 0x87, 0x7f, 0x00, 0x01, 0xfd, 0x00, 0x86, 0x6a, 0x04, 0x03,
    0x03, 0x03, 0x04, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x04, 0x03, 0x03, 0x03, 0x03, 0x83, 0x1b, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x04, 0x21, 0x16, 0x08,
    0x6d, 0xd4, 0xf6, 0x2e, 0x06, 0xfb, 0x1f, 0xca, 0x1a, 0x87, 0xf5, 0xd0, 0x07, 0xd9, 0xe6, 0x42,
    0x24, 0xe9, 0x3f, 0xb0, 0xc4, 0xe3, 0x76, 0xe9, 0x41, 0xba, 0xb5, 0x18, 0x60, 0x13, 0x01, 0xfc,
    0x13, 0xcd, 0xcf, 0x4a, 0x31, 0x06, 0x27, 0x5d, 0xe0, 0xfd, 0x90, 0x14, 0xb7, 0xd8, 0x91, 0x1b,
    0xa4, 0x94, 0x40, 0xf2, 0x74, 0x59, 0xa2, 0x38, 0x10, 0x9a, 0x2f, 0xd2, 0xd3, 0xf3, 0xb4, 0xf6,
    0x50, 0x3d, 0xd5, 0x45, 0x17, 0xd6, 0x64, 0xe0, 0x92, 0xdd, 0xe4, 0x40, 0x66, 0x83, 0xc2, 0xe8,
    0x35, 0xe0, 0x08, 0x26, 0x92, 0xfd, 0x54, 0x70, 0x02, 0x31, 0x54, 0x42, 0x05, 0x57, 0x61, 0x14,
    0xa5, 0xd6, 0x23, 0x44, 0x3f, 0xd1, 0xc3, 0x8c, 0x20, 0x09, 0x1a, 0xa4, 0x90, 0x09, 0x26, 0x31,
    0xc2, 0x23, 0xf5, 0xc6, 0x11, 0x65, 0xc2, 0xe0, 0x09, 0x71, 0x20, 0x36, 0xe1, 0xca, 0x64, 0x0e,
    0x31, 0x05, 0x6f, 0xfa, 0xca, 0xff, 0x5e, 0x2d, 0xa1, 0x4f, 0xe4, 0xe6, 0xd4, 0xa9, 0x03, 0xd7,
    0x17, 0xa6, 0xc4, 0xd5, 0x70, 0xb4, 0x54, 0x71, 0xf5, 0xd2, 0xce, 0x2e, 0xbb, 0x19, 0x33, 0x69,
    0xb5, 0x7d, 0xe6, 0xeb, 0x41, 0x04, 0x91, 0x92, 0xb2, 0xa5, 0x72, 0x48, 0xfb, 0xf6, 0x25, 0x9d,
    0xe4, 0x5f, 0xbb, 0x68, 0x00, 0xd5, 0x53, 0x86, 0x70, 0xcd, 0x10, 0xc8, 0xd6, 0x04, 0xd1, 0x18,
    0x60, 0xca, 0x64, 0x7c, 0xeb, 0x99, 0x67, 0xcb, 0xe6, 0x6a, 0x91, 0x1a, 0x70, 0x8c, 0x44, 0x56,
    0x72, 0x9b, 0x03, 0x90, 0x73, 0xb4, 0x56, 0x9a, 0x94, 0xad, 0xeb, 0x3e, 0xc9, 0x09, 0x69, 0x1d,
    0x11, 0xd4, 0x31, 0x1b, 0x83, 0x3e, 0x53, 0xd0, 0x50, 0x4e, 0x43, 0xde, 0x74, 0xae, 0x64, 0x6b,
    0xca, 0x21, 0xae, 0xa0, 0x66, 0xe5, 0xab, 0x09, 0xe1, 0x37, 0xf6, 0x25, 0x53, 0x2d, 0xc2, 0xa0,
    0x80, 0x84, 0x41, 0xa1, 0xb4, 0xb6, 0x01, 0xcd, 0x82, 0x0e, 0xec, 0x67, 0xe3, 0x19, 0x5c, 0x9d,
    0x43, 0x63, 0xe5, 0xa6, 0xc6, 0x02, 0x83, 0x89, 0xf4, 0xd3, 0x7d, 0x92, 0x66, 0x5b, 0xf4, 0xfd,
    0x04, 0x42, 0xdc, 0x48, 0x91, 0x49, 0x6c, 0x68, 0xc0, 0xbd, 0xf0, 0x5e, 0xa6, 0x88, 0xa0, 0xfe,
    0x64, 0x8e, 0x71, 0xb5, 0xe3, 0x4d, 0xa2, 0xab, 0x81, 0x73, 0xdc, 0xde, 0x30, 0x6d, 0x73, 0x94,
    0x22, 0xb8, 0xc6, 0xb5, 0xd0, 0x7f, 0xf1, 0x46, 0x22, 0x19, 0x8a, 0x96, 0x91, 0x05, 0x55, 0x62,
    0x61, 0xb1, 0xd4, 0xdb, 0x65, 0xe2, 0xe3, 0x4a, 0xd0, 0xa4, 0x96, 0x63, 0x20, 0xc5, 0xc1, 0x16,
    0x52, 0x2c, 0x31, 0xc2, 0xfc, 0x37, 0x9d, 0xe5, 0xa4, 0x0c, 0x35, 0x07, 0x82, 0x0d, 0x44, 0xe7,
    0x87, 0x65, 0x44, 0xf4, 0x54, 0xaf, 0x12, 0xff, 0xd4, 0x0c, 0x8d, 0xf3, 0x6c, 0x05, 0x6d, 0x15,
    0x20, 0x9d, 0xc1, 0xab, 0x71, 0x69, 0xd2, 0x9a, 0xb4, 0x60, 0xa4, 0x10, 0x2d, 0xe6, 0x12, 0x5a,
    0x35, 0x27, 0x3d, 0x7a, 0xe4, 0x7d, 0x74, 0xa5, 0x54, 0x99, 0x36, 0x2d, 0xe5, 0x5c, 0x51, 0xc8,
    0x70, 0x28, 0x40, 0x41, 0x9d, 0x42, 0x70, 0xeb, 0xc1, 0xa3, 0x04, 0xd0, 0x40, 0xef, 0x72, 0x11,
    0xa4, 0x5b, 0x05, 0x37, 0xb4, 0x00, 0x42, 0x03, 0xc3, 0xd4, 0x92, 0x75, 0x6d, 0xb1, 0x3a, 0xe5,
    0xf4, 0xf3, 0x73, 0xf9, 0x60, 0x7f, 0x24, 0xad, 0x00, 0xe4, 0xb4, 0x5b, 0x70, 0x1d, 0x02, 0x61,
    0x79, 0x58, 0x5c, 0x6d, 0x51, 0x69, 0x78, 0x04, 0xa4, 0xc5, 0xd5, 0xa7, 0xe5, 0xb8, 0x55, 0x74,
    0xa6, 0x2b, 0xa4, 0x21, 0x16, 0x38, 0x66, 0x29, 0x3c, 0xb7, 0xf2, 0xd6, 0x1d, 0xe1, 0xad, 0xc7,
    0x20, 0x1f, 0xf4, 0xd1, 0x02, 0x80, 0x81, 0x82, 0xa5, 0x40, 0x03, 0x9b, 0x20, 0x8c, 0x96, 0x7c,
    0x65, 0x07, 0x9e, 0xa9, 0x13, 0x0d, 0x6e, 0x47, 0x72, 0x43, 0x13, 0xd8, 0xa0, 0x4c, 0x30, 0xc7,
    0xf2, 0xd9, 0x0b, 0x7e, 0xe2, 0xac, 0x82, 0x10, 0xc3, 0x37, 0xfe, 0xf5, 0x00, 0x41, 0x4e, 0x5c,
    0x60, 0x3d, 0x46, 0xae, 0xd2, 0x73, 0x75, 0xea, 0x35, 0x47, 0x2a, 0x5d, 0x55, 0x9c, 0xd5, 0x56,
    0x31, 0xcc, 0xd4, 0x48, 0xd2, 0x4a, 0x96, 0x12, 0x94, 0x28, 0x32, 0x8a, 0x60, 0xfb, 0x52, 0x06,
    0xc6, 0x33, 0x2a, 0x1a, 0x76, 0xba, 0x94, 0xf4, 0xc1, 0x96, 0x56, 0x94, 0xa4, 0x8c, 0x70, 0x6f,
    0xb8, 0x62, 0xb3, 0x58, 0x65, 0x3a, 0xd4, 0xd1, 0x66, 0x46, 0x3b, 0xbf, 0x5e, 0x3d, 0xeb, 0xd1,
    0x50, 0x5e, 0x82, 0x93, 0xe4, 0x46, 0x84, 0xcc, 0x09, 0x42, 0xa5, 0xac, 0x95, 0x6d, 0x96, 0x89,
    0x33, 0x14, 0x1b, 0xeb, 0x1e, 0x0d, 0xfb, 0x51, 0xc1, 0x2a, 0x31, 0x57, 0x21, 0x14, 0x82, 0x56,
    0x76, 0x4e, 0x56, 0x08, 0x1f, 0xc6, 0x35, 0xdb, 0xa5, 0x1a, 0x0f, 0xdc, 0x33, 0xbc, 0xe6, 0xa9,
    0xf3, 0x53, 0x34, 0xd4, 0x62, 0x15, 0x40, 0x12, 0x41, 0xd6, 0x61, 0x3b, 0xdf, 0xb0, 0x24, 0x40,
    0x06, 0x2b, 0x63, 0xf4, 0x02, 0x46, 0x54, 0x2c, 0xd2, 0x18, 0xb4, 0x35, 0x63, 0x68, 0xef, 0x91,
    0xba, 0x07, 0xb1, 0x5f, 0x17, 0x3a, 0x00, 0x47, 0xa5, 0x01, 0xf5, 0x14, 0x90, 0xa5, 0xb1, 0x73,
    0x59, 0x26, 0x91, 0x79, 0x02, 0x62, 0x88, 0x28, 0xe1, 0x2c, 0x47, 0xa1, 0xa5, 0x53, 0x70, 0x59,
    0xd1, 0xaf, 0x15, 0x44, 0x44, 0xb1, 0x86, 0x09, 0xf9, 0xda, 0x53, 0x57, 0x95, 0xf7, 0xd2, 0x99,
    0x81, 0xd0, 0xbf, 0xbb, 0xc1, 0x91, 0xd4, 0x64, 0xa1, 0x73, 0xe4, 0xaf, 0x91, 0xae, 0x13, 0xe0,
    0xa6, 0x4a, 0x70, 0xee, 0xcf, 0xf8, 0x0f, 0x80, 0x84, 0x07, 0x00, 0x80, 0x84, 0x07, 0x00, 0x80,
    0x84, 0x07, 0x00, 0x80, 0x84, 0x07, 0x00,
];

/// The frame of many short runs, with the run-length transform and order 0,
/// written by the reference implementation of the codec.
///
/// The run lengths are held apart from the literals, and the meta-data of
/// the runs is compressed with the order-0 codec of its own.
#[cfg(all(test, feature = "cram"))]
pub(crate) const RLE_FRAME: &[u8] = &[
    0x40, 0x9f, 0x20, 0x8c, 0x48, 0x86, 0x20, 0x1d, 0x03, 0x04, 0x00, 0x41, 0x42, 0x01, 0x00, 0x01,
    0x87, 0x7c, 0x01, 0x01, 0x01, 0x00, 0xc0, 0x4d, 0x04, 0xf4, 0xcf, 0x4d, 0x04, 0xf8, 0xcf, 0x4d,
    0x04, 0xfc, 0xcf, 0x4d, 0x04, 0x41, 0x42, 0x01, 0x00, 0x82, 0x57, 0x82, 0x55, 0x82, 0x54, 0xb4,
    0x04, 0x22, 0x11, 0xfb, 0x07, 0x08, 0x12, 0xc4, 0xaa, 0xbc, 0x10, 0xb4, 0x04, 0x22, 0x11, 0xab,
    0xc4, 0x95, 0xb9, 0xdd, 0x6b, 0xab, 0xc4, 0x95, 0xb9, 0x96, 0x3e, 0xe7, 0x04, 0x95, 0xb9, 0x96,
    0x3e, 0x99, 0x84, 0x04, 0x99, 0x96, 0x3e, 0x99, 0x84, 0xce, 0x96, 0x60, 0xeb, 0x99, 0x84, 0xce,
    0x96, 0xc8, 0xbc, 0x45, 0xc0, 0xce, 0x96, 0xc8, 0xbc, 0x13, 0xe5, 0x15, 0x47, 0xc8, 0xbc, 0x13,
    0xe5, 0x54, 0xaa, 0x28, 0xbc, 0x13, 0xe5, 0x54, 0xaa, 0xde, 0xfb, 0x37, 0xd3, 0x54, 0xaa, 0xde,
    0xfb, 0x25, 0x37, 0xde, 0xfb, 0x51, 0x48, 0x51, 0x48, 0x44, 0xad, 0x1e, 0x85, 0x51, 0x48, 0x44,
    0xad, 0xab, 0xc4, 0xac, 0x95, 0x44, 0xad, 0xab, 0xc4, 0x95, 0xb9, 0xdd, 0x6b, 0xab, 0xc4, 0xf4,
    0xb9, 0x96, 0x3e, 0xe7, 0x04, 0xf4, 0xb9, 0xc3, 0x2b, 0x99, 0x84, 0x04, 0x99, 0xc3, 0x2b, 0xb6,
    0xa2, 0xce, 0x96, 0x60, 0xeb, 0xb6, 0xa2, 0x52, 0xf8, 0xc8, 0xbc, 0x45, 0xc0, 0x52, 0xf8, 0x80,
    0xfe, 0x13, 0xe5, 0x16, 0x47, 0x80, 0xfe, 0x6b, 0xd2, 0x2a, 0xaa, 0x6e, 0x1d, 0x6b, 0xd2, 0xa8,
    0x38, 0x08, 0xfb, 0x1c, 0xb0, 0xa8, 0x38,
];

/// The frame of many short runs and a run of DNA, with the run-length
/// transform and order 1, written by the reference implementation of the
/// codec.
#[cfg(all(test, feature = "cram"))]
pub(crate) const RLE_ORDER1_FRAME: &[u8] = &[
    0x41, 0x82, 0x65, 0x17, 0x68, 0x05, 0x00, 0x01, 0x02, 0x4e, 0x5a, 0x77, 0x3b, 0x2c, 0x1d, 0x02,
    0xa0, 0x00, 0x01, 0x01, 0x41, 0x43, 0x47, 0x4e, 0x54, 0x5a, 0x00, 0x04, 0x01, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x05, 0x00, 0x07, 0x01,
    0x00, 0x02, 0x01, 0x1e, 0x01, 0x00, 0x02, 0x00, 0x02, 0x01, 0x01, 0x1d, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x04, 0x00,
    0x02, 0x1c, 0x00, 0x00, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x04, 0x61, 0x6c,
    0x0b, 0x00, 0xa0, 0x53, 0xb2, 0x04, 0xc0, 0xe2, 0x2d, 0x00, 0x20, 0x37, 0x2f, 0x00, 0x41, 0x30,
    0x07, 0x7c, 0x20, 0xc0,
];

/// The frame of sixteen byte values, with the bit-packing transform,
/// written by the reference implementation of the codec.
///
/// The symbols were packed two to a byte before the entropy coder, and
/// the map from the packed value to the symbol is the first thing after
/// the length.
#[cfg(all(test, feature = "cram"))]
pub(crate) const PACK_FRAME: &[u8] = &[
    0x80, 0x83, 0x00, 0x10, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x81, 0x40, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x00, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x82, 0x80, 0x00, 0x00, 0xa6, 0x82, 0x00, 0x00, 0xcb,
    0x84, 0x00, 0x00, 0xef, 0x86, 0x00, 0x00, 0x10, 0x08, 0x34, 0x9a, 0x59, 0x2d, 0x7d, 0xbf, 0x82,
    0x40, 0xa6, 0xd3, 0xcb, 0x64, 0xef, 0xf7, 0x82, 0x08, 0xa6, 0x9a, 0xcb, 0x2c, 0xef, 0xbe, 0x10,
    0x08, 0x34, 0x9a, 0x59, 0x2d, 0x7d, 0xbf, 0x82, 0x40, 0xa6, 0xd3, 0xcb, 0x64, 0xef, 0xf7, 0x82,
    0x08, 0xa6, 0x9a, 0xcb, 0x2c, 0xef, 0xbe, 0x10, 0x08, 0x34, 0x9a, 0x59, 0x2c, 0x7d, 0xbe, 0x82,
    0x40, 0xa6, 0xd2, 0xcb, 0x64, 0xef, 0xf6, 0x00, 0x08, 0x00, 0x9a, 0x00, 0x2c, 0x00, 0xbe,
];

/// The frame of a run of DNA, striped into four streams, written by the
/// reference implementation of the codec.
///
/// The frame carries the length of the whole, the number of streams, the
/// length of each of them and then the streams, each a frame of its own.
#[cfg(all(test, feature = "cram"))]
pub(crate) const STRIPE_FRAME: &[u8] = &[
    0x08, 0x66, 0x04, 0x1b, 0x1a, 0x1a, 0x1a, 0x30, 0x41, 0x41, 0x41, 0x54, 0x41, 0x43, 0x43, 0x43,
    0x43, 0x43, 0x43, 0x4e, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47,
    0x47, 0x47, 0x10, 0x43, 0x47, 0x4e, 0x54, 0x00, 0x03, 0x08, 0x01, 0x14, 0x80, 0x70, 0x3d, 0x02,
    0x80, 0xa0, 0xe5, 0x00, 0x80, 0x70, 0x65, 0x01, 0x80, 0x44, 0x30, 0x04, 0x30, 0x47, 0x47, 0x47,
    0x43, 0x47, 0x54, 0x54, 0x54, 0x54, 0x54, 0x54, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x30, 0x54, 0x54, 0x54, 0x41, 0x43, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x4e, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43,
];

/// The frame of "abracadabra" four times and a "d", stored as it is
/// because the data was too short to be worth compressing, written by the
/// reference implementation of the codec.
#[cfg(all(test, feature = "cram"))]
pub(crate) const CAT_FRAME: &[u8] = &[
    0x20, 0x2d, 0x61, 0x62, 0x72, 0x61, 0x63, 0x61, 0x64, 0x61, 0x62, 0x72, 0x61, 0x61, 0x62, 0x72,
    0x61, 0x63, 0x61, 0x64, 0x61, 0x62, 0x72, 0x61, 0x61, 0x62, 0x72, 0x61, 0x63, 0x61, 0x64, 0x61,
    0x62, 0x72, 0x61, 0x61, 0x62, 0x72, 0x61, 0x63, 0x61, 0x64, 0x61, 0x62, 0x72, 0x61, 0x64,
];

/// The frame of a run of DNA, interleaving thirty-two states instead of
/// four, written by the reference implementation of the codec.
#[cfg(all(test, feature = "cram"))]
pub(crate) const N32_FRAME: &[u8] = &[
    0x04, 0x88, 0x4c, 0x41, 0x43, 0x47, 0x4e, 0x54, 0x00, 0x83, 0x01, 0x83, 0x01, 0x83, 0x01, 0x83,
    0x7c, 0x83, 0x01, 0xbf, 0x52, 0x08, 0x00, 0x53, 0xc3, 0x09, 0x00, 0xb3, 0xc6, 0x0a, 0x00, 0x40,
    0xad, 0x0b, 0x00, 0xbf, 0x52, 0x08, 0x00, 0x53, 0xc3, 0x09, 0x00, 0xb3, 0xc6, 0x0a, 0x00, 0x40,
    0xad, 0x0b, 0x00, 0xbf, 0x52, 0x08, 0x00, 0x53, 0xc3, 0x09, 0x00, 0xb3, 0xc6, 0x0a, 0x00, 0x40,
    0xad, 0x0b, 0x00, 0xa8, 0xcb, 0x0b, 0x00, 0xa8, 0xcb, 0x0b, 0x00, 0xa8, 0xcb, 0x0b, 0x00, 0xa8,
    0xcb, 0x0b, 0x00, 0xc9, 0x92, 0x01, 0x00, 0x89, 0xd5, 0x01, 0x00, 0x07, 0x06, 0x02, 0x00, 0xb6,
    0x2f, 0x02, 0x00, 0xc9, 0x92, 0x01, 0x00, 0x89, 0xd5, 0x01, 0x00, 0x07, 0x06, 0x02, 0x00, 0xb6,
    0x2f, 0x02, 0x00, 0xc9, 0x92, 0x01, 0x00, 0x89, 0xd5, 0x01, 0x00, 0x07, 0x06, 0x02, 0x00, 0xb6,
    0x2f, 0x02, 0x00, 0xa8, 0xcb, 0x0b, 0x00, 0xa8, 0xcb, 0x0b, 0x00, 0xa8, 0xcb, 0x0b, 0x00, 0xa8,
    0xcb, 0x0b, 0x00, 0x78, 0x61, 0x49, 0x44, 0x03, 0xa8, 0xc0, 0xfd, 0x78, 0x61, 0x49, 0x44, 0x03,
    0xa8, 0xc0, 0xfd, 0x78, 0x61, 0x49, 0x44, 0x03, 0xa8, 0xc0, 0xfd, 0x78, 0x61, 0x49, 0x44, 0x03,
    0xa8, 0xc0, 0xfd, 0x78, 0x61, 0x49, 0x44, 0x03, 0xa8, 0xc0, 0xfd, 0x78, 0x61, 0x49, 0x44, 0x03,
    0xa8, 0xc0, 0xfd, 0x1d, 0x99, 0x1d, 0x99, 0x1d, 0x99, 0x1d, 0x99, 0x1d, 0x99, 0x1d, 0x99, 0x1d,
    0x99, 0x1d, 0x99, 0x3c, 0x51, 0xd6, 0xe4, 0x7a, 0x86, 0xa1, 0xed, 0x3c, 0x51, 0xd6, 0xe4, 0x7a,
    0x86, 0xa1, 0xed, 0x3c, 0x51, 0xd6, 0xe4, 0x7a, 0x86, 0xa1, 0xed, 0x3c, 0x51, 0xd6, 0xe4, 0x7a,
    0x86, 0xa1, 0xed, 0x3c, 0x51, 0xd6, 0xe4, 0x7a, 0x86, 0xa1, 0xed, 0x3c, 0x51, 0xd6, 0xe4, 0x7a,
    0x86, 0xa1, 0xed, 0x81, 0xec, 0x81, 0xec, 0x81, 0xec, 0x81, 0xec, 0x81, 0xec, 0x81, 0xec, 0x81,
    0xec, 0x81, 0xec, 0xcb, 0x51, 0x02, 0x43, 0xfb, 0x67, 0xf6, 0xde, 0xcb, 0x51, 0x02, 0x43, 0xfb,
    0x67, 0xf6, 0xde, 0xcb, 0x51, 0x02, 0x43, 0xfb, 0x67, 0xf6, 0xde, 0xcb, 0x51, 0x02, 0x43, 0xfb,
    0x67, 0xf6, 0xde, 0xcb, 0x51, 0x02, 0x43, 0xfb, 0x67, 0xf6, 0xde, 0xcb, 0x51, 0x02, 0x43, 0xfb,
    0x67, 0xf6, 0xde, 0x63, 0xb9, 0x63, 0xb9, 0x63, 0xb9, 0x63, 0xb9, 0x63, 0xb9, 0x63, 0xb9, 0x63,
    0xb9, 0x63, 0xb9, 0x14, 0x51, 0x8b, 0xe5, 0x7e, 0x78, 0x1a, 0x1f, 0x14, 0x51, 0x8b, 0xe5, 0x7e,
    0x78, 0x1a, 0x1f, 0x14, 0x51, 0x8b, 0xe5, 0x7e, 0x78, 0x1a, 0x1f, 0x14, 0x51, 0x8b, 0xe5, 0x7e,
    0x78, 0x1a, 0x1f, 0x14, 0x51, 0x8b, 0xe5, 0x7e, 0x78, 0x1a, 0x1f, 0x14, 0x51, 0x8b, 0xe5, 0x7e,
    0x78, 0x1a, 0x1f, 0x9a, 0x29, 0x9a, 0x29, 0x9a, 0x29, 0x9a, 0x29, 0x9a, 0x29, 0x9a, 0x29, 0x9a,
    0x29, 0x9a, 0x29, 0x1a, 0xa0, 0x18, 0x84, 0x16, 0x68, 0x2c, 0x7e, 0x1a, 0xa0, 0x18, 0x84, 0x16,
    0x68, 0x2c, 0x7e, 0x1a, 0xa0, 0x18, 0x84, 0x16, 0x68, 0x2c, 0x7e, 0x1a, 0xa0, 0x18, 0x84, 0x16,
    0x68, 0x2c, 0x7e, 0x1a, 0xa0, 0x18, 0x84, 0x16, 0x68, 0x2c, 0x7e, 0x1a, 0xa0, 0x18, 0x84, 0x16,
    0x68, 0x2c, 0x7e,
];

#[cfg(all(test, feature = "cram"))]
mod tests {
    use super::*;

    /// The bytes of "abracadabra" four times and a "d".
    fn abracadabra() -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..4 {
            out.extend_from_slice(b"abracadabra");
        }
        out.push(b'd');
        out
    }

    /// The run of DNA the oracle encoded.
    fn dna() -> Vec<u8> {
        b"ACGTACGTACGTTGCAAGGCCTTACGTACGTACGTACGTACGTNNNACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGT"
            .to_vec()
    }

    /// Every byte value, twenty times over.
    fn every_byte() -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..20 {
            out.extend(0u8..=255);
        }
        out
    }

    /// Eight hundred runs of five bytes each.
    fn many_runs() -> Vec<u8> {
        let mut out = Vec::new();
        for i in 0..800 {
            for _ in 0..5 {
                out.push(65 + (i % 3) as u8);
            }
        }
        out
    }

    /// The runs of the run-length frame: zeros, then ones, twos and 'Z'.
    fn runs() -> Vec<u8> {
        let mut out = vec![0u8; 120];
        out.extend(vec![1u8; 60]);
        out.extend(vec![2u8; 45]);
        out.extend(vec![b'Z'; 30]);
        out
    }

    /// Sixteen byte values, twenty-four times over.
    fn small_alphabet() -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..24 {
            out.extend(0u8..16);
        }
        out
    }

    /// The data of the thirty-two state frame.
    fn n32_data() -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..70 {
            out.extend_from_slice(b"ACGTACGTACGTNNNN");
        }
        out.truncate(1100);
        out
    }

    /// The order-0 frame of the reference implementation decodes back to
    /// the bytes it was written from: the four states take every fourth
    /// byte.
    #[test]
    fn the_order0_frame_of_the_reference_implementation_decodes() {
        let want = abracadabra();
        assert_eq!(want.len(), 45);
        assert_eq!(
            decode(ORDER0).as_deref(),
            Some(&want[..]),
            "the order-0 frame is not decoded"
        );
    }

    /// The order-1 frame of the reference implementation decodes back to
    /// the bytes it was written from: the four states take a quarter of the
    /// data each, and every byte is decoded in the context of the one
    /// before it.
    #[test]
    fn the_order1_frame_of_the_reference_implementation_decodes() {
        let want = dna();
        assert_eq!(want.len(), 102);
        assert_eq!(
            decode(ORDER1).as_deref(),
            Some(&want[..]),
            "the order-1 frame is not decoded"
        );
    }

    /// The order-1 frame whose table the reference implementation
    /// compressed: the table has a context for every byte value, and it is
    /// over a thousand bytes long.
    #[test]
    fn the_order1_frame_with_a_compressed_table_decodes() {
        let want = every_byte();
        assert_eq!(want.len(), 5120);
        assert_eq!(
            decode(ORDER1_TABLE).as_deref(),
            Some(&want[..]),
            "the order-1 frame with a compressed table is not decoded"
        );
    }

    /// The run-length frame of the reference implementation decodes back
    /// to the bytes it was written from: the runs are expanded after the
    /// entropy decoder, and the run lengths are compressed with the
    /// order-0 codec of their own.
    #[test]
    fn the_rle_frame_of_the_reference_implementation_decodes() {
        let want = many_runs();
        assert_eq!(want.len(), 4000);
        assert_eq!(
            decode(RLE_FRAME).as_deref(),
            Some(&want[..]),
            "the run-length frame is not decoded"
        );
    }

    /// The run-length frame whose data the entropy decoder coded in order
    /// 1.
    #[test]
    fn the_rle_order1_frame_of_the_reference_implementation_decodes() {
        let mut want = runs();
        want.extend_from_slice(&dna());
        assert_eq!(want.len(), 357);
        assert_eq!(
            decode(RLE_ORDER1_FRAME).as_deref(),
            Some(&want[..]),
            "the run-length order-1 frame is not decoded"
        );
    }

    /// The bit-packing frame of the reference implementation decodes back
    /// to the bytes it was written from: the symbols were packed two to a
    /// byte and are unpacked after the entropy decoder.
    #[test]
    fn the_pack_frame_of_the_reference_implementation_decodes() {
        let want = small_alphabet();
        assert_eq!(want.len(), 384);
        assert_eq!(
            decode(PACK_FRAME).as_deref(),
            Some(&want[..]),
            "the bit-packing frame is not decoded"
        );
    }

    /// The striped frame of the reference implementation decodes back to
    /// the bytes it was written from: the four streams are the columns of
    /// the transposed data.
    #[test]
    fn the_stripe_frame_of_the_reference_implementation_decodes() {
        let want = dna();
        assert_eq!(
            decode(STRIPE_FRAME).as_deref(),
            Some(&want[..]),
            "the striped frame is not decoded"
        );
    }

    /// The frame of the reference implementation that holds the data as it
    /// is, because the data was too short to be worth compressing.
    #[test]
    fn the_cat_frame_of_the_reference_implementation_decodes() {
        let want = abracadabra();
        assert_eq!(
            decode(CAT_FRAME).as_deref(),
            Some(&want[..]),
            "the raw frame is not decoded"
        );
    }

    /// The frame of the reference implementation that interleaves
    /// thirty-two states instead of four.
    #[test]
    fn the_n32_frame_of_the_reference_implementation_decodes() {
        let want = n32_data();
        assert_eq!(want.len(), 1100);
        assert_eq!(
            decode(N32_FRAME).as_deref(),
            Some(&want[..]),
            "the thirty-two state frame is not decoded"
        );
    }

    /// The 7-bit integer of the specification: seven bits per byte, the
    /// most significant group first, the top bit set on every byte but the
    /// last.
    #[test]
    fn the_seven_bit_integer_reads_every_width() {
        let cases: &[(&[u8], u32)] = &[
            (&[0x00], 0),
            (&[0x7f], 127),
            (&[0x81, 0x00], 128),
            (&[0x81, 0x7f], 255),
            (&[0x82, 0x00], 256),
            (&[0x83, 0x80, 0x40], 49216),
        ];
        for (bytes, want) in cases {
            let mut slice = &bytes[..];
            assert_eq!(read_uint7(&mut slice), Some(*want), "for {bytes:02x?}");
        }
        // Six bytes carry more than thirty-five bits: a number this reader
        // cannot hold.
        let mut slice = &[0x80, 0x80, 0x80, 0x80, 0x80, 0x01][..];
        assert!(
            read_uint7(&mut slice).is_none(),
            "the long number was not refused"
        );
        // A number that does not end is refused.
        let mut slice = &[0x80, 0x80][..];
        assert!(
            read_uint7(&mut slice).is_none(),
            "the unfinished number was not refused"
        );
    }

    /// A frame this reader cannot decode is refused, not guessed at.
    #[test]
    fn a_frame_that_is_not_one_this_reader_can_decode_is_refused() {
        // The reserved flag bit: the specification reserves it for a
        // future order.
        let mut frame = ORDER0.to_vec();
        frame[0] = 0x02;
        assert!(decode(&frame).is_none(), "the reserved bit was not refused");

        // A length that no caller knows, because the frame does not carry
        // one.
        let mut frame = ORDER0.to_vec();
        frame[0] = 0x10;
        assert!(
            decode(&frame).is_none(),
            "the missing length was not refused"
        );

        // A frame that ends before the bytes it says it holds.
        let frame = &ORDER0[..ORDER0.len() - 4];
        assert!(decode(frame).is_none(), "the short frame was not refused");

        // A table whose frequencies do not fill the range of a state.
        let mut frame = ORDER0.to_vec();
        frame[7] = 0x07;
        assert!(
            decode(&frame).is_none(),
            "the table that does not add up was not refused"
        );

        // A state below the lower bound of the range.
        let mut frame = ORDER0.to_vec();
        frame[12] = 0x00;
        frame[13] = 0x00;
        frame[14] = 0x00;
        frame[15] = 0x00;
        assert!(decode(&frame).is_none(), "the low state was not refused");

        // An order-1 table scaled to a number of bits the specification
        // does not permit.
        let mut frame = ORDER1.to_vec();
        frame[2] = 0xb0;
        assert!(
            decode(&frame).is_none(),
            "the table of eleven bits was not refused"
        );

        // A pack map of more symbols than the specification permits.
        let mut frame = PACK_FRAME.to_vec();
        frame[3] = 0x11;
        assert!(
            decode(&frame).is_none(),
            "the pack map of seventeen symbols was not refused"
        );

        // A pack map of no symbols at all.
        let mut frame = PACK_FRAME.to_vec();
        frame[3] = 0x00;
        assert!(
            decode(&frame).is_none(),
            "the pack map of no symbols was not refused"
        );

        // A striped frame with no stream at all.
        let mut frame = STRIPE_FRAME.to_vec();
        frame[3] = 0x00;
        assert!(decode(&frame).is_none(), "the empty stripe was not refused");

        // A frame that is too short to hold its own header.
        assert!(decode(&[0x00, 0x00]).is_none(), "the stub was not refused");
        assert!(decode(&[]).is_none(), "the empty frame was not refused");
    }
}
