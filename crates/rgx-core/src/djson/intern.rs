// SPDX-License-Identifier: Apache-2.0

//! The shadow of the arena's string table: the hash index that answers
//! "have I seen this string?" without a scan.
//!
//! # Why this is not `std::collections::HashMap`
//!
//! The `alloc` crate has **no `HashMap`**. `std::collections::HashMap` is
//! the only one the standard library offers, and it is `std` -- which is
//! exactly what a `#![no_std]` build cannot have. What the `no_std` build
//! had instead was a *scan* over the whole string table: a lookup compared
//! the key's bytes against every string in the document, which is quadratic
//! in the number of distinct keys.
//!
//! So this is a hash table, written for this crate: open addressing with
//! linear probing, the key's hash stored beside its index, and the arena's
//! own string table as the key storage. Three things came out of writing
//! it. A slot that holds the *index* of the key does not hold a second copy
//! of it, so the `std` build stopped paying one `String` allocation per
//! distinct key. The slot carries the hash, so a probe compares 64 bits
//! before it compares bytes, and a key that is not in the table is usually
//! rejected by the first slot it touches. And the hash travels with the
//! entry, so growing the table re-hashes nothing.
//!
//! # Collisions are answered, not assumed away
//!
//! Two different strings with the same hash are two different entries. The
//! probe walks until it finds a free slot, and a candidate is accepted only
//! when its *bytes* match, so a collision costs a longer walk and never a
//! wrong answer. The test that forces every key into the same hash is
//! `two_keys_with_one_hash_stay_two_entries`.
//!
//! # The hash is the one thing the two configurations do not share
//!
//! Everything above is the same code in both builds, and it is faster than
//! what the `std` build had. The hash is not, and the difference is a
//! capability, not a choice:
//!
//! * With `std`, the hash is the standard library's: SipHash-1-3, seeded
//!   from the operating system. A document cannot be crafted to make its
//!   keys collide, which matters for a tool that reads files it did not
//!   write.
//! * Without `std`, there is no entropy to seed with -- the `core` crate
//!   has no random number generator, and the `libc` that a syscall would
//!   need comes in with the `std` feature -- so the hash is this crate's
//!   own, with a fixed seed, and it is the fast one.
//!
//! That is the whole reason the `no_std` configuration is the faster of the
//! two on this path: it pays for a hash it can afford instead of one that
//! resists an attacker, and it is not the only thing that got faster.
//!
//! The trade is worth writing down in both directions. The `std` build is
//! the one most users run, and it keeps the flood-resistant hash. The
//! `no_std` build is the one that reads a document an attacker may have
//! written, and it does not: a document crafted so that all of its keys
//! land in one bucket makes that build's interning quadratic, where the
//! `std` build's stays linear. A `no_std` build that needs the resistance
//! would have to bring an entropy source of its own.

use alloc::string::String;
use alloc::vec::Vec;

use core::fmt;

/// One slot of the table.
///
/// The slot carries the key's hash *and* the key's index, so a probe reads
/// one cache line and rejects a candidate on 64 bits before it compares a
/// single byte.
#[derive(Clone, Copy)]
struct Slot {
    /// The key's hash.
    hash: u64,
    /// The key's index in the arena's string table, or [`Slot::FREE_INDEX`]
    /// when the slot is free.
    index: usize,
}

impl Slot {
    /// The index that marks a free slot.
    const FREE_INDEX: usize = usize::MAX;

    /// What a free slot holds.
    const FREE: Slot = Slot {
        hash: 0,
        index: Self::FREE_INDEX,
    };
}

/// The shadow of a string table: the hash index from a string to its index.
///
/// The table is open addressing with linear probing, and it never fills
/// past half: a fuller table probes longer, and the probe is the cost this
/// table exists to remove. The capacity is a power of two, so the bucket is
/// a mask and not a division.
///
/// The keys are not in here. A slot holds the *index* of the key in the
/// arena's string table, and the comparison that decides whether a
/// candidate is the key being looked for is made against that table --
/// which is why [`StringIndex::lookup`] takes it.
#[derive(Clone)]
pub(crate) struct StringIndex {
    /// The slots. `slots.len()` is a power of two, or zero.
    slots: Vec<Slot>,
    /// The number of occupied slots.
    len: usize,
    /// The hasher's state, with the `std` feature.
    ///
    /// The state belongs to the *table*, not to the thread that fills it: a
    /// hash that changed from one thread to the next would put the same
    /// string in two buckets, and a lookup from another thread would miss a
    /// key that is there. The standard library's `RandomState` draws a
    /// fresh key every time it is made, so every table gets its own.
    #[cfg(feature = "std")]
    state: std::collections::hash_map::RandomState,
}

impl Default for StringIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for StringIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StringIndex")
            .field("len", &self.len())
            .field("slots", &self.slots.len())
            .finish()
    }
}

impl StringIndex {
    /// The smallest table the index ever allocates.
    const MIN_SLOTS: usize = 8;

    /// A table with no entries.
    pub(crate) fn new() -> Self {
        Self {
            slots: Vec::new(),
            len: 0,
            #[cfg(feature = "std")]
            state: std::collections::hash_map::RandomState::new(),
        }
    }

    /// The hash of a string's bytes, in this table.
    ///
    /// With the `std` feature this is the standard library's randomised
    /// hasher, seeded from the operating system, so a document cannot be
    /// crafted to make its keys collide. Without it there is no entropy to
    /// seed with -- `core` has no random number generator and the `libc` a
    /// syscall would need comes in with the `std` feature -- so this is a
    /// fixed-seed hash of this crate's own.
    #[cfg(feature = "std")]
    #[inline]
    pub(crate) fn hash_of(&self, bytes: &[u8]) -> u64 {
        use core::hash::BuildHasher;
        self.state.hash_one(bytes)
    }

    /// The hash of a string's bytes, in this table.
    ///
    /// See the `std` version of this function for why the two differ.
    #[cfg(not(feature = "std"))]
    #[inline]
    pub(crate) fn hash_of(&self, bytes: &[u8]) -> u64 {
        fixed_seed_hash(bytes)
    }

    /// The number of strings in the table.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Whether the table holds no strings.
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The number of slots the table has.
    #[cfg(test)]
    pub(crate) fn slots_len(&self) -> usize {
        self.slots.len()
    }

    /// Reserve room for `n` more strings.
    ///
    /// The parser knows how many strings a document carries before it
    /// interns any of them, so this is where the table stops growing.
    pub(crate) fn reserve(&mut self, n: usize) {
        let want = self.len.saturating_add(n);
        if want.saturating_mul(2) > self.slots.len() {
            self.rehash(Self::slots_for(want));
        }
    }

    /// The number of slots a table holding `n` entries needs.
    ///
    /// The table never fills past half, so the slots are twice the entries
    /// -- rounded up to a power of two, because the bucket is a mask.
    fn slots_for(n: usize) -> usize {
        let mut slots = Self::MIN_SLOTS;
        while slots < n.saturating_mul(2) {
            // The doubling saturates: the loop stops at the first power
            // of two above `n`, and a table that large is not a table.
            slots = slots.saturating_mul(2);
        }
        slots
    }

    /// Move every entry into a fresh table of `slots` slots.
    ///
    /// The hash travels with the entry, so growing costs no re-hashing: a
    /// key is hashed once, when it is interned, and never again.
    fn rehash(&mut self, slots: usize) {
        let old = core::mem::take(&mut self.slots);
        self.slots = alloc::vec![Slot::FREE; slots];
        self.len = 0;
        for slot in old {
            if slot.index != Slot::FREE_INDEX {
                self.place(slot.hash, slot.index);
            }
        }
    }

    /// The mask that turns a hash into a bucket.
    fn mask(&self) -> usize {
        debug_assert!(!self.slots.is_empty(), "the mask of an empty table");
        self.slots.len() - 1
    }

    /// Put `(hash, index)` in the first free slot of its probe sequence.
    fn place(&mut self, hash: u64, index: usize) {
        let mask = self.mask();
        let mut slot = (hash as usize) & mask;
        loop {
            if self.slots[slot].index == Slot::FREE_INDEX {
                self.slots[slot] = Slot { hash, index };
                self.len += 1;
                return;
            }
            slot = (slot + 1) & mask;
        }
    }

    /// The index of `probe` in the string table, if it is in there.
    ///
    /// `hash` must be the hash of `probe`'s bytes, and `strings` the table
    /// the index refers to. A candidate is accepted only when its bytes
    /// match, so a hash collision costs a longer walk and not a wrong
    /// answer.
    pub(crate) fn lookup(&self, hash: u64, probe: &str, strings: &[String]) -> Option<usize> {
        if self.is_empty() {
            return None;
        }
        let mask = self.mask();
        let mut slot = (hash as usize) & mask;
        loop {
            let entry = self.slots[slot];
            if entry.index == Slot::FREE_INDEX {
                return None;
            }
            if entry.hash == hash {
                let index = entry.index;
                if strings[index] == probe {
                    return Some(index);
                }
            }
            slot = (slot + 1) & mask;
        }
    }

    /// Record that the string at `index` hashes to `hash`.
    pub(crate) fn insert(&mut self, hash: u64, index: usize) {
        if (self.len + 1).saturating_mul(2) > self.slots.len() {
            self.rehash(Self::slots_for(self.len + 1));
        }
        self.place(hash, index);
    }
}

/// The constants the fixed-seed hash mixes with.
///
/// Two odd 64-bit constants: the golden ratio, and a second one that is
/// not related to it. Nothing here is a secret and nothing here is a key --
/// the hash is not a cryptographic one and does not pretend to be.
#[cfg(not(feature = "std"))]
const MIX_A: u64 = 0x9E37_79B9_7F4A_7C15;
#[cfg(not(feature = "std"))]
const MIX_B: u64 = 0xC2B2_AE3D_27D4_EB4F;

/// The fixed-seed hash of a byte string.
///
/// A multiply-xor round over eight-byte words, then a finalizer. The round
/// is the shape the fast hashes use -- the compiler's own, and the browser
/// engine's before it -- and the finalizer is what makes the *low* bits
/// usable: a hash table picks its bucket from the low bits of the hash,
/// while a multiply leaves its entropy in the high ones.
#[cfg(not(feature = "std"))]
#[inline]
fn fixed_seed_hash(bytes: &[u8]) -> u64 {
    // The length goes in first, so that a key and the same key with a byte
    // appended are two different keys.
    let mut hash = MIX_A ^ (bytes.len() as u64).wrapping_mul(MIX_B);
    let mut chunks = bytes.chunks_exact(8);
    for chunk in &mut chunks {
        let word = u64::from_le_bytes(chunk.try_into().expect("8 bytes"));
        hash = mix(hash ^ word, MIX_B);
    }
    let rest = chunks.remainder();
    if !rest.is_empty() {
        // The tail is mixed with its own length, so that "ab" and "ab\0"
        // -- the same eight bytes once padded -- are two keys and not one.
        let mut buf = [0u8; 8];
        buf[..rest.len()].copy_from_slice(rest);
        let word = u64::from_le_bytes(buf);
        hash = mix(hash ^ word, (rest.len() as u64) ^ MIX_A);
    }
    finish(hash)
}

/// The multiply: the high half of a 64x64 product folded into the low one.
///
/// The two halves are folded together because a product's middle bits are
/// the ones that move the most when the input changes, and the low half
/// alone is the one the table reads.
#[cfg(not(feature = "std"))]
#[inline]
fn mix(x: u64, y: u64) -> u64 {
    let full = (x as u128).wrapping_mul(y as u128);
    let low = full as u64;
    let high = (full >> 64) as u64;
    low ^ high
}

/// The finalizer: move the entropy down to the bits the table reads.
///
/// Without it the table would be picking its buckets out of the low bits
/// of a hash whose entropy is in the high ones, and every key would land
/// in the same handful of buckets.
#[cfg(not(feature = "std"))]
#[inline]
fn finish(mut hash: u64) -> u64 {
    hash ^= hash >> 32;
    hash = hash.wrapping_mul(MIX_A);
    hash ^= hash >> 29;
    hash = hash.wrapping_mul(MIX_B);
    hash ^ (hash >> 32)
}

#[cfg(test)]
mod tests {
    use super::StringIndex;

    use alloc::string::String;
    use alloc::vec::Vec;

    use std::collections::{HashMap, HashSet};

    /// The keys the tests use: short, and with the shape a JSON key has.
    fn keys(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("key_{i:06}")).collect()
    }

    /// A table over `keys`, and the string table its indices refer to.
    fn build(keys: &[String]) -> (StringIndex, Vec<String>) {
        let mut index = StringIndex::new();
        let mut strings = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let hash = index.hash_of(key.as_bytes());
            index.insert(hash, i);
            strings.push(key.clone());
        }
        (index, strings)
    }

    #[test]
    fn every_key_is_found_where_it_was_put() {
        let keys = keys(1_000);
        let (index, strings) = build(&keys);
        assert_eq!(index.len(), keys.len());
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(
                index.lookup(index.hash_of(key.as_bytes()), key, &strings),
                Some(i),
                "key {key} was not found at {i}"
            );
        }
    }

    #[test]
    fn a_key_that_was_never_put_is_not_found() {
        let keys = keys(64);
        let (index, strings) = build(&keys);
        for missing in ["", "key", "key_000064", "KEY_000001", "key_000001 "] {
            assert_eq!(
                index.lookup(index.hash_of(missing.as_bytes()), missing, &strings),
                None,
                "{missing} was found and was never put"
            );
        }
    }

    #[test]
    fn the_table_agrees_with_the_standard_library() {
        // The oracle: the standard library's map, which the test harness
        // links even in the `no_std` configuration.
        let keys = keys(2_000);
        let mut oracle: HashMap<&str, usize> = HashMap::new();
        for (i, key) in keys.iter().enumerate() {
            oracle.insert(key.as_str(), i);
        }
        let (index, strings) = build(&keys);
        for (key, want) in &oracle {
            assert_eq!(
                index.lookup(index.hash_of(key.as_bytes()), key, &strings),
                Some(*want),
                "the table and the standard library disagree about {key}"
            );
        }
        assert_eq!(index.len(), oracle.len());
    }

    #[test]
    fn two_keys_with_one_hash_stay_two_entries() {
        // Every key in the same bucket: the table has to walk past the
        // first one to find the second, and has to keep both.
        let strings = vec![String::from("alpha"), String::from("beta")];
        let mut index = StringIndex::new();
        index.insert(42, 0);
        index.insert(42, 1);
        assert_eq!(index.len(), 2);
        assert_eq!(index.lookup(42, "alpha", &strings), Some(0));
        assert_eq!(index.lookup(42, "beta", &strings), Some(1));
        assert_eq!(index.lookup(42, "gamma", &strings), None);
    }

    #[test]
    fn the_table_survives_growth() {
        // Every growth re-places every entry, so a table that has grown
        // many times is the one that can lose an entry.
        let keys = keys(20_000);
        let (index, strings) = build(&keys);
        assert_eq!(index.len(), keys.len());
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(
                index.lookup(index.hash_of(key.as_bytes()), key, &strings),
                Some(i),
                "key {key} was lost by a growth"
            );
        }
    }

    #[test]
    fn the_hash_spreads_the_keys_over_the_buckets() {
        // The table picks its bucket from the low bits of the hash, so the
        // low bits have to carry the entropy. 4096 keys over 4096 buckets
        // fill about 2600 of them even with a perfect hash -- a hash that
        // left its entropy in the high bits would fill a handful.
        let index = StringIndex::new();
        let mut used: HashSet<u64> = HashSet::new();
        for key in keys(4096) {
            used.insert(index.hash_of(key.as_bytes()) & 0xFFF);
        }
        assert!(
            used.len() > 2_000,
            "the low bits carried only {} of 4096 buckets",
            used.len()
        );
    }

    #[test]
    fn two_keys_with_one_hash_survive_a_growth() {
        // The collision and the growth together: a table that has to
        // re-place eight entries that all claim the same bucket has to
        // keep their order, or the lookup walks past the one it wanted.
        let keys: Vec<String> = [
            "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta",
        ]
        .iter()
        .map(|k| String::from(*k))
        .collect();
        let mut index = StringIndex::new();
        let mut strings = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            index.insert(42, i);
            strings.push(key.clone());
        }
        // Eight entries in a table that holds half of eight slots is the
        // point where the table has to grow.
        assert!(index.slots_len() > 8, "the table did not grow");
        assert_eq!(index.len(), keys.len());
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(
                index.lookup(42, key, &strings),
                Some(i),
                "the key {key} was lost by a growth"
            );
        }
        assert_eq!(index.lookup(42, "absent", &strings), None);
    }

    #[test]
    fn the_table_never_fills_past_half() {
        // The load factor is the table's performance contract: a table
        // that fills up probes longer and longer.
        let mut index = StringIndex::new();
        let keys = keys(500);
        let mut strings = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let hash = index.hash_of(key.as_bytes());
            index.insert(hash, i);
            strings.push(key.clone());
            assert!(
                index.len() * 2 <= index.slots_len(),
                "the table holds {} entries in {} slots",
                index.len(),
                index.slots_len()
            );
        }
        // And the same after a reservation that sizes it in one go.
        let mut reserved = StringIndex::new();
        reserved.reserve(1_000);
        assert!(reserved.slots_len() >= 2_000);
        assert!(reserved.len() * 2 <= reserved.slots_len());
    }

    #[test]
    fn an_arena_built_on_one_thread_is_readable_on_another() {
        // The hash belongs to the table, not to the thread that fills it.
        // A hash that changed from one thread to the next would put the
        // same string in two buckets: the lookup would miss a key that is
        // there, and the string would be interned twice.
        let mut arena = crate::djson::value::Arena::new();
        arena.intern(String::from("alpha"));
        arena.intern(String::from("beta"));
        let (first, before, after) = std::thread::spawn(move || {
            let before = arena.strings().len();
            let first = arena.intern(String::from("alpha"));
            let second = arena.intern(String::from("alpha"));
            assert_eq!(first, second, "the same text got two indices");
            (first, before, arena.strings().len())
        })
        .join()
        .expect("the other thread panicked");
        assert_eq!(first, 0);
        assert_eq!(before, 2);
        assert_eq!(after, 2, "the string was interned a second time");
    }
}
