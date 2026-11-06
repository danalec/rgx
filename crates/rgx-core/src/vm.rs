// SPDX-License-Identifier: Apache-2.0

//! The Pike VM: running an NFA over bytes, leftmost-first.
//!
//! [`find`] promises the leftmost match at or after the offset it was
//! given. A fresh start thread is added at every position, below the
//! threads carried over from the previous one — an earlier-started
//! thread outranks a later one. The moment a `Match` is on the list
//! the search stops.

use alloc::vec;
use alloc::vec::Vec;

use super::byteclass::ByteSet;
use super::nfa::{Inst, Program};
use super::syntax::Assert;

/// One thread: where it is in the program, and the capture slots it has
/// set so far.
///
/// Captures are per-thread rather than global because two threads
/// exploring the same program can disagree about where group 1 ended —
/// that disagreement is exactly what `((a)|(b))` does at every
/// position. A single global slot table would report the wrong group
/// for one of the two branches.
#[derive(Clone, Default)]
struct Thread<S> {
    pc: usize,
    /// Where in `hay` this thread stands. A `Match` thread's `at` is
    /// where the match *ends*, which is not the position the search loop
    /// has reached: a match completed at 1 is still on the list while
    /// the loop walks on to 2.
    at: usize,
    /// `slots[i]` is the offset at which slot `i` was set, or `None`.
    slots: S,
}

/// The visited bitmap for one thread list.
///
/// `Vec<bool>` here is a malloc per search, and a search now happens
/// once per candidate rather than once per line. A program up to 64
/// instructions — nearly all of them — keeps the set in a `u64` and
/// allocates nothing.
enum Mark {
    /// One bit per program position, inlined in a `u64`. Holds programs
    /// of 1..=64 instructions with zero allocation.
    Bits(u64),
    /// 256-bit inline bitmap for programs of 65..=256 instructions —
    /// still zero allocation.
    Wide([u64; 4]),
    /// Anything wider than 256 positions.
    Bytes(Vec<bool>),
}

impl Mark {
    /// A clear set wide enough for `width` positions.
    fn new(width: usize) -> Self {
        if width <= 64 {
            Mark::Bits(0)
        } else if width <= 256 {
            Mark::Wide([0; 4])
        } else {
            Mark::Bytes(vec![false; width])
        }
    }

    /// Whether position `i` is on the list.
    #[inline]
    fn get(&self, i: usize) -> bool {
        match self {
            Mark::Bits(b) => (*b & (1u64 << (i & 63))) != 0,
            Mark::Wide(w) => {
                if i < 256 {
                    (w[i >> 6] & (1u64 << (i & 63))) != 0
                } else {
                    false
                }
            }
            Mark::Bytes(v) => v.get(i).copied().unwrap_or(false),
        }
    }

    /// Put position `i` on the list. Out of range is ignored, which is the
    /// same answer a shorter bitmap would have given.
    #[inline]
    fn set(&mut self, i: usize) {
        match self {
            Mark::Bits(b) => *b |= 1u64 << (i & 63),
            Mark::Wide(w) => {
                if i < 256 {
                    w[i >> 6] |= 1u64 << (i & 63);
                }
            }
            Mark::Bytes(v) => {
                if let Some(cell) = v.get_mut(i) {
                    *cell = true;
                }
            }
        }
    }

    /// Empty the set.
    #[inline]
    fn clear(&mut self) {
        match self {
            Mark::Bits(b) => *b = 0,
            Mark::Wide(w) => *w = [0; 4],
            Mark::Bytes(v) => v.fill(false),
        }
    }
}

/// A thread's capture slots, addressed rather than iterated.
///
/// The slot count is `2 * (groups + 1)`, fixed the moment the pattern is
/// compiled. For every pattern in ordinary use the table can be an array
/// inline in the [`Thread`], and copying a thread becomes a `memcpy`
/// rather than a `malloc`. The previous `Vec` was allocated once per
/// byte position of the haystack.
///
/// Two implementations rather than one, dispatched on the slot count by
/// [`dispatch`], so a pattern with more capture groups than the largest
/// inline table still reports all of them.
trait Slots: Clone {
    /// A table of `n` unset slots.
    fn blank(n: usize) -> Self;
    /// How many slots the table holds.
    fn len(&self) -> usize;
    /// Record `v` at slot `i`, or do nothing when `i` is out of range.
    fn set(&mut self, i: usize, v: Option<usize>);
    /// What slot `i` holds, or `None` when `i` is out of range.
    fn get(&self, i: usize) -> Option<usize>;
}

/// The longest haystack an [`Inline`] slot table can address.
///
/// A `u32` is 4 bytes vs the 16 of `Option<usize>`, so the two-slot table
/// is 24 bytes — a fourth of the work of clearing per search.
///
/// 4 GiB is the price, named so [`dispatch`] sends a haystack longer than
/// this to [`Heap`]: an offset that does not fit can never alias [`UNSET`]
/// and be read as a group that never participated.
const MAX_NARROW_OFFSET: usize = u32::MAX as usize;

/// An unset narrow slot.
const UNSET: u32 = u32::MAX;

/// The inline table: the common case, and the one the corpus takes.
///
/// `N == 2` is the implicit start/end pair of a pattern with no capture
/// groups, and it is dispatched on its own so the `Thread` is 24 bytes
/// rather than 72.
struct Inline<const N: usize>([u32; N]);

impl<const N: usize> Default for Inline<N> {
    fn default() -> Self {
        Inline([UNSET; N])
    }
}

impl<const N: usize> Clone for Inline<N> {
    fn clone(&self) -> Self {
        Inline(self.0)
    }
}

impl<const N: usize> Slots for Inline<N> {
    fn blank(_n: usize) -> Self {
        Inline([UNSET; N])
    }
    fn len(&self) -> usize {
        N
    }
    fn set(&mut self, i: usize, v: Option<usize>) {
        if let Some(cell) = self.0.get_mut(i) {
            *cell = match v {
                Some(x) => x as u32,
                None => UNSET,
            };
        }
    }
    fn get(&self, i: usize) -> Option<usize> {
        self.0
            .get(i)
            .copied()
            .filter(|&c| c != UNSET)
            .map(|c| c as usize)
    }
}

/// The heap table, for a pattern with more capture groups than any inline one
/// is worth carrying in every thread. Rare, and correct rather than fast.
#[derive(Clone, Default)]
struct Heap(Vec<Option<usize>>);

impl Slots for Heap {
    fn blank(n: usize) -> Self {
        Heap(vec![None; n])
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn set(&mut self, i: usize, v: Option<usize>) {
        if let Some(cell) = self.0.get_mut(i) {
            *cell = v;
        }
    }
    fn get(&self, i: usize) -> Option<usize> {
        self.0.get(i).copied().flatten()
    }
}

/// How many threads one half of the list holds before it takes the heap.
///
/// A half can never hold more entries than the program is wide, because
/// `add_thread` admits each `pc` at most once — so 8 covers every pattern
/// up to 8 instructions, which is most of them. A wider table is more
/// stack to clear on entry; the alternative is a `malloc` per search.
const LIST_CAP: usize = 8;

/// The VM's two thread lists.
///
/// **Both halves live in one array with `cur` choosing between them** rather
/// than in two `Vec`s that have to be swapped. Swapping 768 bytes of
/// thread records at every byte position of the haystack would cost more
/// than the allocation it replaces, and this loop runs once per byte.
///
/// `K` is [`LIST_CAP`] (size of BOTH halves together) for the inline case
/// and `0` for the heap one, which is a compile-time constant in each
/// instantiation: the `if K == 0` folds away.
struct Lists<S, const K: usize> {
    buf: [Thread<S>; K],
    heap: Vec<Thread<S>>,
    len: [usize; 2],
    cur: usize,
    /// Instructions in the program, an upper bound on one half.
    cap: usize,
}

impl<S: Slots + Default, const K: usize> Lists<S, K> {
    fn new(cap: usize) -> Self {
        Self {
            // `from_fn` rather than `[x; K]`: the latter needs `Copy`,
            // which a slot table is not, and it is the lowering that turns
            // this into the memset it needs to be anyway.
            buf: core::array::from_fn(|_| Thread::default()),
            heap: if K == 0 {
                vec![Thread::default(); 2 * cap]
            } else {
                Vec::new()
            },
            len: [0; 2],
            cur: 0,
            cap,
        }
    }

    /// Make `half` the current list and empty it.
    #[inline]
    fn select(&mut self, half: usize) {
        self.cur = half;
        self.len[half] = 0;
    }

    /// Where `half`'s entries start.
    #[inline]
    fn base(&self, half: usize) -> usize {
        if K == 0 {
            half * self.cap
        } else {
            half * (K / 2)
        }
    }

    /// Append to the current list.
    #[inline]
    fn push(&mut self, t: Thread<S>) {
        let half = self.cur;
        let i = self.base(half) + self.len[half];
        if K == 0 {
            self.heap[i] = t;
        } else {
            self.buf[i] = t;
        }
        self.len[half] += 1;
    }

    #[inline]
    fn len_at(&self, half: usize) -> usize {
        self.len[half]
    }

    /// `pc_at` with the half's `base` already computed, so the inner thread
    /// loop's per-iteration cost stops recomputing `base(half)` through
    /// `cell(...)`.
    #[inline]
    fn pc_at_b(&self, base: usize, i: usize) -> usize {
        self.cell_b(base + i).pc
    }

    /// `end_at` with the half's `base` already computed.
    #[inline]
    fn end_at_b(&self, base: usize, i: usize) -> usize {
        self.cell_b(base + i).at
    }

    /// `slots_at` with the half's `base` already computed.
    #[inline]
    fn slots_at_b(&self, base: usize, i: usize) -> &S {
        &self.cell_b(base + i).slots
    }

    /// `cell` with `j` already known.
    #[inline]
    fn cell_b(&self, j: usize) -> &Thread<S> {
        if K == 0 {
            &self.heap[j]
        } else {
            &self.buf[j]
        }
    }
}

/// A successful match: where it starts and ends, and the groups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub start: usize,
    pub end: usize,
    /// `groups[i]` is `(start, end)` for capture group `i`, counting
    /// from 1. A group that did not participate is `None`.
    pub groups: Vec<Option<(usize, usize)>>,
}

/// The leftmost match at or after `at`, or `None`.
pub fn find(prog: &Program, hay: &[u8], at: usize) -> Option<Match> {
    dispatch(prog, hay, at, false, false)
}

/// Whether a match BEGINS exactly at `at`, without saying where it ends.
///
/// This is not `find_at(..).is_some()`. A searcher deciding one line does
/// not need the extent, and buying it costs a greedy pattern its tail:
/// `(pub|fn) [a-z]+` on `pub fn helper` costs 245 ms over 686 thousand
/// candidates on a 235 MB corpus — the VM has to run the greedy star to
/// the end of the haystack to find out how far the match reaches.
///
/// "Does ANY thread sit at `Match`" has the same answer and stops at the
/// first byte that can accept, because the accepting thread is added to
/// the list at the position where the star could stop.
pub fn matches_at(prog: &Program, hay: &[u8], at: usize) -> bool {
    dispatch(prog, hay, at, true, true).is_some()
}

/// Whether a match begins ANYWHERE in `hay` — the "does this line match
/// at all" question, and the only sound confirm for a prefilter whose
/// literal sits at an offset nothing knows.
///
/// Anchoring at 0 would be a different question: `matches_at(prog,
/// b"    xyz", 0)` for `[a-z]*xyz` is false, while the line plainly
/// matches.
pub fn matches_anywhere(prog: &Program, hay: &[u8]) -> bool {
    dispatch(prog, hay, 0, false, true).is_some()
}

/// The leftmost-first match that BEGINS exactly at `at`, or `None`.
///
/// Not `find(prog, hay, at)` with a check on the start. A Pike VM
/// re-seeds a fresh start thread at every position, so a failed
/// anchored check through `find` would scan the rest of the haystack
/// seeding threads that can only find matches the caller has rejected.
/// `e[0-9]` on a 235 MB corpus went from 10.2 s to 17.4 s when its
/// prefilter started confirming with `find`: each of the ~79% of
/// lines that hold an `e` failed the `[0-9]` and then re-scanned to
/// the end.
///
/// Within one starting position the ordering is unchanged, so `a|ab` on
/// `ab` reports `a`, exactly as [`find`] does.
pub fn find_at(prog: &Program, hay: &[u8], at: usize) -> Option<Match> {
    dispatch(prog, hay, at, true, false)
}

/// Pick a slot representation for this program.
///
/// A pattern with no capture groups has exactly two slots and takes
/// [`Inline<2>`]; up to three groups takes [`Inline<8>`]; anything
/// wider takes [`Heap`]. Each arm is a separate instantiation of the
/// loop; `prog.slots` is read once per search.
fn dispatch(prog: &Program, hay: &[u8], at: usize, anchored: bool, boolean: bool) -> Option<Match> {
    if boolean {
        return pick::<Inline<0>>(prog, hay, at, anchored, true);
    }
    // See [`MAX_NARROW_OFFSET`]: a haystack an inline table cannot address
    // goes to the heap table, whatever the program's slot count says.
    let slots = if hay.len() <= MAX_NARROW_OFFSET {
        prog.slots
    } else {
        usize::MAX
    };
    match slots {
        0..=2 => pick::<Inline<2>>(prog, hay, at, anchored, boolean),
        3..=4 => pick::<Inline<4>>(prog, hay, at, anchored, boolean),
        5..=8 => pick::<Inline<8>>(prog, hay, at, anchored, boolean),
        _ => pick::<Heap>(prog, hay, at, anchored, boolean),
    }
}

/// Inline thread storage for a program narrow enough, the heap otherwise.
fn pick<S: Slots + Default>(
    prog: &Program,
    hay: &[u8],
    at: usize,
    anchored: bool,
    boolean: bool,
) -> Option<Match> {
    // `boolean` is a CONST: a runtime one put a second branch in the
    // innermost loop of every search, and patterns that cannot use it —
    // `a|b`, `e.`, whose confirm is one byte long — measured 3% slower
    // for a decision they never take.
    match (prog.insts.len() <= LIST_CAP, boolean) {
        (true, false) => run::<S, LIST_CAP, false>(prog, hay, at, anchored),
        (true, true) => run::<S, LIST_CAP, true>(prog, hay, at, anchored),
        (false, false) => run::<S, 0, false>(prog, hay, at, anchored),
        (false, true) => run::<S, 0, true>(prog, hay, at, anchored),
    }
}

fn run<S: Slots + Default, const K: usize, const BOOLEAN: bool>(
    prog: &Program,
    hay: &[u8],
    at: usize,
    anchored: bool,
) -> Option<Match> {
    let n = hay.len();
    if at > n {
        return None;
    }
    let blank = S::blank(prog.slots);
    let width = prog.insts.len();

    // Set up ONCE per search, not once per byte. A search now happens once
    // per candidate, not per line, so the buffers are sized so a narrow
    // program does not touch the allocator at all. Measured on a 31-byte
    // line `e[0-9]` confirm: 88 ns and 3 allocations before, 22 ns and
    // none after.
    let mut lists = Lists::<S, K>::new(width);
    let mut on_c = Mark::new(width);
    let mut on_n = Mark::new(width);
    let _ = add_thread(prog, hay, &mut lists, &mut on_c, prog.start, at, blank);

    let mut pos = at;
    loop {
        if pos >= n {
            // Input exhausted. Every thread before the first `Match` is
            // a `Byte` that can no longer consume anything, so the first
            // `Match` in the list is the answer.
            let cur = lists.cur;
            let base = lists.base(cur);
            for i in 0..lists.len_at(cur) {
                if matches!(prog.insts[lists.pc_at_b(base, i)], Inst::Match) {
                    return Some(finish(
                        lists.slots_at_b(base, i),
                        prog.slots,
                        lists.end_at_b(base, i),
                    ));
                }
            }
            return None;
        }

        // Otherwise the highest-priority thread decides. A `Match` further down
        // the list does not end the search while a higher-priority
        // alternative is still alive and can still consume: for `ab|a`
        // on "ab" the "a" branch reaches `Match` before the "ab" branch
        // finishes.
        //
        // The list can be empty — a start thread whose assertion fails,
        // such as `\z` at offset 0 of a non-empty haystack. Anchored there
        // is no next position, and an empty list can never be added to
        // again, so it is the end.
        let cur = lists.cur;
        if anchored && lists.len_at(cur) == 0 {
            return None;
        }
        // The accepting test, and the two forms of it are the whole of
        // what `boolean` changes. Head-only is leftmost-FIRST: the
        // highest priority thread is the one that gets to report.
        // Any is not: the caller only wants to know that a match EXISTS.
        //
        // The scan is skipped for a one-thread list, where the head IS
        // the only thread: `a|b` and `e.` keep a single thread per
        // position and were paying for a loop to be told what one
        // comparison says.
        let base = lists.base(cur);
        if lists.len_at(cur) > 0 {
            let hit = if BOOLEAN && lists.len_at(cur) > 1 {
                (0..lists.len_at(cur))
                    .find(|&i| matches!(prog.insts[lists.pc_at_b(base, i)], Inst::Match))
            } else if matches!(prog.insts[lists.pc_at_b(base, 0)], Inst::Match) {
                Some(0)
            } else {
                None
            };
            if let Some(i) = hit {
                return Some(finish(
                    lists.slots_at_b(base, i),
                    prog.slots,
                    lists.end_at_b(base, i),
                ));
            }
        }

        let b = hay[pos];

        lists.select(1 - cur);
        on_n.clear();
        for i in 0..lists.len_at(cur) {
            // Copied out one at a time rather than iterated by reference:
            // the body pushes into the list, so no borrow of it can be live.
            let pc = lists.pc_at_b(base, i);
            match prog.insts[pc] {
                Inst::Byte(set, next) => {
                    // Pool indirection: the `set` is an id into
                    // `prog.sets`. A typical program has 3 to 8 distinct
                    // classes, so the pool fits in L1.
                    if prog.sets[set as usize].contains(b) {
                        let t_slots = lists.slots_at_b(base, i).clone();
                        let _ =
                            add_thread(prog, hay, &mut lists, &mut on_n, next, pos + 1, t_slots);
                    }
                }
                // A completed match is carried forward, not dropped:
                // it is the fallback for every higher-priority thread
                // that dies before the input runs out. Carried verbatim
                // rather than through `add_thread`: a match ends where it
                // was accepted, and re-adding it at `pos + 1` would slide
                // every completed match forward one byte per step until
                // it reached the end of the haystack.
                Inst::Match => {
                    if !on_n.get(pc) {
                        on_n.set(pc);
                        let t_end = lists.end_at_b(base, i);
                        let t_slots = lists.slots_at_b(base, i).clone();
                        lists.push(Thread {
                            pc,
                            at: t_end,
                            slots: t_slots,
                        });
                    }
                }
                Inst::Jump(_) | Inst::Split(_, _) | Inst::Save(_, _) | Inst::Assert(_, _) => {
                    unreachable!("epsilon instruction survived add_thread")
                }
            }
        }
        // Seed the next position last, so it sits below every thread
        // that started earlier — but only for an unanchored search.
        if !anchored {
            let _ = add_thread(
                prog,
                hay,
                &mut lists,
                &mut on_n,
                prog.start,
                pos + 1,
                S::blank(prog.slots),
            );
        }

        core::mem::swap(&mut on_c, &mut on_n);
        pos += 1;
    }
}

/// Follows epsilon transitions from `pc`, pushing every byte-consuming
/// or accepting thread reached onto `list` in priority order.
///
/// `on` is the visited bitmap for this list: a program position already
/// on the list must not be added twice, because the first thread to
/// reach it is the higher-priority one and carries the captures that
/// belong to the match being reported.
///
/// # Why the walk hands its state back
///
/// When a `Split` is a greedy star, `Split(body, exit)`, `exit` is where
/// the body *ended up* after iterating. It must see the capture state the
/// body reached, or `(a*)*` over an empty haystack reports its group as
/// not having participated. Real alternation arms (`(a)|x`) must not
/// inherit one another's groups.
///
/// The two cases are told apart by the return value: a walk reports the
/// state it held when it was stopped, and a walk is only ever stopped by
/// re-entering a position already on the list, which is exactly what a
/// loop is.
///
/// The position of the re-entry makes the difference between an iteration
/// that consumed something and one that did not. A repetition stops at
/// its first empty iteration: `(a*)*` over `aa` reports `(0, 2)`, not
/// the empty `(2, 2)` the final empty iteration would give. The empty
/// iteration is still a path the VM explores, so the exit has to
/// *decline* its capture state unless the iteration moved.
fn add_thread<S: Slots + Default, const K: usize>(
    prog: &Program,
    hay: &[u8],
    list: &mut Lists<S, K>,
    on: &mut Mark,
    pc: usize,
    pos: usize,
    slots: S,
) -> Option<(S, usize)> {
    if on.get(pc) {
        return Some((slots, pos));
    }
    on.set(pc);
    match prog.insts[pc] {
        Inst::Jump(t) => add_thread(prog, hay, list, on, t, pos, slots),
        Inst::Split(a, b) => {
            let first = add_thread(prog, hay, list, on, a, pos, slots.clone());
            // The exit keeps the body's captures only when the body came
            // back through here having consumed something. An empty
            // iteration is a path the VM explores but an engine must not
            // count — its state is discarded and the pre-body state stands.
            let exit_slots = match &first {
                Some((looped, _)) if !advanced_any(looped, &slots) => looped.clone(),
                _ => slots,
            };
            let second = add_thread(prog, hay, list, on, b, pos, exit_slots);
            second.or(first)
        }
        Inst::Save(slot, next) => {
            let mut slots = slots;
            slots.set(slot, Some(pos));
            add_thread(prog, hay, list, on, next, pos, slots)
        }
        Inst::Assert(kind, next) => {
            if assert_holds(kind, hay, pos) {
                add_thread(prog, hay, list, on, next, pos, slots)
            } else {
                None
            }
        }
        Inst::Byte(_, _) | Inst::Match => {
            list.push(Thread { pc, at: pos, slots });
            None
        }
    }
}

/// Whether `after` moved any capture slot forward relative to `before`.
///
/// A repetition stops at its first *empty* iteration; an engine that has
/// already consumed something reports the last iteration that did. An
/// empty iteration is a path the VM explores all the same, so the exit
/// has to tell the two apart: an iteration that consumed strictly moved
/// some slot forward, and one that consumed nothing left every slot
/// where it was. `(a*)*` over an empty haystack is the case that
/// needs the other branch — "strictly moved", not "unchanged".
fn advanced_any<S: Slots>(after: &S, before: &S) -> bool {
    (0..after.len()).any(|i| match (after.get(i), before.get(i)) {
        (Some(x), Some(b)) => x > b,
        _ => false,
    })
}

fn assert_holds(kind: Assert, hay: &[u8], pos: usize) -> bool {
    let n = hay.len();
    match kind {
        Assert::StartText => pos == 0,
        Assert::EndText => pos == n,
        Assert::StartLine => pos == 0 || hay[pos - 1] == b'\n',
        Assert::EndLine => pos == n || hay[pos] == b'\n',
        Assert::WordBoundary => is_word_at(hay, pos.wrapping_sub(1)) != is_word_at(hay, pos),
        Assert::NotWordBoundary => is_word_at(hay, pos.wrapping_sub(1)) == is_word_at(hay, pos),
    }
}

/// Whether `hay[i]` is an ASCII word byte. `i` may be one past the end,
/// which reads as "not a word byte" — what makes a boundary at the
/// start or end of the text work.
fn is_word_at(hay: &[u8], i: usize) -> bool {
    match hay.get(i) {
        Some(&b) => b.is_ascii_alphanumeric() || b == b'_',
        None => false,
    }
}

fn finish<S: Slots>(slots: &S, used: usize, end: usize) -> Match {
    let start = slots.get(0).unwrap_or(end);
    let mut groups = Vec::new();
    // Group `i` occupies slots `2i` and `2i+1`, so it exists only when
    // both indices are in range.
    //
    // `used` is `prog.slots`, NOT the table's capacity. An `Inline<8>`
    // holds a six-slot pattern's worth of table with two spare cells,
    // and reading the bound off the capacity would report two extra
    // groups that the pattern does not have — a wrong answer, not a slow
    // one, and nothing else in the tree would notice.
    let mut i = 1;
    while 2 * i + 1 < used {
        let open = slots.get(2 * i);
        let close = slots.get(2 * i + 1);
        groups.push(match (open, close) {
            (Some(a), Some(b)) if b >= a => Some((a, b)),
            // A group that opened but never closed cannot happen in a
            // well-formed program, but a half-set slot must not be
            // reported as a match.
            _ => None,
        });
        i += 1;
    }
    Match { start, end, groups }
}

/// The set of bytes a match can *begin* with.
///
/// Not every byte the pattern can consume: this walks from the entry
/// through the epsilon transitions and unions only the classes at the
/// frontier — for `abc` it is `{a}`, not `{a, b, c}`. A searcher
/// uses it to skip a line whose first byte is not in the set without
/// running the VM.
pub fn first_bytes(prog: &Program) -> Option<ByteSet> {
    let mut out = ByteSet::empty();
    let mut seen = vec![false; prog.insts.len()];
    let mut stack = vec![prog.start];
    while let Some(pc) = stack.pop() {
        if seen[pc] {
            continue;
        }
        seen[pc] = true;
        match prog.insts[pc] {
            Inst::Byte(set, _) => out = out.union(&prog.sets[set as usize]),
            Inst::Jump(t) => stack.push(t),
            Inst::Split(a, b) => {
                stack.push(a);
                stack.push(b);
            }
            Inst::Save(_, next) | Inst::Assert(_, next) => stack.push(next),
            // A pattern that can match without consuming anything has no
            // first byte; the caller decides what to do about that.
            Inst::Match => {}
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
mod list_capacity_tests {
    use alloc::borrow::ToOwned;
    use alloc::boxed::Box;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec::Vec;

    use super::{find, find_at, matches_anywhere, run, Inline, Match, Program};

    /// The number of threads one list can hold: every instruction that can
    /// SURVIVE on one. `add_thread` admits each `pc` at most once per list, and
    /// a `Jump`, `Split`, `Save` or `Assert` is resolved inside the walk
    /// rather than occupying a slot, so only `Byte` and `Match` can be handed
    /// to [`super::Lists::push`].
    ///
    /// This is the number the inline table has to be able to give ONE HALF.
    fn demand(p: &Program) -> usize {
        p.insts
            .iter()
            .filter(|i| matches!(i, super::Inst::Byte(..) | super::Inst::Match))
            .count()
    }

    fn prog(pat: &str) -> Program {
        let parsed = crate::syntax::parse(pat.as_bytes()).expect("pattern parses");
        crate::nfa::compile(&parsed.ast, parsed.groups)
    }

    /// The shipped search at the inline tier, against the self-sizing heap
    /// arm. The heap arm allocates `2 * width` threads and so can hold any
    /// program; it is the definition the inline tier is held to.
    type Tier<'p> = (
        &'static str,
        Box<dyn for<'h> Fn(&'h [u8], usize, bool) -> Option<Match> + 'p>,
    );

    fn tiers_for<'p>(p: &'p Program) -> Vec<Tier<'p>> {
        let mut v: Vec<Tier<'p>> = Vec::new();
        if p.insts.len() <= super::LIST_CAP {
            v.push((
                "inline",
                Box::new(move |h: &[u8], at, an| run::<Inline<2>, 8, false>(p, h, at, an)),
            ));
        }
        v.push((
            "heap",
            Box::new(move |h: &[u8], at, an| run::<Inline<2>, 0, false>(p, h, at, an)),
        ));
        v
    }

    /// Patterns, chosen to reach every arm of the capacity argument.
    ///
    /// A bounded repetition is the shape that makes an unanchored search
    /// accumulate (each step's fresh seed joins the chain on the list, so
    /// it decides how much table a program needs). An alternation is the
    /// widest program per thread. Both sweep a range of counts so a
    /// program landing just under `LIST_CAP` is covered.
    fn patterns() -> Vec<String> {
        let mut v: Vec<String> = ["a", "ab", "abc", "a|b|c|d", "a(b|c)d(e|f)", "(a|b)(c|d)"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        for n in 1..=8usize {
            v.push(format!("a{{{n}}}b"));
            v.push(format!("a{{{n}}}b."));
            v.push(format!("a{{{n}}}[bc]"));
        }
        v
    }

    fn haystacks() -> Vec<Vec<u8>> {
        vec![
            b"abcd|abc|def|ghiaabcd|efababcghiaabcdabc".to_vec(),
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec(),
            // Nothing but the byte a repetition wants, so every step adds
            // a seed instead of dying.
            b"aaaaaaaaaabaaaaaaaaac".to_vec(),
            b"ab".to_vec(),
            b"".to_vec(),
            b"xyz".to_vec(),
        ]
    }

    /// The inline table is a storage decision and must not be able to change
    /// an answer — or to run off the end of itself.
    ///
    /// The hazard: [`super::Lists::push`] indexes `buf` unguarded, so a
    /// program with more threads than its half has slots writes past the
    /// end. That is a panic in the binary, not a wrong answer, so a parity
    /// test cannot catch it. `LIST_CAP` is the bound that prevents it.
    ///
    /// Two tiers (inline and heap) are checked against each other at every
    /// offset of every fixture, anchored and unanchored. They must agree
    /// on the whole `Option<Match>` — not merely on whether a match exists
    /// — because a slot table that mixed itself up could report the right
    /// start with the wrong end.
    #[test]
    fn the_inline_table_holds_the_program_and_agrees_with_the_heap() {
        for pat in patterns() {
            let p = prog(&pat);
            let tiers = tiers_for(&p);
            for hay in haystacks() {
                for at in 0..=hay.len() {
                    for anchored in [true, false] {
                        let want = tiers.last().expect("the heap arm is always legal").1(
                            &hay, at, anchored,
                        );
                        for (name, f) in &tiers[..tiers.len() - 1] {
                            assert_eq!(
                                f(&hay, at, anchored),
                                want,
                                "{name} disagrees with the heap arm on {pat:?} ({} wide, demand {}, \
                                 anchored={anchored}) at {at}",
                                p.insts.len(),
                                demand(&p)
                            );
                        }
                    }
                }
            }
        }
    }

    /// The entry points a searcher actually calls, against the heap arm.
    ///
    /// Start and end only, because `find_at` goes through [`super::dispatch`]
    /// and picks its slot table by the program's group count, while these
    /// comparisons are pinned to `Inline<2>`; a pattern with a capture group
    /// cannot record it at that width and differs in `groups` alone. The
    /// extent is what a confirm reads.
    #[test]
    fn the_public_entry_points_agree_with_the_heap_arm() {
        for pat in patterns() {
            let p = prog(&pat);
            for hay in haystacks() {
                for at in 0..=hay.len() {
                    let want =
                        run::<Inline<2>, 0, false>(&p, &hay, at, true).map(|m| (m.start, m.end));
                    let got = find_at(&p, &hay, at).map(|m| (m.start, m.end));
                    assert_eq!(got, want, "find_at on {pat:?} at {at}");
                }
                assert_eq!(
                    find(&p, &hay, 0).map(|m| (m.start, m.end)),
                    run::<Inline<2>, 0, false>(&p, &hay, 0, false).map(|m| (m.start, m.end)),
                    "find on {pat:?}"
                );
                assert_eq!(
                    matches_anywhere(&p, &hay),
                    run::<Inline<2>, 0, true>(&p, &hay, 0, false).is_some(),
                    "matches_anywhere on {pat:?}"
                );
            }
        }
    }

    /// The gate itself: a program is searched on the inline table exactly when
    /// it is no wider than `LIST_CAP`, and the heap arm sizes itself from the
    /// width either way. Restated rather than read off `pick`, so that a
    /// change to the constant and a change to the match cannot drift apart
    /// without one of the tests above noticing.
    #[test]
    fn a_program_is_searched_inline_exactly_when_it_fits() {
        for pat in patterns() {
            let p = prog(&pat);
            let inline = p.insts.len() <= super::LIST_CAP;
            let tiers = tiers_for(&p);
            assert_eq!(
                tiers.len() == 2,
                inline,
                "{pat:?} is {} wide: {}",
                p.insts.len(),
                if inline {
                    "should be inline"
                } else {
                    "should be on the heap"
                }
            );
        }
    }
}
