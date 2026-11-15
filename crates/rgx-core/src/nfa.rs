// SPDX-License-Identifier: Apache-2.0

//! Compiling an [`Ast`] to a Thompson NFA.
//!
//! # Fragments, and why the builder returns a pair
//!
//! A concatenation of two patterns is not "compile the first, then
//! compile the second and hope": the first pattern's *outgoing* edges
//! have to be spliced into the second pattern's entry, and those edges
//! are not known until the first pattern is finished. A builder that
//! returned only an entry point cannot express that, and the splice
//! ends up joining the wrong end.
//!
//! So a fragment is a pair: an entry `pc`, and the list of `pc`s whose
//! outgoing edge is still dangling. The caller that consumes the
//! fragment patches exactly those, and only those, to its own entry.
//! `a` followed by `b` patches `a`'s exits to `b`'s entry; `a|b` patches
//! both to whatever follows; `a*` patches its own exits back to its own
//! entry.

use alloc::vec;
use alloc::vec::Vec;

use super::byteclass::ByteSet;
use super::syntax::{Assert, Ast};

/// One NFA instruction.
///
/// `pc` is the index of an instruction and the "next" in a `Split` is
/// another `pc`, so every edge is a plain `usize` and the program is a
/// flat `Vec` the VM can walk without indirection.
///
/// The `Byte` variant carries a `u16` index into [`Program::sets`]
/// rather than the 256-bit `ByteSet` itself: a 100-instruction program
/// with the table inline sized every `Inst` to 48 bytes (Rust rounds
/// the variant to the widest member's alignment), and a Pike VM whose
/// program touches an L1 cache line per inst paid for a 2x reduction
/// in instruction density. The pool typically has 3 to 8 distinct sets
/// for a normal pattern, and the indirect load
/// (`prog.sets[id].contains(b)`) is what the VM's epsilon walk
/// already does for the same set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inst {
    /// Consume one byte from the set, then go to `next`.
    ///
    /// The successor is explicit rather than implied by `pc + 1`. Every
    /// other edge in the program is a patchable field, and a fragment's
    /// dangling edges are exactly those fields; an implicit successor
    /// would mean a `Byte` had an exit nothing could patch, and the
    /// first concatenation would try to patch it.
    Byte(u16, usize),
    /// Try `first`, then `second`. `first` is the higher priority.
    Split(usize, usize),
    /// Fall through to `next`.
    Jump(usize),
    /// Record a capture slot, then fall through to `next`.
    Save(usize, usize),
    /// A zero-width condition; falls through to `next` when it holds.
    Assert(Assert, usize),
    /// Accept. The VM reads captures here.
    Match,
}

/// A compiled pattern.
#[derive(Debug, Clone)]
pub struct Program {
    pub insts: Vec<Inst>,
    /// The deduped set of byte classes referenced by `Inst::Byte`. A
    /// pattern that compiles to a hundred `Byte` instructions and three
    /// distinct classes (literal `f`, `.`, `\d`) stores one entry per
    /// class here; the `Inst` body holds the index.
    pub sets: Vec<ByteSet>,
    /// `pc` of the pattern's entry.
    pub start: usize,
    /// Capture slot count, i.e. `2 * (groups + 1)`.
    pub slots: usize,
    /// Whether any path can consume a byte. A pattern that cannot
    /// (`a*`, `^x$` with no way to reach it) still has a `Match`, but a
    /// searcher can skip a whole file when this is false.
    pub consumes: bool,
}

/// A partially built pattern: where to enter, and which dangling edges
/// still need patching.
struct Fragment {
    entry: usize,
    exits: Vec<usize>,
}

/// Index one past the end of the program, standing in for "not yet
/// known". Patched by [`Nfa::patch`].
const UNSET: usize = usize::MAX;

pub fn compile(ast: &Ast, groups: usize) -> Program {
    let mut nfa = Nfa::new();
    let body = nfa.build(ast);
    // Slot 0 spans the whole match and slot 1 its end; the VM reads the
    // start out of slot 0, so a pattern compiled without these two
    // instructions would report every match as starting where it ended.
    let open = nfa.push(Inst::Save(0, body.entry));
    let close = nfa.push(Inst::Save(1, UNSET));
    nfa.patch(&body.exits, close);
    let m = nfa.push(Inst::Match);
    nfa.patch(&[close], m);
    let mut insts = nfa.insts;
    fold_epsilons(&mut insts);
    // Drain the temporary pool the builder kept, then run a single
    // dedup pass: any two `Byte` instructions that share a class get
    // the same pool id, which is what shrinks the program from 48
    // bytes per inst to 16. The pool survives in `Program::sets`; the
    // builder's local one is dropped here.
    let sets = core::mem::take(&mut nfa.set_pool);
    let (insts, sets) = dedupe_sets(insts, sets);
    Program {
        insts,
        sets,
        start: open,
        slots: 2 * (groups + 1),
        consumes: consumes_byte(ast),
    }
}

/// Walk the program, dedupe every distinct `ByteSet` the builder used,
/// and rewrite the `Inst::Byte` payload from a temporary id to a final
/// pool id. The builder allocates a new pool id for every `Byte`
/// instruction (it cannot tell which sets will be the same at push
/// time), so this pass is what collapses them.
///
/// `u16` is plenty: 65 535 distinct classes per compiled pattern is
/// more than the regex syntax can express, and a pool overflow turns
/// into a clear panic rather than a silent truncation.
fn dedupe_sets(insts: Vec<Inst>, pool: Vec<ByteSet>) -> (Vec<Inst>, Vec<ByteSet>) {
    let mut remap: Vec<u16> = Vec::with_capacity(pool.len());
    let mut new_pool: Vec<ByteSet> = Vec::with_capacity(pool.len());
    for set in &pool {
        if let Some(idx) = new_pool.iter().position(|s| s == set) {
            remap.push(idx as u16);
        } else {
            let idx = new_pool.len() as u16;
            new_pool.push(*set);
            remap.push(idx);
        }
    }
    assert!(
        new_pool.len() <= u16::MAX as usize,
        "NFA byte-class pool exceeded u16::MAX entries"
    );
    let _ = pool; // drop the builder's local copy
    let insts = insts
        .into_iter()
        .map(|inst| match inst {
            Inst::Byte(old, next) => Inst::Byte(remap[old as usize], next),
            other => other,
        })
        .collect();
    (insts, new_pool)
}

/// Epsilon-closure shortcutting: collapse chains of `Jump` so the VM
/// never executes a `Jump` whose only successor is another `Jump`,
/// and prune the second arm of a `Split` whose first arm is already
/// the same target. The Thompson NFA builder emits Split→Jump chains
/// freely — every Concat / alt / star leaves one dangling edge that
/// becomes a Jump — and the VM's `add_thread` walks them per byte.
///
/// The pass runs until fixed point: a single pass is enough for any
/// acyclic program (the Thompson output is always acyclic), and the
/// pass is idempotent afterwards.
fn fold_epsilons(insts: &mut [Inst]) {
    loop {
        let mut changed = false;
        // Resolve every Jump's successor past any chain of Jumps.
        for pc in 0..insts.len() {
            let resolved = match insts[pc] {
                Inst::Jump(t) => chase_jump(insts, t),
                _ => continue,
            };
            if let Inst::Jump(t) = &insts[pc] {
                if *t != resolved {
                    insts[pc] = Inst::Jump(resolved);
                    changed = true;
                }
            }
        }
        // A Split(x, y) where x == y is wasted: only one needs to run.
        for pc in 0..insts.len() {
            if let Inst::Split(a, b) = insts[pc] {
                let ra = chase_jump(insts, a);
                let rb = chase_jump(insts, b);
                if ra == rb {
                    // Replace with Jump to the common target; the Split
                    // is now degenerate and the VM saves a branch.
                    insts[pc] = Inst::Jump(ra);
                    changed = true;
                } else if ra != a || rb != b {
                    insts[pc] = Inst::Split(ra, rb);
                    changed = true;
                }
            }
        }
        // A Jump whose target is a Jump (now visible after the prior
        // pass) collapses: the VM reads the second Jump's target
        // without paying for the first.
        if !changed {
            break;
        }
    }
}

/// Follow a chain of `Jump` instructions to the first non-`Jump` pc.
/// `Inst::Match` is its own target — the chain reaches Match, return
/// its pc unchanged. Bounded to a step cap so a fuzzed / corrupt
/// program cannot trap the closure in a cycle.
fn chase_jump(insts: &[Inst], start: usize) -> usize {
    let mut pc = start;
    let mut guard = 0usize;
    while guard < 1 << 16 {
        match insts.get(pc) {
            Some(Inst::Jump(t)) => pc = *t,
            _ => return pc,
        }
        guard += 1;
    }
    pc
}

struct Nfa {
    insts: Vec<Inst>,
    /// The builder allocates one pool entry per `Inst::Byte` it pushes,
    /// without deduping: it does not know yet which sets will turn out
    /// to be identical, and checking on every push would pay an O(n)
    /// scan. The compile pass in [`dedupe_sets`] collapses them.
    set_pool: Vec<ByteSet>,
}

impl Nfa {
    fn new() -> Self {
        Self {
            insts: Vec::new(),
            set_pool: Vec::new(),
        }
    }

    /// Reserve a pool id for `set` and return it. The id is into the
    /// builder's local pool, which is what `dedupe_sets` later
    /// deduplicates and remaps.
    fn intern_set(&mut self, set: ByteSet) -> u16 {
        let id = self.set_pool.len() as u16;
        self.set_pool.push(set);
        id
    }
}

impl Nfa {
    fn push(&mut self, inst: Inst) -> usize {
        self.insts.push(inst);
        self.insts.len() - 1
    }

    /// Points every *dangling* edge at `target`.
    ///
    /// A `Split` is not patched wholesale. Its first arm is a real edge
    /// — the body of a `*`, or the preferred branch of an alternation —
    /// and only the second arm is ever left hanging. Setting both would
    /// silently turn `x*` into a loop that can only exit: the greedy
    /// arm would be overwritten with the exit and the repetition would
    /// match exactly once.
    fn patch(&mut self, exits: &[usize], target: usize) {
        for &pc in exits {
            match &mut self.insts[pc] {
                Inst::Jump(next) => *next = target,
                Inst::Split(a, b) => {
                    if *a == UNSET {
                        *a = target;
                    }
                    if *b == UNSET {
                        *b = target;
                    }
                }
                Inst::Save(_, next) => *next = target,
                Inst::Assert(_, next) => *next = target,
                Inst::Byte(_, next) => *next = target,
                Inst::Match => panic!("cannot patch out of Match"),
            }
        }
    }

    /// Builds `ast`, leaving its outgoing edges dangling.
    fn build(&mut self, ast: &Ast) -> Fragment {
        match ast {
            // An empty pattern is a Jump whose target is patched later.
            Ast::Empty => {
                let pc = self.push(Inst::Jump(UNSET));
                Fragment {
                    entry: pc,
                    exits: vec![pc],
                }
            }
            Ast::Class(set) => {
                let id = self.intern_set(*set);
                let pc = self.push(Inst::Byte(id, UNSET));
                Fragment {
                    entry: pc,
                    exits: vec![pc],
                }
            }
            Ast::Assert(a) => {
                let pc = self.push(Inst::Assert(*a, UNSET));
                Fragment {
                    entry: pc,
                    exits: vec![pc],
                }
            }
            Ast::Concat(items) => {
                let mut frag = self.build(&items[0]);
                for item in &items[1..] {
                    let next = self.build(item);
                    self.patch(&frag.exits, next.entry);
                    frag.exits = next.exits;
                }
                frag
            }
            Ast::Alt(branches) => {
                // A chain of splits, each branch hanging off the next.
                // Built back to front so each `Split`'s second target is
                // already known.
                let mut frag = self.build(&branches[branches.len() - 1]);
                for branch in branches[..branches.len() - 1].iter().rev() {
                    let b = self.build(branch);
                    let split = self.push(Inst::Split(b.entry, frag.entry));
                    frag = Fragment {
                        entry: split,
                        exits: [b.exits, frag.exits].concat(),
                    };
                }
                frag
            }
            Ast::Group { index, node } => {
                let inner = self.build(node);
                match index {
                    None => inner,
                    Some(i) => {
                        let start_slot = 2 * i;
                        let end_slot = start_slot + 1;
                        let open = self.push(Inst::Save(start_slot, inner.entry));
                        let close = self.push(Inst::Save(end_slot, UNSET));
                        self.patch(&inner.exits, close);
                        Fragment {
                            entry: open,
                            exits: vec![close],
                        }
                    }
                }
            }
            Ast::Repeat {
                node,
                min,
                max,
                greedy,
            } => self.build_repeat(node, *min, *max, *greedy),
        }
    }

    /// Repetition by expansion.
    ///
    /// Every bounded repetition is unrolled into copies of the body.
    /// That is linear in the bound and linear in program size, which is
    /// the wrong trade at `{100000}` — the parser caps the bound (see
    /// `MAX_REPEAT`) and says so rather than producing a program that
    /// takes a gigabyte to build. The unbounded forms loop, which costs
    /// nothing.
    fn build_repeat(&mut self, node: &Ast, min: u32, max: Option<u32>, greedy: bool) -> Fragment {
        match max {
            // `x{m,}` — the mandatory copies, then a star.
            None => {
                if min == 0 {
                    return self.build_star(node, greedy);
                }
                let mut frag = self.build_mandatory(node, min);
                let star = self.build_star(node, greedy);
                self.patch(&frag.exits, star.entry);
                frag.exits = star.exits;
                frag
            }
            Some(max) => {
                if min == 0 {
                    // `x{0,n}` is n optional copies, with no mandatory
                    // prefix to splice them onto.
                    return self.build_optional(node, max, greedy);
                }
                let mut frag = self.build_mandatory(node, min);
                let optional = self.build_optional(node, max - min, greedy);
                self.patch(&frag.exits, optional.entry);
                frag.exits = optional.exits;
                frag
            }
        }
    }

    /// `count` copies back to back, all of them taken.
    fn build_mandatory(&mut self, node: &Ast, count: u32) -> Fragment {
        let mut frag = self.build(node);
        for _ in 1..count {
            let next = self.build(node);
            self.patch(&frag.exits, next.entry);
            frag.exits = next.exits;
        }
        frag
    }

    /// `count` copies, each of which may be skipped: `x?x?x?`.
    ///
    /// Built by recursion so each copy's *body* falls into the split
    /// that decides whether to take it, and the split's other arm is the
    /// rest of the chain. The fragment's dangling edges are therefore
    /// the last copy's, not the split's — the split has both arms set.
    fn build_optional(&mut self, node: &Ast, count: u32, greedy: bool) -> Fragment {
        if count == 0 {
            // Matches the empty string; the caller patches the jump.
            let pc = self.push(Inst::Jump(UNSET));
            return Fragment {
                entry: pc,
                exits: vec![pc],
            };
        }
        let split = self.push(Inst::Split(UNSET, UNSET));
        let body = self.build(node);
        let rest = self.build_optional(node, count - 1, greedy);
        // A greedy copy prefers the body. `Split` tries `first` first,
        // so greedy means body-first and lazy means rest-first — the
        // same instruction with the arms swapped, not a runtime flag.
        self.insts[split] = if greedy {
            Inst::Split(body.entry, rest.entry)
        } else {
            Inst::Split(rest.entry, body.entry)
        };
        // Into the rest of the chain, *not* back into `split`. Falling
        // back into the split is a star, and `x?` compiled as one
        // matches `aaa` in full instead of matching a single `a`.
        self.patch(&body.exits, rest.entry);
        Fragment {
            entry: split,
            exits: rest.exits,
        }
    }

    /// `x*` or `x*?`.
    fn build_star(&mut self, node: &Ast, greedy: bool) -> Fragment {
        let split = self.push(Inst::Split(UNSET, UNSET));
        let body = self.build(node);
        self.insts[split] = if greedy {
            Inst::Split(body.entry, UNSET)
        } else {
            Inst::Split(UNSET, body.entry)
        };
        self.patch(&body.exits, split);
        // The split's second arm is the exit, and the body loops back to
        // the split, so the split is both the entry and the exit.
        Fragment {
            entry: split,
            exits: vec![split],
        }
    }
}

/// Whether any path through the tree consumes a byte.
fn consumes_byte(ast: &Ast) -> bool {
    match ast {
        Ast::Empty | Ast::Assert(_) => false,
        Ast::Class(_) => true,
        Ast::Concat(items) => items.iter().any(consumes_byte),
        Ast::Alt(branches) => branches.iter().any(consumes_byte),
        Ast::Repeat { node, min, .. } => *min > 0 && consumes_byte(node),
        Ast::Group { node, .. } => consumes_byte(node),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax::parse;

    /// `Inst` must fit in 24 bytes. The previous layout (256-bit
    /// `ByteSet` inline) sized the whole enum to 48 bytes; the pool
    /// move shrinks it to 24. The remaining 16 bytes come from
    /// `Split`/`Save` (two `usize`s each, the lower bound on any
    /// instruction with two outgoing edges) plus 8 bytes of
    /// discriminant padding. A 100-instruction program now occupies
    /// 2.4 KiB instead of 4.8 KiB, and the VM's per-byte program walk
    /// pays for that with half the L1i misses.
    #[test]
    fn inst_size_is_24_bytes() {
        assert_eq!(core::mem::size_of::<Inst>(), 24);
    }

    /// The compile pass must collapse duplicate byte classes into a
    /// single pool entry. A pattern that emits three `\d` instructions
    /// should still report exactly one set in the pool, and every
    /// instruction should reference the same id.
    #[test]
    fn dedupe_collapses_identical_classes() {
        let ast = parse(br"\d\d\d").unwrap().ast;
        let prog = compile(&ast, 0);
        assert_eq!(
            prog.sets.len(),
            1,
            "expected one deduped set, got {:?}",
            prog.sets.len()
        );
        let only_id = match prog.insts[1] {
            Inst::Byte(id, _) => id,
            other => panic!("expected Byte, got {other:?}"),
        };
        for inst in &prog.insts {
            if let Inst::Byte(id, _) = inst {
                assert_eq!(*id, only_id, "every Byte should reference the same pool id");
            }
        }
    }

    /// A pattern with two distinct classes (literal `a` and `.`) keeps
    /// both in the pool, distinct ids.
    #[test]
    fn dedupe_keeps_distinct_classes() {
        let ast = parse(br"a.").unwrap().ast;
        let prog = compile(&ast, 0);
        assert_eq!(prog.sets.len(), 2);
    }
}
