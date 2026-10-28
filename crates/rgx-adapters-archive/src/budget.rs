// SPDX-License-Identifier: Apache-2.0

//! Producer-side work budget, shared by every adapter in this crate.
//!
//! `Ctx::max_members` caps how many entries of an `Outcome::Members` the
//! pipeline recurses into, and that happens *after* the adapter has already
//! built every member. A container advertising 65k tiny entries therefore
//! paid for 65k extractions to produce a list the pipeline then threw away.
//! The cap has to live where the members are built, and `Adapter::extract`
//! never sees a `Ctx`, so the budget lives here and every archive producer
//! in this crate reads it through [`MemberSink`].
//!
//! Defaults are read from `Ctx::default()` so the two cannot drift apart;
//! `RGX_MAX_MEMBERS` and `RGX_MAX_MEMBER_BYTES` override them per process;
//! the byte one takes a plain count or a `k`/`m`/`g` suffix. `-M` wins over
//! both when it differs from its default.
//! A `Ctx` carrying a non-default `max_members` does not reach the
//! producers — the trait signature cannot carry it.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicU64, Ordering};

/// "No process-wide override", so that 0 stays usable as a limit.
const UNSET: u64 = u64::MAX;

/// Ceiling on entries a producer may *look at*, per member of the budget.
/// Members that fail to decode do not consume the member budget, so without
/// this a zip whose 100000 entries all fail would scan its central directory
/// once per entry: 12.6s, and nothing extracted to show for it.
const EXAMINED_PER_MEMBER: usize = 4;

static MEMBERS: AtomicU64 = AtomicU64::new(UNSET);
static BYTES: AtomicU64 = AtomicU64::new(UNSET);

/// What one archive is allowed to cost the producer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    /// Members expanded out of one archive.
    pub members: usize,
    /// Member bytes expanded out of one archive, in total.
    pub bytes: u64,
}

/// The effective budget: override, else environment, else `Ctx::default()`.
pub fn budget() -> Budget {
    Budget {
        members: resolve(
            MEMBERS.load(Ordering::Relaxed),
            "RGX_MAX_MEMBERS",
            rgx_core::Ctx::default().max_members as u64,
        ) as usize,
        bytes: resolve(
            BYTES.load(Ordering::Relaxed),
            "RGX_MAX_MEMBER_BYTES",
            rgx_core::Ctx::default().max_file_size as u64,
        ),
    }
}

/// Replace the budget for this process. `members` must leave room for the
/// truncation note, so it cannot go below 2.
pub fn set_budget(b: Budget) {
    assert!(b.members >= 2, "member budget below 2 cannot hold a notice");
    assert!(b.bytes >= 1);
    MEMBERS.store(b.members as u64, Ordering::Relaxed);
    BYTES.store(b.bytes, Ordering::Relaxed);
}

/// Drop any override, returning to the environment and `Ctx::default()`.
pub fn reset_budget() {
    MEMBERS.store(UNSET, Ordering::Relaxed);
    BYTES.store(UNSET, Ordering::Relaxed);
}

/// The budget for a container nested `depth` levels deep: the process budget
/// halved once per level.
///
/// See [`MemberSink::new`] for why. Two properties matter and both are
/// asserted in the tests: depth 0 is the process budget unchanged, and the sum
/// over a tree of any depth is under twice that budget.
///
/// Exposed for the tests and for an adapter that builds a sink for a container
/// it is about to recurse into itself.
pub fn budget_for_depth(depth: usize) -> Budget {
    let b = budget();
    // Saturating, and the shift is clamped: `depth` is bounded by
    // `Ctx::max_depth` (4 by default) but a caller can pass anything, and
    // shifting a `usize` by its own width is undefined behaviour rather than a
    // zero.
    let shift = depth.min(usize::BITS as usize - 1);
    Budget {
        members: (b.members >> shift).max(2),
        bytes: (b.bytes >> shift).max(1),
    }
}

fn resolve(override_: u64, env: &str, default: u64) -> u64 {
    if override_ != UNSET {
        return override_;
    }
    std::env::var(env)
        .ok()
        .and_then(|v| parse_size(v.trim()))
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

/// A byte count, or one with a `k`/`m`/`g` suffix — the same spelling `-M`
/// takes, so setting the variable to `20G` works rather than being silently
/// ignored in favour of the default.
fn parse_size(v: &str) -> Option<u64> {
    if let Ok(n) = v.parse::<u64>() {
        return Some(n);
    }
    let split = v.find(|c: char| c.is_ascii_alphabetic())?;
    let (num, suffix) = v.split_at(split);
    let mult: f64 = match suffix.to_ascii_lowercase().as_str() {
        "k" | "kb" | "kib" => 1024.0,
        "m" | "mb" | "mib" => 1024.0 * 1024.0,
        "g" | "gb" | "gib" => 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some((num.trim().parse::<f64>().ok()? * mult) as u64)
}

/// Which budget a producer ran out of, for the wording of the notice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stopped {
    MemberCount,
    Bytes,
    Examined,
}

/// Virtual path of the member carrying the truncation notice.
pub const TRUNCATION_MEMBER: &str = "rgx-truncated-members.txt";

/// Virtual path of the member carrying the notice for a decompressed
/// stream. A single-file decompressor has no members of its own to name, so
/// the note stands on its own; the same rule as [`TRUNCATION_MEMBER`]
/// applies, which is that a short read has to be visible.
pub const DECOMPRESSION_NOTE: &str = "rgx-truncated-decompression.txt";

/// Virtual path of the member carrying the notice for entries a codec
/// **declined**, as distinct from entries a budget stopped.
///
/// A refusal is not truncation and must not borrow its wording: the archive
/// was read to its end, the decoder could not decode some of it. Dropping
/// those entries without a word makes an archive look smaller than it is.
pub const UNSUPPORTED_MEMBER: &str = "rgx-unsupported-members.txt";

/// The notice a codec's refusals get, as a searchable member. `refused` is
/// `(entry name, reason)` per declined entry. The count in the text is
/// unbounded on purpose: a budget cap on the note would hide exactly the
/// entries it exists to name.
pub fn unsupported_note(refused: &[(String, String)]) -> (String, Vec<u8>) {
    let mut text = format!(
        "[rgx: {} archive entries could not be decoded by this build:\n",
        refused.len()
    );
    for (name, why) in refused {
        let _ = writeln!(text, "  {name}: {why}");
    }
    text.push_str(
        "  these entries are absent from the search, not empty; the codec that would \
         read them is not built in\n",
    );
    (UNSUPPORTED_MEMBER.to_string(), text.into_bytes())
}

/// The notice a decode the byte budget stopped short gets, as a searchable
/// member. `emitted` is what the decoder produced, `declared` what the
/// container said it was going to produce where the format has a header that
/// could be read before the cap, and `limit` the budget it hit — all from
/// the one number [`Budget::bytes`] is set from.
pub fn decompression_note(emitted: u64, limit: u64, declared: Option<u64>) -> (String, Vec<u8>) {
    let declared = match declared {
        Some(n) => format!(" of {n} declared"),
        None => String::new(),
    };
    let text = format!(
        "[rgx: decompression truncated: {emitted} bytes decoded{declared}; byte budget: \
         {limit} bytes; raise RGX_MAX_MEMBER_BYTES to decode the rest]\n"
    );
    (DECOMPRESSION_NOTE.to_string(), text.into_bytes())
}

/// Builds the `Outcome::Members` payload under a [`Budget`].
///
/// Producers [`reserve`](Self::reserve) before decoding anything and stop as
/// soon as it turns false. [`finish`](Self::finish) then prepends a note
/// member saying the archive was truncated, so a partial extraction is
/// visible rather than looking like a complete one — the same trick as
/// `rgx-core`'s depth-limit note.
pub struct MemberSink {
    out: Vec<(String, Vec<u8>)>,
    limit: Budget,
    used: u64,
    declared: Option<usize>,
    seen: usize,
    stopped: Option<Stopped>,
}

impl MemberSink {
    /// A sink for the container currently being extracted, with a budget
    /// scaled by how deeply nested it is.
    ///
    /// **Why the scaling exists.** Every adapter in this crate builds its own
    /// `MemberSink`, so before this, each container received a *fresh* full
    /// allowance. `Ctx::max_depth` bounds the depth of the tree and says
    /// nothing about its width times height, so the guards were all individually
    /// satisfied by a container that nested them: a 4 MiB zip holding 4096
    /// small zips passes the 4096-member cap at level 0 and then draws 4096
    /// more budgets at level 1. With the shipped defaults that is 16.7 million
    /// members and, because the byte budget is re-granted in full at every
    /// level, up to 4 TiB of expansion from a 4 MiB input.
    ///
    /// Halving per level bounds the whole tree by a geometric series —
    /// `limit * (1 + 1/2 + 1/4 + 1/8) < 2 * limit` at the default depth of 4 —
    /// and leaves the common case untouched: **depth 0 gets exactly the budget
    /// it always had**, so a flat archive, or a tree of ordinary documents,
    /// pays nothing and changes no output. A nested container gets a share,
    /// which is what "one budget for the search" was always meant to mean.
    ///
    /// Halving is on members and on bytes alike. The floor is 2 members because
    /// [`with_budget`] asserts that a budget below 2 cannot hold the truncation
    /// note, and a byte floor so the innermost container still has room to say
    /// anything at all.
    pub fn new() -> Self {
        Self::with_budget(budget_for_depth(rgx_core::current_depth()))
    }

    pub fn with_budget(limit: Budget) -> Self {
        assert!(
            limit.members >= 2,
            "member budget below 2 cannot hold a notice"
        );
        assert!(limit.bytes >= 1);
        Self {
            out: Vec::new(),
            limit,
            used: 0,
            declared: None,
            seen: 0,
            stopped: None,
        }
    }

    /// Entries the container announces, when it announces a count up front.
    /// Only used for the wording of the note.
    pub fn declare(&mut self, entries: usize) {
        self.declared = Some(entries);
    }

    /// How many member bytes are left under the budget. For a producer
    /// whose next step materializes more than the member it is about to
    /// push — a 7z folder is decoded whole before any entry of it can be
    /// refused — the declaration is checked against this before the
    /// materialization, not after.
    pub fn remaining_bytes(&self) -> u64 {
        self.limit.bytes.saturating_sub(self.used)
    }

    /// Reserve room for a member of `declared_size` bytes. False means it
    /// does not fit and the producer must stop; the sink has recorded which
    /// budget said so.
    ///
    /// Producers check this against the *declared* size, before the member
    /// is decoded, so a container that advertises a huge uncompressed
    /// member never pays to produce it.
    pub fn reserve(&mut self, declared_size: u64) -> bool {
        self.seen += 1;
        if self.seen > self.limit.members.saturating_mul(EXAMINED_PER_MEMBER) {
            self.stop(Stopped::Examined);
            return false;
        }
        if self.fits(declared_size) {
            return true;
        }
        self.stop_for(declared_size > self.limit.bytes.saturating_sub(self.used));
        false
    }

    fn fits(&self, size: u64) -> bool {
        self.out.len() < self.limit.members && self.used.saturating_add(size) <= self.limit.bytes
    }

    /// Add a member. False means it did not fit and the producer must stop.
    pub fn push(&mut self, name: String, bytes: Vec<u8>) -> bool {
        let size = bytes.len() as u64;
        if !self.fits(size) {
            self.stop_for(size > self.limit.bytes.saturating_sub(self.used));
            return false;
        }
        self.used += size;
        self.out.push((name, bytes));
        true
    }

    /// Stop reading this archive: at least one entry is going unread.
    pub fn stop(&mut self, reason: Stopped) {
        self.stopped = Some(reason);
    }

    fn stop_for(&mut self, byte_capped: bool) {
        self.stopped = Some(if byte_capped {
            Stopped::Bytes
        } else {
            Stopped::MemberCount
        });
    }

    pub fn finish(mut self) -> Vec<(String, Vec<u8>)> {
        let Some(stopped) = self.stopped else {
            return self.out;
        };
        // The note takes one slot of the budget. Giving up the last real
        // member for it costs nothing: the pipeline's own
        // `.take(ctx.max_members)` drops that member anyway.
        if self.out.len() >= self.limit.members {
            self.out.pop();
        }
        let extracted = self.out.len();
        let mut out = Vec::with_capacity(extracted + 1);
        out.push((
            TRUNCATION_MEMBER.to_string(),
            self.note(stopped, extracted).into_bytes(),
        ));
        out.append(&mut self.out);
        out
    }

    fn note(&self, stopped: Stopped, extracted: usize) -> String {
        let declared = match self.declared {
            Some(n) => format!("{n} entries declared"),
            None => String::from("entry count not declared by the container"),
        };
        let reason = match stopped {
            Stopped::Bytes => "member byte",
            Stopped::Examined => "entry scan",
            Stopped::MemberCount => "member count",
        };
        format!(
            "[rgx: archive truncated: {declared}, {extracted} extracted, {} \
             entries examined ({} budget: {} members / {} bytes); raise \
             RGX_MAX_MEMBERS / RGX_MAX_MEMBER_BYTES to extract the rest]\n",
            self.seen, reason, self.limit.members, self.limit.bytes
        )
    }
}

impl Default for MemberSink {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, any(feature = "decompress", feature = "sevenz", feature = "zip")))]
pub(crate) mod testing {
    use super::{reset_budget, set_budget, Budget};
    use std::sync::Mutex;

    /// The budget is process-wide and the test harness is not, so a test
    /// that changes it would otherwise race every test reading it.
    static LOCK: Mutex<()> = Mutex::new(());

    /// Run `f` with the budget left alone, but not beside another test that
    /// changes it. A test that reads the budget without this can see
    /// another test's low one: `Decompress` reads it on every file it
    /// decodes, so every adapter test goes through here.
    pub(crate) fn locked<R>(f: impl FnOnce() -> R) -> R {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        f()
    }

    /// As [`locked`], with the budget replaced for the duration. The
    /// restore runs even if `f` panics, or a failing test would leave the
    /// budget low for every test after it.
    pub(crate) fn under_budget<R>(members: usize, bytes: u64, f: impl FnOnce() -> R) -> R {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                reset_budget();
            }
        }
        locked(|| {
            set_budget(Budget { members, bytes });
            let _reset = Reset;
            f()
        })
    }
}

#[cfg(test)]
mod depth_scaling {
    use super::{budget, budget_for_depth, reset_budget, set_budget, Budget};

    fn under<R>(members: usize, bytes: u64, f: impl FnOnce() -> R) -> R {
        set_budget(Budget { members, bytes });
        let r = f();
        reset_budget();
        r
    }

    /// **Depth 0 must be the process budget, unchanged.**
    ///
    /// This is the property that makes the whole change safe to ship: a
    /// flat archive, or a tree of ordinary documents, must not see a
    /// different budget than it always did, or every container test and
    /// every user's `-g`-filtered corpus pays for a fix to a problem they
    /// do not have.
    #[test]
    fn the_outermost_container_gets_the_whole_budget() {
        under(4096, 1 << 30, || {
            let b = budget();
            assert_eq!(budget_for_depth(0).members, b.members);
            assert_eq!(budget_for_depth(0).bytes, b.bytes);
        });
    }

    /// **A nested container gets a share, and the shares are geometric.**
    ///
    /// Before this, every level drew the full budget again, so the guards
    /// were each individually satisfied by a container that nested them —
    /// the amplification this exists to stop.
    #[test]
    fn a_nested_container_gets_a_share_and_the_total_stays_under_twice_the_budget() {
        const MEMBERS: usize = 4096;
        const BYTES: u64 = 1 << 30;
        under(MEMBERS, BYTES, || {
            assert_eq!(budget_for_depth(1).members, MEMBERS / 2);
            assert_eq!(budget_for_depth(1).bytes, BYTES / 2);
            assert_eq!(budget_for_depth(2).members, MEMBERS / 4);

            // The worst case a caller can express: a tree in which every
            // level spends its whole share. Sum the geometric series.
            let total: u64 = (0..=4).map(|d| budget_for_depth(d).members as u64).sum();
            assert!(
                total < 2 * MEMBERS as u64,
                "the tree total {total} must stay under twice the budget {}",
                2 * MEMBERS
            );
        });
    }

    /// The floor is what keeps [`super::MemberSink::with_budget`]'s
    /// `members >= 2` assertion true at any depth, and gives an innermost
    /// container enough room to emit the truncation note.
    #[test]
    fn a_very_deep_container_still_gets_a_usable_floor() {
        under(4096, 1 << 30, || {
            for d in [8usize, 32, 64, 1_000] {
                let b = budget_for_depth(d);
                assert!(b.members >= 2, "members floor at depth {d}: {}", b.members);
                assert!(b.bytes >= 1, "bytes floor at depth {d}: {}", b.bytes);
            }
        });
    }
}
