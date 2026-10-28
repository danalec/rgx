// SPDX-License-Identifier: Apache-2.0

//! Which files a query searches, which packs they live in, and how those packs
//! are cut into claimable pieces.
//!
//! This is the whole planner of a pack query, and none of it reads a byte: it
//! turns a decoded manifest and a [`SearchConfig`] into a table of units that
//! workers claim. Holding it here rather than in `rgx-tv` is not tidiness —
//! the boundary invariant the paper states is enforced by [`cut_units`], and
//! the one predicate that decides membership ([`kept_flags`]) is the single
//! place a file can be dropped, so a decoded record and a locator cannot
//! disagree about it.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::tv::format::{FileLoc, FileRecord, Manifest, ManifestHead, RawManifest};
use crate::tv::query::{SearchConfig, SearchMatch};

/// Concatenate the buckets in key order. The key says *where*, so the generic
/// bound is the whole contract: a path that keys by pack keeps pack order, and
/// the buffered path keys by pack and offset because its units are finer.
///
/// Every mode keys its result buckets by the claim itself and concatenates
/// them in that order, so two runs of the same query on the same store
/// print the same bytes in the same order.
pub fn merge_buckets<K: Ord>(
    mut buckets: Vec<(K, Vec<SearchMatch>)>,
    total_lines: usize,
) -> Vec<SearchMatch> {
    buckets.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out: Vec<SearchMatch> = Vec::with_capacity(total_lines);
    for (_, mut b) in buckets {
        out.append(&mut b);
    }
    out
}

/// Splits a manifest's records into the ones that reach the worker loop and the
/// 0-byte ones. Takes the records by value: the cold path moves them.
pub fn split_owned(
    files: Vec<FileRecord>,
    config: &SearchConfig,
) -> (Vec<FileRecord>, Vec<FileRecord>) {
    let mut active = Vec::new();
    let mut empty = Vec::new();
    for f in files {
        if !kept(&f, config) {
            continue;
        }
        if f.is_empty {
            empty.push(f);
        } else {
            active.push(f);
        }
    }
    (active, empty)
}

/// Whether a record is searched at all: not deleted, not binary unless asked,
/// and not over `-M`. One predicate, because the two splitters below are the
/// only two places a file can be dropped and they must drop the same ones.
#[inline]
pub fn kept(f: &FileRecord, config: &SearchConfig) -> bool {
    kept_flags(f.is_deleted, f.is_binary, f.length, config)
}

#[inline]
pub fn kept_loc(f: &FileLoc, config: &SearchConfig) -> bool {
    kept_flags(f.is_deleted(), f.is_binary(), f.length, config)
}

/// One predicate over the three properties that decide membership, so a
/// decoded record and a locator cannot disagree about it.
#[inline]
pub fn kept_flags(is_deleted: bool, is_binary: bool, length: u64, config: &SearchConfig) -> bool {
    if is_deleted {
        return false;
    }
    if !config.search_binary && is_binary {
        return false;
    }
    match config.max_file_size {
        Some(max) if length > max => return false,
        _ => {}
    }
    true
}

/// Applies [`kept`] to a cached index of file records, for a pool whose index
/// was built under different limits than this query carries.
pub fn narrow(idx: &[u32], manifest: &Manifest, config: &SearchConfig) -> Vec<u32> {
    if config.search_binary && config.max_file_size.is_none() {
        return idx.to_vec();
    }
    idx.iter()
        .copied()
        .filter(|&i| kept(&manifest.files[i as usize], config))
        .collect()
}

/// The same split as [`split_owned`], over locators rather than decoded
/// records - the query path, where no path has been decoded. Returns indices
/// into `locs`: the ones that reach the worker loop, and the 0-byte ones.
pub fn split_locs(locs: &[FileLoc], config: &SearchConfig) -> (Vec<u32>, Vec<u32>) {
    let mut active = Vec::with_capacity(locs.len());
    let mut empty = Vec::new();
    for (i, f) in locs.iter().enumerate() {
        if !kept_loc(f, config) {
            continue;
        }
        if f.is_empty() {
            empty.push(i as u32);
        } else {
            active.push(i as u32);
        }
    }
    (active, empty)
}

/// The pre-plan filter: the one n-gram rule ([`crate::ngram::may_reject`])
/// asked over the plan's records before a single byte is planned for
/// reading. A rejected record leaves a hole in the plan, and [`cut_units`]
/// is free to leave holes unread; a surviving record keeps its whole span
/// inside a unit, which is the boundary invariant.
///
/// Coverage follows the raw-bytes rule ([`crate::ngram::covered_raw_bytes`])
/// because the pack search reads the record's own bytes: any signature the
/// format writes covers those. `rollup_ok` is the extraction-fingerprint
/// half of the rollup trust question. `RGX_ABLATE_EXTENTS` stands the whole
/// step down - nothing is rejected and the plan reads as it always did -
/// under the ablation contract: cost may change, answers never do.
pub fn prune_by_ngram(
    active: Vec<u32>,
    locs: &[FileLoc],
    query: Option<&crate::ngram::NgramSig512>,
    rollup_ok: bool,
) -> (Vec<u32>, usize) {
    if crate::ablate_extents() {
        return (active, 0);
    }
    let Some(q) = query else {
        return (active, 0);
    };
    let mut pruned = 0usize;
    let mut out = Vec::with_capacity(active.len());
    for i in active {
        let f = &locs[i as usize];
        if crate::ngram::may_reject(
            &f.ngram,
            crate::ngram::covered_raw_bytes(f.sig_covers_adapter(), rollup_ok),
            q,
        ) {
            pruned += 1;
        } else {
            out.push(i);
        }
    }
    (out, pruned)
}

#[derive(Clone, Copy)]
pub struct Unit {
    /// Position in `table.order` — the pack, for its path and length.
    pub pack: u32,
    /// `files[first..last]` in the plan, ascending, and the first file's offset
    /// is where this unit starts.
    pub first: u32,
    pub last: u32,
    /// Byte range within the pack payload: `start..start + len`.
    ///
    /// A pack is a u64 range by construction — the builder gives a file
    /// larger than the pack target a dedicated pack of its own, and an LLM
    /// checkpoint shard is routinely past 4 GiB. These were `u32` once, and
    /// the cast silently searched only the first 4 GiB of such a pack.
    pub start: u64,
    pub len: u64,
}

/// The size a claim aims for, in bytes. A file larger than this is a unit of
/// its own: it cannot be cut without breaking the boundary invariant, and
/// pretending otherwise would make a unit that holds a piece of a file.
pub const UNIT_BYTES: u32 = 1 << 20;

/// The largest hole between two planned files a unit may span, in bytes.
///
/// The hole is bytes belonging to records the plan dropped -- the n-gram
/// filter's rejects. Below the threshold the bytes are read anyway: one
/// extent per surviving file would cost more in claims and syscalls than
/// the skip saves on a pack that is read sequentially. At the threshold
/// the unit ends and the hole is never paid for. 64 KiB is where a skip
/// stops being arguable on any disk the store targets: it is four pages,
/// less than one NVMe request, and a rejected run of small files above it
/// is exactly the shape the filter's separation leaves behind.
pub const MAX_EXTENT_GAP: u32 = 64 * 1024;

/// Which packs to read, in what order, and which files each one answers for.
pub struct PackPlan {
    /// The manifest as it was read, so a result can decode the name of the
    /// file it belongs to. Held rather than dropped: this is the buffer the
    /// paths are slices of.
    pub raw: Arc<RawManifest>,
    /// Every file's fixed fields, in manifest order.
    pub locs: Arc<Vec<FileLoc>>,
    /// Indices into `locs`, ascending within each pack's run.
    pub files: Vec<u32>,
    /// Pack `p`'s files are `files[bounds[p] .. bounds[p + 1]]`. An empty range
    /// means every file in that pack was skipped: deleted, 0-byte or binary.
    pub bounds: Vec<u32>,
    /// The claimable pieces of every pack, longest first, which is the greedy
    /// order for a fixed set of workers and the same one the pack queue used.
    pub units: Vec<Unit>,
}

impl PackPlan {
    pub fn build(
        raw: Arc<RawManifest>,
        head: &ManifestHead,
        locs: Arc<Vec<FileLoc>>,
        active: &[u32],
    ) -> PackPlan {
        let np = head.packs.len();

        // `pack_id` to position, by direct index rather than by hash. The
        // ids are a dense range the manifest itself defines, so the hash
        // was pure overhead. The table is one allocation of `max_id + 1`
        // and a miss is a sentinel rather than a `None`.
        let max_id = head.packs.iter().map(|p| p.pack_id).max().unwrap_or(0) as usize;
        let mut slot_of = vec![u32::MAX; max_id + 1];
        for (pos, p) in head.packs.iter().enumerate() {
            slot_of[p.pack_id as usize] = pos as u32;
        }

        let mut counts = vec![0u32; np];
        for &fi in active {
            let id = locs[fi as usize].pack_id as usize;
            if let Some(&pos) = slot_of.get(id) {
                if pos != u32::MAX {
                    counts[pos as usize] += 1;
                }
            }
        }

        let mut bounds = vec![0u32; np + 1];
        for i in 0..np {
            bounds[i + 1] = bounds[i] + counts[i];
        }

        // `active` is ascending, so every pack's run comes out ascending too.
        let mut files = vec![0u32; bounds[np] as usize];
        let mut fill: Vec<u32> = bounds[..np].to_vec();
        for &fi in active {
            let id = locs[fi as usize].pack_id as usize;
            if let Some(&pos) = slot_of.get(id) {
                if pos != u32::MAX {
                    let w = &mut fill[pos as usize];
                    files[*w as usize] = fi;
                    *w += 1;
                }
            }
        }

        let units = cut_units(&files, &bounds, &locs);
        PackPlan {
            raw,
            locs,
            files,
            bounds,
            units,
        }
    }
}

/// Cut every pack's file run into units of at most [`UNIT_BYTES`], at file
/// boundaries, longest unit first.
///
/// The cut is a single pass over the file run: a unit grows until the next
/// file would take it past the target, and then the file starts the next
/// one. A file bigger than the target is a unit by itself rather than a cut
/// one -- the loop below cannot split it, and a unit holding part of a file
/// would report that file twice. A gap of [`MAX_EXTENT_GAP`] or more
/// between one file's end and the next file's start also ends the unit:
/// those bytes are the plan's rejects and reading them is the cost the
/// sparse read exists to remove. Every file sits whole inside exactly one
/// unit -- the boundary invariant -- so a cut can lose bytes of a hole and
/// never bytes of a file.
pub fn cut_units(files: &[u32], bounds: &[u32], locs: &[FileLoc]) -> Vec<Unit> {
    let mut units: Vec<Unit> = Vec::with_capacity(bounds.len());
    for p in 0..bounds.len().saturating_sub(1) {
        let (from, to) = (bounds[p] as usize, bounds[p + 1] as usize);
        let mut k = from;
        while k < to {
            let first = k;
            let start = locs[files[k] as usize].offset;
            let mut end = start;
            while k < to {
                let f = &locs[files[k] as usize];
                let f_end = f.offset.saturating_add(f.length);
                if k > first {
                    // A hole at or past the threshold ends the unit rather
                    // than being read. `RGX_ABLATE_EXTENTS` spans every
                    // hole: the ablation's arm reads the whole pack exactly
                    // as the plan always did.
                    if !crate::ablate_extents()
                        && f.offset.saturating_sub(end) >= u64::from(MAX_EXTENT_GAP)
                    {
                        break;
                    }
                    // A file that does not fit joins the next unit; a file that is
                    // bigger than a whole unit is one by itself, because there is
                    // no legal cut inside it.
                    if f_end.saturating_sub(start) > u64::from(UNIT_BYTES) {
                        break;
                    }
                }
                // `max` because `end` is the furthest byte reached, not the
                // last file's own end: a manifest whose offsets do not
                // ascend must not shrink a unit below its own start.
                end = end.max(f_end);
                k += 1;
            }
            units.push(Unit {
                pack: p as u32,
                first: first as u32,
                last: k as u32,
                start,
                len: end.saturating_sub(start),
            });
        }
    }
    units.sort_by_key(|u| core::cmp::Reverse(u.len));
    units
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ngram::{build_stored_sig512, query_sig512};
    use crate::tv::format::FileLoc;

    fn loc(id: u64, offset: u64, length: u64) -> FileLoc {
        FileLoc::test_loc(id, 0, offset, length, 0)
    }

    fn with_sig(mut f: FileLoc, text: &[u8]) -> FileLoc {
        f.ngram = build_stored_sig512(text).into_words();
        f
    }

    #[test]
    fn a_gap_at_the_threshold_ends_the_unit_and_one_under_it_does_not() {
        let at = u64::from(MAX_EXTENT_GAP);
        let under = u64::from(MAX_EXTENT_GAP - 1);

        // The hole is the space between the first file's end and the second
        // file's start: exactly at the threshold it is skipped, one byte
        // under it the read spans it.
        let locs = vec![loc(0, 0, 100), loc(1, 100 + at, 50)];
        let units = cut_units(&[0, 1], &[0, 2], &locs);
        assert_eq!(
            units.len(),
            2,
            "a hole exactly at MAX_EXTENT_GAP must end the unit, not be read"
        );

        let locs = vec![loc(0, 0, 100), loc(1, 100 + under, 50)];
        let units = cut_units(&[0, 1], &[0, 2], &locs);
        assert_eq!(
            units.len(),
            1,
            "a hole one byte under MAX_EXTENT_GAP must be read with its files"
        );
    }

    #[test]
    fn a_chain_of_small_gaps_collapses_into_one_unit() {
        // f0 [0,100), f1 [110,210), f2 [220,320): two 10-byte holes.
        let locs = vec![loc(0, 0, 100), loc(1, 110, 100), loc(2, 220, 100)];
        let units = cut_units(&[0, 1, 2], &[0, 3], &locs);
        assert_eq!(units.len(), 1, "small holes merge into one extent");
        assert_eq!((units[0].start, units[0].len), (0, 320));
    }

    #[test]
    fn every_file_sits_whole_inside_exactly_one_unit() {
        let locs = vec![
            loc(0, 0, 100),
            loc(1, 200, 50),
            loc(2, 100_000, 50),
            loc(3, 100_100, 10),
        ];
        let units = cut_units(&[0, 1, 2, 3], &[0, 4], &locs);
        for (i, f) in locs.iter().enumerate() {
            let covering: Vec<&Unit> = units
                .iter()
                .filter(|u| (u.first..u.last).contains(&(i as u32)))
                .collect();
            assert_eq!(
                covering.len(),
                1,
                "file {i} must be claimed by exactly one unit"
            );
            let u = covering[0];
            let (s, e) = (u.start, u.start + u.len);
            assert!(
                f.offset >= s && f.offset + f.length <= e,
                "file {i} must sit whole inside its unit's byte range"
            );
        }
        for u in &units {
            let (s, e) = (u.start, u.start + u.len);
            assert!(
                !(s < 250 && e > 100_000),
                "no unit may span the hole past the threshold"
            );
        }
    }

    #[test]
    fn the_pre_plan_filter_leaves_holes_the_cut_never_reads() {
        let q = query_sig512("needle", false).expect("a literal query has a signature");
        let a = with_sig(loc(0, 0, 100), b"needle at the start");
        let b = with_sig(loc(1, 100, 70_000), b"nothing to see here at all");
        let c = with_sig(loc(2, 70_100, 100), b"needle at the end");
        let locs = vec![a, b, c];

        let (kept, pruned) = prune_by_ngram(vec![0, 1, 2], &locs, Some(&q), true);
        assert_eq!(
            pruned, 1,
            "the record without the needle's grams is rejected"
        );
        assert_eq!(kept, vec![0, 2]);

        let units = cut_units(&kept, &[0, 2], &locs);
        assert_eq!(
            units.len(),
            2,
            "the rejected record's 70,000-byte span is a hole the cut skips"
        );
        let read: u64 = units.iter().map(|u| u.len).sum();
        assert_eq!(
            read, 200,
            "only the kept spans are read; the hole is never paid for"
        );
    }

    #[test]
    fn a_small_hole_is_read_rather_than_issued_around() {
        let q = query_sig512("needle", false).expect("a literal query has a signature");
        let a = with_sig(loc(0, 0, 100), b"needle at the start");
        let b = with_sig(loc(1, 100, 1_000), b"nothing to see here at all");
        let c = with_sig(loc(2, 1_100, 100), b"needle at the end");
        let locs = vec![a, b, c];

        let (kept, pruned) = prune_by_ngram(vec![0, 1, 2], &locs, Some(&q), true);
        assert_eq!((kept.as_slice(), pruned), (&[0u32, 2u32][..], 1));
        let units = cut_units(&kept, &[0, 2], &locs);
        assert_eq!(
            units.len(),
            1,
            "a hole under the threshold is read with its neighbours: one \
             extent per surviving file would cost more than the skip saves"
        );
    }

    #[test]
    fn a_rollup_under_a_foreign_fingerprint_is_never_rejected() {
        let q = query_sig512("needle", false).expect("a literal query has a signature");
        let plain = with_sig(loc(0, 0, 100), b"nothing to see here at all");
        let rollup = with_sig(
            FileLoc::test_loc(1, 0, 100, 100, FileLoc::SIG_COVERS_ADAPTER),
            b"nothing to see here at all",
        );
        let locs = vec![plain, rollup];

        // Without the fingerprint match only the plain record may fall.
        let (kept, pruned) = prune_by_ngram(vec![0, 1], &locs, Some(&q), false);
        assert_eq!(pruned, 1);
        assert_eq!(
            kept,
            vec![1],
            "a rollup the query cannot vouch for must stand unfiltered"
        );

        // With it, both are ordinary covered records.
        let (kept, pruned) = prune_by_ngram(vec![0, 1], &locs, Some(&q), true);
        assert_eq!(pruned, 2);
        assert!(kept.is_empty());
    }

    #[test]
    fn the_ablation_rejects_nothing() {
        let _guard = crate::ABLATE_EXTENTS_LOCK.lock().unwrap();
        let q = query_sig512("needle", false).expect("a literal query has a signature");
        let a = with_sig(loc(0, 0, 100), b"nothing to see here at all");
        let locs = vec![a];

        let (_, pruned) = prune_by_ngram(vec![0], &locs, Some(&q), true);
        assert_eq!(pruned, 1);

        crate::set_ablate_extents(true);
        let (kept, pruned) = prune_by_ngram(vec![0], &locs, Some(&q), true);
        // The gap rule stands down too: a hole the plan would skip is
        // spanned, which is what "reads the whole pack as it always did"
        // means.
        let hole = vec![loc(0, 0, 100), loc(1, 100 + u64::from(MAX_EXTENT_GAP), 50)];
        let units = cut_units(&[0, 1], &[0, 2], &hole);
        crate::set_ablate_extents(false);
        assert_eq!(
            pruned, 0,
            "the ablation's cost is the plan, never the answer"
        );
        assert_eq!(kept, vec![0]);
        assert_eq!(
            units.len(),
            1,
            "under the ablation no hole is skipped, at any size"
        );
    }
}
