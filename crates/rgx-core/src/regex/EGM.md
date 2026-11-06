# regex

## Overview
The differential suite for the byte-mode regex engine. The engine itself lives in `../regex.rs`; this directory holds its `#[cfg(test)]` module — the file that holds the ranged pre-confirm and the surrounding anchor machinery to the claims the engine's own headers make.

The ranged check's correctness claim is the same law every other prefilter is held to — a byte every match contains, at an offset that may be a range — and the proof of that is `required.rs`'s property test over the trap grid. What is here is the other half: that the check is *built*, that it is built for the right range, and that the shapes it must decline are declined on purpose. None of that is observable in a differential, because a check that rejects nothing returns the same answers as one that rejects correctly.

The suite is therefore not a differential against another engine but a set of assertions about the engine's own construction: that a variable-length prefix builds a ranged check, that a pattern with nothing to range over gets none, that a ranged check never rejects a position the VM accepts, and that it never reads past the end of a line. The remainder holds the anchor selection, the candidate stream and the case-folding behaviour as assertions of the same kind; only the glob translation is compared against the `regex` crate, which is already a dev-dependency, and the replacement templates are pinned to hand-written expected strings.

## Interface
- `fn fast(re: &ByteRegex) -> &FastLiteral` — the pattern's prefilter, borrowed from the regex the caller keeps alive.
- `fn text(bytes: &[u8]) -> String` — the lossy UTF-8 rendering used when a test has to name bytes.
- Tests over the ranged pre-confirm: `a_variable_length_prefix_builds_a_ranged_check`, `a_pattern_with_nothing_to_range_over_gets_no_ranged_check`, `a_ranged_check_never_rejects_a_position_the_vm_accepts`, `a_ranged_check_never_reads_past_the_end_of_a_line`.
- Tests over the substring anchor: `a_substring_anchor_is_only_built_once_and_only_known_when_its_offset_is`, `a_caseless_literal_never_becomes_a_known_substring_anchor`, `a_substring_scan_reports_every_occurrence_including_overlapping_ones`, `an_overlapping_required_literal_is_still_a_candidate`, `an_overlapping_literal_behind_an_unknown_offset_is_still_a_candidate`.
- Tests over the anchor plan: `a_pattern_with_no_ranged_path_still_answers_every_position`, `the_confirm_price_moves_exactly_the_anchors_it_is_supposed_to`, `the_remembered_plan_is_the_measured_plan`, `e_09_candidates_are_a_tie_the_prices_break`, `an_unrepresentative_fill_pools_rather_than_replaces`.
- Tests over syntax and replacement: `unicode_mode_flags_parse_as_no_ops`, `translated_globs_run_against_the_oracle`, `escape_round_trips_the_literal_bytes`, `replacement_templates_expand_like_rg`, `a_grouped_repetition_does_not_pin_what_follows_it`, `the_flagship_mask_still_decides`, `captures_iter_is_non_overlapping`, `foo_dot_star_bar_direct_confirmation_and_quenching`, `two_byte_literal_maps_candidates`.

## Invariants
- A ranged check must never reject a position the Pike VM accepts: the check is a *filter*, and a filter that rejects a real match is a wrong answer, not a slow one.
- A ranged check must never read past the end of the line it is offered.
- The ranged vector is asserted to be non-empty for the pattern it was built for, at the range it was built for — a check that rejects nothing returns the same answers as a correct one, so only the count can say the optimisation happened.
- A caseless literal never becomes a known-substring anchor: the prefilter found `em` and not `EM` once, which is not slow but wrong, and the differential suite did not catch it because no case in it had a caseless literal behind an unknown offset.
- A substring anchor is built once, and its offset is known only when the anchor's position in the pattern is fixed.
- The candidate stream does not change the result: a match is not a literal match, so a searcher must confirm every candidate with the full matcher, and the candidate stream is a prefilter over them.
- The one oracle comparison is against the `regex` crate's `bytes` API with no builder options, over ASCII inputs and a pattern that carries the `(?-u)` flag, because rgx is byte-mode and the two engines are only *specified* to agree there.

## Side Effects
- None. The suite is compiled only under `#[cfg(test)]`, builds its haystacks in memory, and touches no file, process or global state.

## Verification
- Run: `cargo test --release --locked --workspace`
