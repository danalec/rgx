# searcher

## Overview
The searcher's own test suite and the differential oracle that holds it to another engine. The searcher itself lives in `../searcher.rs`; this directory holds its two `#[cfg(test)]` modules.

`tests.rs` is the line-contract suite: what a line is, when it is reported, what the terminator does, how context lines are tagged, and what the buffer roll has to carry across a fill boundary. `oracle.rs` is the differential the crate lost with `grep-searcher`, rebuilt against the `regex` crate — which is already a dev-dependency, so it costs nothing new.

The oracle is restricted to where the two engines are specified to agree. rgx is byte-mode; `regex` is Unicode by default and its `.` counts a codepoint where rgx's counts a byte. So the comparison uses ASCII haystacks and patterns with `RegexBuilder` and `.unicode(false)`. What is compared is *which lines matched*, not byte offsets: line splitting is rgx's own job, so a differential on offsets would mostly re-test the tokenizer.

## Interface
- `oracle.rs`:
  - `struct LineNumbers(Vec<u64>)` — a `Sink` that records only the 1-based line numbers reported as matched, in order. The bytes are re-derivable from the line number and the haystack, and comparing them would compare the tokenizer twice.
  - `fn cfg_line_numbers() -> Config` — the searcher configuration the oracle drives: binary detection off, line numbers on.
  - `fn split_lines(hay: &[u8]) -> Vec<&[u8]>` — the oracle's own line split.
  - `fn oracle_lines(pattern: &str, hay: &[u8]) -> Vec<u64>` — the lines the `regex` crate matches.
  - `fn rgx_lines(pattern: &[u8], hay: &[u8]) -> Option<Vec<u64>>` — the lines rgx matches over a slice.
  - `fn rgx_lines_reader(pattern: &[u8], hay: &[u8], chunk: usize) -> Vec<u64>` — the same over the reader path, at a given chunk size.
  - `fn oracle_accepts(pattern: &str) -> bool` — whether the oracle can express the pattern at all.
  - `fn compare(pattern: &str, hay: &[u8]) -> Result<(), String>` — the differential for one pattern/haystack pair.
  - `fn oracle_multiline_lines(pattern: &str, hay: &[u8], dot_all: bool) -> Vec<u64>`, `fn rgx_multiline_lines(...)`, `fn multiline_pass(...)` — the multi-line differential.
  - Tests: `the_searcher_agrees_with_regex_across_the_matrix`, `the_reader_path_agrees_with_the_slice_path_across_the_matrix`, `the_searcher_spans_lines_when_multi_line_is_set`, `multiline_alone_does_not_make_dot_cross_a_newline`, `multi_line_is_off_by_default_and_the_two_answers_differ`, `lookaround_is_refused_rather_than_mis_evaluated`, `the_oracle_matrix_is_ascii_so_the_comparison_is_valid`, `unicode_mode_is_what_would_break_the_comparison_not_the_input_alone`.
- `tests.rs`:
  - `struct Recorded` — a `Sink` that keeps the matched lines and the context lines separately; `matched_lines()`, `context_lines()`.
  - `struct Typed` — a `Sink` that records the context kind (`ContextKind`) as well.
  - `fn cfg_default() -> Config`, `fn run(pattern, hay, config) -> Recorded`, `fn run_typed(...) -> Typed`, `fn run_counted(...) -> (Recorded, u64)`, `fn run_reader_counted(...)`.
  - Tests over the line contract: `reports_the_matching_line_with_its_terminator`, `a_final_line_without_a_terminator_is_still_a_line`, `several_matches_on_one_line_report_the_line_once`, `a_match_in_the_last_line_of_a_buffer_with_no_terminator_is_found`, `an_empty_haystack_reports_nothing`, `inverted_match_reports_the_complement_lines`, `quit_after_bounds_reported_matches`, `a_sink_returning_false_stops_the_search`.
  - Tests over the line numbers: `line_numbers_count_from_one`, `line_numbers_are_reported_when_context_needs_them_and_skipped_otherwise`.
  - Tests over context: `after_context_is_reported_as_context_not_as_a_match`, `after_context_stops_at_the_end_of_the_buffer`, `before_context_precedes_the_match_and_is_tagged_before`, `before_context_respects_the_configured_count`, `before_context_is_none_when_the_match_is_first`, `before_and_after_context_are_tagged_distinctly`, `two_nearby_matches_do_not_reprint_the_shared_line`, `before_context_carries_line_numbers_when_enabled`, `quit_after_still_emits_the_after_context_of_the_last_match`, `quit_after_with_before_context_emits_the_before_context_of_the_first_match`.
  - Tests over binary handling: `binary_quit_ends_the_search_at_a_nul`, `binary_quit_searches_the_prefix_when_the_nul_is_past_the_probe`, `binary_quit_finds_nothing_when_no_line_precedes_the_nul`, `binary_quit_is_a_no_op_when_there_is_no_nul`, `binary_convert_reports_the_nul_and_searches_the_bytes_as_they_are`, `binary_none_treats_a_nul_as_an_ordinary_byte`.
  - Tests over the candidate stream: `a_candidate_stream_finds_the_same_lines_as_the_per_line_path`, `a_candidate_stream_that_reports_nothing_finds_nothing`, `a_line_is_confirmed_from_the_stream_and_never_rescanned`, `the_stream_hands_each_offset_to_exactly_one_line`, `an_every_offset_stream_agrees_with_a_reported_one`, `a_byte_stream_agrees_with_a_reported_one`, `a_byte_occurrence_on_the_terminator_is_not_a_candidate_for_the_line`, `a_match_has_to_fit_inside_the_line_that_offers_it`, `a_matcher_with_no_prefilter_still_finds_every_line`, `the_reader_path_agrees_with_the_slice_path_with_a_stream`, `a_sparse_stream_over_many_lines_finds_every_needle`.
  - Tests over the buffer roll and the skip: `the_reader_path_agrees_with_the_slice_path_on_a_small_input`, `a_match_across_a_buffer_boundary_survives_the_roll`, `the_reader_path_finds_many_lines_across_many_fills`, `a_reader_binary_nul_stops_the_search_at_the_first_buffer`, `a_needle_in_a_line_longer_than_the_buffer_is_found`, `a_buffer_the_anchor_finds_nothing_in_is_skipped`, `a_buffer_the_anchor_finds_something_in_is_not_skipped`, `a_dense_buffer_is_never_skipped`, `a_pattern_with_no_required_literal_is_never_skipped`, `a_pattern_that_matches_an_empty_line_is_never_skipped`, `an_inverted_search_is_never_skipped`, `a_buffer_with_after_context_still_owed_is_not_skipped`, `counting_and_quiet_are_unaffected_by_the_skip`, `line_numbers_survive_a_skipped_reader_buffer`, `a_slice_is_skipped_whole_or_not_at_all`, `a_skipped_buffer_with_no_final_newline_still_counts_its_last_line`, `an_empty_file_is_skipped_and_reports_nothing`, `a_one_byte_file_is_handled_either_way`, `a_match_on_the_last_byte_of_a_buffer_is_found`, `a_match_across_the_64_kib_fill_boundary_is_found`, `before_context_reaches_back_into_a_skipped_buffer`, `the_byte_count_covers_skipped_buffers`, `a_sparse_reader_search_finds_every_needle_with_the_skip_active`.
  - Tests over the jump: `the_jump_agrees_with_the_line_walk_and_actually_fires`, `the_jump_fires_on_slice_searches`, `a_match_is_never_lost_or_duplicated_across_a_jump`, `a_jumped_line_is_numbered_from_its_own_offset_not_the_buffers`, `before_and_after_context_survive_a_jump`, `context_around_a_jumped_gap_is_the_right_lines`, `an_inverted_search_never_jumps_and_still_prints_everything`, `a_match_across_the_64_kib_fill_boundary_is_found_by_the_jump`, `before_context_reaches_back_across_a_jumped_gap`, `the_byte_count_covers_jumped_regions`, `counting_is_unaffected_by_the_jump`.
  - Tests over the match mask and non-ASCII lines: `a_match_mask_settles_a_line_from_its_bits_with_no_confirm`, `a_line_shorter_than_the_mask_offers_nothing_and_one_exactly_its_width_offers_one_bit`, `a_terminator_map_too_short_to_cover_the_region_falls_back_instead_of_reading_past_it`, `no_core_drops_the_whole_buffer_rather_than_retaining_it`, `a_mask_bit_does_not_settle_a_line_the_byte_engine_may_not_decide`, `a_clean_line_without_a_candidate_is_not_a_match`, `a_clean_match_window_settles_a_non_ascii_line_without_the_delegate`, `fn utf8_len(b: u8) -> usize`.
  - Tests over what the searcher will not skip: `a_pattern_with_no_required_literal_is_explicitly_out_of_reach`, `a_nullable_pattern_is_explicitly_out_of_reach`, `a_file_with_no_final_newline_is_numbered_through_its_last_line`, `an_empty_file_and_a_one_byte_file_are_both_uneventful`, `a_match_on_the_last_byte_of_the_buffer_is_found`.
  - Tests over the match shape: `a_pattern_that_can_match_the_terminator_does_not_match_the_line`, `a_pattern_that_is_only_the_terminator_matches_nothing`, `a_match_may_end_on_the_last_content_byte`, `a_greedy_pattern_that_would_swallow_the_terminator_still_matches`, `anchors_are_line_anchors`, `a_nullable_pattern_matches_every_line`.

## Invariants
- A line is terminated by the line terminator, and the terminator is included in the bytes reported to a sink; a final line with no terminator is still a line.
- The search advances by the line, so several matches on one line report that line once.
- Context lines go through `Sink::context` and never through `Sink::matched`.
- A sink that returns `false` from `matched` stops the search.
- The reader path and the slice path must agree: the same haystack produces the same matched lines whether it arrives whole or in chunks.
- A match may end on the last content byte, but a match that would swallow the terminator is rejected for it; anchors are line anchors.
- A skipped buffer (one the anchor finds nothing in) must still be accounted for: its lines count, and the before-context that reaches back into it is still delivered.
- The oracle's skips are cases where the two engines are *specified* to differ; adding a skip for a case that merely turns out to be inconvenient is how the file stops meaning anything.
- Lookaround is refused rather than mis-evaluated, and Unicode mode is the thing that would break the comparison rather than the ASCII input alone.

## Side Effects
- None. Both modules are compiled only under `#[cfg(test)]`, build their haystacks in memory, and touch no file, process or global state.

## Verification
- Run: `cargo test --release --locked --workspace`
