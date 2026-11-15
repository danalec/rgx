# Brotli test vectors

Third-party vectors for `src/brotli/`. Every `.br` file here was written by
the **reference `brotli` CLI, version 1.2.0** (the C implementation, from
Git for Windows), not by anything in this repository and not by a Rust
port. They are committed so the test suite runs with no external tool
installed.

A round trip through our own encoder and decoder would prove nothing about
interoperability: it passes just as happily against a broken
implementation. The module that used to sit here was exactly that mistake --
a literal-only subset of a format it did not implement, which passed its
own round trips and could not read one of these files. These files are the
reason the current decoder is believed to work.

The acceptance bar is **byte-identity against the plaintext**, asserted
twice: once against the decoder in isolation, and once end to end through
`Decompress`, so a change to the call site cannot swap in something the
vectors never tested.

**That bar is about the decoder, and it is not the bar that says rgx can
search a `.br`.** Both assertions stop at `Decompress.extract`, which returns
before anything downstream of the adapter exists. `rgx -c hello brotli_big_q0.br`
reported nothing at all for months on this corpus while every one of these
tests stayed green: the decoder produced all 120,552 bytes correctly, the
adapter handed them on, and the *searcher* then threw them away. What the
corpus needs to cover the search is a property of the payload, not of the
bitstream, and three of the nine payloads have had it all along without
anything asserting it -- see the NUL section under "What the corpus covers".
The check for that is `the_corpus_holds_a_payload_with_a_nul_in_it` here, and
the check that the shipped binary answers for a `.br` the way it answers for
its own payload is `a_brotli_stream_whose_payload_holds_a_nul_is_found_by_the_real_binary`
in `tests/cli.rs`, which runs the real binary.

## Payloads

`brotli_*.plain` and `brotli_*.bin` are the *uncompressed* originals. All
deterministic; no randomness that is not from a fixed seed, no timestamps.

| Payload | Bytes | What it is |
| --- | --- | --- |
| `brotli_empty.plain` | 0 | empty input, so the stream is a header and an end mark |
| `brotli_one.plain` | 1 | `Z`, one byte, the smallest non-empty stream |
| `brotli_tiny.plain` | 2 | `Hi` |
| `brotli_text.plain` | 9280 | Lorem ipsum, compresses ~56:1 |
| `brotli_rep.plain` | 23400 | one 100-byte phrase repeated 234 times -- long matches, tiny output |
| `brotli_rand.bin` | 65536 | pseudo-random (xorshift, fixed seed) -- incompressible, so the reference stores it |
| `brotli_runs.bin` | 55144 | 8 KB of one byte, 4096 short runs, 4 KB of zero, then `AB` pairs -- long copies at small distance |
| `brotli_utf8.plain` | 30044 | nineteen scripts plus emoji, CJK and RTL, so the UTF8 and Signed literal context modes have something to discriminate on |
| `brotli_big.plain` | 120552 | code, a 16 KB pattern repeated, a 5 KB run, a 40 KB random section, then the *same* 16 KB pattern about 90 KB back -- long-distance matches and several meta-blocks in one stream |

## Vectors

Reproduce any row with the command in its `brotli` column, run in this
directory. The reference `-f` flag overwrites.

| Vector | Payload | brotli command | Bytes | What it pins down |
| --- | --- | --- | --- | --- |
| `brotli_text_q0` | text | `brotli -f -k -q 0` | 220 | quality 0, stored (ISUNCOMPRESSED) meta-blocks |
| `brotli_text_q1` | text | `brotli -f -k -q 1` | 180 | quality 1 |
| `brotli_text_q2` | text | `brotli -f -k -q 2` | 173 | quality 2, block splitting starts |
| `brotli_text_q3` | text | `brotli -f -k -q 3` | 154 | quality 3 |
| `brotli_text_q4` | text | `brotli -f -k -q 4` | 154 | quality 4 |
| `brotli_text_q5` | text | `brotli -f -k -q 5` | 165 | quality 5 |
| `brotli_text_q6` | text | `brotli -f -k -q 6` | 165 | quality 6 |
| `brotli_text_q7` | text | `brotli -f -k -q 7` | 165 | quality 7 |
| `brotli_text_q8` | text | `brotli -f -k -q 8` | 165 | quality 8 |
| `brotli_text_q9` | text | `brotli -f -k -q 9` | 165 | quality 9 |
| `brotli_text_q10` | text | `brotli -f -k -q 10` | 163 | quality 10, the static dictionary |
| `brotli_text_q11` | text | `brotli -f -k -q 11` | 168 | quality 11, the static dictionary and its transformations |
| `brotli_text_q11_w10` | text | `brotli -f -k -q 11 -w 10` | 168 | WBITS 10, the smallest window RFC 7932 has |
| `brotli_text_q11_w24` | text | `brotli -f -k -q 11 -w 24` | 168 | WBITS 24, the largest |
| `brotli_text_q5_w0` | text | `brotli -f -k -q 5 -w 0` | 165 | WBITS chosen by the encoder |
| `brotli_text_q5_comment` | text | `brotli -f -k -q 5 -C $(printf 'rgx brotli vector' \| base64)` | 184 | a **metadata** meta-block, whose bytes are neither output nor window |
| `brotli_rep_q0` | rep | `brotli -f -k -q 0` | 94 | repetitive at quality 0 |
| `brotli_rep_q5` | rep | `brotli -f -k -q 5` | 28 | single-symbol literal code, long backward references |
| `brotli_rep_q9` | rep | `brotli -f -k -q 9` | 28 | quality 9 |
| `brotli_rep_q11` | rep | `brotli -f -k -q 11` | 34 | quality 11 |
| `brotli_rand_q0` | rand | `brotli -f -k -q 0` | 65540 | incompressible at quality 0 |
| `brotli_rand_q1` | rand | `brotli -f -k -q 1` | 65540 | incompressible at quality 1 |
| `brotli_rand_q5` | rand | `brotli -f -k -q 5` | 65541 | incompressible at quality 5 |
| `brotli_rand_q9` | rand | `brotli -f -k -q 9` | 65541 | incompressible at quality 9 |
| `brotli_rand_q11` | rand | `brotli -f -k -q 11` | 65541 | incompressible at quality 11 |
| `brotli_runs_q0` | runs | `brotli -f -k -q 0` | 19002 | runs at quality 0 |
| `brotli_runs_q5` | runs | `brotli -f -k -q 5` | 11415 | runs at quality 5 |
| `brotli_runs_q9` | runs | `brotli -f -k -q 9` | 11675 | runs at quality 9 |
| `brotli_runs_q11` | runs | `brotli -f -k -q 11` | 9986 | runs at quality 11 |
| `brotli_utf8_q0` | utf8 | `brotli -f -k -q 0` | 1268 | multi-byte text, quality 0 |
| `brotli_utf8_q1` | utf8 | `brotli -f -k -q 1` | 1202 | multi-byte text, quality 1 |
| `brotli_utf8_q5` | utf8 | `brotli -f -k -q 5` | 974 | multi-byte text, quality 5 |
| `brotli_utf8_q9` | utf8 | `brotli -f -k -q 9` | 962 | multi-byte text, quality 9 |
| `brotli_utf8_q10` | utf8 | `brotli -f -k -q 10` | 941 | multi-byte text, quality 10 |
| `brotli_utf8_q11` | utf8 | `brotli -f -k -q 11` | 905 | multi-byte text, quality 11 |
| `brotli_big_q0` | big | `brotli -f -k -q 0` | 40784 | long-distance matches, quality 0 |
| `brotli_big_q1` | big | `brotli -f -k -q 1` | 40631 | long-distance matches, quality 1 |
| `brotli_big_q5` | big | `brotli -f -k -q 5` | 40625 | long-distance matches, quality 5 |
| `brotli_big_q9` | big | `brotli -f -k -q 9` | 43545 | long-distance matches, quality 9 |
| `brotli_big_q11` | big | `brotli -f -k -q 11` | 40583 | long-distance matches, quality 11 |
| `brotli_one_q11` | one | `brotli -f -k -q 11` | 6 | a single byte |
| `brotli_tiny_q5` | tiny | `brotli -f -k -q 5` | 7 | two bytes |
| `brotli_empty_q9` | empty | `brotli -f -k -q 9` | 2 | empty input |

## What the corpus covers, and what it does not

`the_brotli_corpus_exercises_every_shape_claimed` in `src/lib.rs` counts
what the decode actually reached and fails if a path stops being reached,
so the claim below is checked rather than asserted. On this corpus:

- 35 meta-blocks, of which 7 are stored (ISUNCOMPRESSED) and 1 is metadata
- 109 block switches, so NBLTYPES above 1 in all three categories
- 41 simple prefix codes, 419 complex ones, 21 single-symbol codes
- 12 context maps, every one of them inverse-move-to-front transformed,
  with 158 zero-runs through the RLE path
- every one of the 16 short distance codes, plus NDIRECT and the computed
  distance formula
- 192 static dictionary references across 17 distinct word transformations
- window sizes 10, 14, 15, 16, 17, 18 and 24

One gap, stated rather than papered over: the **MSB6** literal context
mode is not in the corpus, because the reference encoder never chose it for
any payload here. It is a one-line formula in `src/brotli/context.rs`, and
`every_literal_context_mode_is_pinned` covers all four modes directly so
the line is not untested.

### The NUL in the payload, and why it is now asserted

`the_brotli_corpus_exercises_every_shape_claimed` above counts decoder
paths. It cannot count a *payload* property, and the one that mattered was
unasserted until `the_corpus_holds_a_payload_with_a_nul_in_it` was added.
Three of the nine payloads carry a NUL and six do not:

| Payload | First NUL | Consequence when it was missed |
| --- | --- | --- |
| `brotli_big` (120,552 B) | 305 | `rgx -c hello` on all five `brotli_big_q*.br` printed nothing |
| `brotli_rand` (65,536 B) | 51 | every `brotli_rand_q*.br` unsearchable |
| `brotli_runs` (55,144 B) | 8,347 | every `brotli_runs_q*.br` unsearchable |
| `brotli_text`, `brotli_rep`, `brotli_utf8` | none | looked like adequate coverage, and was |

Every NUL is inside the first 64 KiB, which is the window the on-disk binary
heuristic reads, so the payloads that *looked* most thorough -- real code,
a long-distance-match stress, a UTF-8 sweep -- were the ones that hid it and
the payloads a reader would guess were the risky ones were all clean.

The mechanism was never in this directory. `Decompress` returns the decoded
stream as a `Members` outcome whose single member is named after the stripped
stem, so `process` recurses into an extensionless name, no adapter claims it,
and the payload comes back labelled `via: "raw"`. `src/main.rs`'s
`unit_searcher` read that as "these are the file's own bytes" and applied
`BinaryDetection::Quit` -- which reports nothing at all once a NUL sits in the
window, not even the lines before it. Same bytes uncompressed: 20 matches.
Through `.br`: none. The fix is to ask `Found::path` whether the unit is the
file itself, which is the question the label was standing in for.

`brotli --large_window` is deliberately **not** in the corpus. That bitstream
is explicitly not RFC 7932 -- the CLI says so -- so a decoder that claims
RFC 7932 conformance should reject it, and a fixture that decoded would be
evidence the decoder is too permissive.

## The tables

`src/brotli/tables.rs` is generated by `scripts/gen-brotli-tables.py` from
the RFC text itself: the static dictionary (Appendix A), the 121 word
transformations (Appendix B) and the three literal-context lookup tables
(Section 7.1). Each is checked against the CRC-32 the RFC prints next to
it, so a bad transcription fails the generator rather than producing a
decoder that decodes something else.
