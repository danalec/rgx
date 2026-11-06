# RuleBankMask — multi-rule shared nibble-cover scanner (`rgx-core::rulebank`)

Direction 2 of the post-SOTA roadmap. One new module,
`crates/rgx-core/src/rulebank.rs`, plus the `pub mod rulebank;` line in
`crates/rgx-core/src/lib.rs` (placed alphabetically, between `required` and
`scan`). No other file touched.

## API shipped

```rust
// One shared nibble-cover plane: the (lo_lut, hi_lut) pair a byte class
// compiles to. Exact: passes(b) iff b is a member of the class.
pub struct Plane { lo_lut: [u16; 16], hi_lut: [u16; 16] }
impl Plane {
    pub fn from_class(class: &ByteClass) -> Self;   // scan::ByteClass
    pub fn passes(&self, b: u8) -> bool;
    pub fn lo_lut(&self) -> &[u16; 16];
    pub fn hi_lut(&self) -> &[u16; 16];
}

pub struct RuleSpec<'a> {
    pub pattern: &'a str,
    pub case_insensitive: bool,
}

pub struct RuleHit { pub rule: usize, pub start: usize, pub end: usize }

pub struct RuleBank { /* planes, per-rule plans+matchers, n-gram queries */ }
impl RuleBank {
    pub fn build(rules: &[RuleSpec<'_>]) -> Result<Self>;      // crate::Result
    pub fn rule_count(&self) -> usize;
    pub fn unique_planes(&self) -> usize;
    pub fn total_conditions(&self) -> usize;
    pub fn screen(&self, file_sig: &NgramSig512) -> Vec<usize>;
    pub fn candidates(&self, hay: &[u8]) -> Vec<(usize, usize)>;          // (rule, offset)
    pub fn candidates_subset(&self, hay: &[u8], rules: &[usize]) -> Vec<(usize, usize)>;
    pub fn search(&self, hay: &[u8]) -> Vec<RuleHit>;                     // confirmed
    pub fn search_subset(&self, hay: &[u8], rules: &[usize]) -> Vec<RuleHit>;
    pub fn matcher(&self, rule: usize) -> &ByteRegex;                     // caller-side confirm
}
```

CLI flow the API is designed for: `build` once per rule set (per process,
shared across the walk; the bank is `Send + Sync` by construction), then per
file `screen(&file_sig)` -> surviving rule indices ->
`search_subset(file_bytes, &survivors)` -> hits. A caller that wants its own
confirm loop takes `candidates` + `matcher(rule)`.

`build` fails only on an uncompilable pattern (naming the rule, via
`crate::anyhow!`); a rule the mask analysis declines is not an error.

## What is prefiltered vs confirmed

- **Prefiltered (may over-report, FNR = 0):** the candidate offsets.
  Extraction reuses `required::match_mask` — the exact plan the
  single-pattern `scan::MatchMask` consumes — so a rule's conditions are the
  byte classes *every* match of a branch must hold at known offsets. A
  branch = AND over shifted plane masks; a rule = OR over branches. A
  candidate offset satisfies one branch but need not be a match.
- **Confirmed (exact):** `RuleBank::search` runs each rule's own
  `ByteRegex` (`Matcher::find_span_at`) on each candidate, so its hits are
  exactly what the matcher reports alone: leftmost-first, non-overlapping,
  per rule.
- **Upstream screen (may over-report, never loses):** `screen` asks
  `NgramSig512::contains_query` per rule with the rule's
  `ngram::query_sig512` (built from `required::anywhere`). A rule whose
  query is `None` (folded literal, no 4-byte required literal) always
  survives; an all-zero file signature admits every rule. `None` means "do
  not filter", never "nothing matches" — ngram.rs's law, inherited.
- **Unconditional rules:** `required::match_mask` declines some shapes (an
  assertion anywhere, empty-matching patterns). Such a rule gets every
  offset `0..=hay.len()` as candidate and is filtered only by its matcher.

## The three stages, as implemented

1. **Cross-rule plane dedup.** `Plane::from_class` is `scan::ByteClass::tables`'
   nibble scheme (its doc comment) widened from 8 to 16 mask bits so no
   class is refused; the pair is exact (`passes` = class membership).
   `build` interns identical `(lo_lut, hi_lut)` pairs once for the bank —
   one evaluated plane feeds every rule that references it.
2. **Single-pass register bank.** `scan()` walks 64-byte blocks of candidate
   starts. Per block each unique plane is evaluated ONCE over the block's
   read window (the block plus the bank's widest condition shift) into one
   bitmask; per rule the branch conditions AND the shifted bitmasks
   (condition at offset k reads the plane's mask shifted by k); a block whose
   union of all rules' candidate masks is zero is early-outed before any
   emit or confirm. Reads past the window/haystack read as zero bits, so a
   condition reaching past EOF fails instead of aliasing.
3. **Union upstream screen.** as above.

The FNR argument is a superset chain: plane = exact class (never fewer
bytes) x conditions are required of every match of their branch x OR over
branches x confirm is the rule's own matcher. The paper's Theorem 4.1
(FNR = 0 for the single-pattern mask) is inherited rule by rule; the tests
below hold it against the matcher alone.

## Measured dedup numbers (100-rule bank)

Bank: 104 realistic secret/credential/PII rules written literally in
`tests::a_hundred_realistic_rules_compile_with_far_fewer_unique_planes_than_conditions`
(AWS/GCP key shapes, GitHub/GitLab/CI tokens, OpenAI/Anthropic/Google/HF
tokens, Slack/Stripe/Twilio/SendGrid/Mailgun, npm/PyPI/DO registries, JWTs,
PEM markers/SSH keys, hex/UUID/hash runs, secret assignments, connection
strings, base64 blobs, PII: emails, IPv4, credit-card-like digit runs, SSN,
phones, auth headers).

| figure | value |
|---|---|
| rules | 104 |
| total conditions (every `(plane, offset)` instance) | 2195 |
| unique planes after cross-rule dedup | 73 |
| ratio | **3.3%** (1 plane per ~30 conditions) |

Asserted margin in the test: `unique * 20 <= total` (unique planes <= 5% of
conditions), i.e. the measured number with headroom, so the claim cannot rot
into a rounding error. Most of the margin comes from unrolled repeats
(`AKIA[0-9A-Z]{16}` alone is 20 conditions -> 4 planes) and from byte
classes shared across rules (hex, `[0-9]`, `[A-Z]`-row shapes, base64url
vs base64 classes are distinct planes here because the plane pair is exact
— sharing is class-identity, not projection-identity).

## FNR test design

`tests::every_match_of_every_rule_survives_the_bank_as_a_hit_and_a_candidate`:

- **Bank (11 rules):** literal+repetition (`AKIA[0-9A-Z]{16}`), alternation
  (`secret_(id|token)=`), char classes + unbounded repeat
  (`[0-9a-fA-F]{32,}`), class inside literals (`-----BEGIN [A-Z ]+-----`),
  sliding tail (`eyJ[A-Za-z0-9_-]+\.`), folded literal (`(?i)password=`),
  an assertion the analysis declines (`\bAKIA...`), an empty-matching
  pattern (`x*`), an email shape, and two overlap/leftmost-first shapes
  (`abcd|b`, `(foo|foobar)bar`).
- **Haystack matrix (~30):** empty, prose, credential-shaped text, dense
  hex and `AKIA` carpets, JWT, email, mixed-case assignments, the same
  credential at padding lengths 0..129 so a match straddles every 64-byte
  seam, and three deterministic LCG noise buffers (64/65/257 bytes).
- **Oracle:** each rule's `ByteRegex` walked independently (leftmost-first,
  non-overlapping `find_span_at` loop) — no bank in the path.
- **Assertions:** bank hits == oracle hits per rule per haystack (exact
  span equality), every oracle match start is in `candidates`, and a
  non-vacuity floor: **2916 true match starts checked** (asserted >= 50).

Supporting tests: `a_plane_accepts_exactly_the_bytes_of_its_class` (plane =
class over all 256 bytes), screen semantics (zero sig admits all; file with
only rule j's literal keeps j and prunes only the impossible; `None`-query
rule survives), early-out (`!`x300 haystack -> zero candidates, zero hits,
no panic; empty haystack too), and `fuzz::never_panics_on_arbitrary_bytes`
(`fuzzkit::assert_never_panics`, 2000 rounds x 3 fixtures, small bank =
planned + declined + empty-matching rules; drives candidates, search and
screen).

## Verification (run in the worktree)

| command | result |
|---|---|
| `cargo fmt --all -- --check` | pass (exit 0) |
| `cargo clippy -p rgx-core --all-targets -- -D warnings` | pass (exit 0, no warnings) |
| `cargo test -p rgx-core --release` | **698 passed, 0 failed, 6 ignored** (unit) + **5 doc-tests passed** |

The 698 unit tests include the 6 new `rulebank` tests (5 in `tests` + 1 in
`fuzz`); rgx-core stood at 692 passing before this change on this commit.
Note AGENTS.md §6's snapshot says 696 for rgx-core — that snapshot rots
(per its own warning) and was not re-snapped here.

## Follow-ups left open

- **SIMD plane fill.** The per-block plane evaluation is a scalar per-byte
  loop into a `u64` bitmask. The `pshufb` pair of `scan::ByteClass::tables`
  is the vectorized form of the same LUT scheme and would slot into
  `Plane` unchanged; not built because correctness was the deliverable and
  the repo's benchmarking rules require a measured number before a kernel
  rewrite (`pair_offsets` is already 40-46 GB/s; a rewrite gains nothing
  until this fill is measured as the bottleneck).
- **Mask widths beyond `u64` blocks.** Conditions read up to
  `max_shift` bytes past a block; the window scratch grows as
  `ceil((64 + max_shift)/64)` words per plane. A bank of pathological rules
  (e.g. `{200,}` unrolls) pays a wider window. A cap that drops the
  furthest conditions (sound: fewer conditions = more candidates) is the
  cheap fix if a real rule set ever trips it.
- **`decides` is ignored on purpose.** A `MaskPlan` that decides could skip
  the confirm entirely (a set bit is a match). The bank currently confirms
  every candidate uniformly; honoring `decides` per rule is a sound
  optimization (the single-pattern path does it) but needs the same
  line-cut reasoning as `MatchMask::line_cut` before it can settle a line,
  so it was left out rather than half-done.
- **Screen + walk integration.** `screen` consumes a stored
  `NgramSig512` (`build_stored_sig512`, BOM-aware) exactly as the TV pack
  manifest carries it; wiring it into `--serve`/the walk is caller-side and
  not part of this module.
