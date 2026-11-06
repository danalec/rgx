=== tv-ablate: 2026-10-14T02:59:01Z ===
store=C:\Users\danalec\.rgx-bench\ablate-store root=C:\Users\danalec\.rgx-bench\tree threads=32 rounds=7
arms: base | no-ngram (RGX_ABLATE_NGRAM=1) | no-mask (RGX_ABLATE_MASK=1) | both-off
[ms] = best of 7 paired rounds, arm order rotated, warm cache, wall clock,
output discarded. An arm whose summed -c differs from base's is a false negative
or a superset: its row prints the counts and no timings.
e                | base     63.0 | no-ngram     63.0 | no-mask     62.0 | both-off     62.0 | (ms)
e.               | base     67.0 | no-ngram     66.0 | no-mask     66.0 | both-off     66.0 | (ms)
foo.*bar         | base     58.0 | no-ngram     58.0 | no-mask     58.0 | both-off     57.0 | (ms)
e[0-9]           | base     57.0 | no-ngram     57.0 | no-mask     57.0 | both-off     57.0 | (ms)
a|b              | base     62.0 | no-ngram     63.0 | no-mask     63.0 | both-off     62.0 | (ms)
pub fn           | base     61.0 | no-ngram     62.0 | no-mask     61.0 | both-off     61.0 | (ms)
(pub|fn) [a-z]+  | base     63.0 | no-ngram     63.0 | no-mask     72.0 | both-off     72.0 | (ms)
let mut          | base     54.0 | no-ngram     54.0 | no-mask     54.0 | both-off     55.0 | (ms)
fn main          | base     57.0 | no-ngram     57.0 | no-mask     57.0 | both-off     57.0 | (ms)
