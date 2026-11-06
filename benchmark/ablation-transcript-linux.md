=== tv-ablate: 2026-10-14T09:22:27Z ===
store=/home/danalec/.rgx-bench/ablate-store root=/home/danalec/.rgx-bench/tree threads=10 rounds=7
arms: base | no-ngram (RGX_ABLATE_NGRAM=1) | no-mask (RGX_ABLATE_MASK=1) | both-off
[ms] = best of 7 paired rounds, arm order rotated, warm cache, wall clock,
output discarded. An arm whose summed -c differs from base's is a false negative
or a superset: its row prints the counts and no timings.
e                | base     71.0 | no-ngram     71.0 | no-mask     69.0 | both-off     66.0 | (ms)
e.               | base    102.0 | no-ngram     98.0 | no-mask     99.0 | both-off     99.0 | (ms)
foo.*bar         | base     51.0 | no-ngram     51.0 | no-mask     50.0 | both-off     49.0 | (ms)
e[0-9]           | base     52.0 | no-ngram     50.0 | no-mask     50.0 | both-off     52.0 | (ms)
a|b              | base     69.0 | no-ngram     73.0 | no-mask     82.0 | both-off     79.0 | (ms)
pub fn           | base     57.0 | no-ngram     58.0 | no-mask     59.0 | both-off     56.0 | (ms)
(pub|fn) [a-z]+  | base     64.0 | no-ngram     67.0 | no-mask     98.0 | both-off     96.0 | (ms)
let mut          | base     47.0 | no-ngram     47.0 | no-mask     49.0 | both-off     48.0 | (ms)
fn main          | base     48.0 | no-ngram     46.0 | no-mask     47.0 | both-off     48.0 | (ms)
