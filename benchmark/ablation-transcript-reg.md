=== tv-ablate: 2026-10-14T03:00:17Z ===
store=C:\Users\danalec\.rgx-bench\ablate-store-reg root=C:\Users\danalec\.cargo\registry\src threads=10 rounds=7
arms: base | no-ngram (RGX_ABLATE_NGRAM=1) | no-mask (RGX_ABLATE_MASK=1) | both-off
[ms] = best of 7 paired rounds, arm order rotated, warm cache, wall clock,
output discarded. An arm whose summed -c differs from base's is a false negative
or a superset: its row prints the counts and no timings.
e                | base    181.0 | no-ngram    180.0 | no-mask    181.0 | both-off    181.0 | (ms)
e.               | base    211.0 | no-ngram    212.0 | no-mask    208.0 | both-off    209.0 | (ms)
foo.*bar         | base    143.0 | no-ngram    144.0 | no-mask    143.0 | both-off    143.0 | (ms)
e[0-9]           | base    149.0 | no-ngram    149.0 | no-mask    148.0 | both-off    148.0 | (ms)
a|b              | base    186.0 | no-ngram    187.0 | no-mask    202.0 | both-off    202.0 | (ms)
pub fn           | base    147.0 | no-ngram    145.0 | no-mask    144.0 | both-off    145.0 | (ms)
(pub|fn) [a-z]+  | base    173.0 | no-ngram    175.0 | no-mask    253.0 | both-off    251.0 | (ms)
let mut          | base    143.0 | no-ngram    143.0 | no-mask    142.0 | both-off    143.0 | (ms)
fn main          | base    141.0 | no-ngram    142.0 | no-mask    141.0 | both-off    141.0 | (ms)
