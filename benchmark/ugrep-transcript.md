=== tv-ugrep: 2026-10-14T03:08:52Z ===
store=C:\Users\danalec\.rgx-bench\ablate-store root=C:\Users\danalec\.rgx-bench\tree threads=32 rounds=7
arms: rg (ripgrep) | rgx (direct) | tv (pack store) | ug (ugrep -E -J)
[ms] = best of 7 paired rounds, arm order rotated, warm cache, wall clock,
output discarded. Rows with unequal summed -c print counts, not timings.
e                | rg    150.0 | rgx    129.0 | tv     63.0 | ug    272.0 | (ms)
e.               | rg    154.0 | rgx    140.0 | tv     67.0 | ug    283.0 | (ms)
foo.*bar         | rg    138.0 | rgx    127.0 | tv     58.0 | ug    269.0 | (ms)
e[0-9]           | rg    137.0 | rgx    131.0 | tv     57.0 | ug    266.0 | (ms)
a|b              | rg    149.0 | rgx    133.0 | tv     62.0 | ug    280.0 | (ms)
pub fn           | rg    144.0 | rgx    135.0 | tv     62.0 | ug    270.0 | (ms)
(pub|fn) [a-z]+  | rg    146.0 | rgx    137.0 | tv     63.0 | ug    298.0 | (ms)
let mut          | rg    134.0 | rgx    125.0 | tv     55.0 | ug    266.0 | (ms)
fn main          | rg    138.0 | rgx    123.0 | tv     56.0 | ug    270.0 | (ms)
