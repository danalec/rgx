=== tv-ugrep: 2026-10-14T03:20:43Z ===
store=C:\Users\danalec\.rgx-bench\log-store root=C:\Users\danalec\.rgx-bench\log-corpus threads=32 rounds=7
arms: rg (ripgrep) | rgx (direct) | tv (pack store) | ug (ugrep -E -J)
[ms] = best of 7 paired rounds, arm order rotated, warm cache, wall clock,
output discarded. Rows with unequal summed -c print counts, not timings.
status=200       | rg     67.0 | rgx     74.0 | tv     44.0 | ug     67.0 | (ms)
ERROR            | rg     68.0 | rgx     75.0 | tv     43.0 | ug     67.0 | (ms)
svc[0-9]+        | rg     71.0 | rgx     77.0 | tv     44.0 | ug     76.0 | (ms)
cache miss       | rg     66.0 | rgx     73.0 | tv     43.0 | ug     67.0 | (ms)
backoff_ms       | rg     67.0 | rgx     73.0 | tv     44.0 | ug     68.0 | (ms)
queue depth=[0-9]+ | rg     67.0 | rgx     81.0 | tv     45.0 | ug     67.0 | (ms)
