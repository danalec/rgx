=== tv-cold: 2026-10-17T03:36:56Z ===
store=/home/danalec/.rgx-bench/cold-v5-disk root=/home/danalec/.rgx-bench/tree pattern=fn main threads=10 samples=5
cold = first query after sync + drop_caches; warm = same query right after.
ms, one sample per line; the summary prints min and median per arm.
manifest version: 5 (built by `rgx --tv-build` on the tree as of 2026-10-17)
store filesystem: zpcachyos/ROOT/cos/home (zfs) -- NOT /tmp, which is tmpfs on this host
tv cold: 347.0 311.0 312.0 317.0 313.0
tv warm: 87.0 85.0 83.0 84.0 83.0
tv summary: cold min 311.0 / med 313.0 | warm min 83.0 / med 84.0
tv penalty: 228.50 ms (cold median minus warm median; MAD-dropped sample 1 = 347.0)
rgx cold: 224.0 94.0 102.0 96.0 97.0
rgx warm: 78.0 74.0 85.0 73.0 73.0
rgx summary: cold min 94.0 / med 97.0 | warm min 73.0 / med 74.0
rgx penalty: 22.50 ms (cold median minus warm median; MAD-dropped sample 1 = 224.0)
rg cold: 89.0 88.0 86.0 89.0 100.0
rg warm: 63.0 63.0 66.0 64.0 66.0
rg summary: cold min 86.0 / med 89.0 | warm min 63.0 / med 64.0
rg penalty: 24.50 ms (cold median minus warm median; MAD-dropped sample 5 = 100.0)
rgx pays 0.10x the prepared arm's cold penalty (22.50 ms against 228.50 ms).
rg pays 0.11x the prepared arm's cold penalty (24.50 ms against 228.50 ms).
