=== tv-cold: 2026-10-14T09:24:13Z ===
store=/home/danalec/.rgx-bench/ablate-store root=/home/danalec/.rgx-bench/tree pattern=fn main threads=10 samples=5
cold = first query after sync + drop_caches; warm = same query right after.
ms, one sample per line; the summary prints min and median per arm.
tv cold: 100.0 55.0 54.0 56.0 57.0
tv warm: 52.0 51.0 50.0 51.0 53.0
tv summary: cold min 54.0 / med 56.0 | warm min 50.0 / med 51.0
rgx cold: 311.0 104.0 105.0 102.0 101.0
rgx warm: 80.0 78.0 78.0 81.0 76.0
rgx summary: cold min 101.0 / med 104.0 | warm min 76.0 / med 78.0
rg cold: 99.0 99.0 88.0 91.0 89.0
rg warm: 75.0 63.0 63.0 72.0 70.0
rg summary: cold min 88.0 / med 91.0 | warm min 63.0 / med 70.0
