# Multivolume RAR5 set

Five volumes of one archive, written here by **RARLAB `Rar.exe` 7.20**:

```
Rar.exe a -ma5 -m3 -v1k -ep1 rar5-mv.rar note.txt body.txt
```

`-v1k` is deliberately far below the 20 KB the two members need, so the set
splits: `body.txt` is chopped across volumes 2..5 and only volume 1 holds a
whole member (`note.txt`). The `.expected` files are the two source text
files.

This set lives here rather than beside the other fixtures in
`crates/rgx-adapters-archive/testdata/rar/` because it is only reachable
through `Archive::open_multi`, which takes every volume at once. The adapter
contract is one byte slice per file, so no `.rar` handler can reach it — the
multivolume capability belongs to the codec, not to rgx end to end.

`UnRAR x` reassembles the set correctly; `tests/multivolume.rs` holds the
codec to the same bytes.
