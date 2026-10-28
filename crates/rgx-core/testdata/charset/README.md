# The multi-byte charset fixtures

These are the reference implementation's own encodings of the texts beside
them, written by `scripts/gen_charset_mb_tables.py`:

- `<name>.bin` — the bytes, in the encoding the name says.
- `<name>.expected` — the text those bytes hold, in UTF-8.

The texts are written in the script and not here, and the script is the
source of truth for both: it is the thing that has to be regenerated when a
table changes. Regenerate with:

```sh
python scripts/gen_charset_mb_tables.py
```

`vectors.txt` holds a sample of every table — every 97th position of the
two-byte and the three-byte ones, and the first, the middle and the last
position of every four-byte range — with the codepoint the reference says
it holds.

The tables themselves are generated, so they cannot be mistyped; what the
sample pins down is the *decoder's* indexing of them. That is not a
formality: the first version of the generator printed GB18030's four-byte
ranges in decimal with a `0x` in front, so the table held `0x80` where the
reference says `0x128`, and every four-byte character was wrong by a
constant. The sample is what caught it.
