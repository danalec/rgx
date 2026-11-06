# rgx-adapters-office

Office, OpenDocument and e-book adapters, fully in-process — no external
tool. The OOXML and ODF formats are zip containers of XML parts, so the
adapter reads the zip itself and renders the relevant parts to plain
text; the legacy binary formats are read through a shared CFB reader.
Tag-stripped text is plainer than pandoc's rendering and good enough for
grep.

## What it claims

| adapter | extensions | reach |
|---|---|---|
| `office` | docx, docm, dotx, dotm, xlsx, xlsm, xltx, xltm, pptx, pptm, potx, potm, ppsx, odt, ott, ods, ots, odp, otp, odg, odgi, odi, otg, epub, vsdx, vssx, vstx, xps, oxps | Reveal |
| `rtf` | rtf | Render |
| `doc` | doc, dot | Reveal |
| `ppt` | ppt, pot, pps | Reveal |
| `xls` | xls, xlt, xlm | Reveal |
| `tex` | tex, latex, ltx | Render |
| `visio` | vsd | Reveal |
| `markup` | rst, org, mediawiki, wiki, ipynb, textile, man, 1–9, md, markdown, gfm, html, htm, xhtml, t2t, fb2 | Render |
| `abiword` | abw | Reveal |
| `hwp-raw` | hwd | Reveal |
| `wordperfect` | wpd, wps, wfb | Reveal |

The three `Reach::Render` adapters read formats ripgrep already handles:
control words, destination groups and the font table come out of RTF, the
preamble and control words out of LaTeX, and `<script>`, `<style>` and
link targets out of HTML and Markdown. Each is a strict subset as a
search space, so under the default `Policy::Source` the file's own bytes
stay the answer and the rendering is offered instead of substituted for
them. They remain reachable under `RGX_ADAPTER_VIEW=render` and `=both`.

## How it works

Which parts of the zip matter is decided per container kind:
word processing, spreadsheet and presentation ML for OOXML; `content.xml`,
`meta.xml` and `styles.xml` for ODF; the OPS (X)HTML and NCX parts for
EPUB; page XML for VSDX and XPS. Spreadsheets get a cell-aware reader that
emits `A1: value` lines with the shared string table resolved. The legacy
binaries are read record by record: a Word FIB and piece table, the
PowerPoint record stream with its persist directory, and BIFF records with
the shared string table.

An XML part is capped at 8 MiB and the extracted text at 16 MiB. When the
cap truncates something, the output says so instead of ending quietly.

**The encoding a document declares is the encoding it is read in.** An
HTML page's `<meta charset>` (and the older `http-equiv` form), an XHTML
prolog and a FictionBook's prolog all say what their bytes are, and the
legacy binaries say it in their own formats: the 8-bit text of a Word
document is cp1252, RTF's plain text is 7-bit ANSI, and BIFF5's strings are
cp1252 while BIFF8's narrow form is Latin-1. Reading any of them as UTF-8
does not read them differently, it replaces every byte above 0x7F with
U+FFFD — and in the BIFF8 narrow case it dropped the whole cell. The
decoding goes through `rgx-core::charset`; the cp1252 table there is
generated from the reference implementation, so it is not a hand-typed copy
of 32 characters.

## Licence

Apache-2.0 only. See [LICENSE-APACHE](https://github.com/danalec/rgx/blob/main/crates/rgx-adapters-office/LICENSE-APACHE), and the
repository's [COPYING](https://github.com/danalec/rgx/blob/main/COPYING) for what the licence covers and what
it does not.
