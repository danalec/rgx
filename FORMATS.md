# rgx — the formats

What rgx reads, format by format: what each family gives, what the reader
does with the bytes, and what it refuses. The list of the families, and what
the adapters are for, is in the [README](README.md#what-it-reads); the
measurements and the rest of the project are there too.

The gaps are at the end of this file: a format that is silently
unsearchable is worse than one that is documented as such.
## What it reads

| family | formats |
|---|---|
| archive | zip (+35 aliases, including `.gem` `.nupkg` `.crate` `.e57` `.uof/.uot/.uos/.uop`; the iWork packages `.pages/.numbers/.key` are zip containers too, and only their members are searchable — the document itself lives in a compressed IWA archive) · 7z · tar · cpio · ar · deb · git-pack · git bundle · Subversion dump (`.dump`: node paths, actions, revisions) · rar (store + RAR5) · gz bz2 xz zstd lz4 brotli, including `tar.*` · a PostgreSQL custom dump (`.dump`, `pg_dump -Fc` — see [A database dump](#a-database-dump)) · a borg segment (no extension at all: `data/0/2` is claimed by its magic — see [A borg repository](#a-borg-repository)) |
| images | ISO 9660 (Joliet + Rock Ridge names, files extracted) · SquashFS 4 (six codecs, files extracted) · WIM · VHD · VHDX · QCOW2 · VMDK · VDI · EROFS · APFS · HFS+ (catalog names) · DMG (the `koly`/UDIF trailer) · `.img` dispatching to ISO, DMG, HFS+ or an MBR/GPT partition table |
| office | docx · xlsx · pptx · ODF (incl. `.odi`) · epub · vsd / vsdx · xps · rtf · legacy `.doc/.dot/.xls/.ppt` · WordPerfect (`.wpd/.wps/.wfb`) · AbiWord `.abw` · Hangul raw `.hwd` · LaTeX (`.tex/.latex/.ltx`) and the lightweight markup family (markdown, HTML, RST, org-mode, MediaWiki, Textile, txt2tags, Jupyter notebooks, troff man pages) — dark by default, see the note below the table |
| pdf | text in-process — xref streams, object streams, CID fonts, the full filter zoo · the text rendering mode is tracked, so a hidden layer is named and a document whose whole layer is invisible hands its page images over for OCR beside the layer — see [A hidden text layer](#a-hidden-text-layer) · encrypted PDFs under the standard security handler when the user password is empty (RC4 40/128, AES-128, AES-256) — see [Encrypted PDFs](#encrypted-pdfs) |
| llm | gguf · safetensors · npy · onnx · protobuf (`.pb` `.onnx` `.model` `.mlmodel`) · tiktoken · keras · torch · pickle |
| tabular | sqlite · duckdb · dbf (and the Visual FoxPro container `.dbc`, which is a dBase table) · SYLK · DIF · Lotus 1-2-3 (wks, wk1, wk3, wk4, 123 — see [the gaps](FORMATS.md#known-gaps) for wk2) · Microsoft Access (mdb/accdb) · LMDB `data.mdb` (both share `.mdb` and are told apart by magic) · shapefile · parquet · arrow · ERI (`.eri`: an NTFS path index, one path per line) · mat v5 · netcdf-3 / CDF-1 and CDF-2 (the dimensions, the variables, their attributes and their **values**, one line per element with the index that locates it) · NASA CDF-3 (the variables, their types and shapes, their attributes, and their **values**) · hdf5 — and the two families that are HDF5 underneath: a netCDF-4 `.nc` and a MATLAB v7.3 `.mat` (an HDF5 file behind a 512-byte user block). A netCDF-4 file in the current layout keeps its names in a fractal heap; the heap, its B-tree and the object header are walked, so the names are read — and so are the names of a group that keeps them in the object header instead, which is what a small file has, and the **attributes** of the file and of every member, with the values the file's own datatype gives them, and the **members of the types** — the names and values of an enumeration, the names and types of a compound · and the **values of the datasets** the file stores in one block, one line per element with the index that locates it · MongoDB BSON · Redis RDB and AOF (`appendonly.aof`: the `aof-use-rdb-preamble` snapshot plus the command log after it) · LevelDB / RocksDB (the `LOG` write-ahead log, and `.ldb`/`.sst` sorted tables whose Snappy-compressed blocks the in-house decoder opens) · Zarr (the `.zarray` manifest of the v2 layout and the `zarr.json` of the v3 one, and the values in the chunks beside it — see [The Zarr array](#the-zarr-array)) |
| media | EXIF (jpeg/tiff/png/webp) · GIF and BMP headers · **PSD** (header, image resources, XMP/IPTC/EXIF) · **JPEG 2000** (JP2 container and raw codestream) · **JPEG XL** (container: EXIF and XMP) · **OpenEXR** (header attributes, channels, windows) · audio tags (ID3v1/v2, RIFF INFO, FLAC and the Ogg comment block — Vorbis, Opus and Theora alike) · video headers, Matroska chapters and tags · the ASF family (`.wmv/.wma/.asf`: the content description, whose strings are UTF-16) · fits · dicom · font tables · e-book metadata (MOBI/AZW/AZW3/PRC: title, author, publisher, ISBN) |
| 3d | glb · stl · ply · fbx · pcd · las and laz (the LASzip-compressed twin, decoded point for point) · vtk · blend · 3ds · NIfTI volumes (`.nii`: dimensions, voxel type, spacing, orientation) · MRC/CCP4 volumes (`.mrc/.ccp4/.map`: dimensions, cell, mode, the ten label slots) |
| mail | mbox · eml · emlx · msg · pst/ost · wab (Windows Address Book) · MMDF mailboxes · Thunderbird `.msf` indexes · Apple mailbox index — attachments recurse through the chain |
| inspect | forensic triage on any binary: magic ID, structure carving, strings, entropy, x509 |
| inspect · documents | OLE2/CFB compound files (`.hwp` `.one` `.nsf` `.mpp` `.cdr` · StarOffice 6/7 `.sxw/.sxc/.sxi/.sxd` …) · binary property lists (`.bplist` `.icloud` `.mobileconfig`) · multi-page TIFF and raw formats (`.nef` `.dng` `.cr2` …) · DjVu · ISO-BMFF `ftyp`/`meta`/`ilst` (`.heic` `.avif` `.3gp`) · Windows shell links (`.lnk`: target, arguments, working directory) · CALS rasters (`.cal` `.ct1` `.ct2`: the eleven-record header and the Group 4 page) · JEDMICS C4 (`.c4`: the 128-byte header of mixed endianness and its tiled page) |
| inspect · databases | Firebird and InterBase header pages (`.fdb` `.gdb`: ODS version, page size, page count, creation time, flags — the rows live behind `RDB$PAGES` and are not walked) |
| inspect · executables | PE `.rsrc` (the `RT_VERSION` tree, `VS_FIXEDFILEINFO`, `StringFileInfo`) · Mach-O `__cstring`/`__cfstring` · ELF `.comment` and `NT_GNU_BUILD_ID` · DEX string pool · WASM `name`/`producers` sections |
| inspect · science | GRIB 1/2 (parameter names from code table 4.2, edition 1 simple packing and edition 2 DRT 5.0/5.2/5.3/5.4 values decoded, the **spherical harmonics** of both editions and the **bi-Fourier** of edition 2 (DRT 5.53) — the coefficients, in the spectral order of code table 3.7) · BUFR · SEG-Y (EBCDIC textual header, shot and CDP per trace) · CERN ROOT · N5 · N5z |
| inspect · CAD | DWG (version code) · Parasolid transmit files · ACIS `.sab` · Revit `.rvt` (compound directory) · MicroStation DGN · the text CAD formats — DXF · IFC/STEP · IGES · ACIS `.sat` · STL — are *rendered*: the file's own bytes stay the default answer, and the rendering (an entity's name beside its values) appears under `RGX_ADAPTER_VIEW=render` — see [The text CAD formats](#the-text-cad-formats) |
| inspect · graphics | plotter drawings (HP-GL `.plt` `.hpgl` `.hgl`) — *rendered*: the file's own bytes stay the default answer, and the rendering (a polyline with its points, a label with its place) appears under `RGX_ADAPTER_VIEW=render` — see [The plotter drawing](#the-plotter-drawing) · graphics metafiles (CGM `.cgm`) — *revealed*: the file is binary, so the element stream with its geometry is the answer |
| inspect · genomics | BAM · BCF 1 and 2 · CRAM 3 (both walk BGZF block by block) · SAM when it is BGZF-compressed — a plain `.sam` is left to `rg` on purpose · the flat files of the same family — FASTA · FASTQ · VCF · GFF/GTF · PDB · mmCIF — are *rendered*: the file's own bytes stay the default answer, and the rendering (sequences unwrapped, fields separated by spaces, a summary of what the file holds) appears under `RGX_ADAPTER_VIEW=render` — see [The flat files](#the-flat-files) |
| docs | OCR via an external `tesseract` on `*.ocr.jpg`, `*.ocr.png`, `*.ocr.pdf` — a scanned PDF's page images are handed over, so the claim works on any tesseract build (see [Scanned PDFs](FORMATS.md#scanned-pdfs)) · a faxed page (CCITT G3/G4) and a JBIG2 page (ITU-T T.88) are decoded in-house first · `.pub` via `soffice` |


Adapters extract searchable structure, not payloads: model metadata and tensor
shapes, EXIF and tag values, schemas and rows. Plain-text formats (csv, json,
log, …) need no adapter and are searched raw. That same structure is
searchable as *facts* — as a predicate, not as a pattern — see
[Searching by what a file is](README.md#searching-by-what-a-file-is).

That last sentence is a decision, not an omission. FASTA, FASTQ, GFF, GTF, SAM,
VCF, PDB, mmCIF, `.m3u`, `.pls` and `.xmp` are all line-oriented text that
`rg` already reads perfectly, entities included. An adapter that *answered* for
them would strip nothing and add nothing, and under `RGX_ADAPTER_VIEW=render` it
would actively *delete* bytes `rg` would have matched. rgx stays a superset of
ripgrep by not claiming them.

Twelve of them are now claimed anyway, as **renderings** — the same reach the
markup family below declares, and the same rule: the file's own bytes remain
the default answer, and the rendering appears only when asked for. The
difference is that a rendering is not obliged to be a faithful copy. Joining a
FASTA's wrapped sequence and putting a VCF's tab-separated columns side by side
are things the file's own bytes cannot be matched against: `chr1 11869` is a
pattern that the file does not contain and the rendering does. See
[The flat files](#the-flat-files) for what the sequencing six give and
what they do not, [The text CAD formats](#the-text-cad-formats) for the
five CAD ones, and [The plotter drawing](#the-plotter-drawing) for the
plotter file.

The same holds for the desktop pointers — `.gdoc`, `.gsheet`, `.gslides`,
`.desktop` and `.url`. A `.gdoc` is one line of JSON whose `name` and `url`
sit whole on that line, and a `.desktop` is a short INI file whose `Exec=`
and `URL=` lines are already lines of the file. A rendering of them would
repeat what the file says rather than reveal what it hides, so they are left
to `rg` too — except for `.lnk`, which is a binary shell link and is read.

**A handful of text formats do have an adapter, and it is dark by default.**
`.html` `.htm` `.xhtml` `.md` `.markdown` `.gfm` `.rst` `.org` `.t2t` `.textile`
`.fb2` `.wiki` `.mediawiki` `.ipynb`, the LaTeX trio `.tex` `.latex` `.ltx`,
troff man pages (`.man`, `.1`–`.9`) and `.rtf` are all line-oriented text `rg`
reads perfectly, and every one of those extractors is lossy on it — the HTML arm
drops `<script>`, `<style>` and `<head>` bodies, the Markdown arm drops front
matter and link targets, the RTF arm drops the control words and the `\*`
destination groups. So they declare `Reach::Render`: the file's own bytes remain
the default answer, and the rendering appears only when asked for it. An SVN
`.dump` is declared the same way, because `.dump` is a shared extension and the
reader has to see the bytes before it can know whether this is an SVN repository
at all.

```sh
rgx --json needle doc.md                          # "adapter":"raw"
RGX_ADAPTER_VIEW=render rgx --json needle doc.md   # "adapter":"markup"
```

A `.tflite` is *not* on that list and not in the table above, and the omission is
deliberate: a TFLite model is FlatBuffers, so the protobuf reader would either
refuse it or — worse — accept a buffer and print field names that do not exist.
Leaving `.tflite` unclaimed is not a gap: the file still falls through to the raw
search and keeps `rg`'s answer.


## The facts each format gives

The facts are what a filter asks about: a name and a value, and the value
is the one the adapter read out of the file. This is the catalogue, and the
`--filter` of the [README](README.md#searching-by-what-a-file-is) is the
grammar that asks about it.
| fact | where it comes from |
|---|---|
| `path` | the file's path, or the logical path inside a container |
| `ext` | the extension of that path |
| `format` | the adapter that answered for the file (`raw` when none did) |
| `mime` | the MIME type the extension claims — `application/pdf`, `message/rfc822` |
| `lang` | the language the extension claims — `rust`, `python` |
| `container` | the kind of container a member is inside — `zip`, `7z` |
| `archive.entry` | how many entries the container holds |
| `author`, `title`, `subject`, `keywords`, `creator`, `producer`, `creationdate`, `moddate` | a PDF's `/Info` dictionary |
| `mail.from`, `mail.to`, `mail.subject`, `mail.date` | a message's headers |
| `mail.messages` | how many messages an mbox holds |
| `has.attachments` | present only when the message really has attachments |
| `exif.make`, `exif.model`, `exif.camera`, `exif.gps`, `exif.datetime` | a photo's EXIF block |
| `tensor.name`, `tensor.shape`, `tensor.dtype` | a safetensors model's tensors |
| `tensor.count` | how many tensors a GGUF header declares |
| `table.name`, `table.column` | a table's columns — sqlite, parquet, dbf |
| `zarr.shape`, `zarr.chunks`, `zarr.dtype`, `zarr.compressor`, `zarr.order` | a Zarr array's manifest |
## Scanned PDFs

They are the same story with the sign flipped, and worth being
explicit about: a PDF whose pages carry no text layer falls back to its own
bytes rather than to metadata alone, because raw compressed bytes are more
searchable than a title and a page count.

A PDF whose pages are *drawn* rather than photographed has no page image to
hand over, so its pages are rasterised first — poppler's `pdftoppm` (or
`pdftocairo`) writes one PNG per page at 300 dpi, and those are what the tool
reads. The rasteriser is opt-in by presence: without it the answer names the
tool that is missing and says the page was not rasterised, and the file's
own bytes are still searched.

Naming one `scan.ocr.pdf` routes it to the `docs` adapter's external
`tesseract`, and the claim **does not depend on how `tesseract` was built**:
tesseract reads images and answers a PDF with `Pdf reading is not supported`
unless its build was made with PDF support — measured here, `tesseract` 5.5.3
refuses it by file argument and by stdin alike. So rgx opens the PDF itself,
takes each page's image out, and hands the tool a picture per page, which is
what a scanned page is anyway. Verified end to end: `scan.ocr.pdf` — a PDF
whose only content is a JPEG and whose text layer is empty, which `rg`
returns nothing for — comes back as its text, with `--json` naming `ocr`.
The image path is verified too: `scan.ocr.png` returns its text, and an
ordinary `plain.png` is not routed there at all.

A scan stored as **CCITT G3 or G4** — the fax encodings, which carry the page
as a run-length program against the previous row rather than as a picture — is
decoded in-house and handed over as a picture too, so the same `scan.ocr.pdf`
naming works for a faxed page. The decoder is ITU-T T.4/T.6 proper: the
2D modes place each row's changing elements against the previous row's, and a
row that is decoded against the wrong reference renders a *plausible* page
rather than failing, which is why the corpus is compared byte for byte against
the encoder's own input. Verified end to end: a PDF whose only page image is
CCITT G4 comes back as its text, with `--json` naming `ocr`, and `rg -a` finds
nothing in the file itself.

A scan stored as **JBIG2** (ITU-T T.88) is the same story one format on: the
page is a program against a pixel template and a dictionary of glyphs, not a
picture, so it is decoded in-house — the arithmetic regions, the symbol
dictionary and the text region that places its glyphs — and handed over as a
picture. The two variants the decoder does not implement, the Huffman codings
and the refinement/aggregate codings, are refused by name rather than
approximated. Verified end to end: a PDF whose only page image is a JBIG2
text region comes back as its text, with `--json` naming `ocr`.

## A database dump

It is the same story one format on. A `pg_dump -Fc` custom
archive is a container — a header, a table of contents, and one compressed
block per table — and the rows sit inside a zlib stream, an LZ4 frame or a
zstd frame that `rg` cannot see past. rgx decodes it in-house: the table of
contents names every object, and each table's rows come out as the `COPY`
block `pg_restore` prints, byte for byte.

Two things in that format are load-bearing, and both are places where a
reader can be *nearly* right and still desync on the second entry.
PostgreSQL's "gzip" is zlib framing (RFC 1950), not gzip (RFC 1952) — its
`compress_gzip.c` calls `deflateInit` with the default window, and the
default window is a zlib wrapper. And the integers are sign-magnitude
little-endian, not two's complement: `WriteInt` writes the sign separately
and shifts the magnitude right, so `-1` is `01 01 00 00 00` and a reader
that decodes it as two's complement reads a length of 3 as -1 and stops.

Verified end to end: a `pg_dump -Fc` of a table with a row in it comes back
as that row, with `--json` naming `pgdump`, and `rg -a` finds nothing in the
file itself. The *plain* dump (`pg_dump -Fp`) is SQL text, which `rg` already
reads, so it is not claimed; and the *directory* dump (`-Fd`) is a directory
of per-table gzip files that the decompress adapter already opens, with only
its schema left in a `toc.dat` that this reader declines by name.

When `tesseract` does refuse, it refuses loudly — its own message becomes a
searchable `[rgx: adapter 'ocr' failed: …]` note **beside** the file's
bytes, which are still searched, so nothing is lost to silence. The same is
true of a tesseract installed without language data, which is a real state:
the note then names the `eng.traineddata` it could not open.

## A hidden text layer

A PDF can carry text that is not on the page. `3 Tr` makes the glyphs
invisible, and `7 Tr` makes them invisible and clips them at the same time;
the text is still in the file, and a reader that does not watch the
rendering mode reads it exactly as it reads visible text.

rgx watches it now. The rendering mode follows the content stream, it is
text state (so `BT` and `ET` do not reset it, and each page starts from the
default), and the note says what was hidden. A document whose text layer is
*entirely* invisible and that carries page images answers with both views:
the hidden text stays in a `text.txt` member, and the page images are
handed over as `page-N.ocr.jpg`, which the `docs` adapter OCRs. The two
are not alternatives — the layer is the file's own content and the picture
is the page — so the OCR of the picture is *added* to the layer and neither
replaces the other. A document with both visible and invisible runs says
how many of each it has, and keeps the text.

Verified end to end: two PDFs that differ only in the token `0 Tr` against
`3 Tr` answer differently — the invisible one comes back as
`invisible-layer.pdf!text.txt` with the hidden text and the note, plus
`invisible-layer.pdf!page-1.ocr.jpg` that tesseract really read, and the
visible one comes back as the file's own text, with no member and no note.

A PDF whose visible content is *drawn* — vectors, curves, a table of text
— has no page image of its own, so there is nothing to hand over and its
hidden text is all rgx would have. The `scan.ocr.pdf` naming still works, and
still means "OCR this file's pages": the pages are rasterised by poppler's
`pdftoppm` (or `pdftocairo`) at 300 dpi and handed over as pictures, one per
page, so the OCR of the picture is added to the layer the same way a scanned
page's is. The rasteriser is opt-in by presence, like every other external
tool here: a machine without it gets an answer that says the page was not
rasterised, instead of one that pretends it was.

## A borg repository

A borg repository is a directory of segments: `data/0/0`, `data/0/1`, and
so on. A segment has no extension and no dot in its name, so it is the one
format rgx claims by what it **is** rather than by what it is called — the
adapter's magic prefix is `BORG_SEG`, and the name is the stronger claim,
so the magic only speaks when the name is silent. That costs a caller one
short read per file no adapter claims by name, and it is the only way to
reach a segment at all.

A segment of a repository created with `borg init --encryption=none` gives
back the files it holds, under the names they had in the backup. The item
metadata is MessagePack and names the chunks of each file, and the chunks
are compressed in the segment, so `rg` finds nothing where rgx finds the
content.

Four things in that format are load-bearing, and they are transcribed from
borg 1.2's own source rather than from a description of it. The entry
header is a CRC, a size and a tag, and the size counts the whole entry,
the CRC included, so the entries tile the file exactly; the CRC covers
the size and the tag, then the id, then the data, in that order, and not
itself. The payload carries an envelope: one byte says which key the
repository uses, and for a repository without encryption the next two
bytes name the compressor. A chunk's id **is** the entry's id, so the
chunks of a file are found by id without reading the index. And an item's
metadata is a *sequence* of maps, not one map: the first is the "safe"
metadata of the archive's top item, and the rest are the full items with
their sizes and their chunk lists — a reader that decodes one map and
stops reports the directory and nothing else. The MessagePack integers
are big-endian, in network byte order, which is the opposite of every
other binary format in this crate and a mistake this reader made and the
tests now pin.

Verified end to end: a `borg create` of a directory with two files in it
comes back as those two files, under their names and under the segment's
own path — `data/0/2/data/factura.txt` — and `rg` finds nothing in the
segment itself. The repository created with `init --encryption=keyfile` is
the same refusal as an encrypted PDF: the structure of the segment is
still readable, and the payload is not, and the note says that the
repository key is the one thing a search tool may not ask for.

The two answers are tagged differently, and the tag says what happened. A
segment that yields files answers them as *members*, and a member is
searched as the plain text it is, so `--json` reports `"adapter":"raw"`
for it — the same tag a member of a zip gets. A segment whose payload is
encrypted is answered in place, by the adapter itself, and there
`--json` reports `"adapter":"borg"`.

What a single segment cannot say is also said: a segment is one file, and
a backup is many, so the chunks of a file larger than one segment are in
another one, and the reader says which chunks are elsewhere instead of
inventing the rest.

## The flat files

FASTA, FASTQ, VCF, GFF/GTF, PDB and mmCIF are the formats the sequencing
world writes by hand, and every one of them is plain text that `rg` reads
perfectly. So they are **rendered**, not answered: under the default
`Policy::Source` the file's own bytes are the answer and the renderer is not
consulted at all, and under `RGX_ADAPTER_VIEW=render`
the rendering is what gets searched. The default answer is unchanged; the
rendering is a second view of the same file.

Three things make the rendering worth asking for.

**A wrapped sequence can be matched.** A FASTA's sequence is written 60 or 80
columns wide by every tool that writes one, and a motif that straddles the
wrap is split across two lines. `rg` cannot match across a line break; the
rendering joins the lines. Measured on a fixture written to the
specification: a sixteen-base motif placed five bases before the wrap is in
no line of the file, `rg` finds nothing, and the rendering finds it — on one
line, with the record's description above it.

**Two adjacent fields can be matched.** A VCF and a GFF separate their
columns with a tab and a PDB separates its fields with fixed columns, so
`chr1 11869` — or a residue with its chain and its number — is one pattern
in the rendering and not one in the file. The attributes are also put in a
single shape whatever dialect wrote them: GFF3's `Name=BRCA1` and GTF's
`gene_name "BRCA1"` come out as `Name=BRCA1` and `gene_name=BRCA1`, so one
search finds both.

**The file is summarised.** The rendering opens with what the file holds —
how many records, of how many kinds, over how many sequences — which is a
question the file answers only by being read all the way through.

What the rendering does not do is guess. A PDB record whose layout the
specification does not fix is passed through as it was written, and a mmCIF
loop whose values do not fill its rows says so instead of grouping the
remainder into a row that never existed.

## The text CAD formats

DXF, IFC/STEP, IGES, the ASCII ACIS `.sat` and STL are plain text that `rg`
reads perfectly, so they are **rendered**, not answered, exactly like the flat
files above: under the default `Policy::Source` the file's own bytes are the
answer and the renderer is not consulted at all, and under
`RGX_ADAPTER_VIEW=render` the rendering is what gets searched. The default
answer is unchanged; the rendering is a second view of the same file.

They were left unclaimed until the question was measured instead of argued.
The objection was that a renderer which drops what the file carries is a
subset of ripgrep — true of the markup family, whose arms drop `<script>`
bodies and LaTeX control words, and false of a renderer that only *joins*
what the file already says. A CAD entity is exactly that, and each of the
five puts the entity's name beside its values.

**A DXF's group codes put the name apart from the values.** The entity's
type is a group code on a line of its own, its layer is another, and its
coordinates are three more:

```text
entity: LINE on layer LAYER1
  start: 0.0, 0.0, 0.0
  end: 100.0, 50.0, 0.0
```

**A STEP instance is one very long line.** The file writes the entity, its
attributes and its name with no space between them; the rendering puts them
apart and says which instance is which, so `#7: IFCWALL` is one match there
and none in the file:

```text
#7: IFCWALL('3vB2YO$MX4xv5uQQUeJKF', #6, derived, 'Contrato ACME', derived, ...)
```

**An IGES entity's name and its parameters are sections apart.** The name
lives in the directory entry, the parameters in the parameter section, and
the only thing that says which belongs to which is a pointer counted in
records. The rendering puts the entity's heading and its parameters under
one another, and the entity's *name* — which the file never writes — comes
from the specification's index of entity types:

```text
entity: 110 (Line)
  status: 00000001
  matrix: 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0
  start: 0.0, 0.0, 0.0
  end: 100.0, 50.0, 0.0
```

**An ACIS record is a run of tokens on one line, and its pointers are
indices.** `$0` means "the entity at index zero", which is the transform;
the rendering says so.

**An STL facet's three vertices are three lines.** The rendering puts them
on one, so the pattern `0.0, 0.0, 0.0 | 10.0, 0.0, 0.0` is one match there
and none in the file:

```text
facet 1: normal 0.0, 0.0, 1.0
  vertices: 0.0, 0.0, 0.0 | 10.0, 0.0, 0.0 | 0.0, 10.0, 0.0
```

What the rendering does not do is guess. A STEP instance's geometry is the
numbers the file wrote and not a point in space; an IGES parameter whose
layout the specification does not fix is passed through as it was written;
an ACIS record's twelve matrix values are the matrix the file wrote and not
an evaluated transform.

`.stl` is claimed twice, and that is the design rather than an accident: the
`threed` crate answers the *binary* form, which ripgrep cannot read at all,
and the `inspect` crate answers the *ASCII* form, which ripgrep reads
perfectly. A `bail!` does not end the chain, so the ASCII file reaches the
reader that can render it.

## The plotter drawing

An HP-GL file is a stream of plotter commands: a two-letter mnemonic, its
parameters, and a semicolon. `PU` lifts the pen, `PD` lowers it, `PA` gives a
point in the plotter's own units, `SP` picks a pen, `CI` draws a circle, `LB`
writes a label. The commands *are* the drawing: the picture is not written
down anywhere, it is the path the pen took.

That makes it a **rendering**, not an answer, for the same reason the CAD
formats are: the bytes are text `rg` already reads, so under the default
`Policy::Source` the file's own bytes are the answer and the renderer is not
consulted at all. What the rendering adds is the join. A polyline is a `PD`
here and a `PA` there, with the points split across commands and the pen state
carrying the rest of the meaning:

```text
pen 1: polyline (0,11181) (230,11507)
pen 1: label "#RES BW 3." at (1052,0)
```

`polyline (0,11181) (230,11507)` is one match in the rendering and none in the
file, which writes `PA0,11181;PD;PA230,11507`.

What the rendering does not do is project. `SC` and `IP` decide what a number
*means*, and they are reported rather than applied; the arcs are reported as
the arcs the file names, not as the points they pass through.

`.plt` is also the extension of a gnuplot script, so the reader declines a
file whose stream is not a run of plotter commands: a gnuplot script falls
through to the raw search and is found there, in its own words.

The fixture is a capture from an HP 8595E plotter, taken from the HPGL-Plotter
project (Apache-2.0), and the reader was checked against the seven real HP-GL
drawings that project carries — a Cassini trajectory, a DSN antenna, a spectrum
analyser plot, the space shuttle, a Tektronix screen and two more: 1,487
polylines out of the Cassini drawing, 2,736 out of the antenna, and no panic on
any of them, nor on a truncated copy of each.

## The metafile and the two bilevel rasters

Three binary formats, and the reach all three declare is `Reveal`: their bytes
are not text, so `rg` reads none of them and the adapter's answer *is* the
answer. What the answer carries is what the file holds as numbers — a
polyline's points, a page's size, a tile count — and those are the patterns a
user writes.

**A CGM is a stream of elements.** Each one opens with a 16-bit header (a
class, an id, and the length of its parameter list) and its parameters are
binary: coordinates, colours, flags, text. The rendering gives every element a
line of its own and gives the primitives their geometry:

```text
polyline: (100,100) (200,200) (300,50)
circle: centre (500,500) radius 100
text: CONTRATO ACME at (10,20)
```

`polyline: (100,100) (200,200) (300,50)` is one match in the rendering and none
in the file, which holds `00 64 00 64 00 c8 00 c8` and nothing that says
*polyline*.

The reader was checked against the 353 real metafiles of the W3C/OASIS WebCGM
2.1 test suite: the walk lands exactly on the end of every one of them, and
the element sequence matches an independent reader on 353 of 353. That corpus
also corrected the specification's silences, and the adapter follows the corpus
where the two disagree — the metafile element's first byte is the *name's
length in characters* and not a version number, the integer precision counts
*bits* and not bytes, and a string is prefixed with its length and not
wrapped in a final character. The five files of the corpus that write their
text in the two-byte character set are reported by name rather than guessed
at.

**A CALS Raster is a header of eleven records and a Group 4 picture.** The
2048-byte header holds `srcdocid`, `dstdocid`, `txtfilid`, `figid`, `srcgph`,
`doccls`, `rtype`, `rorient`, `rpelcnt`, `rdensity` and `notes`, each written
as `<identifier>: <value>` and padded with spaces to 128 bytes; the image
starts at offset 2048. The rendering joins what the file keeps apart — the
pel count and the density on one line, each record on a line of its own:

```text
cals: type 1, 1728x2200 pels at 200 dpi, orientation 000,270
srcdocid: SAMPLE DOCUMENT
```

**A JEDMICS C4 is a 128-byte header of mixed endianness and a tiled picture.**
The index offset, the line height and the byte width are Intel; the data
offset, the dpi and the file type are network; the Hollerith field is
eighty bytes of card. The rendering says what the header says, and checks it
against itself — a header whose data offset does not match its own tile index
is declined rather than believed:

```text
c4: 1728x2200 pixels (216 bytes wide), 200 dpi, 20 tiles
format: 4
tiles: 4 wide x 5 high, 20 index entries, 170-189 bytes per tile, G4 compressed
```

## The picture formats

A picture is not text, and rg calls a JPEG binary and moves on. What a
picture *says about itself* — the camera, the place, the title in its XMP,
the dimensions, the colour space — is text, and rgx reads it.

| format | what is read | adapter |
|---|---|---|
| JPEG, PNG, WebP | the EXIF block, tag by tag | `exif` |
| TIFF | the EXIF block of the first page (a multi-page TIFF defers to the page walker) | `tiff` |
| camera RAW — the TIFF-based ones (CR2, DNG, NEF, ARW, PEF, SRW, RW2) | the TIFF IFD chain and its tags | `tiff-pages` |
| GIF, BMP | the header, and the comments a GIF carries | `gif`, `bmp` |
| **PSD, PSB** | the header (dimensions, channels, depth, colour mode), the inventory of the image resources, and the text of the ones that are text: XMP, IPTC, the EXIF block | `psd` |
| **JPEG 2000** — JP2 container | the brand, the image header (dimensions, components, bit depth), the colour space, the resolution, the XMP, and the EXIF of a `uuid` box | `jpeg2000` |
| **JPEG 2000** — raw codestream | the SIZ marker: dimensions, tile size, and every component's bit depth and signedness | `jpeg2000` |
| **JPEG XL** | the container's brand, its EXIF block and its XMP | `jpegxl` |
| **OpenEXR** | the header attributes: the channels and their pixel types, the data and display windows (so the dimensions), the compression, the comments | `openexr` |
| HEIF, HEIC, AVIF | the ISO-BMFF `ftyp` brand, the item inventory and the property boxes | `isobmff` |
| PDF | the text layer, and the `/Info` dictionary | `pdf` |

No pixel is decoded, no wavelet is inverted and no tile is unpacked: the
header is the payload.

**What each one does not read.** A JPEG XL's dimensions live in the
codestream's size header, which is entropy-coded, so they are not read and
the file says so. A PSD's layer names are inside the layer section and are
not walked — the image *resources* are, and those are where the XMP, the
IPTC and the EXIF live.

**The camera RAW that is not a TIFF is not claimed.** An Olympus ORF, a
Canon CRW, a Fujifilm RAF and a Sigma X3F have a container of their own,
so they fall back to the raw search instead of being read as a TIFF they
are not. A Panasonic RW2 *is* a TIFF, with the magic number 0x55 where a
TIFF has 0x2A — and the answer says which container it read, so an RW2 is
never mistaken for a plain TIFF.

**The check.** Every row above is pinned by a test that runs the real
binary over a real file of that format and asks *which adapter answered*
(`tests/raster_formats.rs`). A format that quietly fell back to the raw
search would still find the occasional ASCII run in a header, so the test
asks for the adapter and not for a hit.

## Encrypted PDFs

They are opened in-process, but only the case that is honestly
answerable. Most PDFs that carry `/Encrypt` are encrypted with an *empty user
password*: they open in any viewer without a prompt, because only the owner
password guards them. Those were unreadable before and are read now — RC4 at
40 and 128 bits, AES-128 and AES-256, revisions 2, 3, 4 and 6.

The refusal matters more than the capability, and it is the design rather
than a limitation: **every key is proved against the file's `/U` entry before
a single byte is decrypted.** A document whose `/U` does not reproduce under
the derived key is passed through to the raw-byte search, never decrypted
with a key that would produce plausible-looking noise. That check is why the
reader cannot answer with a page of mojibake it cannot tell from text.

A **non-empty user password** is a refusal, not a failure. It is a secret,
and a search tool has no business guessing one. The file's own bytes stay
searchable, which is exactly the answer for a document nobody can open.

An adapter may also declare a **dotted** extension. `docs` claims `ocr.jpg`,
so `scan.ocr.jpg` is OCR'd while an ordinary `scan.jpg` is only read for its
EXIF — the more specific claim wins, and it runs first.

A **block container** is not a filesystem. VHD, VHDX, QCOW2, VMDK, VDI,
EROFS, APFS and HFS+ wrap a block device, and reading one means mounting it —
so rgx reports what the container says about itself (geometry, UUID, backing
chain, features, and for the filesystems with a readable catalogue, the file
names) and never claims to have read the payload. ISO 9660 and SquashFS are
the other kind: they carry a catalogue, and their files come out as members
you can search:

```sh
rgx "invoice total" disc.iso        # -> disc.iso!README.TXT:1:invoice total 42
rgx "Wi2k" backup.vhd               # -> the creator of the image
```

A **big image is not a big read.** The image adapters read the *metadata* —
the EXIF block, the page table — and never the pixels, so an image's size
does not change what comes out of it: measured, a 24-megapixel JPEG and a
48 MB twelve-page TIFF are both read. The paths that *do* expand are the
ones with stated caps: a PDF stream stops at 256 MiB inflated, and a fax or
a JBIG2 page at 64 megapixels.

## The Zarr array

A Zarr array is a directory: a `.zarray` manifest and the chunks beside it.
The manifest is JSON and `rg` reads it, but it *describes* the array rather
than holding it — the same eight bytes are eight `u1`, one `f8` or a
ten-character string depending on the `dtype` line, and a chunk says nothing
at all about which. So the values are read, and the manifest's own bytes stay
in the answer: a search for `zarr_format` still finds it, under the numbers.

The **v3 layout** is read too, and it is the one `zarr-python` writes by
default: the metadata in a `zarr.json`, the chunks under `c/` named by a key
encoding, and a pipeline of codecs that says how the bytes of a chunk
become the elements. The v2 layout's manifest is a dotfile and the v3
layout's is not, so the two are told apart by their content and not by
their name.

```sh
rgx "42" array/                        # the values, and the manifest's JSON above them
rgx --filter 'zarr.compressor:zlib' . array/
```

The chunks are decompressed with the codec the manifest names — zlib, gzip,
zstd or bzip2 — and the `delta` filter's running sum is put back. **Blosc**,
the codec `zarr-python` asks for by default, is read too: the frame is a
header, a table of block offsets and the blocks, and the blocks are LZ4 with
the byte shuffle applied to them. The frames were checked against the two
implementations that write them, c-blosc itself and `numcodecs`, the codec
library `zarr-python` sits on, so the numbers are not a reader's own opinion
of its own output.

The sharding codec is specified in
[zarr-specs](https://zarr-specs.readthedocs.io/en/latest/v3/codecs/sharding-indexed/),
and the rectilinear grid is an extension of it, in
[zarr-extensions](https://github.com/zarr-developers/zarr-extensions) -- the
word "irregular" is in no Zarr document.

The v3 pipeline's **transpose** codec is read too. It permutes the axes of
a chunk's elements, and the reader puts them back, so the values come out
with the array's own axes and not with the order they were stored in. A
transpose whose order is not a permutation of the array's axes is refused
by name, the way `zarr-python` refuses it.

## Where the formats are specified

Each format has a document that says what its bytes are, and an
implementation that writes them. Both are named here: the specification is
the claim, the oracle is what the reading is checked against.

| format | the specification | the oracle that checks it |
|---|---|---|
| GRIB, both editions | the WMO Manual on Codes **WMO-No. 306**, Vol. I.2 Part B -- there is no WMO-No. 307, `codes.wmo.int/307` is a 404 -- rendered octet by octet at <https://www.nco.ncep.noaa.gov/pmb/docs/grib2/grib2_doc/> | NOAA's g2c and ECMWF's ecCodes; the spectral DRTs are **5.50/5.51/5.53** (5.40/5.41 are JPEG2000 and PNG) |
| CRAM 2.1 | the CRAM 2.1 specification, in the [hts-specs repository](https://github.com/samtools/hts-specs), and `CRAMcodecs.pdf` for the encodings | htsjdk and htslib |
| CRAM 1.0 | **none.** The `samtools/hts-specs` history has never held a `CRAMv1.pdf` -- the commits API for that path returns `[]` -- and the 2.1 document says 2.0 "tidied up implementation vs specification differences in 1.0": the two 1.0 implementations disagreed | htslib reads a 1.0 *container*; the record layer has no text at all |
| CRAM 4.0 | an **unmerged pull request** ([hts-specs #502](https://github.com/samtools/hts-specs/pull/502), `CRAMv4.tex`): VLQ/zig-zag instead of ITF-8/LTF-8, and it does not define its own version bytes | none: no CRAM 4 file exists |
| Zarr v3 sharding | zarr-specs, `sharding-indexed` v1.0 -- <https://zarr-specs.readthedocs.io/en/latest/v3/codecs/sharding-indexed/> | zarr-python 3.4.1, which writes the fixture |
| Zarr chunk grid | the **rectilinear** grid, in [zarr-extensions](https://github.com/zarr-developers/zarr-extensions) (the word "irregular" is in no Zarr document) | zarr-python, with `array.rectilinear_chunks` enabled |
| blosc | c-blosc's own [`README_CHUNK_FORMAT.rst`](https://github.com/Blosc/c-blosc/blob/main/README_CHUNK_FORMAT.rst): `0 blosclz`, `1 lz4\|lz4hc`, `2 snappy`, `3 zlib`, `4 zstd` -- the **format** codes, which are not the library codes | c-blosc's `bloscread.exe` and numcodecs, which writes every codec but snappy; the snappy frame came from c-blosc 1.18.1, the last release with the snappy built in |
| FoxPro `.dcx` | the CDX compound index, each claim cited to the CodeBase source | the repository's own `EXPENSES.DCX`; Harbour's and XSharp's readers |
| netCDF CDF-5 | PnetCDF's Appendix G -- <https://cucis.ece.northwestern.edu/projects/PNETCDF/CDF-5.html> -- and netCDF's own Appendix B | the specification's own annotated byte dump; `ncgen -v 5` |
| NASA's CDF-1/CDF-2 | the CDF **Internal Format Description**, NASA GSFC -- <https://spdf.gsfc.nasa.gov/pub/software/cdf/doc/cdf_Internal_Format.pdf> | `cdflib`, whose reader knows the two magics -- but whose **writer** produces CDF-3, not them: the files are NASA's own, from NASA SPDF and from `cdflib`'s test files |
| HDF5 | the HDF5 **File Format Specification**, versions 1.0-4.0 -- <https://support.hdfgroup.org/documentation/hdf5/latest/_s_p_e_c.html> -- Appendix VII names the five chunk indexes | the HDF5 library's own source |
| Lotus 1-2-3 | **no vendor byte-level document is online.** The `.wk2` extension is a rename of `.wk1` (both carry the BOF code `0x0406`), and two working readers -- Gnumeric's and LibreOffice's -- dispatch both the same way | the corpus' own `.wk1` files, which already carry `0x0406` |
| borg, restic, kopia, duplicacy | each project's own format document -- borg's is [Borg Internals](https://borgbackup.readthedocs.io/en/stable/internals.html) | -- but the **blocker is the secret**, not the format: an encrypted repository needs a passphrase, and a search tool may not ask for one |

## Known gaps

Stated rather than papered over, because a format that is silently
unsearchable is worse than one that is documented as such.

- **The filter is a filter, not an index.** `--filter` asks the question of
  every file the walk finds, and the files it does not know about are files it
  cannot answer for. The facts *can* be kept — `--facts-build` writes them to
  a JSON Lines index and `--facts-index` answers the same `--filter`
  expression from it, without walking the corpus — but the index is a
  separate artefact, not something the search does: a run that was asked
  for a pattern still walks the corpus and still reads the bytes, because
  the pattern is a question about the text and the index holds facts. The
  extraction itself *is* memoised — `--cache` keys the memo by the file's
  content, so a copy of a file, or a file that moved, is not extracted
  again — and what the index adds on top is the facts themselves, so that
  a question about a corpus that changes once is answered without walking
  it at all.
- **A member is named, not addressed.** A zip inside an ISO, a PDF attached to
  a PST, a backup inside a disk image: the pipeline recurses four container
  levels deep by default (`--max-adapter-depth` moves that), and every member
  carries a logical path — `bundle.zip!script.py`,
  `outer.zip!middle.zip!inner.zip!deep/marker.txt` — where the `!`
  separates the container from the member and the member keeps the
  separators it had inside the container. What the path does *not* carry is
  where inside the member a hit is: a PDF is one text, so
  `archive.zip!doc.pdf` names no page, and a spreadsheet's sheet, a
  paragraph's index and a cell's address are not in the path at all. The `!`
  is also reserved: in a name it separates a container from a member, so a
  file called `report.txt!draft` is read as the container `report.txt` and
  the member `draft`. The budget is halved per level, so a tree of
  containers expands to under twice what one container would.
- **Encrypted PDFs need an empty user password** — the standard security
  handler is implemented in full (revisions 2, 3, 4, 6), but only the case
  where the user password is empty, which is the overwhelmingly common one
  and the only one a search tool can answer without a secret. A file that
  needs a password is declined, its bytes stay searchable, and the `/U`
  check is what decides: a key that does not reproduce `/U` is never used.
  Revision 5 is declined rather than implemented, because its `/U` carries
  no tag that independently confirms a derived key — the one failure mode
  worth refusing rather than guessing at. Non-standard handlers
  (`/Adobe.PubSec`, the old Acrobat 3 bullet scheme) and public-key
  handlers are named and declined.
- **A PDF's rendering mode is tracked, and a page is rasterised by an
  external tool.** Text
  drawn with `3 Tr` (or `7 Tr`) is invisible on the page, and the reader
  follows the rendering mode through the content stream: the same page with
  `0 Tr` and with `3 Tr` no longer answers identically. A document whose
  text layer is *entirely* invisible and that carries page images answers
  with both views — the hidden text stays in a `text.txt` member and the
  page images are handed over as `page-N.ocr.jpg`, so the OCR of the
  picture is *added* to the layer and neither replaces the other; a
  document with both visible and invisible runs says how many of each it
  has. A PDF whose visible content is *drawn* rather than photographed has
  no page image of its own, so the `scan.ocr.pdf` naming rasterises its
  pages with poppler's `pdftoppm` (or `pdftocairo`) at 300 dpi and hands
  them over as pictures, one per page — the same answer a scanned page
  gets. What is left: a document that *mixes* a photographed page with a
  drawn one hands over only the photographed page, because the page images a
  document carries are read as one flat list and nothing in it says which
  page an image came from; and the rasteriser is opt-in by presence, so a
  machine without poppler is told the page was not rasterised rather than
  given nothing at all.
- **A borg segment is read, and a segment names nothing.** A borg
  repository is a directory of segments — `data/0/2`, with no extension and
  no dot in its name — and this is the one format rgx claims by what it
  IS: the adapter's magic prefix is `BORG_SEG`, and the name is the
  stronger claim, so the magic only speaks when the name is silent. A
  segment of a repository created with `init --encryption=none` gives back
  the files it holds, under the names they had in the backup: the item
  metadata is MessagePack and names the chunks of each file, and the chunks
  are compressed in the segment, so `rg` finds nothing where rgx finds the
  content. The layout is transcribed from borg 1.2's own source, not from
  a description of it. What is left: the contents of an encrypted
  repository, where the key is the blocker and the refusal is the same one
  an encrypted PDF gets; and a file whose chunks span two segments, since
  a segment is one file and the reader says which chunks are elsewhere
  rather than inventing the rest.
- **restic, kopia, duplicacy — the payload is encrypted, and that is the
  blocker, not the routing.** Measured, not assumed: a restic repository
  leaks nothing by default, and `--insecure-no-password` leaves the blobs
  compressed rather than encrypted. A kopia repository is opaque from its
  first byte, its own description file included. So what is missing is a
  *secret*, and a secret is the one thing a search tool may not ask for —
  it is the same refusal as an encrypted PDF, not a design that a routing
  change would unlock. A borg repository is the exception that proves the
  rule: a borg segment written without encryption is read, and one written
  with it is not, and the difference is the key and nothing else.
- **A backup split into zstd chunks is already readable.** A file of
  concatenated zstd frames is what the in-house zstd decoder opens, frame
  after frame: measured, a four-frame file of 10 KiB standing for 590 KiB of
  text comes back with its content, and `rg -a` finds nothing in it.
- **Google Takeout needs nothing either.** A Takeout archive is a zip of
  JSON, HTML and CSV, and the zip adapter already opens it: measured, the
  photo's JSON, the bookmark's HTML and the sheet's CSV all come back with
  their inner paths.
- **`.dropbox` is not claimed.** It is a proprietary binary that the Dropbox
  client writes, and rgx does not guess at a layout: a reader built on an
  assumed structure invents fields that are not there, which is the failure
  this whole crate is written against.
- **The text CAD formats are claimed, as renderings.** DXF, IFC/STEP, IGES, the
  ASCII ACIS `.sat` and STL are line-oriented text like the flat files, and
  they get the same treatment: the file's own bytes stay the default answer,
  and the rendering — an entity's name beside its values, which a DXF's group
  codes and a STEP's records do not — appears under `RGX_ADAPTER_VIEW=render`. Measured
  on a fixture: the pattern `IFCWALL('3vB2', #6` is one match in the
  rendering and none in the file.
- **`mysqldump` is SQL text**, like a plain `pg_dump`, and `rg` reads it:
  measured, MySQL 8.4's dump of two tables is 47 lines of SQL and `rg` finds
  the row. Its shape differs from PostgreSQL's — one `INSERT` per table
  rather than a `COPY` block per table — so a table's rows all land on one
  line, 115 characters for the two rows measured here and one line for the
  whole table however many rows it has, and that is the line `rg` prints.
  MariaDB's dump splits the tuples one per line, so there the rows are
  already lines. A reader that split MySQL's rows would answer a different
  question from the file's, so it is not claimed.
- **A declared encoding is honoured, and the multi-byte CJK ones are in.**
  A MIME part's `charset=`, an HTML `<meta charset>`, an XHTML prolog, an
  RFC 2047 header and the 8-bit text of an old Word, Excel or RTF file are
  all read in the encoding they declare — `rgx-core::charset`, with the
  tables generated from the reference implementation. The multi-byte CJK
  encodings are in as well: Shift_JIS, EUC-JP (with the three-byte
  JIS X 0212), Big5, EUC-KR, and GB18030 with its four-byte form, the
  extension to the Unicode planes. Their high half is a *pair* of bytes, and
  reading them one at a time does not read them differently — it reads them
  wrongly — so a file in one of them now answers in the characters it was
  written in: a search for こんにちは finds こんにちは. The single-byte
  tables that were missing are in as well — Windows-1258, KOI8-U and
  EBCDIC (code page 037, whose every byte is in its table, because its
  low half is not ASCII) — and so are the EBCDIC code pages other
  than 037: IBM500, IBM1047, IBM1140, IBM875, IBM1026 and IBM273, each
  with the labels the IANA charset registry gives it. IBM866 is read as
  well, and it is not an EBCDIC page but the Cyrillic code page of the
  PC. The encodings that declare themselves by *changing* mid-stream are
  read now too: **ISO-2022-JP**, with the designations of RFC 1468 —
  ASCII, JIS X 0201 Roman and Katakana, JIS X 0208 and JIS X 0212 —
  and **UTF-7**, the `+<base64>-` form of RFC 2152. What is still not
  there, and refused by name: GB2312 and the ISO-2022-JP-2 and
  ISO-2022-JP-3 charsets, which are not RFC 1468, and the predecessor of
  UTF-7, UNICODE-1-1-UTF-7.
- **LevelDB / RocksDB checksums are verified** — the write-ahead log's
  per-record CRC-32C is checked, and a record that fails it ends the walk
  where it happened and says so. A sorted table's per-block checksum is
  checked too: it is over the bytes as they are in the file, so it is
  verified *before* the in-house Snappy decoder sees them, and a block that
  fails it is a block whose bytes are wrong rather than one the decoder
  disagreed about. The structural walk still bounds every read by the block
  handles.
- **The CDF layouts that are not netCDF's** — `CDF\x05` (the netCDF
  library's own CDF-5: the classic model with a 64-bit data section), NASA's
  CDF-1 (`00 00 FF FF`) and NASA's CDF-2 (`CD F2 60 02`) carry a descriptor
  of their own, and each of them is now read as its own layout rather than
  parsed with netCDF's offsets. **CDF-5** is the classic layout with the
  widths the specification gives it: the counts and the lengths in 64 bits
  instead of 32, the `ABSENT` list as a 32-bit zero followed by a 64-bit
  one, the streaming marker as eight `0xFF` instead of four, and the five
  types the edition adds (`NC_UBYTE`, `NC_USHORT`, `NC_UINT`, `NC_INT64`,
  `NC_UINT64`) read with their own width and sign — the type tag `0x0A`
  means `NC_INT64` where a *type* appears and keeps meaning
  `NC_DIMENSION` where a *list tag* appears, and the reader decides by the
  place. Its fixture is the file the specification itself prints, byte for
  byte, so the values are the ones the document says they are. **NASA's
  CDF-1 and CDF-2** are the same chain of internal records as CDF-3 — the
  CDR, the GDR, the variable and attribute records — with the record sizes
  and the offsets in 32 bits where CDF-3 has 64, the 128 extra bytes a
  pre-V2.5 file keeps in its variable record, and the dimension variances
  that say which dimensions the file stores. Their values were checked
  against the `cdflib` oracle: 23 999 values of the CDF-1 fixture and 21 of
  the CDF-2 one, with no divergence — the reader declines that file's
  `Epoch` variable, 1 090 more values, because the type carries an
  encoding of its own, and it says so in its own output. The **classic**
  netCDF layouts are read
  to the end: the dimensions, the variables, their attributes, and their
  **values**, one line per element with the index that locates it — a record
  variable's element read out of the record that holds it. The **streaming**
  variant of the classic model is read as well: its header is the one the
  reader walks, and the count of the records — which that header does not
  carry — is what the length of the file holds of them. What is still
  refused, by name: a **streaming CDF-5** file, whose marker is eight
  `0xFF` rather than four, and a streaming file whose only record variable
  is a byte, a char or a short, whose records the specification leaves
  unpadded and this reader does not walk. NASA's **CDF-3** (`CD F3 00 01`)
  is read: its variables,
  their types and shapes, and its attributes, with the compressed-descriptor
  form unpacked first, and its **values**: the blocks a chain of index
  records points at, one line per element, with the index that locates it.
  What is not read: the values of a variable whose data the file
  compressed, or whose records are sparse, or whose type carries an
  encoding of its own — and the reader says which is which, variable by
  variable.
- **Zarr** — the values are read: the manifest says the shape, the dtype
  and the codec, and the chunks beside it are decompressed and decoded. The
  **v3 layout** — the one `zarr-python` writes by default — is read too, and
  so is its **transpose** codec, which permutes the axes of a chunk's
  elements: the values come out with the array's own axes. The
  **consolidated metadata** (`.zmetadata`) of a v2 group is read as well —
  the manifest of every array of the group is in that one file, and the
  chunks of an array are in the array's own directory. The v3 layout, the
  transpose codec and the consolidated metadata are read back by
  `zarr-python` itself, version 3.4.1, before they are committed, so the
  values here are the ones the world agrees on. The **blosc** codec — the
  one `zarr-python` asks for by default — *is* decoded now: the frame is a
  header, a table of block offsets and the blocks, and the blocks are LZ4
  with the byte shuffle applied to them. The frames were checked against the
  two implementations that write them, c-blosc itself and `numcodecs`, the
  codec library `zarr-python` sits on, so the numbers are not a decoder's
  own opinion of its own output. The **sharding codec** is read too: a
  shard is the inner chunks followed by an index of two little-endian 64-bit
  numbers per inner chunk (its offset and its size, with `2^64−1` for an
  empty one), and the index sits at the start or the end of the shard. The
  order of the chunks inside a shard is **not** fixed by the specification,
  so the reader goes through the index and not through the order the writer
  happened to use — `zarr-python` writes them in the Morton order, and a
  reader that assumed the grid order would come out wrong. The **rectilinear
  chunk grid** is read as well (it is the grid that is not the regular one:
  the Zarr specification calls it nothing, and the extension that defines it
  calls it *rectilinear*), with its two axis forms — a step, and a list of
  edges — and with the rule that the edges of an axis may run past its end.
  What is not read is the transpose codec together with the sharding codec
  (the transpose permutes the axes *before* the shard is split, so the inner
  chunks live in the permuted space), a sharding codec inside a sharding
  codec, a transpose inside the sharding codec's own pipeline, an index
  codec other than `bytes` or `crc32c` (the index is found by its size, so
  its pipeline has to be of a fixed size), and a big-endian index. The
  **blosc** frame's other codecs are read now — `blosclz`, `zstd` and `zlib`
  — and the codec a frame names is read from the frame's own enumeration,
  which is not c-blosc's library one: the frame's code 2 is snappy where
  the library's code 2 is lz4hc, and the frame's code 4 is zstd where the
  library's code 5 is. `snappy` is decoded and there is a frame to check it
  against now: numcodecs has no name for the codec -- its blosc accepts
  blosclz, lz4, lz4hc, zlib and zstd -- so the frame came from c-blosc
  1.18.1, the last release with the snappy built in, and the frame's flags
  say the codec is the snappy one and that the blocks are really snappy
  compressed. Still refused by name: a transpose whose order is not
  a permutation of the array's axes, or one that comes after the `bytes`
  codec, which is a pipeline `zarr-python` refuses. A consolidated group is refused whole when
  one of the arrays it names has a manifest the adapter does not read: the
  answer of a group is the answer of its arrays, and half of one is not an
  answer. A `.zarray` inside a container is refused too: its chunks are not
  beside it.
- **The HDF5 reader reads the names of a netCDF-4 file in the current
  layout, and now its chunked datasets in every layout.** The v2 object
  header, the link info
  message, the v2 B-tree and the fractal heap are walked, and the file the
  netCDF library's own `ncdump` reference covers gives the same 146 names
  in the same order. The other storage is walked too: a group with few
  enough members keeps its names in the object header as link messages
  instead of in a heap, and a small object header puts the rest of its
  messages in continuation chunks — both are read, and a type the file
  shares with other objects is followed to the object header that holds
  it. The **attributes** are read as well, with the value the file's own
  datatype gives them — the file's own attributes and the ones of every
  member, a number as a number, a string as a string, and the bytes of a
  value that is neither as hex. The **members of a type** are read as well:
  the names of an enumeration with the values the file gives them, and the
  names of a compound with the types they hold. The **values** are read as
  well: one line per element, with the index that locates it, and the same
  `ncdump` reference lists them — the datasets the file stores in one block
  and the ones it stores in **chunks**, whose index is read in every one of
  its forms: the v1 B-tree, the single chunk, the implicit index, the fixed
  array, the extensible array and the v2 B-tree. The **old-style groups**
  are read as well: their names live in a symbol
  table — a tree that indexes the nodes of the table and a local heap
  that holds the names — and the reader walks both. The **filters** are
  undone where the reader can: the shuffle, which interlaces the bytes
  of the elements, the Fletcher-32, which appends a checksum of the
  data (and the reader checks that checksum, which is the file's own
  oracle for the bytes), and the **deflate**, which compresses the
  result — the HDF5 library's filter holds a zlib stream, and the reader
  inflates it under the ceiling the chunk's own size gives. The **old
  chunk layout** is read as well: a layout message of the first two
  versions counts the size of an element as a dimension of its own, and
  the reader reads the chunk's shape without it. What is not read: the
  types reported are the HDF5 ones -- `byte` and `schar` are both a
  signed 8-bit integer in the file, so netCDF's own distinction between
  them is not there to read.
  - **The GRIB packings that are not simple** — edition 2's **reduced grids**
    *are* read now: the grid definition section carries an optional list of
    numbers, and the list says how many points each row of the grid holds —
    or, for the third interpretation of code table 3.11, the latitude of each
    row. A reduced grid has no number of columns: the field is missing, all
    ones, and the shape of the grid is in the list. Its oracle is the pair of
    libraries that write and read these files — NOAA's own g2c library and
    ECMWF's ecCodes — which read the same list out of the same bytes; the
    third interpretation has no file in the corpus, so its numbers are
    reported as they stand. Edition 1's **extra octet-14 flags** are read too:
    they name the layout of the second-order packing a section is in, so the
    refusal names the layout instead of the packing in general, and the
    **truncation parameters** J, K and M of a spherical-harmonic grid say how
    many coefficients the section holds. The **spherical harmonics** are
    decoded now, in both editions. A spectral field is packed with its own
    packing — edition 1's "spherical harmonics-complex packing" (which is
    *not* the second-order packing: the second-order one is the grid-point
    packing by differences within groups, and the two share a bit of the
    same flag while having nothing else in common), and edition 2's
    spectral templates 5.50 and 5.51. The values are the spectral ones:
    the coefficients in the order of code table 3.7 (the row `m` outside,
    the wave number `n` inside it, the real part and the imaginary part of
    each), the unpacked subset of them in the file's front — in **IBM**
    float in edition 1 and in **IEEE** in edition 2, which is the trap a
    port falls into — and the rest packed behind it, with the Laplacian
    scale the format applies to them. The 4 160 values of both editions
    were compared with ECMWF's own ecCodes, value by value: the 420 subset
    values that carry no scale agree to the last bit, the ones that do
    carry it — the `n = 20` line of edition 1, which the GRIBEX correction
    touches — agree to 6.4e-16, and the packed and Laplacian-scaled values
    to 2.2e-15. The gap is the reader's own `powf`, the crate being
    `no_std`: it multiplies the same factor ecCodes multiplies, in a
    different order, so the last bit moves.
    Edition 2's template 5.53 — the bi-Fourier variant for limited area
    models, with its own resolution parameters and code tables — is
    decoded now: the IEEE 32-bit subset in the file's front and the packed
    part behind it, with the Laplacian scale the format applies. Its two
    fixtures were written by ECMWF's own ecCodes, by the test program that
    writes these files, and read back by ecCodes 2.50: the 3 128 and 4 096
    values of the two files agree with the oracle to the last bit. What is
    still refused, by name: the rhomboidal and the trapezoidal truncations,
    the edition 1 modes of the spectral packing other than the complex one,
    and a subset whose precision is not the IEEE 32-bit one. The truncations
    are refused because the two references disagree about the size of the
    field — g2c lays the rows out one way and ecCodes counts another, and
    ecCodes refuses the layout in its own encoder and decoder alike, so no
    oracle is left to check a reading against. Edition 2's
    **complex packing** *is* decoded now: data
    representation templates 5.2 and 5.3, with the spatial differencing of
    the first and the second order, the groups the field is split into and
    the reference value each group carries. Its oracle is NOAA's own g2c
    library -- the one NCEP writes those files with -- and every value the
    reader prints was compared with what that library reads out of the same
    bytes. Edition 1's simple packing is decoded too, against the reference
    values of the IBM 360 float the edition's data section specifies.
- **CRAM 2 and 3** — the containers are walked the way the files hold them,
  and the editions that are not read are refused by name. A container's
  `length` is the size of its *blocks* and the container header carries its
  own size, so the next container is `header size + length` bytes on; a
  block occupies its header, its data and — from CRAM 3 on — its CRC32. The
  block count is only a guide: htsjdk writes a CRAM 3.1 file whose second
  container declares 28 blocks and carries 30, so the region a container
  covers is bounded by its `length`. The **CRC32s are verified** now — the one of the container header, over
  the header's own bytes, and the one of each block, over the block's header
  and its data — and the **record encodings are read**: the three maps of
  the compression header, the slice header, the ten codecs of CRAM 2.1 and
  the records of a slice. A slice whose records sit in a block compressed
  with a method this reader does not decode is refused by name, and so are
  the bases of a mapped read, which come from the reference this reader does
  not carry. Every block method the specifications give is decoded now:
  **bzip2**, which CRAM has carried since 2.0, **lzma**, which CRAM 3.0 added
  — and that method is not a bare LZMA stream but the xz container, which the
  in-house reader opens — the **rANS codec**, the 4x8 range coder of CRAM 3.0,
  whose frame the reader opens with the order, the two sizes, the frequency
  table and the four interleaved states the codec specification defines, the
  **rANS Nx16 codec** of CRAM 3.1, which is the same codec with four or with
  thirty-two states and with the tables the specification puts in the frame, the
  **adaptive arithmetic** of CRAM 3.1, whose frame is a flag byte, the length
  and the range-coded bytes, with the run-length, the bit-packing, the striping
  and the external-codec flags the specification gives it, the **name
  tokeniser** of CRAM 3.1, which turns a list of read names into a list of
  token streams and rebuilds the names out of them, the differences to the
  names before them included, and the **fqzcomp** of CRAM 3.1, which codes the
  quality scores of a slice against a context that mixes the quality before,
  the position in the record and the number of changes so far. The frames the
  tests carry were written by the reference implementation of these codecs, the
  htscodecs library, and not by this reader. **CRAM 1** is refused because no CRAM 1 specification is
  published, and that is checkable rather than asserted: the repository
  that holds these documents has never had a `CRAMv1.pdf` — the commits API
  for that path returns an empty array — and the CRAM 2.1 specification says
  of 1.0 that 2.0 "tidied up implementation vs specification differences in
  1.0", so the two implementations of it disagreed with each other. htsjdk's
  own reader cannot read a CRAM 1 container at all: it reads the container's
  length as an int32 for every edition, where CRAM 1 wrote an ITF-8 — though
  htslib's does read the container of a CRAM 1, so the container alone is
  not out of reach; the record layer of a 1.0 is what has no text at all.
  **CRAM 4** is refused because its specification is a draft — an unmerged
  pull request, whose integers are a big-endian VLQ with a zigzag for the
  signed ones instead of the ITF-8 and the LTF-8 — that does not even define
  its own version bytes, and no CRAM 4 file was available to check a reading
  against.
  The oracle is htsjdk: its own container reader reads the same bytes the
  same way, and the eight alignments it reads back out of the fixture are
  the eight this reader totals.
- **Brotli has no magic** — RFC 7932 defines none, so a `.br` file cannot be
  recognised before it is decoded. That one shape is decided by the decoder's
  own error rather than by the pre-check the other suffixes get.
- **The media containers, and what each one still leaves out.** The Ogg
  comment block is the same in every Ogg codec, and it is read in all three
  of them: Vorbis (`\x03vorbis`), Opus (`OpusTags`) and Theora
  (`\x81theora`) each name their own header packet, and a reader that knew
  only the Vorbis one read a Vorbis stream and nothing else. The ASF family
  is read as the one container it is, so a `.wma` gives back its title and
  its description the way a `.wmv` does — which matters more than it looks,
  because ASF stores its strings as UTF-16 and the title of a `.wma` is not
  findable in the raw bytes by a search for its own text. What is left: a
  **bare `.aac`** is an ADTS elementary stream with no container at all, so
  there are no properties in it to read, and the file keeps `rg`'s raw
  answer (the AAC case that carries metadata is `.m4a`, and it is read);
  the **subtitles** (`.srt .sub .vtt .dfxp`) have no adapter, which is not a
  gap in the searchable sense — they are text, and `rg` reads them — but
  their cues and their timings are not parsed, and a **binary** `.sub` is
  cut by the rule that cuts every binary file; and **WordPerfect's text**
  is not decoded: the reader gives the document type and the point size,
  because the text lives in a thesaurus-indexed encoding that no short
  reader decodes, and a reader that guessed at it would print the wrong
  words with the right shape.
- **FoxPro memo and index companions** — the `.dct` beside a container is
  its memo file, and it *is* read: a memo field holds the number of the
  block its text is in, and with the memo file beside it a row carries the
  text and not the number. The `.dcx` is the container's compound index, and
  it **is** read too: its layout — a key expression pool and a B-tree whose
  keys are packed backwards from the end of the page — is established (each
  tag header carries its own 512-byte expression area, and the leaf's
  bit-packed entries are read through a prefix-compressed key heap that
  grows down from the end of the page), and the reader names the index's
  tags, their key expressions, their key widths and the rows they point at.
  The layout was checked against the container's own rows: the 114 keys the
  index decodes are the values of the 57 rows it points at, in both tags,
  with no divergence. The names the index holds are the container's; the
  **tags** and the key expressions are the index's own.
- **Lotus 1-2-3 `.wk2`** — `.wks`, `.wk1`, `.wk3`, `.wk4` and `.123` are
  decoded. The v1/v2 layout is verified against real sheets (`PEYNEVAL.WK1`,
  155 KB, 8 315 records, walking exactly to the `0x0001` EOF record), and the
  v3 and v4 layouts are verified against the same sheet in three formats:
  `example.wk1`, `example.wk3` and `example.wk4` hold one sheet, and every
  label and every number lands on the same address in all three, with the
  same words. A v3 cell is the row, a block byte, the column, and then
  either NUL-terminated text (`0x0016`) or a number in the x87's own 80-bit
  format (`0x0017`); the integer cell (`0x0018`) is left out and counted,
  because its unit is not established — the example sheet's twin reads
  exactly half of it, while the integers of a real v4 sheet only make sense
  as cents. The v4 (`.wk4`) cell layout is the v3's, and its sheet is a
  document of several tables, so the address names the table the cell
  belongs to (`B3R24C27`): of the 1 279 distinct (row, column) pairs of
  `DEMO.WK4`, 591 hold more than one cell. Its labels are read and its
  formulas are not — a formula's token stream and the result it was last
  evaluated to are not decoded, and the result does not say whether it
  holds a number or a string — so the reader says how many cells it left
  out. The Millennium (`.123`) sheet has a cell layout of its own again —
  the row, the column in 256ths of a character, and the payload — and the
  six cells it stores indirectly (their data lives elsewhere in the file)
  are left out and counted. `.wk2` is **the `.wk1` under another name**: 1-2-3
  v2.0 shipped the worksheet as `.wk1` and changed the extension to `.wk2`
  "quickly", so that the number in it would match the version number — the
  record layout did not change with it, and both files carry the BOF version
  code `0x0406`, which two independent readers (Gnumeric's and LibreOffice's)
  dispatch to the same opcode table. No Lotus `.wk2` sample is published
  where the corpus script can reach one, so the corpus holds a copy of the
  `.wk1` under the `.wk2` name, and the fetch script says so where it makes
  it: it is a **dispatch** fixture, which shows that the extension reaches the
  v2 reader and that the bytes under it are the v2 bytes, and says nothing
  new about the bytes — the `.wk1` already exercises those.
