// SPDX-License-Identifier: Apache-2.0

//! The flat files of the sequencing family: **FASTA**, **FASTQ**, **VCF**,
//! **GFF/GTF**, **PDB** and **mmCIF**.
//!
//! **What these are.** The formats the sequencing world writes by hand and
//! reads by eye: a genome as a list of sequences, a run as a list of reads,
//! a set of variants as a table, a set of features as a table, a structure
//! as fixed columns, a structure as a data dictionary. Every one of them is
//! plain text, which is the whole of the difference between them and the
//! containers in the other files of this crate — and it decides what an
//! adapter for them may and may not do.
//!
//! **Why they are rendered and not revealed.** `rg` reads all six, so an
//! adapter that *answered* for them would replace bytes ripgrep already
//! searches, and rgx would answer a subset of what `rg` answers. That is
//! the one thing this crate is built not to do, and it is why the binary
//! formats in this crate are containers: they hold bytes `rg` cannot see,
//! and surfacing them adds to the corpus instead of taking from it.
//!
//! These are therefore [`Reach::Render`], the same reach the markup family
//! in `rgx-adapters-office` declares, and the policy does the rest: under
//! the default `Policy::Source` a rendering adapter is not consulted at all
//! and the file's own bytes are the answer, and under `RGX_ADAPTER_VIEW=render`
//! or `RGX_ADAPTER_VIEW=both` the rendering is what gets searched. The default
//! answer is unchanged; the rendering is an extra view of the same file.
//!
//! (An earlier version of this crate's neighbours gave the opposite reason:
//! that an adapter for these formats "would make rgx a subset of `rg`".
//! That is true of a *revealing* adapter and false of a rendering one, and
//! the distinction is the whole of the difference between `.sam` — which is
//! declined when it is text and inflated when it is BGZF — and a `.fasta`,
//! which is text in both cases and is rendered in both cases.)
//!
//! **What the rendering is for.** Three things, and none of them is "more
//! of the same":
//!
//! 1. *A sequence that is wrapped can be matched.* A FASTA's sequence is
//!    conventionally written 60 or 80 columns wide, and a motif that
//!    straddles the wrap is split across two lines. `rg` cannot match
//!    across a line break; the rendering joins the lines, so it can.
//! 2. *Two adjacent fields can be matched.* A VCF and a GFF separate their
//!    columns with a tab, and a PDB separates its fields with fixed
//!    columns. A search for a chromosome and a position — or a residue and
//!    its chain — is one pattern in the rendering and two in the file, and
//!    the pattern the user can write is the one that matters.
//! 3. *The file is summarised.* The rendering opens with what the file
//!    holds — how many records, of how many kinds, over how many
//!    sequences — which is a question the file answers only by being read
//!    all the way through.
//!
//! **What is not claimed.** `.fa` is not claimed: it is what a Windows
//! linker calls a module definition file and what a Fortran compiler calls
//! a form file, and the name alone does not say which. `.fasta` and its
//! siblings are, and a file that does not open with a `>` is declined so
//! that something else gets its chance.

use alloc::string::String;
#[cfg(any(feature = "gff", feature = "mmcif", feature = "pdb", feature = "vcf"))]
use alloc::string::ToString;
#[cfg(any(feature = "gff", feature = "mmcif", feature = "pdb", feature = "vcf"))]
use alloc::vec::Vec;
use core::fmt::Write as _;
#[cfg(any(feature = "fastq", feature = "gff", feature = "mmcif", feature = "vcf"))]
use rgx_core::bail;
use rgx_core::{decline, Adapter, Outcome, Reach, Result};

/// Bytes one rendering may produce.
///
/// The input is already in memory — the walker reads the file whole before
/// an adapter sees it — so this is not a bound on what can be read, it is a
/// bound on how much *more* the rendering may cost. A 64 MiB ceiling is far
/// above any file whose whole content is worth a second copy, and the
/// rendering says so when it bites rather than stopping in silence.
#[cfg(any(
    feature = "fasta",
    feature = "fastq",
    feature = "gff",
    feature = "mmcif",
    feature = "pdb",
    feature = "vcf"
))]
const MAX_RENDER: usize = 64 << 20;

// ---------------------------------------------------------------------------
// FASTA
// ---------------------------------------------------------------------------

/// A genome as a list of sequences.
#[cfg(feature = "fasta")]
pub struct Fasta;
#[cfg(feature = "fasta")]
impl Adapter for Fasta {
    fn name(&self) -> &'static str {
        "fasta"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["fasta", "fna", "faa", "fas", "frn", "ffn"]
    }
    /// The file is text `rg` already reads: a rendering, never an answer.
    fn reach(&self) -> Reach {
        Reach::Render
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(render_fasta(data)?.into_bytes()))
    }
}

/// The FASTA rendering: one line per record's description, one line per
/// record's sequence, and a summary in front.
///
/// The sequence is joined: a FASTA's sequence is written 60 or 80 columns
/// wide by every tool that writes one, and a motif across that boundary is
/// two lines in the file and one in here.
#[cfg(feature = "fasta")]
fn render_fasta(data: &[u8]) -> Result<String> {
    let src = String::from_utf8_lossy(data);
    let mut body = String::new();
    let mut records = 0usize;
    let mut bases = 0usize;
    let mut longest = 0usize;
    let mut description: Option<&str> = None;
    let mut sequence = String::new();

    for line in src.lines() {
        // The carriage return of a DOS file is not part of a sequence.
        let line = line.trim();
        if let Some(rest) = line.strip_prefix('>') {
            if let Some(desc) = description.take() {
                records += 1;
                bases += sequence.len();
                if sequence.len() > longest {
                    longest = sequence.len();
                }
                let _ = writeln!(body, ">{desc}");
                let _ = writeln!(body, "{}", sequence);
                sequence.clear();
            }
            description = Some(rest.trim());
        } else if description.is_some() {
            sequence.push_str(line);
        } else if !line.is_empty() {
            // Not a failure: a file that does not open with a `>` is some
            // other format, and declining is what lets the next adapter
            // have it.
            decline!("fasta: sequence data before the first '>' header");
        }
    }
    if let Some(desc) = description.take() {
        records += 1;
        bases += sequence.len();
        if sequence.len() > longest {
            longest = sequence.len();
        }
        let _ = writeln!(body, ">{desc}");
        let _ = writeln!(body, "{}", sequence);
    }

    if records == 0 {
        decline!("fasta: no '>' header, so no records");
    }
    Ok(finish(
        &format!("fasta: {records} records, {bases} bases (longest {longest})"),
        &body,
    ))
}

// ---------------------------------------------------------------------------
// FASTQ
// ---------------------------------------------------------------------------

/// A run as a list of reads.
#[cfg(feature = "fastq")]
pub struct Fastq;
#[cfg(feature = "fastq")]
impl Adapter for Fastq {
    fn name(&self) -> &'static str {
        "fastq"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["fastq", "fq"]
    }
    fn reach(&self) -> Reach {
        Reach::Render
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(render_fastq(data)?.into_bytes()))
    }
}

/// The FASTQ rendering: the four logical lines of every read, with the
/// sequence and the quality joined when the writer wrapped them.
///
/// The record's end is not "four lines" — the specification allows the
/// sequence and the quality to be wrapped over as many lines as the writer
/// likes, and the record ends when the quality is as long as the sequence.
/// A reader that took four lines would read half a read as a record and
/// call the rest of the file broken.
#[cfg(feature = "fastq")]
fn render_fastq(data: &[u8]) -> Result<String> {
    let src = String::from_utf8_lossy(data);
    let mut body = String::new();
    let mut reads = 0usize;
    let mut bases = 0usize;
    let mut mismatched = 0usize;

    let mut lines = src.lines().map(|l| l.trim_end_matches('\r'));
    while let Some(header) = lines.next() {
        if header.trim().is_empty() {
            continue;
        }
        let Some(id) = header.strip_prefix('@') else {
            if reads == 0 {
                // The file does not open with a read: it is some other
                // format, and declining is what lets the next adapter have
                // it.
                decline!("fastq: the first record does not start with '@'");
            }
            bail!("fastq: a record does not start with '@'");
        };
        // The sequence, up to the '+' line.
        let mut sequence = String::new();
        let mut saw_plus = false;
        for line in lines.by_ref() {
            if line.starts_with('+') {
                saw_plus = true;
                break;
            }
            sequence.push_str(line.trim());
        }
        if !saw_plus {
            bail!("fastq: a record has no '+' line");
        }
        // The quality, until it is as long as the sequence.
        let mut quality = String::new();
        while quality.len() < sequence.len() {
            let Some(line) = lines.next() else {
                break;
            };
            quality.push_str(line.trim_end());
        }
        if quality.len() != sequence.len() {
            mismatched += 1;
        }
        reads += 1;
        bases += sequence.len();
        let _ = writeln!(body, "@{id}");
        let _ = writeln!(body, "{sequence}");
        let _ = writeln!(body, "+");
        let _ = writeln!(body, "{quality}");
    }

    if reads == 0 {
        decline!("fastq: no '@' header, so no reads");
    }
    let mut summary = format!("fastq: {reads} reads, {bases} bases");
    if mismatched > 0 {
        let _ = write!(
            summary,
            ", {mismatched} read(s) whose quality is not as long as its sequence"
        );
    }
    Ok(finish(&summary, &body))
}

// ---------------------------------------------------------------------------
// VCF
// ---------------------------------------------------------------------------

/// A set of variants as a table.
#[cfg(feature = "vcf")]
pub struct Vcf;
#[cfg(feature = "vcf")]
impl Adapter for Vcf {
    fn name(&self) -> &'static str {
        "vcf"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["vcf"]
    }
    fn reach(&self) -> Reach {
        Reach::Render
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(render_vcf(data)?.into_bytes()))
    }
}

/// The VCF rendering: the header as it was written, and every variant with
/// its columns separated by spaces and its `INFO` field's pairs separated by
/// spaces too.
///
/// The columns of a VCF are tab-separated, and the `INFO` field's pairs are
/// semicolon-separated inside one column. A search for a chromosome and a
/// position is one pattern here and two in the file.
#[cfg(feature = "vcf")]
fn render_vcf(data: &[u8]) -> Result<String> {
    let src = String::from_utf8_lossy(data);
    let mut body = String::new();
    let mut variants = 0usize;
    let mut samples = 0usize;
    let mut contigs = 0usize;
    let mut saw_header = false;

    for line in src.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with('#') {
            if line.starts_with("##contig=") {
                contigs += 1;
            }
            if line.starts_with("#CHROM") {
                saw_header = true;
                // The column header: the sample names are the columns after
                // `FORMAT`.
                let cols: Vec<&str> = line.split('\t').collect();
                if let Some(fmt) = cols.iter().position(|c| *c == "FORMAT") {
                    samples = cols.len().saturating_sub(fmt + 1);
                }
                let _ = writeln!(body, "{}", line.replace('\t', " "));
            } else {
                let _ = writeln!(body, "{line}");
            }
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        if !saw_header {
            if variants == 0 {
                // The file does not open with the column header: it is some
                // other format, and declining is what lets the next adapter
                // have it.
                decline!("vcf: the file does not open with the #CHROM header line");
            }
            bail!("vcf: a variant before the #CHROM header line");
        }
        variants += 1;
        let cols: Vec<&str> = line.split('\t').collect();
        let mut rendered: Vec<String> = Vec::with_capacity(cols.len());
        for (i, col) in cols.iter().enumerate() {
            // The INFO column (the eighth) holds `key=value` pairs joined by
            // semicolons; every other column is one value.
            if i == 7 {
                rendered.push(
                    col.split(';')
                        .filter(|p| !p.is_empty())
                        .collect::<Vec<_>>()
                        .join(" "),
                );
            } else {
                rendered.push((*col).to_string());
            }
        }
        let _ = writeln!(body, "{}", rendered.join(" "));
    }

    if !saw_header {
        decline!("vcf: no #CHROM header line");
    }
    Ok(finish(
        &format!("vcf: {variants} variants, {samples} sample(s), {contigs} contig(s)"),
        &body,
    ))
}

// ---------------------------------------------------------------------------
// GFF / GTF
// ---------------------------------------------------------------------------

/// A set of features as a table.
#[cfg(feature = "gff")]
pub struct Gff;
#[cfg(feature = "gff")]
impl Adapter for Gff {
    fn name(&self) -> &'static str {
        "gff"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["gff", "gff2", "gff3", "gtf"]
    }
    fn reach(&self) -> Reach {
        Reach::Render
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(render_gff(data)?.into_bytes()))
    }
}

/// The GFF/GTF rendering: the nine columns separated by spaces, and the
/// attributes expanded into `key=value` pairs whatever dialect wrote them.
///
/// GFF3 writes `ID=gene1;Name=BRCA1` and GTF writes `gene_id "G1"; gene_name
/// "BRCA1"`, and a search for one of them does not find the other. The
/// rendering puts both in the same shape, because the question the user is
/// asking — "which feature is this" — has the same answer in both.
#[cfg(feature = "gff")]
fn render_gff(data: &[u8]) -> Result<String> {
    let src = String::from_utf8_lossy(data);
    let mut body = String::new();
    let mut features = 0usize;
    let mut kinds: Vec<(String, usize)> = Vec::new();
    let mut seqids: Vec<String> = Vec::new();

    for line in src.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with('#') || line.trim().is_empty() {
            let _ = writeln!(body, "{line}");
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 8 {
            if features == 0 {
                // The file does not open with a feature: it is some other
                // format, and declining is what lets the next adapter have
                // it.
                decline!("gff: the first line has {} columns, not 8 or 9", cols.len());
            }
            // Nine columns are the specification; eight is the GFF2 minimum
            // that carries no phase.
            bail!("gff: a feature has {} columns, not 8 or 9", cols.len());
        }
        features += 1;
        let kind = cols[2].to_string();
        match kinds.iter_mut().find(|(k, _)| *k == kind) {
            Some((_, n)) => *n += 1,
            None => kinds.push((kind, 1)),
        }
        if !seqids.iter().any(|s| s == cols[0]) {
            seqids.push(cols[0].to_string());
        }
        let mut rendered: Vec<String> = cols[..7].iter().map(|c| (*c).to_string()).collect();
        // The attributes are the LAST column: GFF3 puts the phase in column
        // 8 and the attributes in column 9, GFF2 has no phase and puts the
        // attributes in column 8, and GTF puts the frame in column 8 and
        // the attributes in column 9. Reading the attributes out of column
        // 8 — the GFF2 position — turns a GFF3's phase into its attributes
        // and loses every gene name in the file.
        if cols.len() > 8 {
            rendered.push(cols[7].to_string());
        }
        rendered.push(attributes(cols[cols.len() - 1]));
        let _ = writeln!(body, "{}", rendered.join(" "));
    }

    if features == 0 {
        decline!("gff: no feature lines");
    }
    let kinds: Vec<String> = kinds.iter().map(|(k, n)| format!("{n} {k}")).collect();
    Ok(finish(
        &format!(
            "gff: {features} features ({}) on {} seqid(s)",
            kinds.join(", "),
            seqids.len()
        ),
        &body,
    ))
}

/// The attributes of one feature, as `key=value` pairs.
///
/// GFF3's `ID=x;Name=y` and GTF's `gene_id "x"; gene_name "y"` are the same
/// information in two spellings, and both are read here. A part that is
/// neither is kept as it was, because a pair this reader does not
/// understand is still a pair the file wrote.
#[cfg(feature = "gff")]
fn attributes(raw: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for part in raw.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((k, v)) = part.split_once('=') {
            let (k, v) = (k.trim(), v.trim());
            if k.is_empty() {
                out.push(part.to_string());
            } else {
                out.push(format!("{k}={v}"));
            }
            continue;
        }
        // GTF's `key "value"`.
        if let Some((k, v)) = part.split_once(char::is_whitespace) {
            let k = k.trim();
            let v = v.trim().trim_matches('"').trim_matches('\'');
            if !k.is_empty() && !v.is_empty() {
                out.push(format!("{k}={v}"));
                continue;
            }
        }
        out.push(part.to_string());
    }
    out.join(" ")
}

// ---------------------------------------------------------------------------
// PDB
// ---------------------------------------------------------------------------

/// A structure as fixed columns.
#[cfg(feature = "pdb")]
pub struct Pdb;
#[cfg(feature = "pdb")]
impl Adapter for Pdb {
    fn name(&self) -> &'static str {
        "pdb"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["pdb", "ent"]
    }
    fn reach(&self) -> Reach {
        Reach::Render
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(render_pdb(data)?.into_bytes()))
    }
}

/// The PDB rendering: every record whose layout the specification fixes,
/// with its fields separated by spaces.
///
/// A PDB record is a fixed-column table, and the columns are what a reader
/// wants: the atom's name, the residue's name, the chain, the residue
/// number and the coordinates, in that order and separated by spaces. The
/// free-text records — `HEADER`, `TITLE`, `COMPND`, `REMARK` — are joined
/// into one line each, because a PDB wraps them at column 80 and a
/// continuation is a line that starts in column 11.
///
/// The records whose layout this reader does not know are passed through as
/// they were. A guessed column layout is worse than no layout: it puts
/// numbers in the wrong places, and nothing downstream can tell.
#[cfg(feature = "pdb")]
fn render_pdb(data: &[u8]) -> Result<String> {
    let src = String::from_utf8_lossy(data);
    let mut body = String::new();
    let mut atoms = 0usize;
    let mut chains: Vec<String> = Vec::new();
    let mut models = 0usize;
    let mut pending: Option<(String, Vec<String>)> = None;

    for line in src.lines() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        let record = line.get(..6).unwrap_or("").trim().to_string();
        // A continuation of the record above. The PDB writes one two ways:
        // the record name repeated in columns 1-6 with the continuation
        // number in columns 9-10 (`COMPND   2 MOLECULE: ...`), and the name
        // left blank. Both are the same record, continued.
        let continues = pending
            .as_ref()
            .map(|(kind, _)| (line.len() > 10 && line.starts_with(' ')) || record == *kind);
        if continues == Some(true) {
            let (_, parts) = pending.as_mut().unwrap();
            parts.push(line.get(10..).unwrap_or("").trim().to_string());
            continue;
        }
        if let Some((kind, parts)) = pending.take() {
            let _ = writeln!(body, "{}", free_text(&kind, &parts));
        }
        match record.as_str() {
            "ATOM" | "HETATM" => {
                atoms += 1;
                let chain = field(line, 22, 22).to_string();
                if !chain.is_empty() && !chains.contains(&chain) {
                    chains.push(chain);
                }
                let _ = writeln!(body, "{}", atom_line(line));
            }
            "MODEL" => {
                models += 1;
                let _ = writeln!(body, "MODEL {}", field(line, 11, 14));
            }
            "ENDMDL" => {
                let _ = writeln!(body, "ENDMDL");
            }
            "HEADER" | "TITLE" | "COMPND" | "SOURCE" | "REMARK" | "EXPDTA" | "KEYWDS"
            | "AUTHOR" | "REVDAT" | "JRNL" => {
                let rest = line.get(10..).unwrap_or("").trim().to_string();
                pending = Some((record.clone(), vec![rest]));
            }
            _ => {
                // Everything else is passed through as it was written.
                let _ = writeln!(body, "{line}");
            }
        }
    }
    if let Some((kind, parts)) = pending.take() {
        let _ = writeln!(body, "{}", free_text(&kind, &parts));
    }

    if atoms == 0 {
        decline!("pdb: no ATOM or HETATM record");
    }
    Ok(finish(
        &format!(
            "pdb: {atoms} atoms, {} chain(s), {models} model(s)",
            chains.len()
        ),
        &body,
    ))
}

/// One `ATOM`/`HETATM` record, with its columns named.
///
/// The column numbers are the PDB specification's, and they are 1-based and
/// inclusive: the atom's name is columns 13 to 16, the residue's name is 18
/// to 20, and so on.
#[cfg(feature = "pdb")]
fn atom_line(line: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    for (from, to) in [
        (1, 6),
        (7, 11),
        (13, 16),
        (18, 20),
        (22, 22),
        (23, 26),
        (31, 38),
        (39, 46),
        (47, 54),
        (55, 60),
        (61, 66),
        (77, 78),
    ] {
        let v = field(line, from, to);
        if !v.is_empty() {
            parts.push(v.to_string());
        }
    }
    parts.join(" ")
}

/// A free-text record, with its continuation lines joined.
#[cfg(feature = "pdb")]
fn free_text(kind: &str, parts: &[String]) -> String {
    let body: Vec<&str> = parts
        .iter()
        .map(|p| p.as_str())
        .filter(|p| !p.is_empty())
        .collect();
    if body.is_empty() {
        kind.to_string()
    } else {
        format!("{kind} {}", body.join(" "))
    }
}

/// One fixed-column field, 1-based and inclusive.
#[cfg(feature = "pdb")]
fn field(line: &str, from: usize, to: usize) -> &str {
    if from == 0 || from > line.len() {
        return "";
    }
    let start = from - 1;
    let end = to.min(line.len());
    if start >= end {
        return "";
    }
    line[start..end].trim()
}

// ---------------------------------------------------------------------------
// mmCIF
// ---------------------------------------------------------------------------

/// A structure as a data dictionary.
#[cfg(feature = "mmcif")]
pub struct MmCif;
#[cfg(feature = "mmcif")]
impl Adapter for MmCif {
    fn name(&self) -> &'static str {
        "mmcif"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["cif", "mmcif"]
    }
    fn reach(&self) -> Reach {
        Reach::Render
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(render_mmcif(data)?.into_bytes()))
    }
}

/// The mmCIF rendering: the data blocks, their items, and the rows of their
/// loops with the values separated by spaces.
///
/// mmCIF is a small language: a `data_` block holds items (`_tag value`)
/// and loops (`loop_` followed by the tags and then the values, in rows the
/// file does not number), and a value may be a quoted string or a
/// semicolon-delimited block of text that runs to the next line starting
/// with a semicolon. The rendering keeps all of it and separates the values
/// of a row with spaces.
#[cfg(feature = "mmcif")]
fn render_mmcif(data: &[u8]) -> Result<String> {
    let src = String::from_utf8_lossy(data);
    let mut body = String::new();
    let mut blocks = 0usize;
    let mut items = 0usize;
    let mut loops = 0usize;
    let mut rows = 0usize;

    let mut lines = src.lines().map(|l| l.trim_end_matches('\r'));
    let mut tags: Vec<String> = Vec::new();
    let mut values: Vec<String> = Vec::new();
    let mut in_loop = false;
    // The loop's header is written when its first value arrives, so it
    // stands above its rows instead of below them.
    let mut header_written = false;
    // Whether the loop has read a value yet. The tags come first and the
    // values after, so a tag line after the first value is not another tag
    // of this loop: it is the next thing in the file.
    let mut values_seen = false;

    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("data_") {
            if in_loop {
                flush_loop(
                    &mut body,
                    &mut tags,
                    &mut values,
                    &mut loops,
                    &mut rows,
                    &mut header_written,
                );
                in_loop = false;
            }
            blocks += 1;
            let _ = writeln!(body, "{trimmed}");
            continue;
        }
        if trimmed == "loop_" {
            if in_loop {
                flush_loop(
                    &mut body,
                    &mut tags,
                    &mut values,
                    &mut loops,
                    &mut rows,
                    &mut header_written,
                );
            }
            in_loop = true;
            header_written = false;
            values_seen = false;
            tags.clear();
            values.clear();
            continue;
        }
        if in_loop {
            if trimmed.starts_with('_') {
                if !values_seen {
                    // Still collecting the tags.
                    tags.push(trimmed.to_string());
                    continue;
                }
                // The loop's values are in: the next tag belongs to what
                // follows the loop, and a reader that swallowed it would
                // take the tag count of the row and group the values by it.
                flush_loop(
                    &mut body,
                    &mut tags,
                    &mut values,
                    &mut loops,
                    &mut rows,
                    &mut header_written,
                );
                in_loop = false;
                // and this line is an item of its own
            } else if let Some(text) = trimmed.strip_prefix(';') {
                values_seen = true;
                if !header_written {
                    let _ = writeln!(body, "loop_ {}", tags.join(" "));
                    header_written = true;
                }
                // A text block is one value, whatever it holds.
                let mut value = text.to_string();
                for cont in lines.by_ref() {
                    if let Some(done) = cont.strip_prefix(';') {
                        value.push('\n');
                        value.push_str(done);
                        break;
                    }
                    value.push('\n');
                    value.push_str(cont);
                }
                values.push(value);
                while !tags.is_empty() && values.len() >= tags.len() {
                    let row: Vec<String> = values.drain(..tags.len()).collect();
                    let _ = writeln!(body, "{}", row.join(" "));
                    rows += 1;
                }
                continue;
            } else {
                values_seen = true;
                if !header_written {
                    let _ = writeln!(body, "loop_ {}", tags.join(" "));
                    header_written = true;
                }
                // The values of a loop are a *stream* of tokens, not lines:
                // a line may hold several rows and a row may span several
                // lines, and the row is as wide as the loop's tags. A
                // reader that took the line for the value would find one
                // value where a dozen are written.
                for token in cif_tokens(trimmed) {
                    values.push(token);
                }
                while !tags.is_empty() && values.len() >= tags.len() {
                    let row: Vec<String> = values.drain(..tags.len()).collect();
                    let _ = writeln!(body, "{}", row.join(" "));
                    rows += 1;
                }
                continue;
            }
        }
        // An item: `_tag value`, with the value on this line or on the next.
        let (tag, rest) = match trimmed.split_once(char::is_whitespace) {
            Some((t, r)) => (t, r.trim().to_string()),
            None => (trimmed, String::new()),
        };
        let value = if rest.is_empty() {
            // The value is on the next line.
            let Some(next) = lines.next() else {
                bail!("mmcif: the item {tag} has no value");
            };
            let next = next.trim().to_string();
            if let Some(text) = next.strip_prefix(';') {
                let mut value = text.to_string();
                for cont in lines.by_ref() {
                    if let Some(done) = cont.strip_prefix(';') {
                        value.push('\n');
                        value.push_str(done);
                        break;
                    }
                    value.push('\n');
                    value.push_str(cont);
                }
                value
            } else {
                unquote(&next)
            }
        } else if let Some(text) = rest.strip_prefix(';') {
            let mut value = text.to_string();
            for cont in lines.by_ref() {
                if let Some(done) = cont.strip_prefix(';') {
                    value.push('\n');
                    value.push_str(done);
                    break;
                }
                value.push('\n');
                value.push_str(cont);
            }
            value
        } else {
            unquote(&rest)
        };
        items += 1;
        if value.starts_with('\n') {
            // A text block's text starts on the line after the semicolon, so
            // the tag stands on its own line.
            let _ = writeln!(body, "{tag}{value}");
        } else {
            let _ = writeln!(body, "{tag} {value}");
        }
    }
    if in_loop {
        flush_loop(
            &mut body,
            &mut tags,
            &mut values,
            &mut loops,
            &mut rows,
            &mut header_written,
        );
    }

    if blocks == 0 {
        decline!("mmcif: no data_ block");
    }
    Ok(finish(
        &format!("mmcif: {blocks} block(s), {items} item(s), {loops} loop(s), {rows} row(s)"),
        &body,
    ))
}

/// A loop that ended with values that do not fill a row.
///
/// The row width of a loop is the number of its tags, so the values are
/// grouped by that. When they do not divide evenly, the file's rows are not
/// the shape the loop says they are, and this says so rather than grouping
/// the remainder into a row that never existed.
#[cfg(feature = "mmcif")]
fn flush_loop(
    out: &mut String,
    tags: &mut [String],
    values: &mut Vec<String>,
    loops: &mut usize,
    rows: &mut usize,
    header_written: &mut bool,
) {
    if tags.is_empty() {
        values.clear();
        return;
    }
    *loops += 1;
    if !*header_written {
        // A loop with no values at all still names its tags, and the tags
        // are the only thing the file said about it.
        let _ = writeln!(out, "loop_ {}", tags.join(" "));
        *header_written = true;
    }
    while values.len() >= tags.len() {
        let row: Vec<String> = values.drain(..tags.len()).collect();
        let _ = writeln!(out, "{}", row.join(" "));
        *rows += 1;
    }
    // Values left over are a row the file did not finish: they are shown,
    // because a value the file wrote is a value the file wrote.
    if !values.is_empty() {
        let _ = writeln!(
            out,
            "note: {} value(s) of this loop do not fill a row of {}",
            values.len(),
            tags.len()
        );
        let _ = writeln!(out, "{}", values.join(" "));
        values.clear();
    }
}

/// A CIF value with its quotes removed.
#[cfg(feature = "mmcif")]
fn unquote(value: &str) -> String {
    let v = value.trim();
    if v.len() >= 2
        && ((v.starts_with('\'') && v.ends_with('\'')) || (v.starts_with('"') && v.ends_with('"')))
    {
        return v[1..v.len() - 1].to_string();
    }
    v.to_string()
}

/// The values on one line, split the way the CIF grammar splits them.
///
/// A quoted value is one value whatever it holds, and the quote only
/// delimits when it opens a value — `'a b'` is one value with a space in
/// it, and `a'b` is one value with a quote in it.
#[cfg(feature = "mmcif")]
fn cif_tokens(line: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut rest = line.trim();
    while !rest.is_empty() {
        let first = rest.as_bytes()[0];
        if first == b'\'' || first == b'"' {
            let quote = first as char;
            if let Some(end) = rest[1..].find(quote) {
                out.push(rest[1..1 + end].to_string());
                rest = rest[2 + end..].trim_start();
                continue;
            }
        }
        match rest.find(char::is_whitespace) {
            Some(i) => {
                out.push(rest[..i].to_string());
                rest = rest[i..].trim_start();
            }
            None => {
                out.push(rest.to_string());
                rest = "";
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// Composes a rendering: the summary in front, the records behind it.
///
/// The summary goes first because it is the question the file answers
/// slowest, and the records behind it because they are the question the
/// user is usually asking.
#[cfg(any(
    feature = "fasta",
    feature = "fastq",
    feature = "gff",
    feature = "mmcif",
    feature = "pdb",
    feature = "vcf"
))]
fn finish(summary: &str, body: &str) -> String {
    let mut out = String::with_capacity(body.len() + summary.len() + 64);
    let _ = writeln!(out, "{summary}");
    if body.len() <= MAX_RENDER {
        out.push_str(body);
        return out;
    }
    // Cut on a line boundary: a rendering that stops in the middle of a
    // record is a record that reads as if it were whole.
    let bytes = body.as_bytes();
    let mut cut = MAX_RENDER.min(bytes.len());
    while cut > 0 && !body.is_char_boundary(cut) {
        cut -= 1;
    }
    let cut = body[..cut].rfind('\n').map(|i| i + 1).unwrap_or(cut);
    out.push_str(&body[..cut]);
    let _ = writeln!(
        out,
        "note: the rendering stopped at the {MAX_RENDER}-byte ceiling; the rest of the file is not shown"
    );
    out
}

#[cfg(test)]
#[cfg(any(
    feature = "fasta",
    feature = "fastq",
    feature = "gff",
    feature = "mmcif",
    feature = "pdb",
    feature = "vcf"
))]
mod tests {
    //! The fixtures are written by hand to each format's specification and
    //! kept as files, so the end-to-end run reads the same bytes the unit
    //! tests read: a fixture that only exists in a test is a fixture the
    //! binary was never shown.
    //!
    //! The first test is the one that matters: it asserts that the file
    //! itself does **not** contain what the rendering contains, because a
    //! rendering that only re-orders what `rg` already sees would be a
    //! rendering for nothing.

    use super::*;

    #[cfg(feature = "fasta")]
    const FASTA: &[u8] = include_bytes!("../testdata/sample.fasta");
    #[cfg(feature = "fastq")]
    const FASTQ: &[u8] = include_bytes!("../testdata/sample.fastq");
    #[cfg(feature = "vcf")]
    const VCF: &[u8] = include_bytes!("../testdata/sample.vcf");
    #[cfg(feature = "gff")]
    const GFF: &[u8] = include_bytes!("../testdata/sample.gff");
    #[cfg(feature = "gff")]
    const GTF: &[u8] = include_bytes!("../testdata/sample.gtf");
    #[cfg(feature = "pdb")]
    const PDB: &[u8] = include_bytes!("../testdata/sample.pdb");
    #[cfg(feature = "mmcif")]
    const CIF: &[u8] = include_bytes!("../testdata/sample.cif");

    /// The motif that straddles the 60-column wrap of the first record.
    #[cfg(feature = "fasta")]
    const MOTIF: &str = "GGCATTACGGATTCA";

    #[test]
    #[cfg(feature = "fasta")]
    fn a_fasta_sequence_is_joined_across_the_wrap() {
        let text = String::from_utf8_lossy(FASTA);
        // The file does not contain the motif on any line: it is split by
        // the wrap. This is the assertion that gives the rendering a job.
        assert!(
            !text.lines().any(|l| l.contains(MOTIF)),
            "the fixture is supposed to straddle the wrap"
        );
        let out = render_fasta(FASTA).expect("a fasta is ours");
        assert!(
            out.lines().any(|l| l.contains(MOTIF)),
            "the rendering has to carry the joined sequence:\n{out}"
        );
        assert!(out.contains("fasta: 2 records"), "{out}");
        assert!(out.contains(">chr1 Homo sapiens chromosome 1"), "{out}");
    }

    #[test]
    #[cfg(feature = "fasta")]
    fn a_fasta_without_a_header_is_declined() {
        let err = render_fasta(b"ACGT\nACGT\n").expect_err("not a fasta");
        assert!(err.is_decline(), "{err}");
    }

    #[test]
    #[cfg(feature = "fastq")]
    fn a_fastq_read_is_its_four_logical_lines() {
        let out = render_fastq(FASTQ).expect("a fastq is ours");
        assert!(out.contains("fastq: 2 reads"), "{out}");
        // The first read's sequence is wrapped over three lines in the file
        // and is one line here.
        let joined = "ACGTACGTAAGGTTCCAGTACGATCGATCGGATTACAGGCATTACGGATCCATTAGGCATTACG";
        assert!(out.contains(joined), "the sequence was not joined:\n{out}");
        assert!(out.contains("@read1 sample-1/1"), "{out}");
    }

    #[test]
    #[cfg(feature = "fastq")]
    fn a_fastq_whose_quality_is_short_is_said_to_be() {
        let broken = b"@r1\nACGT\n+\nII\n";
        let out = render_fastq(broken).expect("a fastq is ours");
        assert!(
            out.contains("whose quality is not as long as its sequence"),
            "{out}"
        );
    }

    #[test]
    #[cfg(feature = "vcf")]
    fn a_vcf_renders_its_columns_with_spaces() {
        let text = String::from_utf8_lossy(VCF);
        // The file separates its columns with a tab, so the two fields are
        // not adjacent in it.
        assert!(!text.contains("chr1 11869"), "the fixture is tab-separated");
        let out = render_vcf(VCF).expect("a vcf is ours");
        assert!(out.contains("chr1 11869 . G A 60 PASS"), "{out}");
        // The INFO field's pairs are semicolon-separated in the file.
        assert!(out.contains("DP=74 AF=0.5"), "{out}");
        assert!(
            out.contains("vcf: 3 variants, 2 sample(s), 2 contig(s)"),
            "{out}"
        );
    }

    #[test]
    #[cfg(feature = "gff")]
    fn a_gff_and_a_gtf_render_the_same_attribute_in_one_shape() {
        let gff = render_gff(GFF).expect("a gff is ours");
        let gtf = render_gff(GTF).expect("a gtf is ours");
        assert!(gff.contains("Name=BRCA1"), "{gff}");
        assert!(gtf.contains("gene_name=BRCA1"), "{gtf}");
        assert!(gff.contains("gff: 5 features"), "{gff}");
        assert!(gtf.contains("gff: 4 features"), "{gtf}");
    }

    #[test]
    #[cfg(feature = "pdb")]
    fn a_pdb_renders_its_columns_and_joins_its_continuations() {
        let out = render_pdb(PDB).expect("a pdb is ours");
        // The residue, the chain and the number, adjacent.
        assert!(out.contains("MET A 1"), "{out}");
        assert!(
            out.contains("pdb: 6 atoms, 1 chain(s), 0 model(s)"),
            "{out}"
        );
        // The COMPND record's continuation is joined into one line.
        assert!(
            out.contains("COMPND MOL_ID: 1; MOLECULE: HYDROLASE;"),
            "{out}"
        );
    }

    #[test]
    #[cfg(feature = "mmcif")]
    fn a_mmcif_renders_its_loop_rows_and_its_text_block() {
        let out = render_mmcif(CIF).expect("a cif is ours");
        assert!(out.contains("data_1ABC"), "{out}");
        // A loop's row, with its values separated by spaces, and the row is
        // a whole line of its own.
        assert!(
            out.lines()
                .any(|l| l == "ATOM 1 N N MET A 1 11.104 13.207 10.000 1.00 20.00 ?"),
            "the loop's rows have to be lines:\n{out}"
        );
        // The semicolon block, with its three lines.
        assert!(
            out.contains("A title written as a semicolon block,"),
            "{out}"
        );
        assert!(out.contains("which spans three lines"), "{out}");
        assert!(out.contains("mmcif: 1 block(s)"), "{out}");
    }

    #[test]
    #[cfg(all(
        feature = "fasta",
        feature = "fastq",
        feature = "gff",
        feature = "mmcif",
        feature = "pdb",
        feature = "vcf"
    ))]
    fn a_file_that_is_not_a_format_of_ours_is_declined() {
        assert!(render_vcf(b"not a vcf\n")
            .expect_err("no header")
            .is_decline());
        assert!(render_gff(b"not a gff\n")
            .expect_err("no features")
            .is_decline());
        assert!(render_pdb(b"not a pdb\n")
            .expect_err("no atoms")
            .is_decline());
        assert!(render_mmcif(b"not a cif\n")
            .expect_err("no block")
            .is_decline());
        assert!(render_fastq(b"not a fastq\n")
            .expect_err("no reads")
            .is_decline());
    }
}
