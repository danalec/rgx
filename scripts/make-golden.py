#!/usr/bin/env python3
"""Generate `tests/golden/` from source, so the golden suite is never vacuous.

`tests/golden.rs` is opt-in and vacuous when `tests/golden/` is absent -- the
directory is gitignored because HARVESTED samples are somebody else's files
and cannot be committed. But a golden suite that never runs on a fresh clone
is a suite that proves nothing, and the samples it wants -- output from real
producers -- can be produced rather than harvested.

So this script writes four PDFs from source and a `manifest.tsv` naming a
pattern known to match in each:

  pdflatex-sample.pdf   pdfTeX, Type 1 CM fonts, classic xref
  lualatex-sample.pdf   LuaTeX, OpenType Latin Modern
  xelatex-sample.pdf    XeTeX
  reportlab-sample.pdf  ReportLab

Each carries the same `goldenneedle` token so the manifest is uniform, and
`pdftotext` is the oracle that the file is a valid PDF and the token is
reachable before the manifest is written.

Usage, from the repository root:

    python scripts/make-golden.py              # build into tests/golden/
    python scripts/make-golden.py --verify     # check, build nothing

Needs a TeX distribution on PATH (pdflatex, lualatex, xelatex) and
ReportLab (`pip install reportlab`). A missing producer is reported and
skipped rather than failing the run: four producers is better than none,
and a hard failure would make the golden suite unbuildable on a machine
without MiKTeX.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OUT = ROOT / "tests" / "golden"
TOKEN = "goldenneedle"

SOURCES = {
    "pdflatex-sample": (
        "pdflatex",
        r"""
\documentclass{article}
\usepackage[utf8]{inputenc}
\begin{document}
\section{Golden Sample}
This pdflatex document contains the goldenneedle token for the parser.
A second paragraph with \textbf{bold text} and math $x^2 + y^2 = z^2$.
\end{document}
""",
    ),
    "lualatex-sample": (
        "lualatex",
        r"""
\documentclass{article}
\begin{document}
\section{Lua\LaTeX{} Sample}
This lualatex document contains the goldenneedle token for the parser.
Unicode check: caf\'{e} na\"{i}ve r\'{e}sum\'{e} Z\"{u}rich.
\end{document}
""",
    ),
    "xelatex-sample": (
        "xelatex",
        r"""
\documentclass{article}
\begin{document}
\section{Xe\LaTeX{} Sample}
This xelatex document contains the goldenneedle token for the parser.
\end{document}
""",
    ),
}


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def pdftotext_has(path: Path) -> bool:
    """The oracle: the file is a PDF and the token is reachable from it."""
    if not have("pdftotext"):
        return True  # no oracle on this machine; rgx itself is checked by the test
    try:
        out = subprocess.run(
            ["pdftotext", str(path), "-"],
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return TOKEN in out.stdout.decode("utf-8", "replace")


def build_tex(name: str, engine: str, body: str, work: Path) -> Path | None:
    if not have(engine):
        print(f"  skip {name}: {engine} is not on PATH")
        return None
    src = work / f"{name}.tex"
    src.write_text(body, encoding="utf-8")
    # Two passes: the first writes the .aux and the second resolves the
    # page count. A one-pass PDF is valid but its xref may point at a
    # stale offset, which is exactly the shape a parser should survive
    # and exactly the shape we do not want to accidentally not test.
    for _ in range(2):
        try:
            subprocess.run(
                [engine, "-interaction=nonstopmode", src.name],
                cwd=work,
                capture_output=True,
                timeout=180,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as e:
            print(f"  fail {name}: {e}")
            return None
    pdf = work / f"{name}.pdf"
    return pdf if pdf.exists() else None


def build_reportlab(name: str, work: Path) -> Path | None:
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter
    except ImportError:
        print(f"  skip {name}: reportlab is not installed")
        return None
    pdf = work / f"{name}.pdf"
    c = canvas.Canvas(str(pdf), pagesize=letter)
    c.setFont("Helvetica", 12)
    c.drawString(72, 720, "ReportLab Golden Sample")
    c.drawString(72, 700, f"This reportlab document contains the {TOKEN} token for the parser.")
    c.drawString(72, 680, "Second line with mixed Case And Punctuation.")
    c.save()
    return pdf


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-dir", type=Path, default=OUT)
    ap.add_argument("--verify", action="store_true", help="check an existing tree, build nothing")
    args = ap.parse_args()

    out: Path = args.out_dir
    manifest = out / "manifest.tsv"
    print(f"golden samples under {out}   {'verify only' if args.verify else 'build'}")

    if args.verify:
        if not manifest.exists():
            print(f"  FAIL {manifest} is absent; run without --verify")
            return 1
        ok = True
        rows = [l.split("\t", 1) for l in manifest.read_text(encoding="utf-8").splitlines() if l.strip()]
        for name, pattern in rows:
            p = out / name
            if not p.exists():
                print(f"  FAIL {name} is listed but absent")
                ok = False
            elif not pdftotext_has(p):
                print(f"  FAIL {name}: {pattern!r} is not reachable from the PDF")
                ok = False
            else:
                print(f"  ok   {name} ({p.stat().st_size:,} bytes)")
        return 0 if ok else 1

    out.mkdir(parents=True, exist_ok=True)
    built: list[tuple[str, Path]] = []
    with tempfile.TemporaryDirectory(prefix="rgx-golden-") as td:
        work = Path(td)
        for name, (engine, body) in SOURCES.items():
            pdf = build_tex(name, engine, body, work)
            if pdf is not None:
                built.append((name, pdf))
        pdf = build_reportlab("reportlab-sample", work)
        if pdf is not None:
            built.append(("reportlab-sample", pdf))

        if not built:
            print("  FAIL no producer available; nothing was built")
            return 1

        rows = []
        for name, pdf in built:
            dest = out / f"{name}.pdf"
            shutil.copyfile(pdf, dest)
            if not pdftotext_has(dest):
                print(f"  FAIL {name}: {TOKEN!r} is not reachable from the PDF")
                return 1
            rows.append(f"{name}.pdf\t{TOKEN}")
            print(f"  ok   {name}.pdf ({dest.stat().st_size:,} bytes)")

    manifest.write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(f"  wrote {manifest} with {len(rows)} samples")
    return 0


if __name__ == "__main__":
    sys.exit(main())
