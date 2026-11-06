#!/usr/bin/env python3
"""Write the generated half of `crates/rgx-adapters-pdf/fixtures/`.

Three of the PDF shapes `rgx-adapters-pdf` has to get right are ones no
producer emits, because they are only ever intermediates: a `/Type1` font
that is *not* embedded, with nothing but a base encoding to go on, and a
`/Differences` array whose glyph names carry no Unicode. Every real writer
either embeds the font program or writes a `/ToUnicode` CMap. So these are
built here, byte for byte, and `pdftotext` is used as the oracle that the
files are valid PDFs at all before they are committed.

The other fixtures in that directory are real output and are not touched by
this script: `reportlab.pdf` (ReportLab), plus `pdflatex-cm.pdf` and
`lualatex-truetype.pdf`, whose exact build commands are in the test module
that reads them.

Everything is PDF 1.4 with a classic xref table and no compression, so a
reader can be pointed at a byte offset and find an object there. Run from
the repository root:

    python scripts/make-pdf-fixtures.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.normpath(os.path.join(HERE, "..", "crates", "rgx-adapters-pdf", "fixtures"))


class Pdf:
    """A classic-xref PDF written one object at a time."""

    def __init__(self):
        self.objects = [None]  # 1-based, index 0 unused

    def reserve(self):
        self.objects.append(None)
        return len(self.objects) - 1

    def put(self, num, body):
        self.objects[num] = body.encode("latin-1")

    def stream(self, num, extra, data):
        if isinstance(data, str):
            data = data.encode("latin-1")
        head = "<< /Length %d%s >>\nstream\n" % (len(data), extra)
        self.objects[num] = (head.encode("latin-1") + data + b"\nendstream")

    def build(self, root, info=None):
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for num in range(1, len(self.objects)):
            offsets.append(len(out))
            out += b"%d 0 obj\n" % num
            out += self.objects[num]
            out += b"\nendobj\n"
        startxref = len(out)
        out += b"xref\n0 %d\n" % len(self.objects)
        out += b"0000000000 65535 f \n"
        for off in offsets:
            out += b"%010d 00000 n \n" % off
        trailer = "<< /Size %d /Root %d 0 R" % (len(self.objects), root)
        if info:
            trailer += " /Info %d 0 R" % info
        out += b"trailer\n" + trailer.encode("ascii") + b" >>\n"
        out += b"startxref\n%d\n%%%%EOF\n" % startxref
        return bytes(out)


def simple(content, font, resources_indirect=True, extra_objects=(), info=None):
    """One page, one content stream, one font.

    `resources_indirect` writes `/Resources` as an indirect reference, which
    is what every real producer does and what the reader has to follow; the
    fixtures that are about fonts, not about resource lookup, turn it off so
    a failure points at one thing.
    """
    p = Pdf()
    cat, pages, page = p.reserve(), p.reserve(), p.reserve()
    p.put(cat, "<< /Type /Catalog /Pages %d 0 R >>" % pages)
    p.put(pages, "<< /Type /Pages /Kids [%d 0 R] /Count 1 >>" % page)
    res, cont, fnt = p.reserve(), p.reserve(), p.reserve()
    p.put(res, "<< /Font << /F1 %d 0 R >> /ProcSet [ /PDF /Text ] >>" % fnt)
    p.stream(cont, "", content)
    p.put(fnt, font)
    resref = "%d 0 R" % res if resources_indirect else "<< /Font << /F1 %d 0 R >> >>" % fnt
    p.put(
        page,
        "<< /Type /Page /Parent %d 0 R /MediaBox [0 0 300 200] /Resources %s /Contents %d 0 R >>"
        % (pages, resref, cont),
    )
    for num, body in extra_objects:
        p.put(num, body)
    return p.build(cat, info)


def write(name, data):
    path = os.path.join(OUT, name)
    with open(path, "wb") as f:
        f.write(data)
    print("%-28s %6d bytes" % (name, len(data)))


def main():
    os.makedirs(OUT, exist_ok=True)

    # A base-14 Type 1 that is not embedded, with a base encoding and no
    # /ToUnicode. The codes are character codes under WinAnsiEncoding, so
    # every one of them is decodable without a font program.
    write(
        "type1-base-encoding.pdf",
        simple(
            b"BT /F1 14 Tf 20 100 Td [(Valve)-250(the)-250(Tesla)-250(regulator)]TJ ET",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        ),
    )

    # The same font, but the encoding is a /Differences array over
    # StandardEncoding. Two codes come out of /Differences and two out of
    # the base encoding itself: 39 is `quoteright` (U+2019) and 96 is
    # `quoteleft` (U+2018), neither of which is the Latin-1 character of
    # that byte; 0xB1 and 0xD0 are `endash` and `emdash`, which no base
    # encoding here shares and which a reader that stops at /Differences
    # would drop. A reader that falls back to Latin-1 for the first pair
    # returns two wrong characters.
    write(
        "type1-differences.pdf",
        simple(
            b"BT /F1 14 Tf 20 100 Td [(Va'lve's)-250(`quoted`)-250(\261em\320dash)]TJ ET",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Type /Encoding"
            " /BaseEncoding /StandardEncoding /Differences [ 39 /quoteright 96 /quoteleft ] >> >>",
        ),
    )

    # A Type 3 font whose /Differences names glyphs `a97` and `a98`, on a
    # page that also has an ordinary base-14 font. Those names say which
    # glyph of the font, not which character, so the only way to read them
    # is to execute /CharProcs. The base-14 text must survive and the note
    # must name the gap; what must not happen is byte 0x61 turning into the
    # letter `a` and 0x62 into `b`, which is what a Latin-1 fallback reads.
    p = Pdf()
    cat, pages, page = p.reserve(), p.reserve(), p.reserve()
    p.put(cat, "<< /Type /Catalog /Pages %d 0 R >>" % pages)
    p.put(pages, "<< /Type /Pages /Kids [%d 0 R] /Count 1 >>" % page)
    res, cont, t3, proc, t1 = p.reserve(), p.reserve(), p.reserve(), p.reserve(), p.reserve()
    p.put(res, "<< /Font << /F1 %d 0 R /F2 %d 0 R >> >>" % (t1, t3))
    p.stream(
        cont,
        "",
        b"BT /F2 12 Tf 20 150 Td <51 61 62 52> Tj ET\n"
        b"BT /F1 14 Tf 20 100 Td (Valve the Tesla regulator) Tj ET",
    )
    p.stream(proc, "", b"10 w 0 0 0 60 40 re f")
    p.put(
        t3,
        "<< /Type /Font /Subtype /Type3 /FontBBox [0 0 60 40] /FontMatrix [0.01 0 0 0.01 0 0]"
        " /CharProcs << /a97 %d 0 R /a98 %d 0 R >> /Encoding << /Type /Encoding"
        " /Differences [ 97 /a97 98 /a98 ] >> /FirstChar 97 /LastChar 98"
        " /Widths [1000 1000] /Resources << >> >>" % (proc, proc),
    )
    p.put(
        t1,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
    )
    p.put(
        page,
        "<< /Type /Page /Parent %d 0 R /MediaBox [0 0 300 200] /Resources %d 0 R /Contents %d 0 R >>"
        % (pages, res, cont),
    )
    write("type3-opaque-glyph-names.pdf", p.build(cat))

    # A symbolic Type 1 with no /Encoding and no /ToUnicode. Its encoding is
    # in the font program, which needs a Type 1 parser, so the codes are
    # undecodable and the file must say so rather than answer with Latin-1.
    write(
        "type1-symbolic-no-encoding.pdf",
        simple(
            b"BT /F1 14 Tf 20 100 Td (Valve) Tj ET",
            "<< /Type /Font /Subtype /Type1 /BaseFont /SomeSymbolFont"
            " /FontDescriptor << /Type /FontDescriptor /FontName /SomeSymbolFont /Flags 4"
            " /FontBBox [0 -200 1000 900] /ItalicAngle 0 /Ascent 700 /Descent -200"
            " /CapHeight 700 /StemV 80 >> >>",
        ),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
