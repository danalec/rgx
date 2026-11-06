# Fixtures: the GRIB messages

These are **real files**, taken from the reference implementations rather
than written by hand, because the thing being tested is a reader against
files that the format's own tooling produces. A hand-built GRIB message would
only prove that the reader accepts what the test author already believed.

Every file here is covered by its project's licence (pygrib and eccodes are
Apache-2.0) and is kept byte for byte: the directory is `-text` in
`.gitattributes`, so a checkout cannot rewrite a byte of them.

| file | bytes | edition | what it is | where it comes from |
|---|---|---|---|---|
| `grib/regular_latlon_surface.grib1` | 1200 | 1 | ECMWF, 16 x 31 lat/lon grid, 496 values, simple packing, 16 bits per value | <https://raw.githubusercontent.com/jswhit/pygrib/master/sampledata/regular_latlon_surface.grib1> |
| `grib/rotated_ll.grib1` | 369446 | 1 | ECMWF, rotated lat/lon grid (grid type 10), 496 x 372 = 184512 values, simple packing, 16 bits per value | <https://raw.githubusercontent.com/jswhit/pygrib/master/sampledata/rotated_ll.grib1> |
| `grib/reduced_latlon_surface.grib2` | 335528 | 2 | ECMWF, reduced lat/lon grid of 501 rows, 313362 points, simple packing (data representation template 5.0) at 11 bits per value, with a bit map over the points of the grid | <https://raw.githubusercontent.com/jswhit/pygrib/master/sampledata/reduced_latlon_surface.grib2> |
| `grib/spherical_pressure_level.grib1` | 9360 | 1 | ECMWF, spherical harmonics (grid type 50), code table 11 flag 0xc0: the coefficients of a spectrum of triangular truncation 63, with the complex spectral packing and the unpacked subset in IBM floats | <https://raw.githubusercontent.com/jswhit/pygrib/master/sampledata/spherical_pressure_level.grib1> |
| `grib/spherical_pressure_level.grib2` | 9393 | 2 | ECMWF, spherical harmonics (grid definition template 3.50), data representation template 5.51: the same spectrum of triangular truncation 63, with the unpacked subset in IEEE floats | ecCodes' own sample data, the file `samples/sh_pl_grib2.tmpl` of the library; the library is Apache-2.0 |
| `grib/regular_ll.grib` | 8569 | 1 and 2 | eccodes' own test file: edition 1 messages and edition 2 messages in one file, 2 x 2 constant fields | <https://raw.githubusercontent.com/ecmwf/eccodes/master/tests/grib_to_gridspec/regular_ll.grib> |
| `grib/N320.area.grib` | 591 | 2 | eccodes' own test file: one edition 2 message, grid definition template 3.40 | <https://raw.githubusercontent.com/ecmwf/eccodes/master/tests/grib_to_gridspec/N320.area.grib> |
| `grib/gfs_complex_packing.grib2` | 2890 | 2 | NCEP GFS 2.5 degree grid, 10512 points, complex packing (data representation template 5.3) with the first order of the spatial differencing | <https://raw.githubusercontent.com/jswhit/pygrib/master/sampledata/gfs.t12z.pgrbf120.2p5deg.grib2>, the message at offset 145937 |
| `grib/gfs_complex_packing_two_fields.grib2` | 16341 | 2 | the same producer's file: one message with two fields, the u and the v component of the wind, each with its own group tables | <https://raw.githubusercontent.com/jswhit/pygrib/master/sampledata/gfs.t12z.pgrbf120.2p5deg.grib2>, the message at offset 25975 |
| `grib/scanning_mode_with_bitmap.grib2` | 190 | 2 | six points of a grid, one of them without a value: the section holds the five values the bit map marks | <https://raw.githubusercontent.com/jswhit/pygrib/master/sampledata/scanning_mode_with_bitmap.grib2> |
| `grib/second_order_spatial_differencing.grib2` | 396 | 2 | the second order of the spatial differencing, 60 groups over a 40 by 30 grid | written by NOAA's g2c library (`g2_addfield`, data representation template 5.3) from the field 1000 + 3 * column + 2 * row, with the scale factors at zero; the library's code is LGPL-3.0 and none of it is in this file |
| `grib/bifourier_lambert_ellipse_diamond.grib2` | 8098 | 2 | the bi-Fourier field of the limited area models: grid definition template 3.63 (a Lambert conformal grid with modelling subdomains), the resolution N 31 and M 31 with an elliptic truncation, and the data representation template 5.53 with a diamond truncation of the unpacked subset; 3128 values, four to a coefficient | written by ECMWF's ecCodes, by its own test program `tests/grib_lam_bf.cc`, which is the reference writer of these files; the library is Apache-2.0 |
| `grib/bifourier_lambert_rectangle_rectangle.grib2` | 10474 | 2 | the same field with a rectangular truncation of the spectrum and of the unpacked subset: 4096 values, of which the 652 of the subset are not packed | the same producer |

## The bi-Fourier files

`bifourier_lambert_ellipse_diamond.grib2` and
`bifourier_lambert_rectangle_rectangle.grib2` are the same field under two
truncations, and they are the only files here that carry a data
representation template 5.53: the bi-Fourier variant of the complex packing,
which the limited area models use. It has its own resolution parameters --
N and M where the spherical harmonics carry the pentagonal J, K and M -- and
its own code tables: the shape of the truncation of the whole field (code
table 3.25), the shape of the truncation of the unpacked subset (code table
5.25) and the packing mode for the axes (code table 5.26).

They come from ecCodes' own test program, `tests/grib_lam_bf.cc`, which
writes the nine bi-Fourier files the library's test suite reads back. The
program cannot run on Windows as it stands: ecCodes opens its sample files in
text mode, and the sample `samples/lambert_bf_grib2.tmpl` holds `0x1A`
octets, which end a text-mode read. The two files here were written by the
same library, from the same sample and with the same keys and the same
values, and they differ from what the unmodified program writes on Windows in
two octets only -- the two `0x1A` octets of the sample, which the Windows run
had to change to read it at all.

## What the edition 1 files prove

The two simple-packed files are the ones the values hang on. An edition 1
message never states how many values it holds: the count is the number of
grid points the grid description names, so the count and the bits in the
section have to be two readings of the same number. In
`regular_latlon_surface.grib1` that is 16 x 31 = 496 points against 992 bytes
of packed data at 16 bits each, with the section's 8 unused bits accounting
for the rest of the section; in `rotated_ll.grib1` it is 496 x 372 = 184512
points against 369024 bytes. The adapter prints the count and the minimum and
the maximum of the whole field, so a count that did not add up would show up
as a number that does not belong to the grid.

The reference value of the binary data section is an **IBM 360 hexadecimal
float**, which is what the section has always specified and what these files
hold: decoded as IBM, `regular_latlon_surface.grib1` is 270.466796875 K to
311.0986328125 K, a surface temperature; decoded as IEEE-754 the same four
octets give 144.9 K, which no surface reaches. The adapter reads IBM.

## The spherical harmonics

`spherical_pressure_level.grib1` and `spherical_pressure_level.grib2` are the
same spectrum in the two editions: the coefficients of a triangular truncation
of 63, which is 2080 complex coefficients and 4160 values, the real and the
imaginary part of each of them.

The count is the point of these two files. A spectral field has no grid: the
number of values follows the truncation parameters J, K and M, and the order of
the coefficients follows code table 3.7 -- the row `m` from 0 to M, and inside
it the wave number `n` from `m` to N(m), each coefficient as its real part
followed by its imaginary part. The two editions also differ in the
arithmetic: the unpacked subset of the edition 1 file is an IBM hex float and
the one of the edition 2 file an IEEE float, and read as the other one the
first value of the edition 1 file is 145.9099426, a number that appears
nowhere.

The oracle is **ECMWF's ecCodes**, which reads the same two files. The reader
was checked against it value by value, all 4160 of them: the 420 values of
the unpacked subset that carry no scale agree to the last bit, and the rest --
the ones the Laplacian scale of the wave number touches -- agree to a few parts
in 10^16. The scale is computed with a series of its own, because the crate is
`no_std` and `powf` is one of the functions `std` keeps, and a series is not
the library's `pow` to the last bit.

`spherical_pressure_level.grib2` is **ecCodes' own sample data**, kept byte for
byte: it is the file `samples/sh_pl_grib2.tmpl` of the library, the same 9393
bytes and the same SHA-256,
`9996e2a56d69d63eaf9e1d846acbd48981c36c40a5f4bef43dc5d7aebf5b4e18`.
The library is Apache-2.0, and the file holds the ECMWF/IFS sample of a
spherical harmonics field.

## What the edition 2 files prove

The complex packing is the packing every modern NCEP file uses: the field is
split into groups of values that share a bit width, and each group carries a
reference value, a width and a length. The three group tables come first in
the data section, and template 5.3 puts the spatial differencing on top of
them.

The oracle is **NOAA's g2c library**, the one NCEP writes these files with.
Every value the reader prints out of `gfs_complex_packing.grib2` was
compared with what that library reads out of the same bytes, and so were all
307 messages of the file the two fixtures were cut from, field by field.

The second order of the spatial differencing has no small file in the
corpus, so its fixture was written by the same library, with the scale
factors at zero and a field of whole numbers: the values that go in have to
come back whole. The same branch was checked against a real producer's file
-- the WRF model's own `rap.wrfnat.grib2`, whose field is packed with the
second order -- and against the 307 messages of the GFS file, which use the
first order.

`scanning_mode_with_bitmap.grib2` is here for the bit map: six points of a
grid, one of them without a value, and a section that holds the five values
the map marks. The map indexes the *points of the grid*, so it has to be
walked over the grid and not over the values.

## The reduced grids

A **reduced grid** has no number of columns: the number is missing, all ones,
and the shape of the grid is in the *list of numbers* that follows the grid
definition template -- how many points each row of the grid holds, or, for
the third interpretation of code table 3.11, the latitude of each row. Where
that list begins is the length of the template, so the reader has to know how
long the template of that number is; the number of rows the grid declares is
how many numbers there are, and their sum is the number of points of the
grid.

`reduced_latlon_surface.grib2` is a reduced lat/lon grid of 501 rows, from
none at the poles to a thousand points at the widest, 313362 points in all.
`N320.area.grib` is a reduced *Gaussian* grid of 196 rows, and it is the one
where the rows and the number of data points the section declares do not add
up: the rows hold 229287 points and the section says 67001. The reader
reports both and says that they do not agree, rather than making the two
agree.

The oracle is the pair of libraries that write and read these files: **NOAA's
g2c** reads the grid of `reduced_latlon_surface.grib2` as 501 rows whose
list gives the points of each row, and **ECMWF's ecCodes** reads the same
list, the same 501 entries, out of the same bytes -- and both of them read
`N320.area.grib` the same way the reader does.

`reduced_latlon_surface.grib2` is **pygrib's own sample data**, kept byte
for byte: the file here is the file pygrib ships -- the same 335528 bytes,
the same SHA-256 -- so the reader is checked against a message nobody wrote
for it. It is the producer's own file -- ECMWF's, centre 98 -- and it has a
local use section of its own and a bit map over the points of the grid: of
the 313362 points the grid declares, 214661 carry a value, and the data
section holds those.

What the two oracles say of it, exactly: NOAA's g2c reads the section with
`g2_unpack3`, the function the library itself uses, and the list of numbers
it returns is 501 entries summing to 313362, the first 25 of them zero and
the widest row a thousand points, while its `getdim` reports the width as
missing and the height as 501. ECMWF's ecCodes calls the grid `reduced_ll`,
reports `Ni` as 2147483647 -- the missing columns -- and `Nj` as 501, and
its `pl` array is the same 501 numbers, summing to 313362, from 0 to 1000.

## The one that holds both editions

`regular_ll.grib` is a file with edition 1 messages and edition 2 messages in
one, and it is here to keep the two editions apart: the edition 1 messages
are constant fields, a section with no bits per value where every point
holds the reference, and the edition 2 messages go through the edition 2
path unchanged.

## The CRAM file

| file | bytes | edition | what it is | where it comes from |
|---|---|---|---|---|
| `sample.cram` | 1476 | 3.1 | eight reads on `chr1` (100..275, 10M each), one reference and one read group; a header container whose SAM header sits in a gzip block, a data container that declares 28 blocks and carries 30, and the end-of-file marker | written by **htsjdk 5.0.2** (`htsjdk.samtools.CRAMFileWriter`), the Java implementation of the SAM specification |

**Why it is here.** The CRAM container layout has three places where the
obvious reading is wrong, and a file written by hand would have been written
the obvious way -- so it would have proved nothing. A container's `length` is
the size of its *blocks* and the container header carries its own size, so
the next container is `header size + length` bytes on; a block occupies its
header, its data and its CRC32; and the block count is only a guide, because
this file's second container declares 28 blocks and carries 30. This is the
file where the reader walks two containers and totals the eight reads.

**How to regenerate it.** htsjdk's writer asks for a reference even for an
archive of unmapped reads, and there is none here, so the reference answers
with zeros. The input is a SAM file of eleven lines -- three header lines
and eight reads of ten bases -- and the writer is a dozen lines of Java:

```java
CRAMReferenceSource noReference = new CRAMReferenceSource() {
    @Override
    public byte[] getReferenceBases(SAMSequenceRecord contig, boolean aligned) {
        return new byte[contig.getSequenceLength()];
    }

    @Override
    public byte[] getReferenceBasesByRegion(SAMSequenceRecord contig, int start, int end) {
        return new byte[Math.max(0, end - start)];
    }
};

try (SamReader reader = SamReaderFactory.makeDefault().open(Paths.get("fixture.sam"));
     OutputStream out = new FileOutputStream("sample.cram");
     CRAMFileWriter writer =
             new CRAMFileWriter(out, noReference, reader.getFileHeader(), "rgx-fixture")) {
    for (SAMRecord record : reader) {
        writer.addAlignment(record);
    }
}
```

The bytes depend on htsjdk's writer, so a different htsjdk release may
produce a different file; the test asserts the numbers the reader reports
(two containers walked, eight alignments), not the file's bytes. With
htsjdk 5.0.2 the file comes out byte for byte the one in the tree.

**The oracle it gives.** htsjdk's own reader reads the same bytes the same
way: its container reader reports the data container with 1264 bytes of
blocks, 28 blocks declared and eight records, and reading the file back
gives the eight records the reader totals. The layout the reader decodes was
therefore not read off a specification alone.

htsjdk's CRAM writer is Apache-2.0 (htsjdk as a whole is MIT), and the file
holds synthetic sequence data: no code of htsjdk is in it, and nothing of it
comes from a human genome.

**The edition 2 and 1 containers are not files here.** CRAM 2's container
header is pinned by the CRAM 2.1 specification's own byte table for its
end-of-file marker -- 30 bytes, of which the header is 19 -- and it is
checked against htsjdk's container-header reader, which reads those bytes
without having written them. CRAM 1 has no published specification and
htsjdk's reader cannot read a CRAM 1 container at all, so that edition is
refused by name rather than guessed at.
