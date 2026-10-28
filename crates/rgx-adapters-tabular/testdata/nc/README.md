# Fixtures: the netCDF and NASA CDF files

These are **real files**, taken from the projects that write them rather
than written by hand here: a hand-built netCDF file would only prove
that the reader accepts what the test author already believed about it.
The two netCDF files are the *same* test CDF in the two layouts the
netCDF library writes, so the variable list has to read the same in both.

| file | what it is | what it is there for |
|---|---|---|
| `nctest-classic.nc` | netCDF classic (CDF-1), 32-bit offsets | the layout the reader has always owned |
| `nctest-classic-streaming.nc` | netCDF classic (CDF-1) with the streaming marker in place of the record count | the streaming shape of the classic model: the header says the count of the records is indeterminate, and the reader counts them from the length of the file |
| `nctest-64bit-offset.nc` | netCDF 64-bit offset (CDF-2), a 64-bit `begin` | the "CDF-5" of the market: the same header with wider offsets |
| `tiny-cdf5.nc` | netCDF CDF-5 (`CDF\x05`), 140 bytes | the layout whose header counts are 64-bit: the one the CDF-5 specification prints a byte dump of |
| `bad_cdf5_begin.nc` | the netCDF library's own CDF-5 (`CDF\x05`), with `begin` offsets that point past the end of the file | a CDF-5 the netCDF library writes to be rejected: the reader reads its header -- two dimensions, two variables -- and says the values are not there |
| `test_alltypes.cdf` | NASA CDF-3, every data type, a plain descriptor | the types, the attribute scopes, and the little-endian encoding |
| `psp_fld_l2_mag_rtn_1min_20200104_v02.cdf` | NASA CDF-3, a Parker Solar Probe product | a mission file, and the big-endian encoding |
| `fa_esa_l2_eeb_00000000_v01.cdf` | NASA CDF-3, the whole descriptor behind a CCR record | the compressed descriptor, packed with the CDF library's own run-length encoding |
| `de2_ion2s_rpa_19830213_v01.cdf` | NASA CDF-2 (`CD F2 60 02`) | NASA's CDF-2 has a descriptor of its own; its data is in compressed blocks |
| `cl_sp_edi_00000000_v01.cdf` | NASA CDF-2 (`CD F2 60 02`), a Cluster summary parameter | a CDF-2 whose values are stored as they are |
| `ge_k0_cpi_19921231_v02.cdf` | NASA CDF-1 (`00 00 FF FF`), a Geotail product | the pre-V2.6 magic: 32-bit offsets, and a variable record older than V2.5 |

The files are kept byte for byte: the directory is `-text` in
`.gitattributes`, so a checkout cannot rewrite a byte of them.

## Where they come from

| file | where it comes from |
|---|---|
| `nctest-classic.nc` | `Unidata/netcdf-c`, `nctest/ref_nctest_classic.nc` |
| `nctest-classic-streaming.nc` | `Unidata/netcdf-c`, `nctest/ref_nctest_classic.nc`, with the four bytes of the record count set to the marker the specification gives (`\xFF\xFF\xFF\xFF`) |
| `nctest-64bit-offset.nc` | `Unidata/netcdf-c`, `nctest/ref_nctest_64bit_offset.nc` |
| `tiny-cdf5.nc` | the CDF-5 specification's own `od -c` dump of its `tiny.nc`, transcribed byte for byte (`cucis.ece.northwestern.edu/projects/PNETCDF/CDF-5.html`) |
| `bad_cdf5_begin.nc` | `Unidata/netcdf-c`, `nc_test/bad_cdf5_begin.nc` |
| `test_alltypes.cdf` | NASA SPDF, `pub/software/cdf/cdf_test_files/test_alltypes.cdf` |
| `psp_fld_l2_mag_rtn_1min_20200104_v02.cdf` | `lasp/cdflib`, `tests/testfiles/` |
| `fa_esa_l2_eeb_00000000_v01.cdf` | `lasp/cdflib`, `tests/testfiles/` |
| `de2_ion2s_rpa_19830213_v01.cdf` | `lasp/cdflib`, `tests/testfiles/` |
| `cl_sp_edi_00000000_v01.cdf` | NASA SPDF, `pub/software/cdf/cdf_test_files/cl_sp_edi_00000000_v01.cdf` |
| `ge_k0_cpi_19921231_v02.cdf` | NASA SPDF, `pub/software/cdf/cdf_test_files/ge_k0_cpi_19921231_v02.cdf` |

The one file that is not a real file is `tiny-cdf5.nc`: the netCDF
library is not on this machine, and the CDF-5 specification prints the
whole 140-byte file as a byte dump, field by field. Transcribing that
dump is what the file is, and the values in it are the ones the dump
shows.

## The streaming file

The specification is the netCDF **File Format Specification**
(<https://docs.unidata.ucar.edu/netcdf-c/current/file_format_specifications.html>),
the document the classic model comes from: its grammar gives the marker
(`STREAMING = \xFF \xFF \xFF \xFF`, "Indicates indeterminate record count,
allows streaming data") and its note on streaming data says that the count
"must be determined by other means, such as reading them or computing the
current number of records from the file length and other information in the
header".

No implementation writes a streaming netCDF file: the same note says that
"the numrecs field in the header will not be updated as records are added to
the file", and the netCDF library has never implemented the shape ("[This
feature is not yet implemented]"). The fixture is therefore the netCDF
library's own `nctest-classic.nc` with the four bytes of the record count
set to the marker the specification gives. Every other byte is the library's,
the file is the same length, and every value in it is the value the library's
file holds: the reader has to count the records from the length of the file
and give the same values the file with the count in it gives.

## The NASA CDF copyright

The CDF files are NASA's, under the CDF library's notice:

> Common Data Format (CDF)
> Space Physics Data Facility
> NASA/Goddard Space Flight Center
>
> This software may be copied or redistributed as long as it is not sold
> for profit, but it can be incorporated into any other substantive
> product with or without modifications for profit or non-profit. If the
> software is modified, it must include the following notices:
>
>   - The software is not the original (for protection of the original
>     author's reputations from any problems introduced by others)
>
>   - Change history (e.g. date, functionality, etc.)
>
> This copyright notice must be reproduced on each copy made. This
> software is provided as is without any express or implied warranties
> whatsoever.

The netCDF files are under the netCDF library's BSD-3-Clause licence.
