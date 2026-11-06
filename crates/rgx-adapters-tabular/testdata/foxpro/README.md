# Fixtures: the Visual FoxPro container and its companions

These are **real files**, taken from the project that ships them rather
than written by hand here: a hand-built container would only prove that
the reader accepts what the test author already believed about it.

| file | what it is | what it is there for |
|---|---|---|
| `EXPENSES.DBC` | a Visual FoxPro database container: a dBase table whose rows are the tables, views and stored procedures it binds | the container, and the rows that name the block their text is in |
| `EXPENSES.DCT` | the container's memo file: a 512-byte header record and then 64-byte blocks | the text the container's rows point at |
| `EXPENSES.DCX` | the container's compound index: a directory of its tags, and a B-tree per tag | the tags the container's rows are indexed by, and the row every key points at |
| `employees.dbf` | one of the tables the container binds, with a memo field of its own | the table whose row names the block its address is in |
| `employees.FPT` | that table's memo file | the address of the first employee, in the block the row names |
| `employees.CDX` | the compound index of that table: five tags over the table's rows | an index with more than one tag, with keys that are text and keys that are numbers |
| `expense categories.CDX` | the compound index of the table of the categories: one tag | an index with a single tag |
| `expense details.CDX` | the compound index of the table of the details: three tags, one of them over a key that repeats | an index whose tags share their keys |
| `expense reports.CDX` | the compound index of the table of the reports: three tags, one of them over a date | an index with a tag whose keys are dates |

The files are kept byte for byte: the directory is `-text` in
`.gitattributes`, so a checkout cannot rewrite a byte of them.

## The oracle

The container's rows are the oracle, and they are the producer's own: a
row of the container names the block its text is in, and the memo file has
that block. The test walks every row of the container and checks that the
block it names is a block the memo file holds — and that what the block
holds is the name the row gives: the name of the field the row is about,
or the name of the file of the table the row binds. Three files agree, and
none of them was written by the test.

The memo file's own header is the second check: it says the number of the
next free block, and that is one past the last block the table points at.

## The index, and the rows it points at

The compound index is the oracle for itself, twice over. Its own leaves
say what they are made of: the widths of the three fields every entry
packs add up to the length of one entry, and the space the leaf header
says is free is the space the entries and the keys do not take. The test
checks both on every leaf of every file here.

And the container is the oracle for the index of the container. The index
holds one key per row the container keeps — the FOR expression
(`.NOT.DELETED()`) keeps the deleted rows out, and the two rows of the
container that carry the `*` delete flag are exactly the two rows the
index does not hold — and every key of the index is what the row it points
at says: the parent id right-aligned in ten characters, the type of the
object, and the name of it in lower case.

## Where they come from

| file | where it comes from |
|---|---|
| all nine | `Valentin-Kaiser/go-dbase`, `examples/test_data/database/` |

They can be fetched again with:

```sh
curl -sL -o EXPENSES.DBC https://raw.githubusercontent.com/Valentin-Kaiser/go-dbase/main/examples/test_data/database/EXPENSES.DBC
curl -sL -o EXPENSES.DCT https://raw.githubusercontent.com/Valentin-Kaiser/go-dbase/main/examples/test_data/database/EXPENSES.DCT
curl -sL -o EXPENSES.DCX https://raw.githubusercontent.com/Valentin-Kaiser/go-dbase/main/examples/test_data/database/EXPENSES.DCX
curl -sL -o employees.dbf https://raw.githubusercontent.com/Valentin-Kaiser/go-dbase/main/examples/test_data/database/employees.dbf
curl -sL -o employees.FPT https://raw.githubusercontent.com/Valentin-Kaiser/go-dbase/main/examples/test_data/database/employees.FPT
curl -sL -o employees.CDX https://raw.githubusercontent.com/Valentin-Kaiser/go-dbase/main/examples/test_data/database/employees.CDX
curl -sL -o "expense categories.CDX" "https://raw.githubusercontent.com/Valentin-Kaiser/go-dbase/main/examples/test_data/database/expense%20categories.CDX"
curl -sL -o "expense details.CDX" "https://raw.githubusercontent.com/Valentin-Kaiser/go-dbase/main/examples/test_data/database/expense%20details.CDX"
curl -sL -o "expense reports.CDX" "https://raw.githubusercontent.com/Valentin-Kaiser/go-dbase/main/examples/test_data/database/expense%20reports.CDX"
```

## The licence

The files are the project's, under its notice:

> BSD 3-Clause License
>
> Copyright (c) 2022, Valentin Kaiser
> All rights reserved.
>
> Redistribution and use in source and binary forms, with or without
> modification, are permitted provided that the following conditions are met:
>
> 1. Redistributions of source code must retain the above copyright notice, this
> list of conditions and the following disclaimer.
>
> 2. Redistributions in binary form must reproduce the above copyright notice,
> this list of conditions and the following disclaimer in the documentation
> and/or other materials provided with the distribution.
>
> 3. Neither the name of the copyright holder nor the names of its
> contributors may be used to endorse or promote products derived from
> this software without specific prior written permission.
>
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
> AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
> IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
> DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
> FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
> DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
> SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
> CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
> OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
> OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
