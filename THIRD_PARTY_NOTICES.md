# Third-party notices

This project contains or derives from the work below. Their notices apply to
those parts; the MIT licence in LICENSE covers the original code only.

## VW_Flash

The LZSS10 decompressor in `sgo_frf.py` is ported from VW_Flash's
`extractodx.decompress_raw_lzss10`, and the DQ381/DQ400e/DL382 container
layouts were cross-checked against its modules.

- Project: https://github.com/TheFlashBold/VW_Flash
- Copyright (c) 2022-2024, Brian Ledbetter and contributors
- Licence: BSD 2-Clause

```
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```

VW_Flash's `lzss/` subdirectory is GPL-licensed; no code from that
subdirectory is used here.

## PyCryptodome

AES is provided by PyCryptodome (BSD 2-Clause, Legrandin and contributors),
installed from PyPI as a build dependency.

## Python and Tcl/Tk

Bundled by PyInstaller from the Python distribution (PSF licence) and Tcl/Tk
(BSD-style licence).

## Key material and reverse-engineered tables

`frf.key` and the substitution tables in `sgo_tables.py` were recovered by
reverse engineering for interoperability. They are not the author's property,
are not covered by the MIT licence, and are shipped only because the tool
cannot work without them.
