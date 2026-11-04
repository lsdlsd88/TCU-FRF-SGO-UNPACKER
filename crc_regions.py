"""CRC cell locations per TCU flash layout, for restore protection.

Derived from tvbox/dick-site/dick-staging/flash_crc.py (the DICK backend
checksum profiles), which is validated against the real corpus: each profile
lists the data range and the checksum cell that follows it.

Only the locations are used here. A restore does not recompute checksums, so
the cells are added to the "never write" regions instead — writing calibration
bytes would otherwise clobber the cell with donor bytes.

algo:
  crc32inv  ~zlib.crc32(data[start:end]) as LE u32
  crc32     zlib.crc32(data[start:end])  as LE u32
  crc16_8408 CRC-16 reflected 0x8408, init 0xFFFF, as LE u16
"""

import struct
import zlib

CRC32INV = "crc32inv"
CRC32 = "crc32"
CRC16 = "crc16_8408"

_T16 = []
for _b in range(256):
    _c = _b
    for _ in range(8):
        _c = (_c >> 1) ^ 0x8408 if _c & 1 else _c >> 1
    _T16.append(_c)

# name: (size, algo, cells[(label, data_start, data_end, cell_offset)], markers)
PROFILES = {
    "mqb-0x178000": (0x178000, CRC32INV,
                     (("maps", 0x20000, 0x3FFFC, 0x3FFFC),
                      ("app", 0x40000, 0x16FFFC, 0x16FFFC)), ()),
    "g2-0x280000": (0x280000, CRC32INV,
                    (("maps", 0x20000, 0x3FFFC, 0x3FFFC),), ()),
    "vr-0x150010": (0x150010, CRC32INV,
                    (("maps", 0x0, 0x1FFFC, 0x1FFFC),), ()),
    "dq400e-0x280000": (0x280000, CRC32INV,
                        (("maps", 0x40000, 0x7FFFC, 0x7FFFC),
                         ("main", 0x80000, 0x17FFFC, 0x17FFFC)), ()),
    "dq400e-0x2A0000": (0x2A0000, CRC32INV,
                        (("maps", 0x40000, 0x7FFFC, 0x7FFFC),
                         ("main", 0x80000, 0x17FFFC, 0x17FFFC)), ()),
    "dl501-0x178000": (0x178000, CRC16,
                       (("app", 0x40000, 0x16FFFE, 0x16FFFE),),
                       (b"EV_TCMDL501",)),
    "dl501-0x180000": (0x180000, CRC16,
                       (("app", 0x40000, 0x16FFFE, 0x16FFFE),),
                       (b"EV_TCMDL501",)),
    "dl501g2-0x180000": (0x180000, CRC16,
                         (("app", 0x40000, 0x17FFFE, 0x17FFFE),),
                         (b"EV_TCMDL501",)),
    "dl501g2-0x280000": (0x280000, CRC16,
                         (("app", 0x40000, 0x17FFFE, 0x17FFFE),),
                         (b"EV_TCMDL501",)),
    "dl501g2-0x2A0000": (0x2A0000, CRC16,
                         (("app", 0x40000, 0x17FFFE, 0x17FFFE),),
                         (b"EV_TCMDL501",)),
    "vl381-0x178000": (0x178000, CRC16,
                       (("maps", 0x20000, 0x3FFFE, 0x3FFFE),
                        ("app", 0x40000, 0x16FFFE, 0x16FFFE)),
                       (b"EV_TCMVL381",)),
    "vl381-0x180000": (0x180000, CRC16,
                       (("maps", 0x20000, 0x3FFFE, 0x3FFFE),
                        ("app", 0x40000, 0x16FFFE, 0x16FFFE)),
                       (b"EV_TCMVL381",)),
    "vl381-0x200000": (0x200000, CRC16,
                       (("maps", 0x20000, 0x3FFFE, 0x3FFFE),
                        ("app", 0x40000, 0x16FFFE, 0x16FFFE)),
                       (b"EV_TCMVL381",)),
    "dl382-0x280000": (0x280000, CRC32,
                       (("app", 0x80000, 0xBFF7C, 0xBFF7C),
                        ("maps", 0xC0000, 0x27FF7C, 0x27FF7C)),
                       (b"EV_TCMDL382",)),
}


def cell_value(data, start, end, algo):
    if algo == CRC32INV:
        return (~zlib.crc32(data[start:end])) & 0xFFFFFFFF
    if algo == CRC32:
        return zlib.crc32(data[start:end]) & 0xFFFFFFFF
    value = 0xFFFF
    for byte in data[start:end]:
        value = (value >> 8) ^ _T16[(value ^ byte) & 0xFF]
    return value & 0xFFFF


def _cell_size(algo):
    return 2 if algo == CRC16 else 4


def _stored(data, offset, algo):
    size = _cell_size(algo)
    if offset + size > len(data):
        return None
    return int.from_bytes(data[offset:offset + size], "little")


def identify(data):
    """Pick the profile whose checksum cells validate in this image.

    Returns (profile_name, cell_ranges) or (None, []). Matching is by cell
    validation rather than exact file size, because the same layout appears
    with and without trailing padding; at least one cell must validate, so an
    unknown layout is left unprotected instead of guessed.
    """
    best = (0, None)
    for name, (_size, algo, cells, markers) in PROFILES.items():
        if markers and not any(marker in data for marker in markers):
            continue
        width = _cell_size(algo)
        if any(offset + width > len(data) for _l, _s, _e, offset in cells):
            continue
        hits = 0
        for _label, start, end, offset in cells:
            stored = _stored(data, offset, algo)
            if stored is not None and stored == cell_value(data, start, end, algo):
                hits += 1
        if hits > best[0]:
            best = (hits, name)
    if not best[1]:
        return None, []
    name = best[1]
    _size, algo, cells, _markers = PROFILES[name]
    width = _cell_size(algo)
    ranges = sorted((offset, offset + width) for _l, _s, _e, offset in cells)
    return name, ranges
