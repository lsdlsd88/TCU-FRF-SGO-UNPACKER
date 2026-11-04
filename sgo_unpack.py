"""SGML Object File (SGO v2) parser/unpacker.

Port of calledit/SGML_Object_File_reader read_sgo.php, validated against
its test_data, extended for the getriebe (DSG TCU) files.

Layout (all u32 = LE):
  0x00 "SGML Object File\\0"          (17 bytes)
  0x11 u32 compat (=2)
  0x15 u32 checksum
  0x19 u32 indexIDENT
  0x1d u32 indexBaudrate2000
  0x21 u32 indexKwp2000Rei
  0x25 u32 indexKwp2000Acp
  0x29 u32 indexKwp2000Sa2
  0x2d u32 indexDataBlocks   (points at [count][offsets...] tables)
  IDENT: 260-byte XOR-FF filename field; 5-byte version field; u32
  SA2:   u32 count; count bytes script
  DataBlocks table: u32 count; count x u32 descriptor offsets
  Descriptor (0x19 bytes) at each offset:
    +0x00 3B id/start (see note), +0x03 1B format, +0x04 3B size_after_decomp,
    +0x07 3B erase_start, +0x0a 3B erase_end, +0x0d 3B check_start,
    +0x10 3B check_end, +0x13 2B checksum, +0x15 u32 data_size
    then data_size bytes of payload. Format 0 is XOR-FF plaintext;
    format 1 needs a family cipher even when stored/decoded sizes match.
Three-byte addresses/sizes are big-endian (also in the PHP reader).
Both address interpretations are retained for old analysis scripts.
"""

import struct
import sys
from pathlib import Path

from sgo_early import decrypt_feedback


def be24(b):
    return (b[0] << 16) | (b[1] << 8) | b[2]


def le24(b):
    return b[0] | (b[1] << 8) | (b[2] << 16)


_XOR_FF_TABLE = bytes(i ^ 0xFF for i in range(256))


def xorff(b):
    # bytes.translate is C-speed; the generator it replaces cost one Python
    # call per byte and showed up in the fingerprint profile.
    return bytes(b).translate(_XOR_FF_TABLE)


def xorff_str(b):
    out = []
    for c in b:
        if c == 0:
            break
        out.append(c ^ 0xFF)
    return bytes(out).decode("latin1")


def decrypt_table(data, table):
    """Decode format-1 stored bytes; verified on VO1b/RN1b PQ DQ250.

    Includes the container XOR-FF layer. State starts at zero per block.
    A different TCU family needs its own independently verified table.
    """
    if len(table) != 256 or len(set(table)) != 256:
        raise ValueError("cipher table must be a 256-byte permutation")
    try:
        import sgo_fast
        if sgo_fast.available():
            return sgo_fast.table_decrypt(table, data)
    except Exception:
        pass
    offset = rolling = last = 0
    output = bytearray()
    for value in data:
        plain = table[((value ^ 0xFF) + offset) & 0xFF]
        rolling = (rolling + 0x167) & 0xFFFF
        offset = (offset + plain + last + table[rolling >> 8]) & 0xFF
        last = plain
        output.append(plain)
    return bytes(output)


class SGO:
    def __init__(self, path, data=None):
        self.path = Path(path)
        self.data = self.path.read_bytes() if data is None else data
        d = self.data
        if not d.startswith(b"SGML Object File\x00"):
            raise ValueError("not an SGML Object File")
        self.require(0, 0x31, "header")
        (
            self.compat,
            self.checksum,
            self.i_ident,
            self.i_baud,
            self.i_rei,
            self.i_acp,
            self.i_sa2,
            self.i_blocks,
        ) = struct.unpack_from("<8I", d, 0x11)
        if self.compat != 2:
            raise ValueError(f"unsupported SGO compatibility {self.compat}")

    def require(self, offset, size, label):
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ValueError(
                f"truncated {label}: need {size:#x} bytes at {offset:#x}, "
                f"file size is {len(self.data):#x}"
            )

    def parse(self):
        d = self.data
        self.require(self.i_ident, 269, "IDENT")
        self.name = xorff_str(d[self.i_ident : self.i_ident + 260])
        vpos = self.i_ident + 260
        self.version = xorff_str(d[vpos : vpos + 5])
        self.require(self.i_sa2, 4, "SA2 count")
        self.sa2_count = struct.unpack_from("<I", d, self.i_sa2)[0]
        self.require(self.i_sa2 + 4, self.sa2_count, "SA2 script")
        self.sa2 = d[self.i_sa2 + 4 : self.i_sa2 + 4 + self.sa2_count]

        self.blocks = []
        self.require(self.i_blocks, 4, "block index count")
        nb = struct.unpack_from("<I", d, self.i_blocks)[0]
        self.require(self.i_blocks + 4, nb * 4, "block index")
        self.block_offsets = struct.unpack_from(f"<{nb}I", d, self.i_blocks + 4)
        for bo in self.block_offsets:
            blk = {}
            self.require(bo, 0x19, "block descriptor")
            raw = d[bo : bo + 0x19]
            blk["raw"] = raw
            blk["id_le"] = le24(raw[0:3])
            blk["id_be"] = be24(raw[0:3])
            blk["format"] = raw[3]
            blk["decomp_be"] = be24(raw[4:7])
            blk["erase"] = (be24(raw[7:10]), be24(raw[10:13]))
            blk["check"] = (be24(raw[13:16]), be24(raw[16:19]))
            blk["cksum"] = raw[19:21].hex()
            blk["dsize"] = struct.unpack_from("<I", raw, 0x15)[0]
            self.require(bo + 0x19, blk["dsize"], "block payload")
            blk["data"] = d[bo + 0x19 : bo + 0x19 + blk["dsize"]]
            self.blocks.append(blk)
        return self

    def decode_block(self, index, table=None, *, cipher="progressive"):
        if cipher not in ("progressive", "feedback"):
            raise ValueError("unknown format-1 cipher")
        block = self.blocks[index]
        if block["format"] == 0:
            result = xorff(block["data"])
        elif block["format"] == 1:
            if table is None:
                raise ValueError("format 0x01 requires a verified family cipher table")
            decoder = decrypt_feedback if cipher == "feedback" else decrypt_table
            result = decoder(block["data"], table)
        else:
            raise ValueError(f"unsupported block format {block['format']:#04x}")
        if len(result) != block["decomp_be"]:
            raise ValueError("decoded size differs from descriptor; compression is unsupported")
        return result

    def summary(self):
        lines = [
            f"file: {self.path.name} ({len(self.data)} bytes)",
            f"compat={self.compat} checksum={self.checksum:#010x}",
            f"name={self.name!r} version={self.version!r}",
            f"sa2({self.sa2_count})={self.sa2.hex()}",
            f"blocks: {len(self.blocks)}",
        ]
        for i, b in enumerate(self.blocks):
            lines.append(
                f"  [{i}] @{self.block_offsets[i]:#x}: id(le/be)={b['id_le']}/{b['id_be']:#x} "
                f"fmt={b['format']} decomp={b['decomp_be']:#x} erase={b['erase'][0]:#06x}-{b['erase'][1]:#06x} "
                f"check={b['check'][0]:#06x}-{b['check'][1]:#06x} cksum={b['cksum']} dsize={b['dsize']:#x} "
                f"(actual {len(b['data'])})"
            )
        return "\n".join(lines)


def main():
    for arg in sys.argv[1:]:
        sgo = SGO(arg).parse()
        print(sgo.summary())
        print()


if __name__ == "__main__":
    main()
