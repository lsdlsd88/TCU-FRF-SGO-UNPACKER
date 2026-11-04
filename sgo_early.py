"""Early 02EA format-1 byte feedback cipher, verified on the mF8J read.

This table maps (current stored byte + previous stored byte) modulo 256
to plaintext. The previous stored byte starts at FF for every block.
Unlike the later PQ cipher, there is no rolling 0x167 counter. The
container XOR-FF layer is already folded into this table/convention.
See DQ250_EARLY_UNPACKING.md for recovery and independent-read evidence.
"""

EARLY_LAYOUTS = {(0x8000, 0x68000), (0x68000, 0x8000)}
EARLY_TABLE_SHA256 = "5d09da393a8051c1418dbe216a6f20221777036f54b2cac3481cd093effee17f"
EARLY_TABLE = bytes.fromhex(
    "036840dfb959d1648401ce3c70ea8b0c52716a4765c950c376e7f96b5ab2ed1ae8a2"
    "b5b08c13ef14266680558d5c1df388a02dde6df4ebbce9163bddf1ae0f46985b62"
    "79d42e3a05f7cb5f354b810d30aa1ce2ee9196dbfab49da5c7776c18e1b629835e"
    "8faf3139459ccd22be0044bb93e3c47f92d9580acfd307bf4a4d2ff6367c4256540"
    "4c0f2c61f25069b1048a44fe01551197e2bbd89024108a73e27a169b1fde5baf56f"
    "756797d073782c0b3343e612b7856387fc604e3d86727b2334a809dc38f8c5204953"
    "1137a9a67d17d20ec11bc8d7ff24d54cccf0a35d94fe57b3ad822a1efb99e4d69e"
    "b88a28d88eda9ac26eec32617495219f90acca3fab7a"
)


def decrypt_feedback(data, table=EARLY_TABLE):
    if len(table) != 256 or len(set(table)) != 256:
        raise ValueError("cipher table must be a 256-byte permutation")
    try:
        import sgo_fast
        if sgo_fast.available():
            return sgo_fast.feedback(table, data)
    except Exception:
        pass
    previous = 0xFF
    output = bytearray()
    for stored in data:
        output.append(table[(stored + previous) & 0xFF])
        previous = stored
    return bytes(output)
