#!/usr/bin/env python3
"""FRF support: decrypt VAG .frf containers and extract DQ250-MQB /
DQ200-MQB / DQ381 flash.

An .frf is a keystream-encrypted ZIP (key: frf.key, ported from the MIT
licensed VW_Flash project). Members are either .sgo files (feed them straight
into the SGO tooling) or .odx diagnostic containers whose FLASHDATA blocks are
hex-encoded and family-encrypted:
  - DQ250-MQB / DQ381-family: progressive substitution (mqb_dsg_key.bin),
    LZSS10-compressed; DQ381 blocks AES-CBC instead.
  - DQ200-MQB (0CW): progressive substitution with its own key table
    (dq200mqb_frf_key.bin, recovered from the Polo crossflash pair at
    firmware 0x1053C - same key address as DQ250-MQB), LZSS10-compressed.
    Verified: FL_0CW300046P_6230 ASW == stap-4 post-flash bench read,
    1,245,184 bytes, 0 diffs at 0x40000.

Block layouts (bench-aligned):
  DQ250-MQB: DRIVER 0x80E -> 0x0, ASW 0x130000 -> 0x40000,
             CAL 0x20000 -> 0x20000, image 1572864.
  DQ200-MQB: FD_2 2062 -> 0x0, ASW 0x130000 -> 0x40000,
             CAL 0x20000 -> 0x14000, image 1572864.
  DQ381: BOOT 0x1FE00 -> 0x10200, ASW 0x10FE00 -> 0x30200,
         CAL 0x3FE00 -> 0x140200, image 0x180000 (unverified layout).

Usage:
    py -3 sgo_frf.py FILE.frf [outdir]     extract members / flash image
"""
import binascii
import io
import re
import sys
import zipfile
from pathlib import Path
import xml.etree.ElementTree as ET

import sgo_tables

HERE = Path(__file__).resolve().parent

# frf block name -> offset in a REAL TC1766 bench read (DQ250-MQB),
# verified against DQ250_MQB_0D9300011T_4801_cTDK_F48M_micro reads:
# CAL sits at 0x20000 and ASW at 0x40000 - exactly 0x10000 lower than the
# VW_Flash binfile layout (0x30000/0x50000). The DRIVER payload has no
# counterpart in bench reads (the box's own boot occupies 0x0-0x20000), so
# it is placed at 0x0 and will differ there by design.
DQ250_MQB_OFFSETS = {"FD_2": 0x0, "FD_3": 0x40000, "FD_4": 0x20000}
IMAGE_SIZE = 1572864

# DQ381 (VW_Flash lib/modules/dq381.py): AES-CBC blocks FD_01DATA/02/03DATA.
# Placement uses VW_Flash binfile offsets; UNVERIFIED against a real read
# (no DQ381 FRF + read pair in the collection yet).
DQ381_OFFSETS = {"FD_01DATA": 0x10200, "FD_02DATA": 0x30200,
                 "FD_03DATA": 0x140200}
DQ381_IMAGE_SIZE = 0x180000
DQ381_AES_KEY = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
DQ381_AES_IV = bytes.fromhex("101112131415161718191A1B1C1D1E1F")

# DQ200-MQB (0CW): DSG progressive cipher with its own key table, verified
# against the Polo crossflash pair: FL_0CW300046P_6230_LkGC_sw.frf decodes
# and its ASW block matches the stap-4 post-flash bench read byte-exact at
# 0x40000 (1,245,184 bytes, 0 diffs). CAL sits at 0x14000 in bench reads
# (identity '0CW300046P GSG DQ200-MQ' found at 0x16004). Key = firmware
# 0x1053C (same key address as DQ250-MQB), bundled as
# dq200mqb_frf_key.bin.
DQ200_MQB_OFFSETS = {"FD_2": 0x0, "FD_3": 0x40000, "FD_4": 0x14000}
DQ200_MQB_IMAGE_SIZE = 1572864

# DQ400e (0DD): same progressive cipher as DQ200 with its own table, recovered
# from the firmware at 0x1698C - the same slot DQ250 keeps its table at
# 0x117B8. Placement verified byte-exact against DQ400_micro-20260907-144855
# (046E/2201): FD_4 0x40000 at 0x40000 and FD_3 0x14AD01 at 0x80000. FD_2
# (0xC00) is an EEPROM block and has no micro counterpart.
# Newer 0DD containers name the same two blocks FD_50/FD_51 (the erase
# routine sits in FD_30 and has no micro counterpart).
DQ400E_OFFSETS = {"FD_3": 0x80000, "FD_4": 0x40000,
                  "FD_50DATA": 0x80000, "FD_51DATA": 0x40000}
DQ400E_IMAGE_SIZE = 0x2A0000

# Aisin AL1000 (Audi 0C8 927 750 / 0C8 927 769, "EV_TCMAL991031"): plain
# blocks FD_0DATA / FD_1DATA, no compression.
# FD_1DATA placement is VERIFIED: FL_0C8927750AM_3626.frf is the same part and
# version ("36G03F0H.MOT", "3626") as the 2 MiB Touareg AL1000 read, and its
# FD_1DATA corresponds byte-for-byte (100.0%) to that read at 0x7000, where the
# identity strings also sit (block 0x3AF0D/0x3AF61 = read 0x41F0D/0x41F63).
# FD_0DATA is NOT placed: no part of it matches the read (best ~15% coincidence),
# and the read's high-entropy 0x80000-0x140000 region is vendor map data, not
# this block. Guessing an address would corrupt a restore.
AL1000_OFFSETS = {"FD_1DATA": 0x7000}
AL1000_IMAGE_SIZE = 0x200000

# DQ500 Temic (0BH): blocks are PLAIN (method 00 - no cipher, no
# compression). Placement verified byte-exact against the converted
# FL_0BH300011K_1724 bins: ASW 0xF8000 at 0x80000, CAL 0x20000 at 0x20000,
# image 1540096.
DQ500_TEMIC_OFFSETS = {"FD_2": 0x80000, "FD_3": 0x20000}
DQ500_TEMIC_IMAGE_SIZE = 1540096

# DL382 (0CK, Temic TriCore, Audi A4-B9): progressive cipher + LZSS10.
# Key table at firmware offset 0x3BB14 (recovered by permutation-table
# scan of VAG_TEMIC_DL382_INT FLASH read). FRF part numbers use car part
# numbers (8W0927155B etc.), block names FD_01DATA..04, method 11.
# Blocks decode and LZSS10 to declared sizes; bench placement needs a
# same-SW read (the donor read has different content in all blocks).
DL382_OFFSETS = {"FD_01DATA": 0x000000, "FD_02DATA": 0x1C0000,
                 "FD_03DATA": 0x040000, "FD_04DATA": 0x0C0000}
DL382_IMAGE_SIZE = 2621440

# DL501 (0B5: 8R2927156M/C and relatives): same substitution table as
# DL382, blocks stored as FD_2 (CAL, 0x20000) and FD_4 (ASW, 0x140000).
# Method 0x01 is cipher-only (no compression), 0x11 is cipher + LZSS10.
# Verified against FL_8R2927156M__0004: CAL carries "8R2927156M 0B5 ...
# Q5__20_MDH_2E6 SG Gen 2" and the ASW has EV_TCM/DL501 at 0x2003A.
DL501_OFFSETS = {"FD_2": 0x020000, "FD_4": 0x040000}
DL501_SIZES = {"FD_2": 0x20000, "FD_4": 0x140000}
DL501_IMAGE_SIZE = 0x280000


# ZF 8HP (AL551/ALX510/AL450, EV_TCMAL551211 / EV_TCMALX51011):
# method 0x22 = 19-byte repeating XOR then LZZ (2047 window). Placement is
# byte-exact against the AL551 bench dump R5F72519R_bhid0301_1034420214
# (SW 4H1927158AD1006) and confirmed by the CAL CRC32 at 0x180244 for
# 4G0927158/4H1927158/8R0927158 FRFs.
ZF8HP_XOR_KEY = b"CyA2008ZFVAGtcuxsam"
ZF8HP_OFFSETS = {"FD_2": 0x006000, "FD_3": 0x020000,
                 "FD_1": 0x040000, "FD_4": 0x180200}
ZF8HP_IMAGE_SIZE = 0x200000


_MASK_STATE = {"mask": bytearray(), "first": 0, "second": 1, "index": 0}


def _extend_mask(mask_state, key, length):
    """Grow the rolling-XOR mask to `length` bytes.

    The mask depends only on the key and the byte position, never on the
    container, so it is built once per process and reused: decrypting then
    becomes one big-integer XOR instead of a per-byte Python loop.
    """
    mask = mask_state["mask"]
    first = mask_state["first"]
    second = mask_state["second"]
    index = mask_state["index"]
    key_length = len(key)
    while len(mask) < length:
        key_byte = key[index]
        first = ((first + key_byte) * 3) & 0xFF
        mask.append(first ^ 0xFF ^ second ^ key_byte)
        second = ((second + 1) * first) & 0xFF
        index += 1
        if index == key_length:
            index = 0
    mask_state["first"] = first
    mask_state["second"] = second
    mask_state["index"] = index
    return mask


def decrypt_frf(key_material: bytes, encrypted_data: bytes) -> bytes:
    """Rolling-XOR FRF container cipher, mask-cached.

    Same bytes as the reference loop, but the keystream is independent of the
    payload, so it is generated once and applied with an integer XOR.
    """
    length = len(encrypted_data)
    if not length:
        return b""
    mask = _extend_mask(_MASK_STATE, key_material, length)
    value = int.from_bytes(encrypted_data, "big") ^ int.from_bytes(mask[:length], "big")
    return value.to_bytes(length, "big")


def decrypt_frf_prefix(key_material: bytes, encrypted_data: bytes,
                       length: int = 4) -> bytes:
    """Decrypt only the first bytes, for the ZIP-magic check.

    The mask is positional, so a prefix is exactly the start of the full mask.
    Testing this before the full decrypt keeps a 234 MB non-FRF from building a
    234 MB keystream (a per-byte Python loop) only to fail on the first byte.
    """
    if not encrypted_data:
        return b""
    length = min(length, len(encrypted_data))
    mask = _extend_mask(_MASK_STATE, key_material, length)
    return bytes(a ^ b for a, b in zip(encrypted_data[:length], mask[:length]))


def dsg_decrypt(key_bytes: bytes, data: bytes) -> bytes:
    """Progressive substitution cipher (no container XOR-FF layer here).
    The rolling counter increments BEFORE its key byte joins the offset
    (order matters; verified against VW_Flash's DSG.decrypt)."""
    key = key_bytes
    out = bytearray(len(data))
    offset = 0
    rolling = 0
    last = 0
    position = 0
    for value in data:
        plain = key[(value + offset) & 0xFF]
        offset = (offset + plain + last) & 0xFF
        rolling += 0x167  # deliberately unbounded, like VW_Flash
        offset = (offset + key[(rolling >> 8) & 0xFF]) & 0xFF
        last = plain
        out[position] = plain
        position += 1
    return bytes(out)


def lzss10(data: bytes, uncompressed_size: int) -> bytes:
    """LZSS10 (Nintendo-style) decompressor, ported from VW_Flash
    extractodx.decompress_raw_lzss10.

    Match copies use slice multiplication instead of a byte-at-a-time append
    loop; overlapping copies are handled by repeating the tail.
    """
    out = bytearray()
    pos = 0
    data_length = len(data)
    while len(out) < uncompressed_size:
        flags = data[pos]
        pos += 1
        for bit in (7, 6, 5, 4, 3, 2, 1, 0):
            remaining = uncompressed_size - len(out)
            if remaining <= 0:
                break
            if not (flags >> bit) & 1:
                if pos >= data_length:
                    raise ValueError("lzss10 stream truncated in literal")
                out.append(data[pos])
                pos += 1
            else:
                if pos + 2 > data_length:
                    raise ValueError("lzss10 stream truncated in match")
                sh = (data[pos] << 8) | data[pos + 1]
                pos += 2
                count, disp = sh >> 10, sh & 0x3FF
                if not 1 <= disp <= len(out):
                    raise ValueError(
                        f"lzss10 stream corrupt: displacement {disp} with "
                        f"{len(out)} bytes decoded (wrong key or garbage)")
                count = min(count, remaining)
                tail = out[-disp:]
                if count <= disp:
                    out += tail[:count]
                else:
                    out += (tail * (count // disp + 1))[:count]
    return bytes(out)


def lzz22(data: bytes, uncompressed_size: int) -> bytes:
    """LZZ decompressor for ODX method 0x22 (inverted flag bits MSB-first,
    5-bit match count + 11-bit displacement, 2047 window)."""
    out = bytearray()
    pos = 0
    while len(out) < uncompressed_size and pos < len(data):
        flags = data[pos]
        pos += 1
        for bit in (7, 6, 5, 4, 3, 2, 1, 0):
            if len(out) >= uncompressed_size:
                break
            if not (flags >> bit) & 1:
                if pos >= len(data):
                    raise ValueError("lzz stream truncated in literal")
                out.append(data[pos])
                pos += 1
            else:
                if pos + 2 > len(data):
                    raise ValueError("lzz stream truncated in match")
                word = (data[pos] << 8) | data[pos + 1]
                pos += 2
                count = word >> 11
                disp = word & 0x7FF
                if disp == 0 or disp > len(out):
                    raise ValueError(
                        f"lzz stream corrupt: displacement {disp} with "
                        f"{len(out)} bytes decoded (wrong key or garbage)")
                start = len(out) - disp
                for k in range(count):
                    out.append(out[start + k])
    return bytes(out)


def extract_odx_dq250(odx_bytes: bytes, dsg_key: bytes):
    """Extract DRIVER/ASW/CAL from a DQ250-MQB ODX; returns (image, blocks)."""
    root = ET.fromstring(odx_bytes)
    mem = root.find("./FLASH/ECU-MEMS/ECU-MEM/MEM")
    flashdatas = {fd.get("ID"): fd for fd in
                  mem.findall("./FLASHDATAS/FLASHDATA")}
    image = bytearray([0xFF]) * IMAGE_SIZE
    blocks = []
    for datablock in mem.findall("./DATABLOCKS/DATABLOCK"):
        size = 0
        for seg in datablock.findall("./SEGMENTS/SEGMENT"):
            size += int(seg.findtext("UNCOMPRESSED-SIZE", "0"))
        for flashdata_ref in datablock.findall(".//FLASHDATA-REF"):
            ref_id = flashdata_ref.get("ID-REF") or ""
            # Block identity is the FLASHDATA ID suffix: ...sw.FD_2 / FD_3 /
            # FD_3ERASE / FD_4. Erase-only blocks carry no data.
            name = ref_id.rsplit(".", 1)[-1]
            if name not in DQ250_MQB_OFFSETS:
                continue
            offset = DQ250_MQB_OFFSETS[name]
            fd = flashdatas.get(ref_id)
            method = fd.find("ENCRYPT-COMPRESS-METHOD").text
            content = fd.find("./DATA").text
            if len(content) <= 2:
                continue  # erase-only block
            raw = binascii.unhexlify(content)
            decrypted = dsg_decrypt(dsg_key, raw) if method[1] != "0" else raw
            # DQ250 flash blocks are always LZSS10-compressed in ODX
            # (extractodx forces is_dsg=True), regardless of the method byte.
            plain = lzss10(decrypted, size)
            if len(plain) < size:
                raise ValueError(
                    f"{name}: decompressed {len(plain):#x} < {size:#x}")
            image[offset:offset + size] = plain[:size]
            blocks.append((name, offset, size))
    return bytes(image), blocks


def extract_odx_dq381(odx_bytes: bytes):
    """Extract BOOT/ASW/CAL from a DQ381 ODX (AES-CBC blocks, VW_Flash
    dq381 module layout). UNVERIFIED against a real read."""
    from Crypto.Cipher import AES
    root = ET.fromstring(odx_bytes)
    mem = root.find("./FLASH/ECU-MEMS/ECU-MEM/MEM")
    flashdatas = {fd.get("ID"): fd for fd in
                  mem.findall("./FLASHDATAS/FLASHDATA")}
    image = bytearray([0xFF]) * DQ381_IMAGE_SIZE
    blocks = []
    for datablock in mem.findall("./DATABLOCKS/DATABLOCK"):
        size = 0
        for seg in datablock.findall("./SEGMENTS/SEGMENT"):
            size += int(seg.findtext("UNCOMPRESSED-SIZE", "0"))
        for flashdata_ref in datablock.findall(".//FLASHDATA-REF"):
            ref_id = flashdata_ref.get("ID-REF") or ""
            name = ref_id.rsplit(".", 1)[-1]
            # normalize: FD_01FLASHDATA -> FD_01DATA
            if name.startswith("FD_") and name.endswith("FLASHDATA"):
                name = name.replace("FLASHDATA", "DATA")
            if name not in DQ381_OFFSETS:
                continue
            offset = DQ381_OFFSETS[name]
            fd = flashdatas.get(ref_id)
            method = fd.find("ENCRYPT-COMPRESS-METHOD").text
            content = fd.find("./DATA").text
            if len(content) <= 2:
                continue
            raw = binascii.unhexlify(content)
            if method[1] != "0":
                # CBC needs full 16-byte blocks; trim any partial tail
                usable = len(raw) - len(raw) % 16
                decrypted = (AES.new(DQ381_AES_KEY, AES.MODE_CBC, DQ381_AES_IV)
                             .decrypt(raw[:usable]))
            else:
                decrypted = raw
            if method[0] in ("A", "a"):
                plain = lzss10(decrypted, size)
            else:
                plain = decrypted
            if len(plain) < size:
                raise ValueError(
                    f"{name}: decompressed {len(plain):#x} < {size:#x}")
            image[offset:offset + size] = plain[:size]
            blocks.append((name, offset, size))
    return bytes(image), blocks


def extract_odx_dq400e(odx_bytes: bytes, key: bytes):
    """Extract FD_3/FD_4 from a DQ400e (0DD) ODX with the progressive cipher
    + LZSS10, at the bench-verified offsets; returns (image, blocks)."""
    root = ET.fromstring(odx_bytes)
    mem = root.find("./FLASH/ECU-MEMS/ECU-MEM/MEM")
    flashdatas = {fd.get("ID"): fd for fd in
                  mem.findall("./FLASHDATAS/FLASHDATA")}
    image = bytearray([0xFF]) * DQ400E_IMAGE_SIZE
    blocks = []
    for datablock in mem.findall("./DATABLOCKS/DATABLOCK"):
        size = 0
        for seg in datablock.findall("./SEGMENTS/SEGMENT"):
            size += int(seg.findtext("UNCOMPRESSED-SIZE", "0") or 0)
        for flashdata_ref in datablock.findall(".//FLASHDATA-REF"):
            ref_id = flashdata_ref.get("ID-REF") or ""
            name = ref_id.rsplit(".", 1)[-1]
            # FD_50FLASHDATA and FD_50DATA name the same block.
            if name.startswith("FD_") and name.endswith("FLASHDATA"):
                name = name.replace("FLASHDATA", "DATA")
            if name not in DQ400E_OFFSETS:
                continue
            fd = flashdatas.get(ref_id)
            method = fd.findtext("ENCRYPT-COMPRESS-METHOD") or "00"
            content = fd.findtext("./DATA") or ""
            if len(content) <= 2:
                continue  # erase-only block
            raw = binascii.unhexlify(content)
            decrypted = dsg_decrypt(key, raw) if method[1] != "0" else raw
            plain = lzss10(decrypted, size)
            if len(plain) < size:
                raise ValueError(
                    f"{name}: decompressed {len(plain):#x} < {size:#x}")
            offset = DQ400E_OFFSETS[name]
            image[offset:offset + size] = plain[:size]
            blocks.append((name, offset, size))
    if not blocks:
        raise ValueError("no FD_3/FD_4 block in this container")
    return bytes(image), blocks


def extract_odx_dq200mqb(odx_bytes: bytes, key: bytes):
    """Extract FD_2/FD_3/FD_4 from a DQ200-MQB (0CW) ODX with the
    progressive cipher (key at firmware 0x1053C, no XOR-FF, unbounded
    rolling) + LZSS10; returns (image, blocks)."""
    root = ET.fromstring(odx_bytes)
    mem = root.find("./FLASH/ECU-MEMS/ECU-MEM/MEM")
    flashdatas = {fd.get("ID"): fd for fd in
                  mem.findall("./FLASHDATAS/FLASHDATA")}
    image = bytearray([0xFF]) * DQ200_MQB_IMAGE_SIZE
    blocks = []
    for datablock in mem.findall("./DATABLOCKS/DATABLOCK"):
        size = 0
        for seg in datablock.findall("./SEGMENTS/SEGMENT"):
            size += int(seg.findtext("UNCOMPRESSED-SIZE", "0") or 0)
        for flashdata_ref in datablock.findall(".//FLASHDATA-REF"):
            ref_id = flashdata_ref.get("ID-REF") or ""
            name = ref_id.rsplit(".", 1)[-1]
            if name not in DQ200_MQB_OFFSETS:
                continue
            offset = DQ200_MQB_OFFSETS[name]
            fd = flashdatas.get(ref_id)
            method = fd.find("ENCRYPT-COMPRESS-METHOD").text
            content = fd.find("./DATA").text
            if len(content) <= 2:
                continue  # erase-only block
            raw = binascii.unhexlify(content)
            decrypted = dsg_decrypt(key, raw) if method[1] != "0" else raw
            plain = lzss10(decrypted, size)
            if len(plain) < size:
                raise ValueError(
                    f"{name}: decompressed {len(plain):#x} < {size:#x}")
            image[offset:offset + size] = plain[:size]
            blocks.append((name, offset, size))
    return bytes(image), blocks


def extract_odx_dq500temic(odx_bytes: bytes, key: bytes = None):
    """Extract ASW/CAL from a DQ500 Temic (0BH) ODX - blocks are plain
    (method 00) or LZSS10 (method 10), placed at the verified bench offsets;
    returns (image, blocks). With `key`, method 11 (table cipher + LZSS10) is
    decrypted as well, which is how some 0DL containers are packed."""
    root = ET.fromstring(odx_bytes)
    mem = root.find("./FLASH/ECU-MEMS/ECU-MEM/MEM")
    flashdatas = {fd.get("ID"): fd for fd in
                  mem.findall("./FLASHDATAS/FLASHDATA")}
    image = bytearray([0xFF]) * DQ500_TEMIC_IMAGE_SIZE
    blocks = []
    for datablock in mem.findall("./DATABLOCKS/DATABLOCK"):
        size = 0
        for seg in datablock.findall("./SEGMENTS/SEGMENT"):
            size += int(seg.findtext("UNCOMPRESSED-SIZE", "0") or 0)
        for flashdata_ref in datablock.findall(".//FLASHDATA-REF"):
            ref_id = flashdata_ref.get("ID-REF") or ""
            name = ref_id.rsplit(".", 1)[-1]
            if name not in DQ500_TEMIC_OFFSETS:
                continue
            offset = DQ500_TEMIC_OFFSETS[name]
            fd = flashdatas.get(ref_id)
            method = (fd.findtext("ENCRYPT-COMPRESS-METHOD") or "00").strip().upper()
            content = fd.find("./DATA").text
            if len(content) <= 2:
                continue  # erase-only block
            plain = binascii.unhexlify(content)
            if key is not None and method[:1] == "1" and method[1:] == "1":
                # Method 11: table cipher, then LZSS10 to the declared size.
                plain = lzss10(dsg_decrypt(key, plain), size)
            elif size and len(plain) != size and method[:1] == "1":
                # Method 10: LZSS10 compression, no cipher (e.g. 0BH300012J).
                plain = lzss10(plain, size)
            if size and len(plain) != size:
                # e.g. 0DL300011H_5210: stored 691,872 but declared 1,015,808
                # (method 11 LZSS). Never place a short block silently.
                raise ValueError(
                    f"{name}: stored {len(plain)} bytes but the segment "
                    f"declares {size} (method-11 compression not supported "
                    f"for this family)")
            if len(plain) > size:
                plain = plain[:size]
            image[offset:offset + len(plain)] = plain
            blocks.append((name, offset, len(plain)))
    return bytes(image), blocks


def extract_odx_al1000(odx_bytes: bytes):
    """Extract the placed blocks of an Aisin AL1000 (0C8 927 750) ODX.

    Only FD_1DATA has a verified address (0x7000, anchored by its identity
    strings); FD_0DATA is left out because its address is unknown. See
    AL1000_OFFSETS.
    """
    root = ET.fromstring(odx_bytes)
    mem = root.find("./FLASH/ECU-MEMS/ECU-MEM/MEM")
    flashdatas = {fd.get("ID"): fd for fd in
                  mem.findall("./FLASHDATAS/FLASHDATA")}
    image = bytearray([0xFF]) * AL1000_IMAGE_SIZE
    blocks = []
    for datablock in mem.findall("./DATABLOCKS/DATABLOCK"):
        size = 0
        for seg in datablock.findall("./SEGMENTS/SEGMENT"):
            size += int(seg.findtext("UNCOMPRESSED-SIZE", "0") or 0)
        for flashdata_ref in datablock.findall(".//FLASHDATA-REF"):
            ref_id = flashdata_ref.get("ID-REF") or ""
            name = ref_id.rsplit(".", 1)[-1]
            if name not in AL1000_OFFSETS:
                continue
            fd = flashdatas.get(ref_id)
            content = fd.find("./DATA").text
            if len(content) <= 2:
                continue
            plain = binascii.unhexlify(content)
            if size and len(plain) != size:
                raise ValueError(
                    f"{name}: stored {len(plain)} bytes but the segment "
                    f"declares {size}")
            offset = AL1000_OFFSETS[name]
            image[offset:offset + len(plain)] = plain
            blocks.append((name, offset, len(plain)))
    return bytes(image), blocks


def extract_odx_dl382(odx_bytes: bytes, key: bytes):
    """Extract FD_01DATA..FD_04DATA from a DL382 (0CK) ODX with the
    progressive cipher (key at firmware 0x3BB14) + LZSS10; returns
    (image, blocks)."""
    root = ET.fromstring(odx_bytes)
    mem = root.find("./FLASH/ECU-MEMS/ECU-MEM/MEM")
    flashdatas = {fd.get("ID"): fd for fd in
                  mem.findall("./FLASHDATAS/FLASHDATA")}
    image = bytearray([0xFF]) * DL382_IMAGE_SIZE
    blocks = []
    for datablock in mem.findall("./DATABLOCKS/DATABLOCK"):
        size = 0
        for seg in datablock.findall("./SEGMENTS/SEGMENT"):
            size += int(seg.findtext("UNCOMPRESSED-SIZE", "0") or 0)
        for flashdata_ref in datablock.findall(".//FLASHDATA-REF"):
            ref_id = flashdata_ref.get("ID-REF") or ""
            name = ref_id.rsplit(".", 1)[-1]
            if name not in DL382_OFFSETS:
                continue
            offset = DL382_OFFSETS[name]
            fd = flashdatas.get(ref_id)
            method = fd.find("ENCRYPT-COMPRESS-METHOD").text
            content = fd.find("./DATA").text
            if len(content) <= 2:
                continue  # erase-only block
            raw = binascii.unhexlify(content)
            decrypted = dsg_decrypt(key, raw) if method[1] != "0" else raw
            plain = lzss10(decrypted, size)
            if len(plain) < size:
                raise ValueError(
                    f"{name}: decompressed {len(plain):#x} < {size:#x}")
            image[offset:offset + size] = plain[:size]
            blocks.append((name, offset, size))
    return bytes(image), blocks


def extract_odx_dl501(odx_bytes: bytes, key: bytes):
    """Extract FD_2/FD_4 from a DL501 (0B5) ODX using the DL382 table.
    Method 0x01 = cipher only, 0x11 = cipher + LZSS10; returns
    (image, blocks)."""
    root = ET.fromstring(odx_bytes)
    mem = root.find("./FLASH/ECU-MEMS/ECU-MEM/MEM")
    if mem is None:
        raise ValueError("ODX has no FLASH/ECU-MEMS/ECU-MEM/MEM node")
    flashdatas = {fd.get("ID"): fd for fd in
                  mem.findall("./FLASHDATAS/FLASHDATA")}
    image = bytearray([0xFF]) * DL501_IMAGE_SIZE
    blocks = []
    for datablock in mem.findall("./DATABLOCKS/DATABLOCK"):
        size = sum(int(seg.findtext("UNCOMPRESSED-SIZE", "0") or 0)
                   for seg in datablock.findall("./SEGMENTS/SEGMENT"))
        for flashdata_ref in datablock.findall(".//FLASHDATA-REF"):
            ref_id = flashdata_ref.get("ID-REF") or ""
            name = ref_id.rsplit(".", 1)[-1]
            if name not in DL501_OFFSETS:
                continue
            fd = flashdatas.get(ref_id)
            if fd is None:
                continue
            method = (fd.findtext("ENCRYPT-COMPRESS-METHOD") or "00").strip().upper()
            content = fd.findtext("./DATA") or ""
            if len(content) <= 2:
                continue  # erase-only block
            raw = binascii.unhexlify(content)
            want = size or DL501_SIZES.get(name, 0)
            if method == "11":
                plain = lzss10(dsg_decrypt(key, raw), want)
            elif method == "01":
                plain = dsg_decrypt(key, raw)
            elif method == "00":
                plain = raw
            else:
                raise ValueError(
                    f"{name}: unsupported method {method} for DL501")
            if want:
                if len(plain) < want:
                    raise ValueError(
                        f"{name}: decoded {len(plain):#x} < {want:#x}")
                plain = plain[:want]
            offset = DL501_OFFSETS[name]
            image[offset:offset + len(plain)] = plain
            blocks.append((name, offset, len(plain)))
    if not blocks:
        raise ValueError("DL501 ODX carries no known flash data blocks")
    return bytes(image), blocks


def extract_odx_zf8hp(odx_bytes: bytes):
    """Extract FD_1..FD_4 from a ZF 8HP (AL551/ALX510) ODX: method 0x22 =
    repeating XOR + LZZ, blocks at the bench-verified offsets; returns
    (image, blocks)."""
    root = ET.fromstring(odx_bytes)
    mem = root.find("./FLASH/ECU-MEMS/ECU-MEM/MEM")
    if mem is None:
        raise ValueError("ODX has no FLASH/ECU-MEMS/ECU-MEM/MEM node")
    flashdatas = {fd.get("ID"): fd for fd in
                  mem.findall("./FLASHDATAS/FLASHDATA")}
    image = bytearray([0xFF]) * ZF8HP_IMAGE_SIZE
    blocks = []
    for datablock in mem.findall("./DATABLOCKS/DATABLOCK"):
        size = 0
        for seg in datablock.findall("./SEGMENTS/SEGMENT"):
            size += int(seg.findtext("UNCOMPRESSED-SIZE", "0") or 0)
        for flashdata_ref in datablock.findall(".//FLASHDATA-REF"):
            ref_id = flashdata_ref.get("ID-REF") or ""
            name = ref_id.rsplit(".", 1)[-1]
            if name not in ZF8HP_OFFSETS:
                continue
            fd = flashdatas.get(ref_id)
            if fd is None:
                continue
            method = (fd.findtext("ENCRYPT-COMPRESS-METHOD") or "00").strip()
            content = fd.findtext("./DATA") or ""
            if len(content) <= 2:
                continue  # erase-only block
            raw = binascii.unhexlify(content)
            if method.upper() == "22":
                stream = bytes(b ^ ZF8HP_XOR_KEY[i % len(ZF8HP_XOR_KEY)]
                               for i, b in enumerate(raw))
            elif method.upper() == "00":
                stream = raw
            else:
                raise ValueError(
                    f"{name}: unsupported method {method} for ZF 8HP")
            plain = lzz22(stream, size)
            if len(plain) != size:
                raise ValueError(
                    f"{name}: decompressed {len(plain):#x} != {size:#x}")
            offset = ZF8HP_OFFSETS[name]
            image[offset:offset + size] = plain
            blocks.append((name, offset, size))
    if not blocks:
        raise ValueError("ZF 8HP ODX carries no known flash data blocks")
    return bytes(image), blocks


def part_number(root):
    """Normalized VAG part number from the ODX FLASH name (no spaces)."""
    for tag in ("./FLASH/LONG-NAME", "./FLASH/SHORT-NAME"):
        text = root.findtext(tag) or ""
        s = re.sub(r"\s+", "", text).upper()
        if s.startswith("FL_"):
            s = s[3:]
        match = re.match(r"([0-9][0-9A-Z]{2}[0-9A-Z]{3}[0-9A-Z]{3}[0-9A-Z]{0,3})", s)
        if match:
            return match.group(1)
    return ""


def families_for_part(part):
    """Families this part number may legitimately decode to.

    0DL/0DE carry both Bosch (AES, FD_01DATA layout) and Temic (method-11
    table cipher, FD_2/FD_3 layout) containers, so a single answer would
    reject the other one as a false positive.
    """
    family = family_for_part(part)
    if family is None:
        return None
    if (part or "")[:3].upper() in ("0DL", "0DE"):
        return {"dq381", "dq500temic"}
    return {family}


def family_for_part(part):
    """Authoritative TCU part -> family map. None means 'not a known TCU'."""
    part = (part or "").upper()
    p9 = part[:9]
    if len(p9) < 9:
        return None
    # Gearbox prefixes win over the 906/907 engine guard: 0DD906556AP is a
    # DQ400e TCU (its software is 0DD300046S), not engine control.
    if p9.startswith("0CW"):
        return "dq200mqb"
    if p9.startswith(("0BH", "0BT")):
        return "dq500temic"
    if p9.startswith(("0DL", "0DW", "0DE", "0GC")):
        return "dq381"
    if p9.startswith("0D9"):
        return "dq250mqb"
    if p9.startswith("0DD"):
        return "dq400e"
    if p9[3:6] in ("906", "907"):
        return None                       # engine control, not a gearbox
    if p9 == "8K0927155":
        return "vl381"
    if p9 in ("8K0927156", "8K1927156", "8K1927155", "8R2927156",
              "4G0927156", "4G0927166"):
        return "dl501"
    if p9 in ("8W0927155", "4G0927153"):
        return "dl382"
    if p9 in ("8R0927158", "4G0927158", "8W0927158"):
        return "zf8hp"
    return None


def extract_odx_auto(odx_bytes: bytes, dsg_key: bytes):
    """Pick the ODX profile from the part-number prefix (SHORT-NAME) with
    block sizes as a fallback fingerprint."""
    root = ET.fromstring(odx_bytes)
    mem = root.find("./FLASH/ECU-MEMS/ECU-MEM/MEM")
    name_node = root.find("./FLASH/SHORT-NAME")
    if name_node is None:
        name_node = root.find("./FLASH/LONG-NAME")
    box_name = (name_node.text or "") if name_node is not None else ""
    prefix = ""
    for tcu_prefix in ("0GC", "0DL", "0DW", "0DE", "0CW", "0AM", "0BT",
                       "0BH", "0AK", "0DD", "8W0", "4G0", "4S0", "80A",
                       "4M8", "4H0", "0C8", "0Z1", "03C", "03L", "0EA",
                       "0AY", "0CT", "0EF", "090", "074", "093", "000"):
        if tcu_prefix in box_name:
            prefix = tcu_prefix
            break

    names = {fd[0].text.rsplit(".", 1)[-1]
             for fd in mem.findall("./FLASHDATAS/FLASHDATA")}

    def fd3_size():
        for datablock in mem.findall("./DATABLOCKS/DATABLOCK"):
            refs = {r.get("ID-REF") or "" for r in
                    datablock.findall(".//FLASHDATA-REF")}
            if any(r.endswith(".FD_3") for r in refs):
                return sum(int(seg.findtext("UNCOMPRESSED-SIZE", "0") or 0)
                           for seg in datablock.findall("./SEGMENTS/SEGMENT"))
        return None

    # normalize block names: some FRFs use FD_01FLASHDATA instead of FD_01DATA
    names_norm = {n.replace("FLASHDATA", "DATA") if n.startswith("FD_")
                  else n for n in names}
    methods = {}
    for fd in mem.findall("./FLASHDATAS/FLASHDATA"):
        key = (fd.get("ID") or "").rsplit(".", 1)[-1]
        methods[key] = (fd.findtext("ENCRYPT-COMPRESS-METHOD") or "00").strip().upper()
    # Family selection is content-driven, not filename-driven:
    #  * the ODX ENCRYPT-COMPRESS-METHOD chooses the cipher family
    #    (22 = ZF XOR+LZZ, AA = AES+LZSS, 00 = plain, 11/01 = table cipher);
    #  * a method-11 container is accepted only when one of the known
    #    substitution tables + block layouts decodes every block to its
    #    declared uncompressed size and the result looks like a TCU image.
    # Part numbers are used only to word the final error message.
    is_tcu = b"EV_TCM" in odx_bytes or b"EV_TCM" in box_name.encode()
    part = part_number(root)
    method_set = {m for m in methods.values() if m and m != "00"}    # Tables are embedded in sgo_tables; an on-disk table file overrides them.
    temic_key = sgo_tables.table("temic")
    dq200_tables = [sgo_tables.table("dq200mqb"),
                    sgo_tables.table("dq200mqb_gen2")]

    def accept(image, blocks, family):
        # A real TCU image carries its ASAM name (EV_TCM...) or, in newer CAL
        # blocks, only its own part number (0DL300013F at CAL 0xFE21). Short
        # markers such as "GSG" occur by chance in undecrypted garbage, so a
        # nine-character part number is the minimum alternative evidence.
        # The part must also belong to this family: a container that decodes
        # under a foreign table is a false positive, not a donor.
        if not (bool(blocks) and len(image) >= 0x10000):
            return False
        allowed = families_for_part(part)
        if allowed is not None and family not in allowed:
            return False
        if b"EV_TCM" in image:
            return True
        sw = (part or "").encode()
        return len(sw) >= 9 and sw in image

    # Aisin AL1000 containers (0C8 927 750) use the plain blocks FD_0DATA /
    # FD_1DATA; identify them by block name before the method-based dispatch.
    if b"FD_0DATA" in odx_bytes and b"FD_1DATA" in odx_bytes:
        image, blocks = extract_odx_al1000(odx_bytes)
        if accept(image, blocks, "al1000"):
            return image, blocks, "al1000"

    if "22" in method_set:
        image, blocks = extract_odx_zf8hp(odx_bytes)
        if accept(image, blocks, "zf8hp"):
            return image, blocks, "zf8hp"
        raise ValueError(f"{part or prefix}: 8HP container did not decode")
    if "AA" in method_set:
        image, blocks = extract_odx_dq381(odx_bytes)
        if accept(image, blocks, "dq381"):
            return image, blocks, "dq381"
        raise ValueError(f"{part or prefix}: AES container did not decode")
    if not method_set or method_set <= {"10"}:
        # 00 = stored plain; 10 = LZSS10 compression with no cipher.
        image, blocks = extract_odx_dq500temic(odx_bytes)
        if accept(image, blocks, "dq500temic"):
            return image, blocks, "dq500temic"
        raise ValueError(
            f"{part or prefix}: "
            + ("compressed container has no known block layout" if method_set
               else "plain container has no known block layout"))

    # method 11 / 01: table cipher, try every table and layout we hold.
    attempts = [(f"dq200mqb#{i}", (lambda t=table:
                                    extract_odx_dq200mqb(odx_bytes, t)))
                for i, table in enumerate(dq200_tables)]
    attempts.append(("dq250mqb", lambda: extract_odx_dq250(odx_bytes, dsg_key)))
    attempts.append(("dl382", lambda: extract_odx_dl382(odx_bytes, temic_key)))
    attempts.append(("dl501", lambda: extract_odx_dl501(odx_bytes, temic_key)))
    attempts.append(("dq400e", lambda: extract_odx_dq400e(
        odx_bytes, sgo_tables.table("dq400e"))))
    # VL381/0CK method-01 (8K0927155...): same block layout as 0B5, but the
    # boot-area table found at flash 0xA001017C of the VL381 image.
    attempts.append(("vl381", lambda: extract_odx_dl501(
        odx_bytes, sgo_tables.table("vl381_01"))))
    # The Temic DQ500 layout (FD_2 at 0x80000, FD_3 at 0x20000) also appears
    # under 0DL, sometimes packed as method 11: table cipher + LZSS10.
    attempts.append(("dq500temic", lambda: extract_odx_dq500temic(odx_bytes)))
    for table_name in ("mqb_dsg", "temic", "dq400e", "dq200mqb",
                       "dq200mqb_gen2", "dq250_pq", "dq250c_pq"):
        attempts.append((f"dq500temic#{table_name}",
                         lambda t=table_name: extract_odx_dq500temic(
                             odx_bytes, sgo_tables.table(t))))
    # Try the part's own family first: a 8K1927156 container is a DL501 one, so
    # its diagnostic must not be crowded out by unrelated tables in the summary.
    preferred = family_for_part(part)
    attempts.sort(key=lambda item: 0 if item[0].split("#")[0] == preferred else 1)
    errors = []
    confirmed = []
    for family, attempt in attempts:
        try:
            image, blocks = attempt()
        except ValueError as exc:
            errors.append(f"{family}: {str(exc)[:64]}")
            continue
        if accept(image, blocks, family.split("#")[0]):
            return image, blocks, family.split("#")[0]
        name = family.split("#")[0]
        if bool(blocks) and len(image) >= 0x10000 and b"EV_TCM" in image:
            # Content-valid but the part table claims another family. Keep it:
            # prefix tables are incomplete and a single prefix can carry more
            # than one family (e.g. 8R2927156 exists as DL501 and DL382).
            confirmed.append((name, image, blocks))
        else:
            errors.append(f"{family}: decoded bytes are not a TCU image")
    if len(confirmed) == 1:
        name, image, blocks = confirmed[0]
        return image, blocks, name

    # Summarise what the container actually declares, so the message states the
    # real obstacle (packed blocks) instead of only naming failed ciphers.
    stored = {}
    for fd in mem.findall("./FLASHDATAS/FLASHDATA"):
        name = (fd.get("ID") or "").rsplit(".", 1)[-1].replace("FLASHDATA", "DATA")
        data = (fd.findtext("./DATA") or "").strip()
        stored[name] = len(data) // 2
    layout = []
    for datablock in mem.findall("./DATABLOCKS/DATABLOCK"):
        declared = sum(int(seg.findtext("UNCOMPRESSED-SIZE", "0") or 0)
                       for seg in datablock.findall("./SEGMENTS/SEGMENT"))
        for ref in datablock.findall(".//FLASHDATA-REF"):
            name = (ref.get("ID-REF") or "").rsplit(".", 1)[-1]
            name = name.replace("FLASHDATA", "DATA")
            if stored.get(name, 0) > 1:
                layout.append("%s %d/%d" % (name, stored[name], declared))
    raise ValueError(
        f"{part or prefix or '?'}: method "
        f"{sorted(set(methods.values()))} container is not supported for this "
        f"family (expected {preferred or '?'}); stored/declared bytes: "
        + ", ".join(layout)
        + "; attempts: " + "; ".join(errors))


def load(path: str):
    """Returns (members, image, blocks, family): members = {name: bytes} from
    the frf zip; for ODX members also the assembled flash image and the
    detected family ('dq250mqb' or 'dq381')."""
    key = (HERE / "frf.key").read_bytes()
    raw = Path(path).read_bytes()
    # Check the ZIP magic on a four-byte prefix first: building the keystream
    # for a large non-FRF (234 MB here) costs a per-byte Python loop and always
    # fails on the first byte anyway.
    if decrypt_frf_prefix(key, raw, 4) != b"PK\x03\x04":
        raise ValueError("frf did not decrypt to a ZIP (wrong key or format)")
    decrypted = decrypt_frf(key, raw)
    if not decrypted.startswith(b"PK"):
        raise ValueError("frf did not decrypt to a ZIP (wrong key or format)")
    try:
        archive = zipfile.ZipFile(io.BytesIO(decrypted))
    except zipfile.BadZipFile as exc:
        raise ValueError(f"frf decrypted to a damaged ZIP: {exc}") from None
    members = {info.filename: archive.read(info) for info in archive.infolist()}
    image = blocks = family = None
    for name, content in members.items():
        if name.lower().endswith(".odx"):
            dsg_key = sgo_tables.table("mqb_dsg")
            image, blocks, family = extract_odx_auto(content, dsg_key)
    return members, image, blocks, family


def load_odx(path: str):
    """Load a bare ODX XML member (already extracted from an FRF container).

    Returns the same shape as load(): (members, image, blocks, family);
    members is empty because there is no ZIP to enumerate."""
    data = Path(path).read_bytes()
    if not data.lstrip()[:1] == b"<":
        raise ValueError("not an ODX XML document (does it need the .frf?)")
    dsg_key = sgo_tables.table("mqb_dsg")
    image, blocks, family = extract_odx_auto(data, dsg_key)
    return {}, image, blocks, family


# --- optional native fast path ---------------------------------------------
# sgo_fast.dll implements the three hot loops in C. It is optional: when the
# DLL is missing (or fails to load) these names stay bound to the Python
# versions above, so behaviour and error messages are unchanged.
_py_dsg_decrypt = dsg_decrypt
_py_lzss10 = lzss10
_py_lzz22 = lzz22
FAST_PATH = None
try:  # pragma: no cover - depends on the build environment
    import sgo_fast as _fast

    if _fast.available():
        FAST_PATH = _fast.path()

        def dsg_decrypt(key_bytes, data):
            return _fast.dsg_decrypt(key_bytes, data)

        def lzss10(data, uncompressed_size):
            return _fast.lzss10(data, uncompressed_size)

        def lzz22(data, uncompressed_size):
            return _fast.lzz22(data, uncompressed_size)
except Exception:  # pragma: no cover - keep the Python implementation
    FAST_PATH = None


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    path = sys.argv[1]
    outdir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(path).parent
    outdir.mkdir(parents=True, exist_ok=True)
    members, image, blocks, _family = load(path)
    for name, content in members.items():
        target = outdir / name.rsplit("/", 1)[-1]
        target.write_bytes(content)
        print(f"member {name} -> {target} ({len(content):,} bytes)")
    if image is not None:
        target = outdir / (Path(path).stem + ".image.bin")
        target.write_bytes(image)
        print(f"flash image -> {target} ({len(image):,} bytes)")
        for name, offset, size in blocks:
            print(f"  {name}: 0x{offset:X} + {size:#x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
