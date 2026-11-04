"""SGO Extract.exe compatibility, ported from cf80c63a94d9... (2013).

Verified against original x86 routines with Unicorn; see verify_legacy_exe.py.
No dependency on the original executable at runtime.
"""

LEGACY = {
    "motronic7": (0, "Motronic 7", 0x200000),
    "edc15": (1, "EDC15", 0x200000),
    "edc16-1m": (2, "EDC16 1 MiB", 0x280000),
    "med9": (3, "MED9", 0x280000),
    "edc16-2m": (4, "EDC16 2 MiB", 0x280000),
    "ppd": (5, "PPD", 0x200000),
    "simos7": (6, "SIMOS 7", 0x80000),
    "med17": (7, "MED17", 0x200000),
}


def bitrev32(value):
    # The EXE reverses bits WITHIN EACH BYTE, preserving byte positions.
    return int.from_bytes(bytes(int(f"{b:08b}"[::-1], 2)
                                for b in value.to_bytes(4, "little")), "little")


def lfsr_decode(data):
    state = bitrev32(0xB38BFCE7)
    out = bytearray()
    for pos in range(0, len(data), 4):
        key = bitrev32(state).to_bytes(4, "big")
        out.extend(c ^ 0xFF ^ k for c, k in zip(data[pos:pos + 4], key))
        for _ in range(3):
            feedback = ((state >> 31) ^ (state >> 21) ^ (state >> 1) ^ state) & 1
            state = ((state << 1) | feedback) & 0xFFFFFFFF
    return bytes(out)


_XOR_FF = bytes(i ^ 255 for i in range(256))


def _xor_bytes(data, data_start, mask, mask_start, count):
    """data[data_start:..+count] XOR mask[mask_start:..+count], at C speed."""
    return (int.from_bytes(data[data_start:data_start + count], "big")
            ^ int.from_bytes(mask[mask_start:mask_start + count], "big")
            ).to_bytes(count, "big")


def record_decode(data, key):
    """XOR-FF sync followed by keyed BE16 literal/RLE records.

    The per-byte generators this used to run (one for the XOR-FF pass, one per
    literal read) dominated the rescan profile: ~15 M generator calls for eight
    containers. `bytes.translate` and an integer XOR produce identical bytes.
    """
    wire = data.translate(_XOR_FF)
    pos = wire.find(b"\x1a\x01")
    if pos < 0:
        raise ValueError("legacy record sync 1A 01 is missing; wrong profile or damaged data")
    pos += 2
    # take() advances the key phase in lock-step with pos (phase == pos - start),
    # so the keystream is applied once, anchored at the sync position. Every
    # literal read then becomes a plain slice; before this each take() did two
    # big-int conversions (82,758 of them for 58 decodes).
    mask = key * (len(wire) // len(key) + 3)
    plain = wire[:pos] + _xor_bytes(wire, pos, mask, 0, len(wire) - pos)
    out = bytearray()

    def take(count):
        nonlocal pos
        if pos + count > len(plain):
            raise ValueError("truncated legacy record")
        result = plain[pos:pos + count]
        pos += count
        return result

    while pos < len(wire):
        count = int.from_bytes(take(2), "big")
        if count >= 0xC000:
            take(3)  # terminal 24-bit field; consumed but not emitted by EXE
            return bytes(out)
        if count >= 0x4000:
            value = take(1)
            count -= 0x4000
            if len(out) + count > 0x1000000:
                raise ValueError("legacy record output exceeds 16 MiB")
            out.extend(value * count)
        else:
            if not count:
                raise ValueError("zero-length legacy literal record")
            if len(out) + count > 0x1000000:
                raise ValueError("legacy record output exceeds 16 MiB")
            out.extend(take(count))
    raise ValueError("legacy record terminator is missing")


def deinterleave(data):
    """EDC16 format 3: transpose nine 64-byte lanes per 576-byte group."""
    if len(data) % 0x240:
        raise ValueError("EDC16 format-3 data must contain complete 576-byte groups")
    return b"".join(data[group + lane:group + lane + 0x40]
                    for lane in range(0, 0x240, 0x40)
                    for group in range(0, len(data), 0x240))


def decode_legacy(block, profile):
    mode = LEGACY[profile][0]
    start = block["check"][0]
    data = block["data"]
    if mode == 0:
        start = start + 0x100000 if start < 0xD0000 else start - 0x800000
        result = record_decode(data, b"GEHEIM")
    elif mode == 3:
        if 0x400000 <= start < 0x408000:
            start -= 0x200000
        result = record_decode(data, b"CodeRobert")
    elif mode == 7:
        if start > 0x800000:
            start -= 0x800000
        result = record_decode(data, b"BiWbBuD101")
    elif mode in (2, 4):
        start = start - 0x700000 if start >= 0x800000 else (
            start - 0x200000 if start >= 0x400000 else start)
        result = lfsr_decode(data)
        if block["format"] == 3:
            result = deinterleave(result)
    elif mode in (5, 6):
        start = block["id_be"] if mode == 5 else block["erase"][1]
        if mode == 5:
            start = {1: 0x80000, 4: 0x20000, 2: 0x40000,
                     0x280000: 0x80000, 0x3E0000: 0x20000,
                     0x40000: 0x40000}.get(start, start & 0x1FFFFF)
        else:
            start = 0x10000 if start == 1 else 0x70000
        result = bytes(c ^ (255 - i % 256) for i, c in enumerate(data))
    else:
        if block["format"] != 0:
            raise ValueError("EDC15 profile supports verified plain format 0 only")
        start = block["id_be"]
        result = bytes(c ^ 255 for c in data)
    if start < 0:
        raise ValueError("negative legacy mapped address; wrong profile")
    if len(result) != block["decomp_be"]:
        raise ValueError(f"legacy output size {len(result):#x} differs from declared "
                         f"{block['decomp_be']:#x}; wrong profile or unsupported data")
    return start, result


def ppd_expand(image):
    """Optional PPD packed region, EXE function 0x403BE0.

    Return expanded bytes at 0x40000, or None if the signature is absent.
    """
    base = 0x1A0100
    if len(image) < base + 16 or int.from_bytes(image[base + 4:base + 8], "big") != 0x400:
        return None
    end = base + int.from_bytes(image[base + 8:base + 12], "big")
    pos = base + 0x400
    if end > len(image) or end < pos:
        raise ValueError("invalid PPD packed-region bounds")
    out = bytearray()
    while pos < end and len(out) < 0x40000:
        flag = image[pos]
        pos += 1
        if flag >= 0x80:
            count = 2 * (flag - 0x7F)
            if pos + count > end:
                raise ValueError("truncated PPD literal")
            out.extend(image[pos:pos + count])
            pos += count
        else:
            if flag:
                count = flag + 1
            else:
                if pos + 2 > end:
                    raise ValueError("truncated PPD count")
                count = int.from_bytes(image[pos:pos + 2], "big")
                pos += 2
            if pos + 2 > end:
                raise ValueError("truncated PPD repeated word")
            out.extend(image[pos:pos + 2] * count)
            pos += 2
        if len(out) > 0x40000:
            raise ValueError("PPD expansion exceeds destination region")
    return bytes(out)
