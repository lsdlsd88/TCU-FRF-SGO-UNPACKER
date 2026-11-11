"""Shared GUI/CLI decoding, full-image assembly, provenance and comparison."""

import hashlib
import json
from pathlib import Path

from sgo_unpack import SGO
from sgo_legacy import LEGACY, decode_legacy, ppd_expand, record_decode
from sgo_early import EARLY_LAYOUTS, EARLY_TABLE

PROFILES = {
    "auto": "AUTO",
    "plain": "Plain SGO",
    "dq250": "DQ250",
    "dq250-early": "DQ250",
    "dq250c": "DQ250",
    "dq200": "DQ200",
    "dq381": "Bosch DQ380/381/500",
    "dq200mqb": "DQ200-MQB",
    "dq500temic": "DQ500-Temic",
    "dl382": "DL382",
    "dl501": "DL501 (0B5)",
    "vl381": "VL381 (0CK)",
    "zf8hp": "ZF 8HP (AL551)",
    "dq400e": "DQ400e (0DD)",
    "custom": "Custom",
    **{key: value[1] for key, value in LEGACY.items()},
}
# Keep internal decoder IDs for manifests and CLI callers, not GUI choices.
GUI_PROFILES = {key: label for key, label in PROFILES.items()
                if key not in ("plain", "dq250-early", "dq250c")}
MAX_IMAGE = 0x2000000
# Legacy record families whose payload carries no family marker, so AUTO can
# only identify them by their key: XOR-FF, the 1A 01 sync, then keyed records
# that must reach each block's declared decoded size. Keyed modes 0/3/7 only.
LEGACY_KEY_PROFILES = {
    "motronic7": b"GEHEIM",
    "med9": b"CodeRobert",
    "med17": b"BiWbBuD101",
}
FAMILY_TABLE_SOURCES = {
    "dq200": "dq200_pq", "dq250": "dq250_pq", "dq250c": "dq250c_pq",
}
# Restore-ORI must never write outside the calibration area. Windows are
# evidence-based: dq250/dq250c keep dataset header + maps in the first
# 64 KiB of the software block (IDENT at 0x300D0, gear table 0x304E5, all
# observed tune deltas end by 0x3DD6F); dq250-early has a dedicated 32 KiB
# parameter block. Profiles without a known calibration area keep the old
# full-region behaviour and are flagged in the save report.
CAL_WINDOWS = {
    # 0x20000-0x30000 stays quiet for PQ SGO candidates (their blocks start
    # at 0x30000), while MQB bench-aligned images carry their CAL there.
    "dq250": (0x20000, 0x40000),
    "dq250c": (0x20000, 0x40000),
    "dq250-early": (0x68000, 0x70000),
    # DQ381 (SH725xx): CAL block 0x3FE00 at 0x140200 (binfile layout,
    # same in bench reads - verified ASW@0x30200 byte-exact vs FL_0GC300012A).
    "dq381": (0x140200, 0x180200),
    # DQ200-MQB (0CW): CAL 0x20000 at 0x14000 in bench reads (verified
    # identity '0CW300046P GSG DQ200-MQ' at 0x16004 in the Polo crossflash
    # post-flash read), ASW 0x130000 at 0x40000.
    "dq200mqb": (0x14000, 0x34000),
    # DQ500 Temic (0BH): CAL 0x20000 at 0x20000, ASW 0xF8000 at 0x80000
    # (verified byte-exact vs the converted FL_0BH300011K_1724 bins).
    "dq500temic": (0x20000, 0x40000),
    # DQ400e (0DD): FD_4 holds the 0x40000-byte calibration at 0x40000
    # (FD_3 is the application at 0x80000, verified on FL_0DD300040B).
    "dq400e": (0x40000, 0x80000),
    # Aisin AL1000 (0C8 927 750 / 0C8 927 769): FD_1DATA holds the identity
    # and calibration text and is anchored at 0x7000 by its strings in the
    # 2 MiB Touareg AL1000 read. FD_0DATA has no verified address.
    "al1000": (0x7000, 0x42000),
    # DL382 (0CK Temic TriCore): CAL 0x20000 at 0x040000 (block offset,
    # needs same-SW bench read validation for exact placement).
    "dl382": (0x040000, 0x0C0000),
    # DQ250-MQB (0D9/0GC) shares the DQ250 map: DRIVER at 0, ASW at 0x40000,
    # CAL (FD_2) at 0x20000, so it needs its own window entry for CRC/fit.
    "dq250mqb": (0x020000, 0x040000),
    # DL501 (0B5): FD_2 is the 128 KB CAL at 0x20000, FD_4 starts the ASW
    # at 0x40000 (bench dump 8R2927156M places EV_TCM at 0x6003A).
    "dl501": (0x020000, 0x040000),
    # VL381/0CK method-01: FD_2 is the 128 KB calibration at 0x20000, same
    # block layout as 0B5 (identity/EV_TCM live in FD_4 at 0x60004/0x60044).
    "vl381": (0x020000, 0x040000),
    # ZF 8HP (AL551/ALX510): CAL data segment 0x190000-0x1FFD60 (A2L, and
    # proven by the CRC32 stored at 0x180244 = CRC32 of that range).
    "zf8hp": (0x190000, 0x1FFD60),
}


def cal_window(profile):
    """Calibration (lo, hi) for restore, or None when unknown."""
    return CAL_WINDOWS.get(profile)


def family_table(profile):
    if profile == "dq250-early":
        return EARLY_TABLE
    import sgo_tables
    return sgo_tables.table(FAMILY_TABLE_SOURCES[profile])


def early_blocks(blocks):
    return bool(blocks) and all(
        b["format"] == 1 and (b["id_be"], b["decomp_be"]) in EARLY_LAYOUTS
        and b["dsize"] == b["decomp_be"] for b in blocks)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def legacy_probe(blocks):
    """Legacy key profile that decodes every block to its declared size.

    The record stream has no magic and the container names no family, so the
    key is the only evidence. A single passing key identifies the family; no
    match, or more than one, stays unknown rather than guessing.
    """
    matches = []
    for profile, key in LEGACY_KEY_PROFILES.items():
        try:
            if all(len(record_decode(block["data"], key)) == block["decomp_be"]
                   for block in blocks):
                matches.append(profile)
        except ValueError:
            continue
    return matches[0] if len(matches) == 1 else None


def decode(sgo, profile="auto", table=None):
    if profile not in PROFILES:
        raise ValueError("unknown decoder profile")
    if profile == "dq250":
        if early_blocks(sgo.blocks):
            profile = "dq250-early"
        elif (sgo.blocks and all(b["format"] == 1 and b["id_be"] == 0x30000
                                and b["decomp_be"] == b["dsize"] == 0xB0000
                                for b in sgo.blocks)):
            if "02ec" in sgo.name.lower():
                profile = "dq250c"
            elif "02ea" not in sgo.name.lower():
                raise ValueError("Cannot determine the DQ250 type from this SGO")
        else:
            raise ValueError("No verified DQ250 decoder for this SGO layout")
    if profile == "auto":
        if all(b["format"] == 0 for b in sgo.blocks):
            profile = "plain"
        elif ("0am" in sgo.name.lower() and "getriebe_dsg" in sgo.name.lower()
              and all(b["format"] == 1 and b["id_be"] == 0x20000 for b in sgo.blocks)):
            profile = "dq200"
        elif ("02ea" in sgo.name.lower() and "getriebe_dsg" in sgo.name.lower()
              and early_blocks(sgo.blocks)):
            profile = "dq250-early"
        elif ("02ea" in sgo.name.lower() and "getriebe_dsg" in sgo.name.lower()
              and all(b["format"] == 1 and b["id_be"] == 0x30000 for b in sgo.blocks)):
            profile = "dq250"
        elif ("02ec" in sgo.name.lower() and "getriebe_dsg" in sgo.name.lower()
              and all(b["format"] == 1 and b["id_be"] == 0x30000 for b in sgo.blocks)):
            profile = "dq250c"
        else:
            profile = legacy_probe(sgo.blocks)
            if profile is None:
                formats = ", ".join(f"0x{value:02X}" for value in
                                    sorted({b["format"] for b in sgo.blocks}))
                raise ValueError(
                    f"No verified automatic decoder for this SGO (block formats "
                    f"{formats}). Select its family/profile explicitly.")
    if profile == "dq250-early" and not early_blocks(sgo.blocks):
        raise ValueError("Early DQ250 only supports verified format-1 software/parameter layouts")
    if profile in FAMILY_TABLE_SOURCES or profile == "dq250-early":
        bundled_table = family_table(profile)
        if table is None:
            table = bundled_table
        elif table != bundled_table:
            raise ValueError(f"{PROFILES[profile]} requires its matching built-in family table; use Custom to override")
    if profile == "custom" and table is None:
        raise ValueError("a family cipher table is required")
    segments = []
    for i, b in enumerate(sgo.blocks):
        if profile in LEGACY:
            start, data = decode_legacy(b, profile)
        else:
            if profile == "plain" and b["format"] != 0:
                raise ValueError("Plain profile only supports format 0")
            cipher = "feedback" if profile == "dq250-early" else "progressive"
            start, data = b["id_be"], sgo.decode_block(i, table, cipher=cipher)
        segments.append((start, data, f"SGO block {i}"))
    return profile, expand_segments(sgo, profile, segments)


SUPPORTED_BLOCK_FORMATS = {0x00, 0x01, 0x03}


def unsupported_reason(sgo):
    """Why no decoder here can unpack this SGO, or None when one can.

    Block format alone is not proof: several legacy containers declare their
    record-coded blocks as 0x11 and still decode through a legacy key (the 8J0
    8J0907404M set does). The legacy probe is only paid for unknown formats.
    """
    formats = sorted({block["format"] for block in sgo.blocks})
    unknown = [value for value in formats if value not in SUPPORTED_BLOCK_FORMATS]
    if not unknown:
        return None
    if legacy_probe(sgo.blocks) is not None:
        return None
    shown = ", ".join(f"0x{value:02X}" for value in unknown)
    return (f"block format {shown} is not supported: no family table, no legacy "
            "key and no LZSS/record packing here decodes it")


def default_size(profile, segments):
    end = max((start + len(data) for start, data, _ in segments), default=0)
    if profile == "dq200":
        return max(0x178000, end)
    if profile == "dq250-early":
        return max(0x70000, end)
    if profile in ("dq250", "dq250c"):
        return max(0x180000, end)
    if profile in LEGACY:
        return max(LEGACY[profile][2], end)
    return end


def assemble(segments, size=None, fill=255, base=None):
    """Place decoded segments at flash offsets, retaining explicit gaps."""
    if not segments:
        raise ValueError("SGO contains no data blocks")
    if not 0 <= fill <= 255:
        raise ValueError("padding byte must be between 00 and FF")
    end = max(start + len(data) for start, data, _ in segments)
    if size is None:
        size = len(base) if base is not None else end
    if not 0 < size <= MAX_IMAGE or end > size:
        raise ValueError(f"flash size must cover {end:#x} bytes and be at most {MAX_IMAGE:#x}")
    if base is not None and len(base) != size:
        raise ValueError("full-read base length must equal the selected flash size")
    ordered = sorted(segments, key=lambda item: item[0])
    cursor = 0
    gaps = []
    for start, data, _ in ordered:
        if start < cursor:
            raise ValueError("overlapping or negative flash regions")
        if start > cursor:
            gaps.append({"start": cursor, "end_exclusive": start, "size": start - cursor})
        cursor = start + len(data)
    if cursor < size:
        gaps.append({"start": cursor, "end_exclusive": size, "size": size - cursor})
    image = bytearray(base) if base is not None else bytearray([fill]) * size
    for start, data, _ in segments:
        image[start:start + len(data)] = data
    return bytes(image), gaps


def compare(image, reference, segments):
    limit = min(len(image), len(reference))
    mismatches = sum(a != b for a, b in zip(image, reference)) + abs(len(image) - len(reference))
    first = next((i for i in range(limit) if image[i] != reference[i]),
                 limit if len(image) != len(reference) else None)
    covered = sum(len(data) for _, data, _ in segments)
    covered_mismatches = sum(sum(a != b for a, b in zip(data, reference[start:start + len(data)]))
                             + max(0, start + len(data) - max(start, len(reference)))
                             for start, data, _ in segments)
    return {"exact_match": image == reference, "output_size": len(image),
            "reference_size": len(reference), "different_bytes": mismatches,
            "first_difference": first, "decoded_bytes": covered,
            "decoded_different_bytes": covered_mismatches,
            "decoded_regions_match": covered_mismatches == 0,
            "reference_sha256": digest(reference)}


def expand_segments(sgo, profile, segments):
    """Apply optional secondary decoding consistently for export and restore."""
    if profile == "ppd" and sgo.blocks[-1]["id_be"] == 0x3A0000:
        image, _ = assemble(segments, default_size(profile, segments))
        expanded = ppd_expand(image)
        if expanded:
            # The packed block remains in the combined image, as in the EXE.
            left, right = 0x40000, 0x40000 + len(expanded)
            preserved = []
            for start, data, label in segments:
                end = start + len(data)
                if end <= left or start >= right:
                    preserved.append((start, data, label))
                else:
                    if start < left:
                        preserved.append((start, data[:left - start], label))
                    if end > right:
                        preserved.append((right, data[right - start:], label))
            segments = preserved + [(left, expanded, "PPD expanded region")]
    return segments


def build_image(filename, output, profile="auto", table=None, size=None, fill=255,
                base_path=None, reference_path=None, export_parts=True):
    source, target = Path(filename), Path(output)
    protected = [source]
    protected.extend(Path(p) for p in (base_path, reference_path) if p)
    if any(target.resolve() == p.resolve() for p in protected):
        raise ValueError("output must not overwrite an SGO, base read or comparison read")
    sgo = SGO(source).parse()
    profile, segments = decode(sgo, profile, table)
    if table is None and (profile in FAMILY_TABLE_SOURCES or profile == "dq250-early"):
        table = family_table(profile)
    base = Path(base_path).read_bytes() if base_path else None
    reference = Path(reference_path).read_bytes() if reference_path else None
    if size is None:
        size = len(base) if base is not None else (len(reference) if reference is not None
                                                  else default_size(profile, segments))
    image, gaps = assemble(segments, size, fill, base)
    manifest = {
        "source": str(source.resolve()), "source_sha256": digest(sgo.data),
        "dataset": sgo.name, "version": sgo.version, "profile": profile,
        "output": str(target.resolve()), "output_size": len(image),
        "output_sha256": digest(image), "checksums_verified": False,
        "table_sha256": digest(table) if table is not None else None,
        "format1_cipher": (("feedback" if profile == "dq250-early" else "progressive")
                           if profile in (*FAMILY_TABLE_SOURCES, "dq250-early", "custom")
                           and any(b["format"] == 1 for b in sgo.blocks) else None),
        "missing_region_source": "full-read base" if base is not None else "padding",
        "padding_byte": fill if base is None else None,
        "base_path": str(Path(base_path).resolve()) if base_path else None,
        "base_sha256": digest(base) if base is not None else None,
        "decoded_bytes": sum(len(data) for _, data, _ in segments),
        "missing_bytes": sum(gap["size"] for gap in gaps), "missing_regions": gaps,
        "segments": [{"start": start, "end_exclusive": start + len(data),
                      "size": len(data), "source": label, "sha256": digest(data)}
                     for start, data, label in segments],
    }
    if reference is not None:
        manifest["comparison"] = compare(image, reference, segments)
        manifest["comparison"]["reference_path"] = str(Path(reference_path).resolve())
        manifest["comparison"]["reference_used_as_base"] = (
            base_path is not None and Path(base_path).resolve() == Path(reference_path).resolve())
    # Derived part filenames are also checked before any write.
    parts = []
    if export_parts and profile == "edc16-1m":
        parts = [("flash", 0x100000, 0x200000), ("mcu", 0, 0x70000)]
    elif export_parts and profile == "edc16-2m":
        parts = [("flash", 0, 0x200000), ("mcu", 0x200000, 0x280000)]
    outputs = [(target, image)]
    for name, left, right in parts:
        if right <= len(image):
            outputs.append((target.with_name(f"{target.stem}.{name}.bin"), image[left:right]))
    manifest_path = target.with_suffix(target.suffix + ".json")
    for path in [p for p, _ in outputs] + [manifest_path]:
        if any(path.resolve() == p.resolve() for p in protected):
            raise ValueError("a derived output would overwrite an input")
    manifest["part_exports"] = [{"output": str(p.resolve()), "size": len(data),
                                 "sha256": digest(data)} for p, data in outputs[1:]]
    target.parent.mkdir(parents=True, exist_ok=True)
    for path, data in outputs:
        path.write_bytes(data)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest
