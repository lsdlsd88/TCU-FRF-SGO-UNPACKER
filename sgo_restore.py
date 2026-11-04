"""Find stock-file candidates and restore only their supplied flash regions."""

from dataclasses import dataclass
from functools import lru_cache
import json
import zlib
from pathlib import Path
import re
import shutil
import threading
import time

from sgo_early import EARLY_LAYOUTS
from frf_family import canonical as canonical_family
from sgo_image import (CAL_WINDOWS, FAMILY_TABLE_SOURCES, MAX_IMAGE, assemble,
                       cal_window, decode, digest)
from sgo_index import (backfill_frf_crcs, build_index, extend_frf_catalogue,
                       extend_index, fingerprint, index_matches_folder)
from sgo_identity import DATASET, flash_identity
from sgo_unpack import SGO

_INDEX_CACHE = {}
_INDEX_LOCK = threading.RLock()
_SW_PART = re.compile(r"[0-9A-Z]{3}(?:300|906|907)[0-9]{3}[A-Z0-9]{0,3}", re.I)
# Donors for these profiles live in FRF/ODX containers, not in the plain-SGO
# library the SGO index fingerprints. Identifiers are the shared family names
# from frf_family; the profile and its donor family are the same word.
FRF_FAMILY_PROFILES = frozenset({"dq381", "dq500temic", "dq200mqb",
                                 "dq250mqb", "dl382", "dl501", "vl381",
                                 "zf8hp", "dq400e"})
# sgo_frf detects a donor's family from its content; this maps that family to
# the restore profile whose calibration window fits the decoded image.
FRF_PROFILE_FOR_DECODED = {
    "dq381": "dq381", "dq200mqb": "dq200mqb", "dq500temic": "dq500temic",
    "dl382": "dl382", "dl501": "dl501", "zf8hp": "zf8hp", "dq250mqb": "dq250",
    "dq400e": "dq400e", "vl381": "vl381",
}


def software_parts(markings):
    return {value.upper() for value in markings if _SW_PART.fullmatch(value)}


def part_base(part):
    """9-digit SW part without its revision letter: 02E300012K -> 02E300012.

    A flash read and its library original can differ in the revision letter
    alone (zerbst v0692s0602ea box = 02E300012K, library SGO = 02E300012F),
    so similar-version search must fall back to the shared base part."""
    match = re.fullmatch(r"([0-9A-Z]{3}(?:300|906|907)[0-9]{3})[A-Z0-9]{0,3}",
                         part, re.I)
    return (match.group(1) if match else part).upper()


_PART_MARK = re.compile(r"(?<![0-9A-Z])[0-9A-Z]{3}[0-9]{6}[A-Z0-9]{0,2}(?![0-9A-Z])")


def observed_parts(data):
    """Base part numbers (revision letter / version suffix stripped) found in
    a flash read. Candidate selection filters on these before any decoding."""
    found = set(_PART_MARK.findall(bytes(data).decode("latin1").upper()))
    sw = flash_identity(data).get("sw")
    for value in (sw if isinstance(sw, (list, tuple)) else [sw]):
        if value:
            found.add(str(value).upper())
    return {part_base(part) for part in found}


def _file_signature(path):
    stat = path.stat()
    return stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


@lru_cache(maxsize=16)
def _decoded_source(path, signature, profile, table):
    """Reuse decoded source bytes, invalidating when that source changes."""
    sgo = SGO(path).parse()
    actual_profile, segments = decode(sgo, profile, table)
    return sgo.name, sgo.version, actual_profile, digest(sgo.data), tuple(segments)


def _directory_signature(folders):
    values = []
    for folder in folders:
        try:
            modified = folder.stat().st_mtime_ns
        except OSError:
            modified = None
        values.append((folder, modified))
    return tuple(values)


_IMAGE_FAMILY_MARKERS = (
    (b"EV_TCMVL381", "vl381"),
    (b"EV_TCMDL501", "dl501"),
    (b"EV_TCMDL382", "dl382"),
    (b"EV_TCMAL551", "zf8hp"),
    (b"EV_TCMALX51", "zf8hp"),
    (b"EV_TCMDQ250", "dq250mqb"),
    (b"EV_TCMDQ200", "dq200mqb"),
    (b"EV_TCMDQ500", "dq500temic"),
    (b"EV_TCMDQ381", "dq381"),
    (b"EV_TCMDQ400", "dq400e"),
)


def _family_from_image(data):
    """Family of a decoded image: SW part prefix first, then ASAM marker.

    The part number identifies the container/layout family (0DL is a DQ381
    container even though its ASAM says EV_TCMDQ500), so it wins; the marker
    is only used when the part is not a known FRF-family prefix.
    """
    family = _family_from_parts(bytes(data))
    if family:
        return family
    head = data[:0x100000]
    tail = data[-0x100000:] if len(data) > 0x100000 else b""
    for marker, marker_family in _IMAGE_FAMILY_MARKERS:
        if marker in head or marker in tail:
            return marker_family
    return None


_IMAGE_SW_PREFIX_FAMILY = {
    # 3-char prefixes that are unambiguous
    "0D9": "dq250mqb", "0GC": "dq250mqb", "0CW": "dq200mqb",
    "0BH": "dq500temic", "0DL": "dq381", "0DW": "dq381",
    "0DE": "dl382", "0CK": "vl381", "0DD": "dq400e",
    # 8K0/8W0/8R0 cover several families; use the full part instead
    "8K0927155": "vl381", "8K0927158": "dl501",
    "8W0927155": "dl382", "8R0927158": "zf8hp",
}


def _family_from_parts(data):
    """Family from the SW part number, using the decoder's own part map.

    One source of truth: sgo_frf.family_for_part decides which family a part
    belongs to, so detection here can never invent a family the decoder would
    reject. 02E/0AM are the SGO-era families and stay on the SGO path.
    """
    import sgo_frf
    import sgo_identity

    identity = sgo_identity.flash_identity(data)
    for part in list(identity["sw"]) + list(identity["parts"]):
        family = sgo_frf.family_for_part(part)
        if family:
            return family
    return None


def _read_index_document(folder, index_path):
    folder = Path(folder)

    def load(path):
        return json.loads(Path(path).read_text(encoding="utf-8"))

    try:
        if index_path:
            path = _restore_index_copy(Path(index_path), folder)
        else:
            candidates = sorted(
                [p for pattern in ("catalogue_*.json", "sgo_index_*.json")
                 for p in folder.glob(pattern)],
                key=lambda p: p.stat().st_mtime_ns, reverse=True)
            if not candidates:
                return None
            path = candidates[0]
        document = load(path)
        if not document.get("frfs"):
            # The app cache can hold SGO sources only (library not writable).
            # The library's own catalogue may still carry decoded FRF rows, so
            # use it for reading even though writes go to the cache.
            in_library = folder / "catalogue.json"
            if in_library.is_file() and Path(in_library) != Path(path):
                try:
                    richer = load(in_library)
                    if richer.get("frfs"):
                        return richer
                except (OSError, ValueError):
                    pass
        return document
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _lookup_document(folder, index_path, progress):
    """Read each index once; check the tree again only when directories change."""
    with _INDEX_LOCK:
        cache = _restore_index_copy(Path(index_path), folder)
        key = str(cache.resolve()), str(folder)
        signature = _file_signature(cache)
        cached = _INDEX_CACHE.get(key)
        if (cached and cached[0] == signature
                and cached[2] == _directory_signature(cached[1])):
            return cached[3], False
        try:
            document = json.loads(cache.read_text(encoding="utf-8"))
            valid = index_matches_folder(document, folder)
        except (OSError, ValueError, KeyError, TypeError):
            valid = False
        if not valid:
            # Cumulative only: adopt newly named files, never rescan the
            # library. A missing index is an error, not a rescan trigger.
            extend_index(folder, cache, progress)
            document = json.loads(cache.read_text(encoding="utf-8"))
            signature = _file_signature(cache)
            built = True
        else:
            built = False
        folders = {folder}
        for item in document.get("sources", ()):
            parent = (folder / item["path"]).parent
            while parent != folder and parent.is_relative_to(folder):
                folders.add(parent)
                parent = parent.parent
        folders = tuple(sorted(folders))
        lookup, parts = {}, {}
        for entry in document["sgos"]:
            match = DATASET.search(entry.get("dataset", ""))
            if match:
                code = match.group().split("_", 1)[0].casefold()
                lookup.setdefault(code, []).append(entry)
            for part in software_parts(entry.get("part_markings", ())):
                # Index under the full marking and its revision-less base so a
                # read whose suffix differs still finds the same-part family.
                for part_key in (part, part_base(part)):
                    bucket = parts.setdefault(part_key, [])
                    if entry not in bucket:
                        bucket.append(entry)
        document["_dataset_lookup"] = lookup
        document["_part_lookup"] = parts
        document["_compatibility_cache"] = {}
        _INDEX_CACHE.clear()  # Retain only the active library's large document.
        _INDEX_CACHE[key] = signature, folders, _directory_signature(folders), document
        return document, built


def _early_entry(entry, size):
    layout = entry.get("block_layout", ())
    return (entry.get("status") == "unsupported-or-corrupt" and bool(layout)
            and "02ea" in entry.get("dataset", "").lower()
            and "getriebe_dsg" in entry.get("dataset", "").lower()
            and all(b.get("format") == 1
                    and (b.get("address"), b.get("decoded_size")) in EARLY_LAYOUTS
                    and b.get("stored_size") == b.get("decoded_size")
                    and b["address"] + b["decoded_size"] <= size for b in layout))


def _selected_entry(entry, profile, size):
    if _early_entry(entry, size):
        return profile in ("auto", "dq250", "dq250-early")
    allowed = ("dq250", "dq250c", "dq250-early") if profile == "dq250" else (profile,)
    return (entry.get("status") == "decoded"
            and (profile == "auto" or entry.get("decoder") in allowed))


def _match_sort_key(size):
    def key(m):
        window = cal_window(m.profile)
        if window:
            comparable = max(1, min(window[1], size) - window[0])
        else:
            comparable = size
        sim = m.fit_similarity if m.fit_compared else m.similarity
        return (-(m.compared_bytes >= comparable // 4), -sim, -m.similarity,
                -m.compared_bytes, str(m.path))
    return key


def _sort_matches(matches, size):
    def rank(m):
        window = cal_window(m.profile)
        if window:
            comparable = max(1, min(window[1], size) - window[0])
        else:
            comparable = size
        sim = m.fit_similarity if m.fit_compared else m.similarity
        return (not m.exact_dataset, -(m.compared_bytes >= comparable // 4),
                -sim, -m.similarity, -m.compared_bytes, str(m.path))
    matches.sort(key=rank)


def _layout(entry):
    return tuple(sorted((b["address"], b["decoded_size"])
                        for b in entry.get("block_layout", ())))


def _similar_versions(data, document, entries, profile, limit):
    """Rank only the same SW part, using cached JSON fingerprints."""
    parts = {part for entry in entries for part in software_parts(entry.get("part_markings", ()))}
    if not parts:
        parts = software_parts(flash_identity(data)["sw"])
    # Revision letters differ between a box and its library original; match
    # the full marking first, then fall back to the shared base part.
    lookup_keys = {key for part in parts for key in (part, part_base(part))}
    versions = {entry.get("software_version") for entry in entries}
    layouts = {_layout(entry) for entry in entries}
    seen = {entry.get("sha256") for entry in entries}
    ranked = []
    for part in sorted(lookup_keys):
        for entry in document["_part_lookup"].get(part, ()):
            version = entry.get("software_version", "")
            if (entry.get("sha256") in seen or version in versions
                    or not re.fullmatch(r"[0-9]{4}", version)
                    or not _selected_entry(entry, profile, len(data))
                    or (layouts and _layout(entry) not in layouts)):
                continue
            seen.add(entry.get("sha256"))
            ranked.append((version, entry))
    # The base part already bounds the set tightly; order revisions newest
    # first and let the caller's byte comparison rank them for real.
    ranked.sort(key=lambda row: row[0], reverse=True)
    selected, selected_versions = [], set()
    for version, entry in ranked:
        if version not in selected_versions:
            selected_versions.add(version)
            selected.append(entry)
            if len(selected) >= 32:
                break
    return selected


def _dataset_matches(data, folder, document, profile, table, local_extras, limit):
    codes = {match.group().split("_", 1)[0].casefold()
             for match in DATASET.finditer(bytes(data).decode("latin1"))}
    if not codes:
        return [], 0, 0, 0
    entries = [entry for code in codes
               for entry in document["_dataset_lookup"].get(code, ())
               if _selected_entry(entry, profile, len(data))]
    # Also run when no exact dataset exists in the library: the read's own SW
    # part then drives the same-part revision search (zerbst case).
    if len(entries) < limit:
        entries.extend(_similar_versions(data, document, entries, profile, limit - len(entries)))
    paths = [(folder / entry["path"], entry) for entry in entries]
    # Source fixtures are fallbacks; don't decode unrelated extras when the
    # library already has the exact embedded dataset identifier.
    if not paths:
        for path in local_extras:
            code = path.stem.split("_", 1)[0].casefold()
            if code in codes:
                paths.append((path, None))
    matches, seen, checked, compatible = [], set(), 0, 0
    for path, entry in paths:
        checked += 1
        try:
            match = candidate_for(data, path, profile, table, entry, deep=False)
            if entry and entry.get("sha256") != match.source_sha256:
                continue
            if match.source_sha256 in seen:
                continue
            seen.add(match.source_sha256)
            dataset = DATASET.search(match.name)
            match.exact_dataset = bool(dataset and dataset.group().split("_", 1)[0].casefold() in codes)
            matches.append(match)
            compatible += bool(entry and _early_entry(entry, len(data)))
        except (OSError, ValueError):
            continue
    _sort_matches(matches, len(data))
    return matches[:limit], checked, sum(_early_entry(e, len(data)) for e in entries), compatible


def changed_ranges(before, after):
    if len(before) != len(after):
        raise ValueError("comparison requires equal-size flash buffers")
    result = []
    start = None
    for offset, (old, new) in enumerate(zip(before, after)):
        if old != new:
            if start is None:
                start = offset
        elif start is not None:
            result.append((start, offset))
            start = None
    if start is not None:
        result.append((start, len(before)))
    return result


@dataclass
class Match:
    path: Path
    name: str
    version: str
    profile: str
    source_sha256: str
    segments: list
    differences: int
    compared_bytes: int
    part_markings: list
    ecu_families: list
    exact_dataset: bool = False
    fit_bytes: int = -1          # calibration sections matched anywhere
    fit_compared: int = 0        # total calibration section bytes
    fit_map: list = None         # per-section (read_offset, fit_offset, matched)
    cal_bytes: int = 0           # whole CAL window: the denominator for both %

    @property
    def match_denominator(self):
        """CAL-window size, so partial-coverage donors cannot score on a sliver."""
        return self.cal_bytes or self.compared_bytes or self.fit_compared or 0

    @property
    def inplace_matches(self):
        """Bytes equal at the same offset inside the CAL window.

        Only SGO-covered bytes can be known to differ; everything else in the
        window (uncovered or beyond this donor's blocks) is not a match.
        """
        covered = min(self.compared_bytes, self.match_denominator)
        return max(0, min(covered, covered - self.differences))

    @property
    def similarity(self):
        """Percent of the CAL window identical at the SAME offset."""
        denominator = self.match_denominator
        if not denominator:
            return 0.0
        return max(0.0, min(1.0, self.inplace_matches / denominator))

    @property
    def fit_similarity(self):
        """Percent of the CAL window matched when sections may move.

        Moving pieces can only add matches: the identity placement is one of the
        candidates, so the moved score is floored at the in-place score. The
        section search itself credits only pieces that pass its acceptance bar,
        which is why it must not be compared directly against a raw in-place
        count. Placement penalties are clamped so no negative percentage shows.
        """
        denominator = self.match_denominator
        if not denominator:
            return 0.0
        if not self.fit_compared:
            return self.similarity
        matched = max(self.fit_bytes, self.inplace_matches)
        return max(0.0, min(1.0, matched / denominator))


SECTION_SIZE = 256
SECTION_PROBE = 256
SECTION_PROBE_HITS = 8
# A piece is placed when at least 7/8 of its bytes match; anything weaker is
# split into four independent quarters and retried at the next level down.
FIT_ACCEPT_NUM, FIT_ACCEPT_DEN = 7, 8
FIT_LEVELS = (SECTION_SIZE, 64, 16)
# A displaced placement claiming an edge eighth with more than
# TRIM_BAD_NUM/TRIM_BAD_DEN mismatching bytes gives that edge back for
# independent re-fitting (it is overhanging into neighbour content).
TRIM_EDGES = True
TRIM_BAD_NUM, TRIM_BAD_DEN = 1, 2


def _overlaps(align, size, consumed):
    return any(align < end and start < align + size for start, end in consumed)


def best_fit_section(section, image, base_offset=None, avoid=()):
    """Locate `section` anywhere in `image`, ignoring offset.

    The section's own address (`base_offset`) is the preferred placement and
    is always scored first: identical content in place beats an identical
    copy elsewhere, because uniform regions (zero runs, padding) match at
    many offsets and `find` only returns the first. A displaced placement is
    chosen only when it strictly beats the baseline. Displaced candidates
    come from progressively smaller exact fragments (256 -> 64 -> 16 bytes).
    Placements overlapping an `avoid` interval are rejected. Returns
    (matched_bytes, offset); matched counts equal byte positions."""
    size = len(section)
    section_int = int.from_bytes(section, "big")

    def score(align):
        if align < 0 or align + size > len(image) or _overlaps(align, size, avoid):
            return None
        xored = section_int ^ int.from_bytes(image[align:align + size], "big")
        return xored.to_bytes(size, "big").count(0)

    best = (0, None)
    if base_offset is not None:
        baseline = score(base_offset)
        if baseline is not None:
            best = (baseline, base_offset)
            if baseline == size:
                return best  # exact in place: never move it
    exact = image.find(section)
    if exact >= 0 and exact != base_offset:
        matched = score(exact)
        if matched is not None and matched > best[0]:
            return matched, exact
    alignments = set()
    for probe_size, hits_allowed in ((SECTION_PROBE, SECTION_PROBE_HITS),
                                     (64, 16), (16, 32)):
        if alignments and probe_size != SECTION_PROBE:
            break  # larger probes already found candidate placements
        for quarter in range(0, size, probe_size):
            probe = section[quarter:quarter + probe_size]
            if len(probe) < probe_size or probe.count(probe[0]) == len(probe):
                continue  # partial tail or uniform bytes match everywhere
            start = 0
            for _ in range(hits_allowed):
                hit = image.find(probe, start)
                if hit < 0:
                    break
                if hit - quarter != base_offset:
                    alignments.add(hit - quarter)
                start = hit + 1
        if alignments:
            break
    for align in sorted(alignments):
        matched = score(align)
        if matched is not None and matched > best[0]:
            best = (matched, align)
    return best


_ECU_PROFILE = {
    "EV_TCMDQ200": "dq200mqb", "EV_TCMDQ250": "dq250mqb",
    "EV_TCMDQ381": "dq381", "EV_TCMDQ400": "dq400e",
    "EV_TCMDQ500": "dq500temic", "EV_TCMDL382": "dl382",
    "EV_TCMDL501": "dl501", "EV_TCMVL381": "vl381",
    "EV_TCMAL551": "zf8hp", "EV_TCMALX510": "zf8hp",
    "EV_TCMAL951": "zf8hp", "EV_TCMAL991": "al1000",
}


def resolve_profile(data, profile="auto"):
    """Concrete family profile for this read.

    A caller that only knows "auto" (external donor, choose-source dialog) still
    needs the calibration window, so the identity strings decide: the EV_TCM
    descriptor first, then the SW/HW part number. An unresolved read keeps the
    profile it was given, so the caller still reports a clear error.
    """
    if profile and profile != "auto" and cal_window(profile):
        return profile
    try:
        info = flash_identity(bytes(data))
    except Exception:
        return profile
    # The part number decides first: 0DL/0DE Bosch units report
    # EV_TCMDQ500021 but share the DQ381 (Bosch) layout, so the EV_TCM string
    # alone would pick the wrong calibration window.
    for part in list(info.get("sw", ())) + list(info.get("hw", ())):
        try:
            import sgo_frf
        except Exception:
            return profile
        family = sgo_frf.family_for_part(str(part))
        if family and cal_window(family):
            return family
    for ecu in info.get("ecu", ()):
        key = str(ecu).upper()
        for prefix, family in _ECU_PROFILE.items():
            if key.startswith(prefix) and cal_window(family):
                return family
    return profile


def cal_fit(data, profile, stock):
    """Score the read's calibration area against the candidate by sectioned
    best-fit. 256-byte sections first; anything below the 7/8 acceptance bar
    is split into four independent 64-byte pieces and retried, then 16-byte
    pieces. Pieces partition the calibration window exactly (no overlaps on
    the read side) and never claim candidate ranges already taken by a
    placed piece. Strongest unconstrained fits claim their placement first,
    so a weaker section's displaced claim cannot steal an exact match's
    region. Returns (fit_bytes, fit_compared, fit_map)."""
    window = cal_window(profile)
    if not window:
        return -1, 0, []
    lo, hi = window
    hi = min(hi, len(data))
    fit_map = []
    fit_bytes = 0
    consumed = []
    # Pass 1: unconstrained best placement per 1 KiB section (own address
    # kept as baseline so in-place revised maps sort honestly).
    prefit = []
    for start in range(lo, hi, FIT_LEVELS[0]):
        section = data[start:start + FIT_LEVELS[0]]
        matched, placed = best_fit_section(section, stock, base_offset=start)
        prefit.append((matched, placed, start, section))
    # Pass 2: strongest fits claim first; conflicted sections re-fit with
    # everything already claimed avoided.
    for matched, placed, start, section in sorted(prefit, key=lambda e: -e[0]):
        if placed is not None and _overlaps(placed, len(section), consumed):
            matched, placed = best_fit_section(section, stock,
                                               base_offset=start,
                                               avoid=consumed)
        accepted = matched >= FIT_LEVELS[0] * FIT_ACCEPT_NUM // FIT_ACCEPT_DEN
        surviving = []
        if not accepted:
            quarter = FIT_LEVELS[0] // 4
            surviving.extend((start + i, section[i:i + quarter], quarter)
                             for i in range(0, FIT_LEVELS[0], quarter))
        else:
            claimed = FIT_LEVELS[0]
            front = back = 0
            if (TRIM_EDGES and placed is not None and placed != start):
                # Edge trim for displaced placements: an edge eighth that is
                # mostly mismatching means the fit overhangs into neighbour
                # content; the edge is retried independently.
                edge = FIT_LEVELS[0] // 8
                xored = (int.from_bytes(section, "big")
                         ^ int.from_bytes(stock[placed:placed + FIT_LEVELS[0]],
                                          "big"))
                xbytes = xored.to_bytes(FIT_LEVELS[0], "big")
                # Bad bytes counted WITHIN each edge eighth, compared to the
                # edge length - not against the whole section size.
                front = edge if edge >= 8 and (edge - xbytes[:edge].count(0)) * TRIM_BAD_DEN > edge * TRIM_BAD_NUM else 0
                back = edge if edge >= 8 and (edge - xbytes[FIT_LEVELS[0] - edge:].count(0)) * TRIM_BAD_DEN > edge * TRIM_BAD_NUM else 0
                if front or back:
                    claimed = FIT_LEVELS[0] - front - back
                    matched = FIT_LEVELS[0] - xbytes[front:FIT_LEVELS[0] - back].count(0)
                    for edge_off, edge_sec in ((start, section[:front]),
                                               (start + FIT_LEVELS[0] - back,
                                                section[FIT_LEVELS[0] - back:])):
                        if edge_sec:
                            surviving.append((edge_off, edge_sec,
                                              len(edge_sec)))
            if claimed >= 8 and matched * 2 >= claimed:
                fit_bytes += matched
                if placed is not None:
                    consumed.append((placed + front, placed + FIT_LEVELS[0] - back))
                fit_map.append({"read_offset": start + front,
                                "fit_offset": placed + front if placed is not None else None,
                                "matched": matched, "size": claimed,
                                "section_size": FIT_LEVELS[0]})
        pending = surviving
        for level_size in FIT_LEVELS[1:]:
            surviving = []
            for offset, section, size in pending:
                matched, placed = best_fit_section(section, stock,
                                                   base_offset=offset,
                                                   avoid=consumed)
                accepted = (level_size == FIT_LEVELS[-1]
                            or matched >= size * FIT_ACCEPT_NUM // FIT_ACCEPT_DEN)
                if not accepted:
                    quarter = size // 4
                    surviving.extend((offset + i, section[i:i + quarter], quarter)
                                     for i in range(0, size, quarter))
                    continue
                front = back = 0
                if (TRIM_EDGES and level_size != FIT_LEVELS[-1]
                        and placed is not None and placed != offset
                        and size >= 8):
                    edge = size // 8
                    xored = (int.from_bytes(section, "big")
                             ^ int.from_bytes(stock[placed:placed + size], "big"))
                    xbytes = xored.to_bytes(size, "big")
                    # Bad bytes counted WITHIN each edge eighth.
                    front = edge if edge >= 8 and (edge - xbytes[:edge].count(0)) * TRIM_BAD_DEN > edge * TRIM_BAD_NUM else 0
                    back = edge if edge >= 8 and (edge - xbytes[size - edge:].count(0)) * TRIM_BAD_DEN > edge * TRIM_BAD_NUM else 0
                    if front or back:
                        matched = size - xbytes[front:size - back].count(0)
                        for edge_off, edge_sec in (
                                (offset, section[:front]),
                                (offset + size - back, section[size - back:])):
                            if edge_sec:
                                surviving.append((edge_off, edge_sec,
                                                  len(edge_sec)))
                claimed = size - front - back
                if claimed >= 8 and matched * 2 >= claimed:
                    fit_bytes += matched
                    if placed is not None:
                        consumed.append((placed + front, placed + size - back))
                    fit_map.append({"read_offset": offset + front,
                                    "fit_offset": placed + front if placed is not None else None,
                                    "matched": matched,
                                    "size": claimed,
                                    "section_size": size})
            pending = surviving
    return fit_bytes, hi - lo, fit_map


def candidate_for(data, path, profile="auto", table=None, indexed=None, deep=True):
    """Compare a read against one stock donor. With deep=False this is the
    coarse ranking pass: decode + whole-window difference count only, no
    per-section placement search."""
    source = Path(path).resolve()
    profile = resolve_profile(data, profile)
    name, version, profile, source_hash, segments = _decoded_source(
        str(source), _file_signature(source), profile, bytes(table) if table is not None else None)
    # Use the same bounds/overlap checks as full-image output.
    assemble(segments, len(data))
    # Rank and report on the calibration area only; app/boot bytes say
    # nothing about which stock file matches this box's maps.
    window = cal_window(profile)
    if window:
        lo, hi = min(window[0], len(data)), min(window[1], len(data))
    else:
        lo, hi = 0, len(data)
    cal_bytes = max(0, hi - lo)
    compared = differences = 0
    for start, payload, _ in segments:
        o_start, o_end = max(start, lo), min(start + len(payload), hi)
        if o_end <= o_start:
            continue
        compared += o_end - o_start
        differences += sum(old != new for old, new in
                           zip(data[o_start:o_end], payload[o_start - start:o_end - start]))
    if not compared:
        raise ValueError("stock file covers no bytes inside the calibration area")
    stock_image, _ = assemble(segments, len(data))
    fit_bytes, fit_compared, fit_map = -1, 0, None
    if deep:
        fit_bytes, fit_compared, fit_map = cal_fit(data, profile, stock_image)
        # Sections outside the SGO's covered blocks (stock keeps the read's own
        # bytes there) self-match trivially and must not count as fit credit.
        seg_spans = [(s, s + len(payload)) for s, payload, _ in segments]
        fit_map = [p for p in fit_map
                   if any(s <= p["read_offset"]
                          and p["read_offset"] + p["size"] <= e
                          for s, e in seg_spans)]
        fit_bytes = sum(p["matched"] for p in fit_map)
        fit_compared = sum(p["size"] for p in fit_map)
    return Match(Path(path), name, version, profile, source_hash,
                 list(segments), differences, compared,
                 indexed.get("part_markings", []) if indexed else [],
                 indexed.get("ecu_families", []) if indexed else [],
                 fit_bytes=fit_bytes, fit_compared=fit_compared,
                 fit_map=fit_map, cal_bytes=cal_bytes)


def refine_match(data, match, table=None, entry=None):
    """Recompute a shortlisted coarse match with the full placement fit."""
    if match.segments and match.segments[0][2] == "raw donor image":
        path = Path(match.path)
        if path.suffix.lower() in (".frf", ".odx"):
            # Raw candidates keep the container path; decode it again in memory.
            import sgo_frf

            load = sgo_frf.load_odx if path.suffix.lower() == ".odx" else sgo_frf.load
            _members, image, _blocks, family = load(str(path))
            profile = FRF_PROFILE_FOR_DECODED.get(family, match.profile)
            return raw_image_match(data, image, profile, True, path)
        return raw_image_candidate(data, path, match.profile, deep=True)
    return candidate_for(data, match.path, match.profile, table, entry, deep=True)


class IndexMissing(ValueError):
    """No saved index for this library: the one-time build has not run yet."""


def _restore_index_copy(cache, folder):
    """Recover a saved index copy; never start a fresh full-library scan."""
    if cache.exists():
        return cache
    bases = []
    for base in (cache.parent, cache.parent.parent, folder, folder.parent):
        base = Path(base)
        if base not in bases:
            bases.append(base)
    candidates = []
    for base in bases:
        exact = base / cache.name
        if exact.is_file() and exact != cache:
            candidates.append(exact)
        candidates.extend(p for p in base.glob(cache.name + ".backup-*") if p.is_file())
        if base == folder:
            # Adopt whatever catalogue name the library already uses.
            candidates.extend(
                p for pattern in ("catalogue_*.json", "sgo_index_*.json")
                for p in base.glob(pattern) if p.is_file() and p != cache)
    candidates = sorted(set(candidates), key=lambda p: p.stat().st_mtime_ns, reverse=True)
    if not candidates:
        raise IndexMissing(
            "No library catalogue for this folder yet. Restore-ORI builds it "
            "once; after that only newly added files are indexed.")
    cache.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(candidates[0], cache)
    return cache


def _frf_candidates(data, frf_path, profile, deep=False):
    """Restore candidates from one FRF donor, decoded entirely in memory.

    The donor's family comes from its own content, and that family selects
    the calibration window, so a folder may hold mixed families. Nothing is
    written beside the donor: no extracted image, no family sidecar.
    """
    import sgo_frf

    frf_path = Path(frf_path)
    if frf_path.suffix.lower() == ".odx":
        members, image, _blocks, family = sgo_frf.load_odx(str(frf_path))
    else:
        members, image, _blocks, family = sgo_frf.load(str(frf_path))
    donor_profile = FRF_PROFILE_FOR_DECODED.get(family, profile)
    matches = []
    if members:
        from sgo_scratch import scratch

        with scratch("sgo_frf_") as scratch_dir:
            for member_name in sorted(members):
                if not member_name.lower().endswith(".sgo"):
                    continue
                extracted = Path(scratch_dir) / Path(member_name).name
                extracted.write_bytes(members[member_name])
                try:
                    matches.append(candidate_for(data, extracted, donor_profile,
                                                 None, deep=deep))
                except (OSError, ValueError):
                    continue
    if image:
        matches.append(raw_image_match(data, image, donor_profile, deep,
                                       frf_path))
    if not matches:
        raise ValueError(f"no flash content in {frf_path.name}")
    return matches


# Decode at most this many FRF containers per lookup: ranked by part and
# software-version distance first, so only the closest ones are opened.
FRF_CANDIDATE_LIMIT = 24
# Decoding a container is the expensive part: rank all candidates with cheap
# 1 KiB CAL-block CRCs, then decode the best ones for exact differences. The
# decoded set is what the donor dialog can offer, so it must comfortably exceed
# the ten candidates a user is expected to see.
FRF_DECODE_LIMIT = 12
# Bound one-time work per lookup so a huge library can never stall a restore:
# at most this many new catalogue entries / CRC backfills are processed now,
# the rest continue on later lookups.
CATALOGUE_UPDATE_LIMIT = 20
CRC_BACKFILL_LIMIT = 40
CRC_BLOCK = 1024


def _cal_crcs(data, profile):
    window = cal_window(profile)
    if not window:
        return []
    lo, hi = window[0], min(window[1], len(data))
    if hi <= lo:
        return []
    return [zlib.crc32(data[offset:offset + CRC_BLOCK])
            for offset in range(lo, hi, CRC_BLOCK)]


def _entry_crcs(entry):
    """Stored 1 KiB CAL-block CRCs for this catalogue entry, if any."""
    stored = entry.get("cal_crc")
    if stored:
        return [int(stored[i:i + 8], 16) for i in range(0, len(stored), 8)]
    return None


def _crc_score(entry_crcs, read_crcs):
    if not entry_crcs or not read_crcs:
        return -1.0
    count = min(len(entry_crcs), len(read_crcs))
    hits = sum(1 for a, b in zip(entry_crcs[:count], read_crcs[:count]) if a == b)
    return hits / count


def _entry_version(entry):
    match = re.search(r"_(\d{3,5})_[A-Za-z0-9]{2,8}", entry.get("file", ""))
    return int(match.group(1)) if match else None


def _read_version(data):
    import sgo_identity

    for value in sgo_identity.flash_identity(data)["version"]:
        if value.isdigit():
            return int(value)
    return None


def _rank_frf_entries(entries, data):
    """Order catalogue entries by part then version closeness; no decoding."""
    version = _read_version(data)
    ranked = []
    for entry in entries:
        entry_version = _entry_version(entry)
        if version is None or entry_version is None:
            distance = 10 ** 9
        else:
            distance = abs(entry_version - version)
        ranked.append((distance, entry.get("file", ""), entry))
    ranked.sort(key=lambda item: (item[0], item[1]))
    return [entry for _distance, _name, entry in ranked]


def _frf_catalogue_matches(data, folder, entries, progress, limit, profile="auto",
                           decode_limit=None):
    """Shortlist catalogue entries, decode only the closest few.

    Ranking is done on cheap 1 KiB CAL-block CRCs (stored in the catalogue, or
    derived from an already cached decoded image) plus software-version
    distance, so no container is decoded just to be ranked. Only
    FRF_DECODE_LIMIT candidates are decoded for exact differences.
    """
    observed = observed_parts(data)
    observed_bases = {part_base(part) for part in observed}
    observed_prefixes = {part[:9].upper() for part in observed}
    shortlist = []
    for entry in entries:
        parts = {part_base(part) for part in entry.get("parts", ())}
        if observed_bases:
            if parts:
                if not (parts & observed_bases):
                    continue
            else:
                # Old catalogue entries have no parts: fall back to the file
                # name, which carries the part prefix.
                name = entry.get("file", "").upper()
                if not any(prefix in name for prefix in observed_prefixes):
                    continue
        shortlist.append(entry)
    read_crcs = _cal_crcs(data, profile)
    version_rank = {entry.get("file"): index
                    for index, entry in enumerate(_rank_frf_entries(shortlist, data))}
    scored = []
    for entry in shortlist:
        score = _crc_score(_entry_crcs(entry), read_crcs)
        scored.append((version_rank.get(entry.get("file"), 10 ** 6),
                       -score, entry))
    # Software version leads (free, from the name); CRC breaks ties.
    scored.sort(key=lambda item: (item[0], item[1]))
    best = [entry for _rank, _score, entry in scored[:FRF_CANDIDATE_LIMIT]]
    decode = [entry for _rank, _score, entry in
              scored[:decode_limit or FRF_DECODE_LIMIT]]
    matches, seen, skipped = [], set(), 0
    for number, entry in enumerate(decode):
        if progress:
            progress(number, len(decode),
                     "Comparing FRF: " + entry.get("file", "?"))
        try:
            # Coarse only: the list is ranked by CRC, and the per-section
            # placement fit runs when a donor is actually restored.
            for match in _frf_candidates(data, folder / entry["file"],
                                         canonical_family(entry.get("family"))):
                if match.source_sha256 in seen:
                    continue
                seen.add(match.source_sha256)
                matches.append(match)
        except (OSError, ValueError):
            skipped += 1
    _sort_matches(matches, len(data))
    del matches[limit:]
    if progress:
        progress(len(decode), len(decode), "Done")
    return matches, skipped


def _folder_frf_entries(folder, data, profile):
    """Catalogue-free shortlist: library FRFs whose name carries the read's part.

    Used when the saved catalogue has no rows for the family (fresh/empty cache
    index). Name-only, so a donor on disk is never invisible just because the
    index was not built yet.
    """
    parts = {part[:9].upper() for part in observed_parts(data)}
    if not parts:
        return []
    entries = []
    for path in sorted(Path(folder).glob("*")):
        if path.suffix.lower() not in (".frf", ".odx") or not path.is_file():
            continue
        try:
            if path.stat().st_size == 0:
                continue
        except OSError:
            continue
        if any(path.name.upper().startswith("FL_" + part) for part in parts):
            entries.append({"file": path.name, "family": profile})
    return entries[:FRF_CANDIDATE_LIMIT * 4]


def find_matches(data, folder, profile="auto", table=None, progress=None, limit=8,
                 extra_files=(), index_path=None, allow_build=False):
    """Use indexed fingerprints to shortlist, then fully decode/compare candidates.

    FRF-only families (dq381, dq200mqb, dq500temic, dl382) shortlist through
    the index's FRF catalogue instead; the plain-SGO library holds no records
    for them."""
    if not 0 < len(data) <= MAX_IMAGE:
        raise ValueError("flash must be between 1 byte and 32 MiB")
    folder = Path(folder).resolve()
    if not folder.is_dir():
        raise ValueError("choose an existing stock library folder")
    started = time.perf_counter()
    if profile != "custom":
        # The read's own ASAM marker wins over the type box: an image that
        # carries EV_TCM... is an FRF/bench image, so the SGO library cannot be
        # its donor and must not be scanned before the FRF catalogue is tried.
        detected = _family_from_image(bytes(data))
        if detected:
            profile = detected
    extra_files = tuple(extra_files)
    local_extras = sorted({Path(p).resolve() for p in extra_files
                           if Path(p).is_file() and Path(p).suffix.lower() == ".sgo"
                           and not Path(p).resolve().is_relative_to(folder)})
    document, index_built = None, False
    if profile in FRF_FAMILY_PROFILES:
        # FRF-only families: read the saved catalogue's frfs section and never
        # validate or rebuild the SGO index (that would rescan the library).
        light = _read_index_document(folder, index_path)
        if light is None:
            # No catalogue at all: still try the library's own FRF names rather
            # than declaring "no matching original" for files that are on disk.
            entries = _folder_frf_entries(folder, data, profile)
            if entries:
                if progress:
                    progress(0, len(entries),
                             f"No catalogue: scanning {len(entries)} library FRFs")
                matches, skipped = _frf_catalogue_matches(
                    data, folder, entries, progress, limit, profile)
                return matches, {
                    "files_scanned": len(entries),
                    "unsupported_or_invalid": skipped,
                    "supported_unique": len({m.source_sha256 for m in matches}),
                    "index_used": False, "index_built": False,
                    "byte_compared_candidates": min(len(entries),
                                                    FRF_CANDIDATE_LIMIT),
                    "lookup_method": "library FRF names (no catalogue)",
                    "lookup_seconds": time.perf_counter() - started,
                    "ranking": "part-prefixed library FRFs byte-compared"}
        if light:
            entries = [entry for entry in light.get("frfs", ())
                       if canonical_family(entry.get("family")) == profile]
            if entries and allow_build and index_path:
                missing = [entry for entry in entries if "cal_crc" not in entry]
                if missing:
                    # CRC build for THIS family only (no folder scan), bounded
                    # per lookup so a big family cannot stall a restore.
                    def crc_progress(done, total, name):
                        if progress:
                            progress(done, total,
                                     "Building CRC index (one-time): " + name)
                    backfill_frf_crcs(folder, Path(index_path), profile,
                                      crc_progress, limit=CRC_BACKFILL_LIMIT)
                    light = _read_index_document(folder, index_path)
                    entries = [entry for entry in light.get("frfs", ())
                               if canonical_family(entry.get("family")) == profile]
            if not entries:
                entries = _folder_frf_entries(folder, data, profile)
                if entries and progress:
                    progress(0, len(entries),
                             f"Catalogue empty: scanning {len(entries)} library FRFs")
            if entries:
                # Add library files for this exact part that the catalogue does
                # not list yet (name only, no decoding) so the exact donor is
                # never missing from the shortlist.
                known = {entry.get("file") for entry in entries}
                parts = {part[:9].upper() for part in observed_parts(data)}
                extra = [{"file": path.name, "family": profile}
                         for path in folder.glob("*")
                         if path.suffix.lower() in (".frf", ".odx")
                         and path.stat().st_size > 0 and path.name not in known
                         and any(path.name.upper().startswith("FL_" + part)
                                 for part in parts)]
                entries = entries + extra
                matches, skipped = _frf_catalogue_matches(
                    data, folder, entries, progress, limit, profile)
                ranked_by_crc = any(entry.get("cal_crc") for entry in entries)
                return matches, {
                    "files_scanned": len(entries),
                    "unsupported_or_invalid": skipped,
                    "supported_unique": len({m.source_sha256 for m in matches}),
                    "index_used": True, "index_built": False,
                    "byte_compared_candidates": min(len(entries),
                                                    FRF_CANDIDATE_LIMIT),
                    "lookup_method": ("frf catalogue (CRC ranking)" if ranked_by_crc
                                      else "frf catalogue (part + version)"),
                    "lookup_seconds": time.perf_counter() - started,
                    "ranking": "family entries only; CAL-block CRC where stored"}
    elif index_path and profile in ("auto", "plain", *FAMILY_TABLE_SOURCES):
        def index_progress(done, total, name):
            if progress:
                progress(done, total, "Indexing stock file: " + name)
        try:
            document, index_built = _lookup_document(folder, index_path, index_progress)
        except IndexMissing:
            if not allow_build:
                raise
            # One-time: there is no index at all for this library. Build it
            # once (the status line says so); later runs only add new names.
            def build_progress(done, total, name):
                if progress:
                    progress(done, total, "Building index (one-time): " + name)
            build_index(folder, Path(index_path), build_progress)
            document, index_built = _lookup_document(folder, index_path, index_progress)
            index_built = True

    if document and profile in FRF_FAMILY_PROFILES:
        # The SGO index has no records for these families: shortlist through
        # its FRF catalogue for the selected family only.
        entries = [entry for entry in document.get("frfs", ())
                   if canonical_family(entry.get("family")) == profile]
        matches, skipped = _frf_catalogue_matches(data, folder, entries, progress,
                                                  limit, profile)
        return matches, {"files_scanned": document["source_count"],
                         "unsupported_or_invalid": skipped,
                         "supported_unique": len({m.source_sha256 for m in matches}),
                         "index_used": not index_built, "index_built": index_built,
                         "indexed_source_count": document["source_count"],
                         "byte_compared_candidates": min(len(entries),
                                                         FRF_CANDIDATE_LIMIT),
                         "lookup_method": "frf catalogue",
                         "lookup_seconds": time.perf_counter() - started,
                         "ranking": "family FRF donors byte-compared on the calibration area"}

    if document:
        matches, checked, compatibility_rechecked, compatibility_decoded = _dataset_matches(
            data, folder, document, profile, table, local_extras, limit)
        if matches:
            if progress:
                progress(checked, checked, "Done")
            return matches, {
                "files_scanned": document["source_count"] + len(local_extras),
                "unsupported_or_invalid": max(0, document["counts"].get("unsupported-or-corrupt", 0)
                                               - compatibility_decoded),
                "supported_unique": len(matches), "index_used": not index_built,
                "index_built": index_built, "indexed_source_count": document["source_count"],
                "compatibility_rechecked": compatibility_rechecked,
                "compatibility_decoded": compatibility_decoded,
                "byte_compared_candidates": checked, "lookup_method": "dataset",
                "similar_versions": sum(not match.exact_dataset for match in matches),
                "lookup_seconds": time.perf_counter() - started,
                "ranking": "exact dataset first; closest revisions of the same SW part; full byte comparison"}
        # No dataset hit: the read's own part numbers decide. Filter the index
        # immediately by family (decoder) and SW part number, revision letter
        # and version stripped, and byte-compare only what survives.
        observed = observed_parts(data)
        compatibility_rechecked = compatibility_decoded = 0
        candidates = []
        for entry in document["sgos"]:
            # Old indexes predate this decoder. Recheck only the newly supported
            # layouts in memory, without rewriting or rebuilding the saved index.
            if (profile in ("auto", "dq250", "dq250-early")
                    and _early_entry(entry, len(data))):
                try:
                    source = folder / entry["path"]
                    signature = _file_signature(source)
                    prior = document["_compatibility_cache"].get(entry["path"])
                    if prior and prior[0] == signature:
                        refreshed = prior[1]
                    else:
                        compatibility_rechecked += 1
                        if progress and compatibility_rechecked % 8 == 0:
                            progress(compatibility_rechecked, document["unique_sgo_count"],
                                     "Checking newly supported early 02EA: " + entry["path"])
                        refreshed = fingerprint(source, folder)
                        document["_compatibility_cache"][entry["path"]] = signature, refreshed
                except OSError:
                    continue
                if (refreshed.get("sha256") == entry.get("sha256")
                        and refreshed.get("status") == "decoded"):
                    entry = refreshed
                    compatibility_decoded += 1
            if entry.get("status") != "decoded":
                continue
            if not _selected_entry(entry, profile, len(data)):
                continue
            entry_parts = {part_base(part)
                           for part in software_parts(entry.get("part_markings", ()))}
            if entry_parts & observed:
                candidates.append(entry)
        entries_by_path = {str((folder / e["path"]).resolve()): e
                           for e in candidates}
        paths = list(dict.fromkeys([folder / e["path"] for e in candidates]
                                   + local_extras))
        matches, seen = [], set()
        skipped = 0
        for number, path in enumerate(paths):
            if progress and number % 8 == 0:
                progress(number, len(paths), "Byte-comparing same-part stock files: " + path.name)
            try:
                match = candidate_for(data, path, profile, table,
                                      entries_by_path.get(str(path.resolve())),
                                      deep=False)
                if match.source_sha256 in seen:
                    continue
                seen.add(match.source_sha256)
                matches.append(match)
                matches.sort(key=_match_sort_key(len(data)))
                del matches[limit:]
            except (OSError, ValueError):
                skipped += 1
        if progress:
            progress(len(paths), len(paths), "Done")
        stats = {"files_scanned": document["source_count"] + len(local_extras),
                 "unsupported_or_invalid": max(0, document["counts"].get("unsupported-or-corrupt", 0)
                                               - compatibility_decoded) + skipped,
                 "supported_unique": document["unique_sgo_count"] + len(seen),
                 "index_used": not index_built, "index_built": index_built,
                 "indexed_source_count": document["source_count"],
                 "compatibility_rechecked": compatibility_rechecked,
                 "compatibility_decoded": compatibility_decoded,
                 "byte_compared_candidates": len(paths),
                 "lookup_method": "family + part filter",
                 "lookup_seconds": time.perf_counter() - started,
                 "ranking": "same family and SW part only; full byte comparison confirms"}
        if not matches and profile == "auto" and document.get("frfs"):
            # No SGO candidate: the read may belong to an FRF-only family.
            entries = [entry for entry in document["frfs"]
                       if canonical_family(entry.get("family")) in FRF_FAMILY_PROFILES]
            matches, frf_skipped = _frf_catalogue_matches(data, folder, entries,
                                                         progress, limit, profile)
            stats["byte_compared_candidates"] += min(len(entries),
                                                     FRF_CANDIDATE_LIMIT)
            stats["unsupported_or_invalid"] += frf_skipped
            stats["lookup_method"] = "fingerprints + frf catalogue"
        return matches, stats

    if profile in FRF_FAMILY_PROFILES or profile == "auto":
        all_frfs = sorted({p.resolve() for p in folder.rglob("*")
                           if p.is_file() and p.suffix.lower() in (".frf", ".odx")})
        # Narrow the scan to donors for the read's own part (the image carries
        # its SW part, e.g. 8K0927155) instead of decoding the whole library.
        parts = {part[:9].upper() for part in observed_parts(data)}
        if parts:
            exact = [p for p in all_frfs
                     if any(p.name.upper().startswith("FL_" + part)
                            for part in parts)]
            if exact:
                all_frfs = exact
            else:
                narrowed = [p for p in all_frfs
                            if any(part in p.name.upper() for part in parts)]
                if narrowed:
                    all_frfs = narrowed
        matches, seen, skipped = [], set(), 0
        for number, path in enumerate(all_frfs):
            if progress:
                progress(number, len(all_frfs), path.name)
            try:
                for match in _frf_candidates(data, path, profile):
                    if match.source_sha256 in seen:
                        continue
                    seen.add(match.source_sha256)
                    matches.append(match)
            except Exception:
                skipped += 1
        _sort_matches(matches, len(data))
        del matches[limit:]
        if progress:
            progress(len(all_frfs), len(all_frfs), "Done")
        return matches, {"files_scanned": len(all_frfs), "unsupported_or_invalid": skipped,
                         "supported_unique": len(seen), "index_used": False,
                         "index_built": False, "byte_compared_candidates": len(all_frfs),
                         "lookup_method": "frf scan",
                         "lookup_seconds": time.perf_counter() - started,
                         "ranking": "family FRF donors byte-compared on the calibration area"}

    # Keep search usable if caller has no persistent index location.
    all_files = sorted({p.resolve() for p in folder.rglob("*")
                        if p.is_file() and p.suffix.lower() == ".sgo"}
                       | {Path(p).resolve() for p in extra_files
                          if Path(p).is_file() and Path(p).suffix.lower() == ".sgo"})
    matches, seen, skipped = [], set(), 0
    for number, path in enumerate(all_files):
        if progress:
            progress(number, len(all_files), path.name)
        try:
            if not 0 < path.stat().st_size <= MAX_IMAGE:
                raise ValueError("empty or oversized stock file")
            match = candidate_for(data, path, profile, table)
            if match.source_sha256 in seen:
                continue
            seen.add(match.source_sha256)
            matches.append(match)
            matches.sort(key=_match_sort_key(len(data)))
            del matches[limit:]
        except (OSError, ValueError):
            skipped += 1
    if progress:
        progress(len(all_files), len(all_files), "Done")
    return matches, {"files_scanned": len(all_files), "unsupported_or_invalid": skipped,
                     "supported_unique": len(seen), "index_used": False,
                     "index_built": False, "byte_compared_candidates": len(all_files),
                     "ranking": "full-region byte comparison"}


_SW_MARK = re.compile(rb"(?<![0-9A-Z])(?:02E3\d{5}|0D9\d{6})[A-Z]{0,2}(?![0-9A-Z])")
# Any VAG-style part number (0XX + six digits, optional revision letter) and
# any readable ASCII run: SW version stamps and identification strings live in
# plain text in the image, not only in the two families above.
_SW_MARK_ANY = re.compile(rb"(?<![0-9A-Z])0[0-9A-Z]{2}[0-9]{6}[A-Z]{0,2}(?![0-9A-Z])")
_ASCII_RUN = re.compile(rb"[\x20-\x7E]{5,}")
# Text runs of more than four characters are identification; anything within
# ten bytes of them is kept too, so short stamps like "200" or "J743" that sit
# beside the SW strings are never written.
_MARKING_MARGIN = 10


def sw_marking_ranges(data):
    """Merged byte ranges that carry the read's own identity. Restore never
    writes over them: the box keeps its SW part numbers, version stamps and
    readable identification text regardless of which SGO supplied the
    calibration bytes."""
    blob = bytes(data)
    marks = sorted([m.span() for m in _SW_MARK.finditer(blob)]
                   + [m.span() for m in _SW_MARK_ANY.finditer(blob)]
                   + [m.span() for m in _ASCII_RUN.finditer(blob)
                      if m.group(0).strip()])
    limit = len(blob)
    marks = sorted((max(0, start - _MARKING_MARGIN),
                    min(limit, end + _MARKING_MARGIN)) for start, end in marks)
    merged = []
    for start, end in marks:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def subtract_ranges(ranges, protected):
    """Cut `protected` intervals out of `ranges`, keeping the rest."""
    out = []
    for start, end in ranges:
        pieces = [(start, end)]
        for ps, pe in protected:
            nxt = []
            for cs, ce in pieces:
                if pe <= cs or ps >= ce:
                    nxt.append((cs, ce))
                    continue
                if cs < ps:
                    nxt.append((cs, ps))
                if pe < ce:
                    nxt.append((pe, ce))
            pieces = nxt
        out.extend(pieces)
    return out


def restore_plan(data, match):
    """Everything the restore preview needs. For profiles with a calibration
    window the plan is PIECE-based and uses the DETECTED mapping: each piece
    is restored by copying the SGO's bytes from the placement where that
    piece's content was found (fit_offset) into the piece's own address in
    the read. Only pieces passing the 8-byte / 50% existence rules are
    applied; runs overlapping the read's SW markings are skipped. Regions
    without a qualifying piece are never written. Profiles without a window
    keep the old whole-range behaviour."""
    stock, _ = assemble(match.segments, len(data), base=data)
    window = cal_window(resolve_profile(bytes(data), match.profile))
    protected = sw_marking_ranges(data)
    crc_profile, crc_ranges = None, []
    try:
        import crc_regions
        crc_profile, crc_ranges = crc_regions.identify(bytes(data))
        if crc_ranges:
            # Checksum cells are never written: the tool does not recompute
            # them, so copying donor bytes there would corrupt the cell.
            protected = sorted(set(protected) | set(crc_ranges))
    except Exception:
        crc_profile, crc_ranges = None, []
    pieces = sorted(match.fit_map or [], key=lambda p: p["read_offset"])
    if window is None:
        return stock, {"mode": "ranges",
                       "ranges": subtract_ranges(
                           changed_ranges(data, stock), protected)}
    if not pieces:
        # No placement map on the match: run the sectioned search anyway, even
        # when everything matches with zero differences, so the preview always
        # works on real sections (256 -> 64 -> 16 -> 8 bytes) instead of raw
        # 1-byte streaks that the section search would never accept.
        _fit_bytes, _fit_compared, pieces = cal_fit(data, match.profile, stock)
        pieces = sorted(pieces or [], key=lambda p: p["read_offset"])
    lo, hi = window
    hi = min(hi, len(data))
    usable = []
    for piece in pieces:
        start = max(piece["read_offset"], lo)
        end = min(piece["read_offset"] + piece["size"], hi)
        src = piece["fit_offset"] + (start - piece["read_offset"])
        if src is None or src < 0 or src + (end - start) > len(stock):
            continue
        length = end - start
        # Changed streaks: read vs the SGO's bytes AT THE MAPPED PLACEMENT,
        # with the read's SW markings never written.
        runs = []
        run = None
        for i in range(length):
            if data[start + i] != stock[src + i]:
                if run is None:
                    run = i
            elif run is not None:
                runs.append((start + run, start + i))
                run = None
        if run is not None:
            runs.append((start + run, start + length))
        piece["ranges"] = subtract_ranges(runs, protected)
        piece["changed"] = sum(e - s for s, e in piece["ranges"])
        piece["matched"] = length - sum(e - s for s, e in runs)
        piece["span"] = (start, end)
        usable.append(piece)
    return stock, {"mode": "pieces", "pieces": usable,
                   "crc_profile": crc_profile,
                   "crc_ranges": [list(pair) for pair in crc_ranges]}


def plan_writes(plan, pieces=None, min_run=1):
    """Flat write list (read_start, sgo_start, length) from a plan: all
    pieces (or the given subset). Streaks of differing bytes shorter than
    `min_run` are skipped, so single config bits are not restored."""
    if plan["mode"] == "ranges":
        return [(s, s, e - s) for s, e in plan["ranges"] if e - s >= min_run]
    chosen = pieces if pieces is not None else plan["pieces"]
    writes = []
    for piece in chosen:
        base = piece["fit_offset"]
        if base is None:
            continue
        for s, e in piece["ranges"]:
            if e - s >= min_run:
                writes.append((s, base + (s - piece["read_offset"]), e - s))
    return writes


def apply_writes(data, stock, writes):
    """Copy stock bytes for each (read_start, sgo_start, length) write."""
    out = bytearray(data)
    for read_start, sgo_start, length in writes:
        out[read_start:read_start + length] = \
            stock[sgo_start:sgo_start + length]
    return bytes(out)


def raw_image_candidate(data, image_path, profile="dq250", deep=True):
    """Candidate from a plain flash image on disk (see raw_image_match)."""
    image = Path(image_path).read_bytes()
    return raw_image_match(data, image, profile, deep, Path(image_path))


def raw_image_match(data, image, profile="dq250", deep=True, source=None):
    """Build a restore candidate from an in-memory flash image.

    No decoded image is ever written to disk: the donor image stays in RAM.
    Sections of the read's calibration window are best-fit located in the
    image, so a donor whose layout is shifted (FRF -0x10000 vs bench) still
    maps correctly. With deep=False only whole-window differences are counted.
    """
    image = bytes(image)
    label = Path(source) if source is not None else Path("donor image")
    profile = resolve_profile(data, profile)
    window = cal_window(profile)
    if window is None:
        raise ValueError(f"no calibration window for profile {profile}")
    lo, hi = window
    hi = min(hi, len(data), len(image))
    if hi <= lo:
        raise ValueError("read is shorter than the calibration window")
    fit_bytes, fit_map = -1, None
    if deep:
        fit_bytes = 0
        fit_map = []
        for start in range(lo, hi, SECTION_SIZE):
            section = data[start:start + SECTION_SIZE]
            claimed = min(SECTION_SIZE, hi - start)
            matched, placed = best_fit_section(section[:claimed], image,
                                               base_offset=start)
            if claimed >= 8 and matched * 2 >= claimed:
                fit_map.append({"read_offset": start, "fit_offset": placed,
                                "matched": matched, "size": claimed})
                fit_bytes += matched
    segments = [(0, image, "raw donor image")]
    differences = sum(a != b for a, b in zip(data[lo:hi], image[lo:hi]))
    return Match(label, label.stem, "", profile,
                 digest(image), segments, differences, hi - lo,
                 [], [], fit_bytes=fit_bytes, fit_compared=hi - lo,
                 fit_map=fit_map, cal_bytes=hi - lo)


def restore(data, match):
    """Restore calibration bytes from well-matched pieces using the detected
    placement mapping. Differences outside the calibration area (application/
    boot firmware), regions without a qualifying piece, and the read's own SW
    part numbers are never written."""
    stock, plan = restore_plan(data, match)
    writes = plan_writes(plan)
    ranges = [(s, s + n) for s, _src, n in writes]
    return apply_writes(data, stock, writes), ranges


def outside_cal_ranges(data, match):
    """Differences the calibration-only restore deliberately leaves alone."""
    window = cal_window(match.profile)
    if window is None:
        return []
    stock, _ = assemble(match.segments, len(data), base=data)
    lo, hi = window
    hi = min(hi, len(data))
    skipped = []
    for start, end in changed_ranges(data, stock):
        if start < lo:
            skipped.append((start, min(end, lo)))
        if end > hi:
            skipped.append((max(start, hi), end))
    return skipped


def save_flash(source_path, original, edited, output_path, match=None, overwrite=False):
    """Write a new full-size flash file and a complete address-range audit."""
    source, target = Path(source_path), Path(output_path)
    manifest = target.with_suffix(target.suffix + ".changes.json")
    protected = [source] + ([match.path] if match else [])
    if any(path.resolve() == item.resolve() for path in (target, manifest) for item in protected):
        raise ValueError("save to a new filename; original flash and stock file are protected")
    if not overwrite and (target.exists() or manifest.exists()):
        raise ValueError("output already exists; choose a new filename")
    ranges = changed_ranges(original, edited)
    report = {"source": str(source.resolve()), "source_sha256": digest(original),
              "output": str(target.resolve()), "output_sha256": digest(edited),
              "size": len(edited), "changed_bytes": sum(end - start for start, end in ranges),
              "changed_range_count": len(ranges), "checksums_verified": False,
              "matched_sgo": str(match.path.resolve()) if match else None,
              "matched_sgo_sha256": match.source_sha256 if match else None,
              "matched_dataset": match.name if match else None,
              "matched_version": match.version if match else None,
              "changed_ranges": [{"start": start, "end_exclusive": end, "size": end - start,
                                  "before_hex_first_64": original[start:min(end, start + 64)].hex(),
                                  "after_hex_first_64": edited[start:min(end, start + 64)].hex()}
                                 for start, end in ranges]}
    if match:
        window = cal_window(match.profile)
        if window:
            lo, hi = window
            hi = min(hi, len(edited))
            stock, gaps = assemble(match.segments, len(edited), base=edited)
            window_gaps = [g for g in gaps
                           if g["start"] < hi and lo < g["end_exclusive"]]
            skipped = outside_cal_ranges(original, match)
            report.update({
                "cal_window": [lo, hi], "cal_only": True,
                "stock_regions_match": stock[lo:hi] == edited[lo:hi],
                "sgo_compared_bytes": match.compared_bytes,
                "regions_absent_from_sgo_preserved": all(
                    original[g["start"]:g["end_exclusive"]] == edited[g["start"]:g["end_exclusive"]]
                    for g in window_gaps),
                "outside_cal_differences_not_restored": {
                    "range_count": len(skipped),
                    "changed_bytes": sum(end - start for start, end in skipped),
                    "ranges": [{"start": s, "end_exclusive": e, "size": e - s}
                               for s, e in skipped[:64]]},
                "missing_regions": gaps})
        else:
            stock, gaps = assemble(match.segments, len(edited), base=edited)
            report.update({
                "cal_window": None, "cal_only": False,
                "stock_regions_match": stock == edited,
                "sgo_compared_bytes": match.compared_bytes,
                "regions_absent_from_sgo_preserved": all(
                    original[g["start"]:g["end_exclusive"]] == edited[g["start"]:g["end_exclusive"]]
                    for g in gaps),
                "missing_regions": gaps})
    target.parent.mkdir(parents=True, exist_ok=True)
    # All validation completes before either output is opened.
    target.write_bytes(edited)
    manifest.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
