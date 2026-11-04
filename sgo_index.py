"""Persistent SGO identity and decoded-block fingerprint index."""

import argparse
import atexit
import json
import mmap
import os
import re
import struct
import time
import zlib
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

_POOL = None
_POOL_NOTE = "not started"

from sgo_image import FAMILY_TABLE_SOURCES, assemble, cal_window, decode, digest
from sgo_unpack import SGO

CHUNK = 256
INDEX_SCHEMA = 3
# Bump when a decoder change could make previously failing containers decode.
# Entries stamped with an older revision are retried once; without this, a
# failed container is marked done forever (empty cal_crc) and never revisited.
DECODER_REVISION = 7
# File types the rescan actually understands; the inventory reports only these.
SUPPORTED_SUFFIXES = (".frf", ".sgo", ".odx", ".sox")
PRINTABLE = re.compile(rb"[\x20-\x7e]{6,}")
PART = re.compile(r"(?<![0-9A-Z])[0-9A-Z]{3}[0-9]{6}[A-Z0-9]{0,2}(?![0-9A-Z])", re.I)
ECU = re.compile(r"\bEV_TCM[A-Z0-9_]{3,32}\b", re.I)
# Gearbox self-description carried in decoded payloads, e.g. "GSG DSG AG7 DCT".
GEARBOX = re.compile(r"GSG\s+DSG\s+AG\d(?:\s+[A-Z]{2,4})?")


def temporary_path(target):
    """Per-process temp name: two instances never fight over one .tmp file."""
    return target.with_name(f"{target.name}.{os.getpid()}.tmp")


def replace_with_retry(temporary, target, attempts=6):
    """os.replace can lose against another writer holding the target open."""
    for attempt in range(attempts):
        try:
            os.replace(temporary, target)
            return
        except OSError:
            if attempt + 1 == attempts:
                try:
                    temporary.unlink()
                except OSError:
                    pass
                raise
            time.sleep(0.15 * (attempt + 1))


def _write_catalogue(document, target):
    """Atomically persist the catalogue (also used when a pass is cancelled)."""
    target = Path(target)
    temporary = temporary_path(target)
    temporary.write_text(json.dumps(document, separators=(",", ":")),
                         encoding="utf-8")
    replace_with_retry(temporary, target)


def identity(path, root, sgo=None):
    stat = path.stat()
    return {"path": path.relative_to(root).as_posix(), "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns}


def indexable(path):
    """Zero-byte entries are placeholders, not firmware: never index them.

    Truncated or corrupt files are still recorded once (as
    unsupported-or-corrupt) so the updater does not reopen them on every run;
    they are never selected as candidates.
    """
    try:
        return (path.is_file() and path.suffix.lower() == ".sgo"
                and path.stat().st_size > 0)
    except OSError:
        return False


def _decoded_strings(data, base, seen, cap=200):
    result = []
    for match in PRINTABLE.finditer(data):
        value = match.group().decode("ascii", "ignore").strip()
        if value and value not in seen:
            seen.add(value)
            result.append({"offset": base + match.start(), "text": value[:256]})
            if len(result) >= cap:
                break
    return result


def fingerprint(path, root):
    result = identity(path, root)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        result.update({"status": "unreadable", "reason": str(exc)[:240]})
        return result
    result["sha256"] = digest(raw)
    try:
        sgo = SGO(path, raw)
        sgo.parse()
        result.update({"dataset": sgo.name, "software_version": sgo.version,
                       "container_checksum": sgo.checksum,
                       "block_layout": [{"format": b["format"], "address": b["id_be"],
                                         "stored_size": b["dsize"],
                                         "decoded_size": b["decomp_be"],
                                         "erase": list(b["erase"]), "check": list(b["check"])}
                                        for b in sgo.blocks]})
        profile, segments = decode(sgo, "auto")
        result["decoder"] = profile
        result["status"] = "decoded"
        result["tables"] = ([FAMILY_TABLE_SOURCES[profile]]
                             if profile in FAMILY_TABLE_SOURCES else [])
        seen = set()
        strings = []
        for address, payload, label in segments:
            strings.extend(_decoded_strings(payload, address, seen))
        # Candidate selection is family + SW part number (schema 3): per-chunk
        # CRC fingerprints and stored strings are deliberately not recorded.
        result["part_markings"] = sorted({m.group().upper() for item in strings for m in PART.finditer(item["text"])})[:80]
        result["ecu_families"] = sorted({m.group().upper() for item in strings for m in ECU.finditer(item["text"])})[:40]
        result["gearbox"] = sorted({m.group(0).strip() for item in strings
                                    for m in GEARBOX.finditer(item["text"])})[:4]
        result["decoded_size"] = sum(len(payload) for _, payload, _ in segments)
        # 1 KiB CAL CRCs, the same measure the FRF catalogue stores, so SGO
        # donors can be pre-filtered by calibration content instead of names.
        window = cal_window(profile)
        if window and segments:
            end = max(address + len(payload) for address, payload, _ in segments)
            image, _ = assemble(segments, end)
            lo, hi = window[0], min(window[1], len(image))
            if hi > lo:
                result["cal_crc"] = "".join(
                    f"{zlib.crc32(image[offset:offset + 1024]):08x}"
                    for offset in range(lo, hi, 1024))
        result["decoder_rev"] = DECODER_REVISION
    except (OSError, ValueError, struct.error) as exc:
        result.update({"status": "unsupported-or-corrupt", "reason": str(exc)[:240]})
    return result


def _copy_mapped_range(mapped, output, start, end, insertions=()):
    cursor = start
    for position, payload in sorted(insertions):
        while cursor < position:
            next_pos = min(position, cursor + 1024 * 1024)
            output.write(mapped[cursor:next_pos])
            cursor = next_pos
        output.write(payload)
    while cursor < end:
        next_pos = min(end, cursor + 1024 * 1024)
        output.write(mapped[cursor:next_pos])
        cursor = next_pos


def _extend_index(root, target, files, progress):
    source_marker = b',"sources":['
    sgo_marker = b'],"sgos":['
    temporary = temporary_path(target)
    with target.open("rb") as source:
        if not target.stat().st_size:
            raise ValueError("existing SGO index is empty; refusing to rescan the library")
        with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            source_key = mapped.find(source_marker)
            if source_key < 0:
                raise ValueError("existing SGO index is malformed; refusing to rescan the library")
            try:
                metadata = json.loads(mapped[:source_key] + b"}")
            except (ValueError, TypeError) as exc:
                raise ValueError("existing SGO index header is invalid; refusing to rescan") from exc
            if (metadata.get("schema") != INDEX_SCHEMA or
                    Path(metadata.get("source_root", "")).resolve() != root):
                raise ValueError("existing SGO index belongs to another folder; refusing to rescan")

            source_start = source_key + len(source_marker)
            source_end = mapped.find(sgo_marker, source_start)
            if source_end < 0:
                raise ValueError("existing SGO index has no SGO records; refusing to rescan")
            try:
                sources = json.loads(b"[" + mapped[source_start:source_end] + b"]")
            except (ValueError, TypeError) as exc:
                raise ValueError("existing SGO source list is invalid; refusing to rescan") from exc

            indexed_names = {item["path"].casefold() for item in sources}
            new_files = [path for path in files
                         if path.relative_to(root).as_posix().casefold() not in indexed_names]
            new_sources, new_records, pending_aliases = [], [], {}
            new_by_hash = {}
            counts = Counter(metadata.get("counts", {}))
            unique_additions = 0

            sgo_start = source_end + len(sgo_marker)
            document_end = len(mapped)
            while document_end and mapped[document_end - 1] in b" \t\r\n":
                document_end -= 1
            if mapped[document_end - 2:document_end] != b"]}":
                raise ValueError("existing SGO index has an invalid end; refusing to rescan")
            sgo_end = document_end - 2
            hash_prefix = b'"sha256":"'
            old_hashes = set()
            pos = sgo_start
            while True:
                pos = mapped.find(hash_prefix, pos, sgo_end)
                if pos < 0:
                    break
                digest_pos = pos + len(hash_prefix)
                old_hashes.add(mapped[digest_pos:digest_pos + 64].decode("ascii"))
                pos = digest_pos + 64

            for number, path in enumerate(new_files, 1):
                if progress:
                    progress(number - 1, len(new_files), "New stock file only: " + path.name)
                item = fingerprint(path, root)
                item_path = item["path"]
                new_sources.append({"path": item_path, "size": item["size"],
                                    "mtime_ns": item["mtime_ns"]})
                counts[item.get("status", "unreadable")] += 1
                digest = item.get("sha256")
                if not digest:
                    continue
                if digest in new_by_hash:
                    new_by_hash[digest].setdefault("aliases", []).append(item_path)
                elif digest in old_hashes:
                    hash_position = mapped.find(hash_prefix + digest.encode("ascii"), sgo_start, sgo_end)
                    aliases_key = mapped.find(b'"aliases":[', hash_position, sgo_end)
                    if hash_position < 0 or aliases_key < 0:
                        raise ValueError("existing SGO hash entry is malformed; refusing to rewrite index")
                    aliases_start = aliases_key + len(b'"aliases":[')
                    aliases_end = mapped.find(b"]", aliases_start, sgo_end)
                    if aliases_end < 0:
                        raise ValueError("existing SGO aliases are malformed; refusing to rewrite index")
                    pending_aliases.setdefault(aliases_end, []).append(
                        (item_path, aliases_end > aliases_start))
                else:
                    item["aliases"] = []
                    new_records.append(item)
                    new_by_hash[digest] = item
                    old_hashes.add(digest)
                    unique_additions += 1

            if progress:
                progress(len(new_files), len(new_files), "Writing incremental index")
            sources.extend(new_sources)
            sources.sort(key=lambda item: item["path"].casefold())
            metadata["generated_utc"] = datetime.now(timezone.utc).isoformat()
            metadata["source_count"] = int(metadata.get("source_count", len(indexed_names))) + len(new_files)
            metadata["unique_sgo_count"] = int(metadata.get("unique_sgo_count", 0)) + unique_additions
            metadata["counts"] = dict(counts)
            metadata["incremental_new_count"] = len(new_files)
            metadata["incremental_skipped_count"] = len(files) - len(new_files)
            alias_insertions = []
            for position, values in pending_aliases.items():
                separator = b"," if values[0][1] else b""
                encoded = [json.dumps(name, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
                           for name, _ in values]
                alias_insertions.append((position, separator + b",".join(encoded)))

            with temporary.open("wb") as output:
                header = json.dumps(metadata, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
                output.write(header[:-1] + b',"sources":')
                output.write(json.dumps(sources, ensure_ascii=True, separators=(",", ":")).encode("utf-8"))
                output.write(b',"sgos":[')
                _copy_mapped_range(mapped, output, sgo_start, sgo_end, alias_insertions)
                for number, item in enumerate(new_records):
                    if sgo_end > sgo_start or number > 0:
                        output.write(b",")
                    output.write(json.dumps(item, ensure_ascii=True,
                                            separators=(",", ":")).encode("utf-8"))
                output.write(b"]}")
    replace_with_retry(temporary, target)
    metadata["sources"] = sources
    metadata["sgos"] = []  # Avoid returning the potentially large array.
    return metadata


def load_container(path):
    """Decode an FRF container or a bare ODX file."""
    import sgo_frf

    path = Path(path)
    if path.suffix.lower() == ".odx":
        return sgo_frf.load_odx(str(path))
    return sgo_frf.load(str(path))


def _get_pool(workers):
    """One process pool for the whole run: spawning costs ~0.5 s on Windows."""
    global _POOL
    if _POOL is None:
        _POOL = ProcessPoolExecutor(max_workers=workers)
        atexit.register(shutdown_pool)
    return _POOL


def shutdown_pool():
    global _POOL
    if _POOL is not None:
        try:
            _POOL.shutdown(wait=False)
        except Exception:
            pass
        _POOL = None


def _parallel_map(jobs, worker, workers=None, on_done=None):
    """Run decode jobs in subprocesses, falling back to serial on failure.

    Decoding a container is CPU- and zlib-bound (FRF unzip + ODX parse + LZSS),
    so one file at a time makes a 1000-file rescan look frozen. Windows spawn
    needs picklable arguments only; both workers below take plain strings.

    `on_done(done, total, result)` is called as each job finishes, so the caller
    can report progress while a batch is still running instead of only after
    all hundred results arrive (which made the window look frozen for a batch).

    The pool is cached across calls: `run_rescan` invokes this once per batch,
    and re-spawning workers each time doubled the total runtime.
    """
    if not jobs:
        return []
    global _POOL_NOTE
    workers = workers or min(os.cpu_count() or 1, 8)
    total = len(jobs)

    def serial():
        out = []
        for number, job in enumerate(jobs, 1):
            result = worker(job)
            out.append(result)
            if on_done:
                on_done(number, total, result)
        return out

    if workers <= 1:
        _POOL_NOTE = "serial (workers=1)"
        return serial()
    try:
        out = [None] * total
        pool = _get_pool(workers)
        futures = {pool.submit(worker, job): index
                   for index, job in enumerate(jobs)}
        done = 0
        pending_exc = None
        for future in as_completed(futures):
            index = futures[future]
            out[index] = future.result()
            done += 1
            if on_done:
                try:
                    on_done(done, total, out[index])
                except BaseException as exc:
                    # Cancellation from the caller must not be mistaken for a
                    # broken pool and retried serially.
                    pending_exc = exc
                    break
        if pending_exc is not None:
            shutdown_pool()
            raise pending_exc
        _POOL_NOTE = f"{workers} worker processes"
        return out
    except Exception as exc:
        if isinstance(exc, RuntimeError) and "cancelled" in str(exc):
            raise
        _POOL_NOTE = f"serial fallback ({type(exc).__name__}: {exc})"[:160]
        shutdown_pool()
        try:
            out = locals().get('out') or [None] * total
        except Exception:
            out = [None] * total
        finished = sum(1 for value in out if value is not None)
        for number, index in enumerate(
                (i for i, value in enumerate(out) if value is None), finished + 1):
            out[index] = worker(jobs[index])
            if on_done:
                on_done(number, total, out[index])
        return out


def pool_status():
    """Human-readable decode-parallelism state, for the GUI log."""
    return _POOL_NOTE


def _frf_entry_job(task):
    """Decode one FRF/ODX into a catalogue entry (runs in a worker process)."""
    from sgo_identity import flash_identity

    root, name = task
    path = Path(root) / name
    try:
        if not path.is_file() or path.stat().st_size == 0:
            return name, None
        members, image, _blocks, family = load_container(path)
        fresh = {"file": name, "family": family,
                 "size": path.stat().st_size,
                 "members": [[key, len(value)]
                             for key, value in sorted(members.items())]}
        if image:
            identity = flash_identity(image)
            fresh["parts"] = sorted({part for part in
                                     list(identity["sw"]) + list(identity["parts"])
                                     if part})
            window = cal_window(family) if family else None
            if window:
                lo, hi = window[0], min(window[1], len(image))
                if hi > lo:
                    fresh["cal_crc"] = "".join(
                        f"{zlib.crc32(image[offset:offset + 1024]):08x}"
                        for offset in range(lo, hi, 1024))
        fresh["decoder_rev"] = DECODER_REVISION
        return name, fresh
    except Exception as exc:
        return name, {"file": name, "family": "unreadable",
                      "reason": str(exc)[:120],
                      "decoder_rev": DECODER_REVISION}


def _frf_crc_job(task):
    """Compute 1 KiB CAL CRCs for one catalogue entry (worker process)."""
    root, name, family = task
    try:
        _members, image, _blocks, entry_family = load_container(Path(root) / name)
        # A decode that succeeded is a TCU image: newer CAL blocks carry only
        # their part number at 0xFE21, not the EV_TCM descriptor, so absence of
        # EV_TCM must not demote the entry to engine-ecu.
        window = cal_window(entry_family or family)
        if image and window:
            lo, hi = window[0], min(window[1], len(image))
            if hi > lo:
                return name, "".join(
                    f"{zlib.crc32(image[offset:offset + 1024]):08x}"
                    for offset in range(lo, hi, 1024)), None
        return name, "", None
    except Exception:
        return name, "", None


def _sgo_fingerprint_job(task):
    """Fingerprint one .sgo container (worker process)."""
    root, path = task
    return fingerprint(Path(path), Path(root))


def _extend_index_json(root, target, files, progress, limit=None):
    """Cumulative fingerprint update that keeps every other catalogue section.

    The streaming version assumed 'sgos' was the last key, which stopped being
    true once the FRF catalogue moved into the same file. This reads the JSON,
    adds only newly named .sgo files and writes it back atomically.
    """
    document = json.loads(target.read_text(encoding="utf-8"))
    sources = document.setdefault("sources", [])
    records = document.setdefault("sgos", [])
    indexed = {item.get("path", "").casefold() for item in sources}
    new_files = [path for path in files
                 if path.relative_to(root).as_posix().casefold() not in indexed]
    if limit:
        new_files = new_files[:limit]
    by_hash = {record.get("sha256"): record for record in records
               if record.get("sha256")}
    counts = Counter(document.get("counts", {}))
    unique_additions = 0
    added = 0
    processed = 0

    def persist():
        sources.sort(key=lambda item: item.get("path", "").casefold())
        document["generated_utc"] = datetime.now(timezone.utc).isoformat()
        document["source_count"] = len(sources)
        document["unique_sgo_count"] = len(records)
        document["counts"] = dict(counts)
        document["incremental_new_count"] = len(new_files)
        document["incremental_skipped_count"] = len(files) - len(new_files)
        _write_catalogue(document, target)

    try:
        for number, path in enumerate(new_files, 1):
            if progress:
                progress(number - 1, len(new_files), "New stock file only: " + path.name)
            item = fingerprint(path, root)
            sources.append({"path": item["path"], "size": item["size"],
                            "mtime_ns": item["mtime_ns"]})
            counts[item.get("status", "unreadable")] += 1
            processed += 1
            digest = item.get("sha256")
            if not digest:
                continue
            added += 1
            if digest in by_hash:
                aliases = by_hash[digest].setdefault("aliases", [])
                if item["path"] not in aliases:
                    aliases.append(item["path"])
            else:
                item["aliases"] = []
                records.append(item)
                by_hash[digest] = item
                unique_additions += 1
    except BaseException:
        # Cancel from progress: persist the containers fingerprinted so far, so
        # the next rescan resumes instead of restarting from zero.
        if processed:
            persist()
        raise
    persist()
    del document["sgos"][len(records):]  # keep the returned copy small
    return document


def extend_index(folder, output, progress=None, limit=None, files=None):
    """Cumulative update only: fingerprint newly named files, never rescan.

    Restore must use this so a lookup can add a new file but can never read the
    whole library again. A missing index is an error, not an invitation to scan.

    `files` lets a caller that already enumerated the library (run_rescan) pass
    the list in, instead of re-walking the folder for every batch.
    """
    root = Path(folder).resolve()
    target = Path(output)
    if not target.exists():
        raise ValueError("no SGO index to extend; create it explicitly first")
    if files is None:
        files = sorted((p for p in root.rglob("*") if indexable(p)),
                       key=lambda p: p.relative_to(root).as_posix().casefold())
    return _extend_index_json(root, target, files, progress, limit)


def frf_retryable(entry):
    """True for catalogue entries that failed only for lack of a decoder."""
    return (str(entry.get("family")) == "unreadable"
            and "decoder" in str(entry.get("reason", "")).casefold())


_PARTIAL_MARKERS = ("did not decrypt to a zip", "damaged zip", "truncated",
                    "zero-prefixed", "partial")


def partial_failure(entry):
    """True when the stored failure was a truncated/incomplete container.

    Such a file can be fixed by re-downloading it, so it is retried on every
    rescan even at the same decoder revision.
    """
    reason = str(entry.get("reason") or "").casefold()
    return any(marker in reason for marker in _PARTIAL_MARKERS)


def crc_pending(entry):
    """True when this entry still needs a decode attempt for its CAL CRCs.

    A failed decode stores an empty cal_crc; that marks the entry as attempted
    but must not mark it as final, or a decoder improvement would never reach
    containers that failed before it existed. Truncated containers are the
    exception: the bytes can change without the decoder changing, so they are
    retried at any revision (the rescan attempts each file only once per run).
    """
    if str(entry.get("family")) == "engine-ecu":
        return False
    if entry.get("cal_crc"):
        return False
    if partial_failure(entry):
        return True
    return entry.get("decoder_rev") != DECODER_REVISION


def extend_frf_catalogue(folder, output, names=None, progress=None):
    """Cumulatively add/refresh FRF entries in the saved index.

    Only the named files are decoded; existing entries are kept. A stale
    'unreadable' entry is retried once, so a decoder added later can claim it.
    """
    import sgo_frf

    root = Path(folder).resolve()
    target = Path(output)
    if not target.exists():
        raise ValueError("no SGO index to update; create it explicitly first")
    document = json.loads(target.read_text(encoding="utf-8"))
    entries = document.setdefault("frfs", [])
    by_name = {entry.get("file"): entry for entry in entries}
    if names is None:
        names = [p.name for p in root.glob("*")
                 if p.suffix.lower() in (".frf", ".odx")]

    todo = [name for name in sorted(set(names))
            if name not in by_name or frf_retryable(by_name[name])]
    if progress:
        progress(0, len(todo), f"decoding {len(todo)} containers")

    def decoded(number, total_jobs, result):
        # Report as each container finishes, not once per batch.
        if progress:
            progress(number, total_jobs, result[0] if result else "")

    results = _parallel_map([(str(root), name) for name in todo],
                            _frf_entry_job, on_done=decoded)
    merged = 0
    try:
        for name, fresh in results:
            if fresh is None:
                continue
            if name in by_name:
                by_name[name].clear()
                by_name[name].update(fresh)
            else:
                entries.append(fresh)
                by_name[name] = fresh
            merged += 1
    except BaseException:
        # Cancelled mid-merge: keep the entries already added.
        if merged:
            document["frf_count"] = len(entries)
            _write_catalogue(document, target)
        raise
    document["frf_count"] = len(entries)
    _write_catalogue(document, target)
    return document


def backfill_frf_crcs(folder, output, family=None, progress=None, limit=None,
                      skip=None):
    """Store 1 KiB CAL-block CRCs for catalogue entries that lack them.

    One decode per container, ever: afterwards ranking is CRC-only and no
    container is opened to decide similarity. `skip` names already attempted in
    this pass, so retried truncations cannot loop forever.

    Returns the names attempted.
    """
    import sgo_frf
    from frf_family import canonical

    root = Path(folder).resolve()
    target = Path(output)
    if not target.exists():
        raise ValueError("no SGO index to update; create it explicitly first")
    document = json.loads(target.read_text(encoding="utf-8"))
    entries = document.setdefault("frfs", [])
    todo = [entry for entry in entries
            if (family is None or canonical(entry.get("family")) == family)
            and (not skip or entry.get("file") not in skip)
            and crc_pending(entry)]
    if limit:
        todo = todo[:limit]
    # Cheap, non-decoding filters stay in this process; everything that needs a
    # container decode goes to worker processes.
    import sgo_frf

    jobs = []
    for entry in todo:
        # 906/907 in the part group is engine control, never a TCU donor, but
        # only when the part is not a gearbox part: 0DD906556AP is a DQ400e
        # TCU (SW 0DD300046S). Let the part table decide first.
        tokens = list(entry.get("parts", ())) + [entry.get("file", "")]
        if any(re.search(r"(?:906|907)[0-9]{3}", token.upper())
               and sgo_frf.family_for_part(token.upper()) is None
               for token in tokens if token):
            entry["family"] = "engine-ecu"
            entry["cal_crc"] = ""
            entry["decoder_rev"] = DECODER_REVISION
            continue
        jobs.append((str(root), entry.get("file", ""), entry.get("family")))
    if progress:
        progress(0, len(jobs), f"decoding {len(jobs)} CAL CRCs")
    results = _parallel_map(jobs, _frf_crc_job)
    by_name = {entry.get("file"): entry for entry in entries}
    merged = 0
    try:
        for number, (name, crc, override) in enumerate(results, 1):
            if progress:
                progress(number, len(jobs), name)
            entry = by_name.get(name)
            if entry is None:
                continue
            if override:
                entry["family"] = override
            entry["cal_crc"] = crc
            entry["decoder_rev"] = DECODER_REVISION
            merged += 1
    except BaseException:
        # Cancel (or any error) raised from progress: keep everything already
        # merged so a cancelled rescan never throws away completed decoding.
        if merged:
            _write_catalogue(document, target)
        raise
    _write_catalogue(document, target)
    return [entry.get("file") for entry in todo]


def sgo_crc_pending(entry):
    """True when a decoded SGO record can and should get CAL CRCs.

    Only decoders with a known calibration window qualify: for the legacy PQ
    profiles without one there is nothing to checksum against, so they are not
    queued for ever.
    """
    if entry.get("status") != "decoded":
        return False
    if entry.get("cal_crc"):
        return False
    if not cal_window(entry.get("decoder")):
        return False
    return entry.get("decoder_rev") != DECODER_REVISION


def _sgo_crc_job(task):
    """Decode one SGO and return its 1 KiB CAL-block CRCs (worker process)."""
    root, relative = task
    try:
        path = Path(root) / relative
        sgo = SGO(path).parse()
        profile, segments = decode(sgo, "auto")
        window = cal_window(profile)
        if not segments or not window:
            return relative, ""
        end = max(address + len(payload) for address, payload, _ in segments)
        image, _ = assemble(segments, end)
        lo, hi = window[0], min(window[1], len(image))
        if hi <= lo:
            return relative, ""
        return relative, "".join(
            f"{zlib.crc32(image[offset:offset + 1024]):08x}"
            for offset in range(lo, hi, 1024))
    except Exception:
        return relative, ""


def backfill_sgo_crcs(folder, output, progress=None, limit=None):
    """Store CAL CRCs for SGO records that have none yet.

    One decode per container, ever: once stored, an SGO donor can be ranked by
    calibration content exactly like an FRF and the decode stays out of the
    search path.
    """
    root = Path(folder).resolve()
    target = Path(output)
    if not target.exists():
        raise ValueError("no SGO index to update; create it explicitly first")
    document = json.loads(target.read_text(encoding="utf-8"))
    entries = document.setdefault("sgos", [])
    todo = [entry for entry in entries if sgo_crc_pending(entry)]
    if limit:
        todo = todo[:limit]
    if not todo:
        return 0
    jobs = [(str(root), entry.get("path", "")) for entry in todo]
    if progress:
        progress(0, len(jobs), f"decoding {len(jobs)} SGO CRCs")

    def done(number, total_jobs, result):
        if progress:
            progress(number, total_jobs, result[0] if result else "")

    results = _parallel_map(jobs, _sgo_crc_job, on_done=done)
    by_path = {entry.get("path"): entry for entry in entries}
    merged = 0
    try:
        for relative, crc in results:
            entry = by_path.get(relative)
            if entry is None:
                continue
            entry["cal_crc"] = crc
            entry["decoder_rev"] = DECODER_REVISION
            merged += 1
    except BaseException:
        if merged:
            _write_catalogue(document, target)
        raise
    _write_catalogue(document, target)
    return merged


def _walk_files(root):
    """Yield (path, entry) for every regular file, using os.scandir.

    pathlib.rglob plus per-entry is_file()/stat() costs ~0.2 s on 3,800 files;
    scandir with cached DirEntry metadata is ~20x cheaper and the rescan plan
    runs on every GUI refresh.
    """
    stack = [str(root)]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            yield Path(entry.path), entry
                    except OSError:
                        continue
        except OSError:
            continue


def rescan_plan(folder, output):
    """Count one Rescan folder pass as a single global work total.

    Newly named SGO files, FRFs the catalogue has not seen yet (or may retry
    now that a decoder exists) and catalogue entries still missing CAL CRCs
    add up to the folder's work units, so the GUI can show one counter that
    only ever moves forward instead of a 0..20 counter per batch.
    """
    root = Path(folder).resolve()
    target = Path(output)
    if not target.exists():
        raise ValueError("no SGO index to extend; create it explicitly first")
    document = json.loads(target.read_text(encoding="utf-8"))
    indexed = {item.get("path", "").casefold() for item in document.get("sources", ())}
    new_sgo = 0
    by_extension = Counter()
    files = 0
    supported = 0
    root_text = str(root)
    for path, entry in _walk_files(root):
        suffix = os.path.splitext(entry.name)[1].lower() or "(none)"
        if suffix not in SUPPORTED_SUFFIXES:
            continue
        files += 1
        by_extension[suffix] += 1
        if suffix != ".sgo":
            continue
        try:
            if entry.stat().st_size <= 0:
                continue
        except OSError:
            continue
        relative = os.path.relpath(entry.path, root_text)
        if relative.replace(os.sep, "/").casefold() not in indexed:
            new_sgo += 1
    entries = list(document.get("frfs", ()))
    by_name = {entry.get("file"): entry for entry in entries}
    new_frf = 0
    try:
        with os.scandir(root_text) as top:
            for entry in top:
                suffix = os.path.splitext(entry.name)[1].lower()
                if suffix not in (".frf", ".odx"):
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                if entry.stat().st_size == 0:
                    continue
                entry_record = by_name.get(entry.name)
                if entry_record is None or frf_retryable(entry_record):
                    new_frf += 1
    except OSError:
        pass
    missing_crc = sum(1 for entry in entries if crc_pending(entry))
    missing_crc += sum(1 for entry in document.get("sgos", ())
                       if sgo_crc_pending(entry))
    return {"new_sgo": new_sgo, "new_frf": new_frf, "missing_crc": missing_crc,
            "files": files,
            "by_extension": dict(sorted(by_extension.items(),
                                        key=lambda item: (-item[1], item[0]))),
            "total": new_sgo + new_frf + missing_crc}


def format_extension_counts(plan):
    """One-line library inventory: '3,793 files: 2,439 SGO, 1,255 FRF, ...'."""
    counts = plan.get("by_extension") or {}
    if not counts:
        return ""
    parts = [f"{count:,} {EXTENSION_LABELS.get(ext, ext.lstrip('.').upper())}"
             for ext, count in counts.items()]
    return f"{plan.get('files', sum(counts.values())):,} files: " + ", ".join(parts)


EXTENSION_LABELS = {".sgo": "SGO", ".frf": "FRF", ".sox": "SOX", ".odx": "ODX"}


def format_index_counts(document):
    """What the catalogue actually holds: '2,024 SGO, 1,222 FRF, 689 with CAL CRCs'."""
    sgos = document.get("sgos") or ()
    frfs = document.get("frfs") or ()
    crcs = sum(1 for entry in frfs if entry.get("cal_crc"))
    return (f"{len(sgos):,} SGO, {len(frfs):,} FRF, "
            f"{crcs:,} with CAL CRCs")

# VAG part/dataset prefixes name the gearbox, so the TCU can be labelled from
# what the catalogue already stores - no decode, and no EV_TCM string (which
# only FRF ODX metadata carries).
TCU_PREFIXES = (
    ("0DL", "DQ500 (0DL)"), ("0BH", "DQ500 (0BH)"), ("0BT", "DQ500 (0BT)"),
    ("0D9", "DQ250 (0D9)"), ("02E", "DQ250 (02E)"),
    ("0AM", "DQ200 (0AM)"), ("0CW", "DQ200 (0CW)"),
    ("0GC", "DQ381 (0GC)"), ("0CK", "DL382 (0CK)"), ("0B5", "DL501 (0B5)"),
    ("0C8", "AL1000 (0C8)"), ("0DD", "DQ400e (0DD)"),
    ("8R0", "ZF 8HP (8R0)"), ("4G0", "ZF 8HP (4G0)"), ("4H0", "ZF 8HP (4H0)"),
    ("8K0", "ZF 8HP (8K0)"), ("8W0", "ZF 8HP (8W0)"), ("0BK", "ZF 8HP (0BK)"),
    ("09G", "Aisin 6sp (09G)"), ("09K", "Aisin (09K)"), ("09M", "Aisin (09M)"),
    ("03G", "S tronic (03G)"),
)


def tcu_label(record):
    """Best TCU label from a catalogue record: dataset + part markings first."""
    text = " ".join([record.get("dataset", "")] + list(record.get("part_markings", ()))).upper()
    found = {name for prefix, name in TCU_PREFIXES if prefix in text}
    if found:
        return " / ".join(sorted(found))
    decoder = record.get("decoder") or ""
    return f"{decoder} (decoder)" if decoder else "unknown"


def label_tcus(folder, output):
    """Fill record["tcu"] for every SGO record; returns how many changed."""
    target = Path(output)
    if not target.exists():
        return 0
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    changed = 0
    for record in document.get("sgos", []):
        label = tcu_label(record)
        if record.get("tcu") != label:
            record["tcu"] = label
            changed += 1
    if changed:
        _write_catalogue(document, target)
    return changed


def format_library_mix(plan):
    """Every supported type with its count: '2,442 stock, 1,255 FRF, 51 SOX'."""
    counts = plan.get("by_extension") or {}
    parts = [f"{counts[ext]:,} {label}"
             for ext, label in EXTENSION_LABELS.items() if counts.get(ext)]
    return ", ".join(parts)


def _gearbox_job(task):
    """Decode one SGO and return the gearbox self-description in its payloads."""
    root, relative = task
    try:
        path = Path(root) / relative
        raw = path.read_bytes()
        sgo = SGO(path, raw)
        sgo.parse()
        _profile, segments = decode(sgo, "auto")
        text = "".join(payload.decode("latin1", "ignore")
                       for _address, payload, _label in segments)
        return relative, sorted({m.group(0).strip() for m in GEARBOX.finditer(text)})[:4]
    except Exception:
        return relative, []


def backfill_gearbox(folder, output, progress=None, limit=None):
    """Record the payload gearbox marker for SGOs that have none yet."""
    target = Path(output)
    if not target.exists():
        return 0
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    records = document.get("sgos", [])
    todo = [record for record in records if "gearbox" not in record]
    if limit:
        todo = todo[:limit]
    if not todo:
        return 0
    root = str(Path(folder).resolve())
    results = _parallel_map([(root, record["path"]) for record in todo], _gearbox_job)
    by_path = {record["path"]: record for record in records}
    for number, (relative, markers) in enumerate(results, 1):
        record = by_path.get(relative)
        if record is None:
            continue
        record["gearbox"] = markers
        if progress and (number % 8 == 0 or number == len(results)):
            progress(number, len(results), relative)
    _write_catalogue(document, target)
    return len(todo)


def prune_missing(folder, output):
    """Drop catalogue records whose file is gone; returns (sgo_removed, frf_removed).

    Sources, SGO records and FRF entries are cumulative by design (a restore may
    run without the library present), so deletion has to be handled explicitly.
    A record is kept only while the file it names still exists.
    """
    root = Path(folder)
    target = Path(output)
    if not target.exists():
        return 0, 0
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0, 0
    sources = document.get("sources", [])
    sgos = document.get("sgos", [])
    frfs = document.get("frfs", [])

    def present(relative):
        return bool(relative) and (root / relative).is_file()

    kept_sources = [item for item in sources if present(item.get("path", ""))]
    kept_paths = {item["path"].casefold() for item in kept_sources}
    kept_sgos = [record for record in sgos
                 if present(record.get("path", ""))
                 or any(alias.casefold() in kept_paths
                        for alias in record.get("aliases", ()))]
    kept_frfs = [entry for entry in frfs if present(entry.get("file", ""))]
    removed_sgo = len(sources) - len(kept_sources)
    removed_frf = len(frfs) - len(kept_frfs)
    if not removed_sgo and not removed_frf:
        return 0, 0
    document["sources"] = kept_sources
    document["sgos"] = kept_sgos
    document["frfs"] = kept_frfs
    document["source_count"] = len(kept_sources)
    document["unique_sgo_count"] = len(kept_sgos)
    document["frf_count"] = len(kept_frfs)
    document["counts"] = dict(Counter(record.get("status", "unknown")
                                      for record in kept_sgos))
    document["generated_utc"] = datetime.now(timezone.utc).isoformat()
    _write_catalogue(document, target)
    return removed_sgo, removed_frf


def run_rescan(folder, output, progress=None, batch=100, plan=None):
    """Rescan a folder in batches, reporting one folder-wide progress figure.

    `batch` is a checkpoint size, not display granularity: every batch rewrites
    the whole catalogue (json serialise + atomic replace, with retries while
    another process holds it), so batches of ten would cost hundreds of writes
    and look frozen between them. Progress is already reported per container
    through the passes' on_done callbacks.

    Each pass below (new SGOs, new FRFs, CAL CRCs) reports 0..batch for its own
    batch, which is useless as a progress display. This wrapper counts items
    and hands the caller (phase, done, total, name) spanning the whole folder:
    done never goes backwards, and total grows only when the CRC pass turns out
    to have more entries than the initial plan knew about.
    """
    root = Path(folder).resolve()
    target = Path(output)
    if plan is None:
        plan = rescan_plan(root, target)
    total = [plan["total"]]
    done = [0]

    def track(phase):
        def report(_local_done, _local_total, name):
            if not name.startswith("Writing"):
                done[0] += 1
            if progress:
                progress(phase, min(done[0], total[0]), total[0], name)
        return report

    # The index is cumulative: drop records whose file no longer exists before
    # the passes, so a deleted container cannot stay a phantom donor.
    removed_sgo, removed_frf = prune_missing(root, target)
    plan["removed_sgo"] = removed_sgo
    plan["removed_frf"] = removed_frf
    # Label every record with its TCU (derived from dataset/parts, no decode).
    plan["tcu_labelled"] = label_tcus(root, target)

    # Enumerate the library once; each batch used to re-walk the whole folder.
    sgo_files = sorted((p for p in root.rglob("*") if indexable(p)),
                       key=lambda p: p.relative_to(root).as_posix().casefold())
    while True:
        document = extend_index(root, target, track("SGO"), limit=batch,
                                files=sgo_files)
        if not document.get("incremental_new_count"):
            break
    names = sorted(p.name for p in root.glob("*")
                   if p.suffix.lower() in (".frf", ".odx")
                   and p.is_file() and p.stat().st_size > 0)
    pending = list(names)
    while pending:
        chunk, pending = pending[:batch], pending[batch:]
        extend_frf_catalogue(root, target, chunk, track("Adding"))
    # Newly added FRFs usually carry their CAL CRCs already; anything that
    # could not be decoded still needs a CRC pass, so widen the total once.
    document = json.loads(target.read_text(encoding="utf-8"))
    total[0] = done[0] + sum(1 for entry in document.get("frfs", ())
                            if crc_pending(entry))
    total[0] += sum(1 for entry in document.get("sgos", ())
                    if sgo_crc_pending(entry))
    attempted = set()
    while True:
        added = backfill_frf_crcs(root, target, None, track("CRC"), limit=batch,
                                  skip=attempted)
        if not added:
            break
        attempted.update(added)
    # SGO records get the same CAL CRCs, so both donor kinds rank alike.
    while True:
        added = backfill_sgo_crcs(root, target, track("CRC"), limit=batch)
        if added == 0:
            break
    # Finally record the payload gearbox marker ("GSG DSG AG7 DCT") for every
    # SGO that predates it; this needs a decode, so it is bounded per batch.
    document = json.loads(target.read_text(encoding="utf-8"))
    total[0] += sum(1 for record in document.get("sgos", ())
                    if "gearbox" not in record)
    while True:
        added = backfill_gearbox(root, target, track("TCU"), limit=batch)
        if added == 0:
            break
    return plan


def build_index(folder, output, progress=None):
    root = Path(folder).resolve()
    if not root.is_dir():
        raise ValueError("SGO index source folder does not exist")
    files = sorted((p for p in root.rglob("*") if indexable(p)),
                   key=lambda p: p.relative_to(root).as_posix().casefold())
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        return _extend_index(root, target, files, progress)

    records, by_hash, sources, counts = [], {}, [], Counter()
    for number, path in enumerate(files, 1):
        if progress:
            progress(number - 1, len(files), path.name)
        item = fingerprint(path, root)
        sources.append({"path": item["path"], "size": item["size"], "mtime_ns": item["mtime_ns"]})
        counts[item.get("status", "unreadable")] += 1
        digest = item.get("sha256")
        if not digest:
            continue
        prior = by_hash.get(digest)
        if prior is not None:
            prior.setdefault("aliases", []).append(item["path"])
        else:
            by_hash[digest] = item
            item["aliases"] = []
            records.append(item)
    if progress:
        progress(len(files), len(files), "Writing index")
    document = {"schema": INDEX_SCHEMA,
                "generated_utc": datetime.now(timezone.utc).isoformat(),
                "source_root": str(root), "chunk_size": CHUNK, "source_count": len(files),
                "unique_sgo_count": len(records), "counts": dict(counts),
                "incremental_new_count": len(files), "incremental_skipped_count": 0,
                "sources": sources, "sgos": records}
    temporary = temporary_path(target)
    temporary.write_text(json.dumps(document, ensure_ascii=True, separators=(",", ":")) + "\n",
                         encoding="utf-8")
    replace_with_retry(temporary, target)
    return document


def index_matches_folder(document, folder):
    root = Path(folder).resolve()
    if document.get("schema") != INDEX_SCHEMA or Path(document.get("source_root", "")).resolve() != root:
        return False
    current = {p.relative_to(root).as_posix().casefold()
               for p in root.rglob("*") if indexable(p)}
    indexed = {item.get("path", "").casefold() for item in document.get("sources", [])}
    # A known filename stays indexed even if its bytes or timestamp change. Only
    # a newly named file or a removed filename requires an index update; the
    # updater reuses all known records without opening their SGO contents.
    return current.issubset(indexed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", help="stock collection root")
    parser.add_argument("output", nargs="?", help="JSON path (default: catalogue.json inside the library folder)")
    parser.add_argument("--update-frfs", action="store_true",
                        help="only add/refresh FRF entries (family, parts, CAL CRCs) "
                             "in the existing index; incremental and resumable")
    args = parser.parse_args()
    if args.output:
        output = Path(args.output)
    else:
        output = Path(args.folder) / "catalogue.json"

    def progress(done, total, name):
        if total <= 10 or done % 25 == 0 or done == total:
            print(f"{done}/{total} {name}", flush=True)

    if args.update_frfs:
        root = Path(args.folder)
        names = sorted(p.name for p in root.glob("*")
                       if p.suffix.lower() in (".frf", ".odx")
                       if p.stat().st_size > 0)
        extend_frf_catalogue(root, output, names, progress)
        backfilled = backfill_frf_crcs(root, output, None, progress)
        document = json.loads(Path(output).read_text(encoding="utf-8"))
        crcs = sum(1 for entry in document.get("frfs", ()) if entry.get("cal_crc"))
        print(json.dumps({"index": str(Path(output).resolve()),
                          "frf_entries": len(document.get("frfs", ())),
                          "with_cal_crc": crcs,
                          "crc_backfilled_now": len(backfilled)}, indent=2))
        return

    document = build_index(args.folder, output, progress)
    print(json.dumps({"index": str(output.resolve()), "source_count": document["source_count"],
                      "unique_sgos": document["unique_sgo_count"], "counts": document["counts"]}, indent=2))


if __name__ == "__main__":
    main()
