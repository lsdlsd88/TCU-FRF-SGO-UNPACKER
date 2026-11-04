"""Extract readable identifiers from flash bytes without filename guesses."""

import re
from itertools import chain


DATASET = re.compile(
    r"v[0-9a-z]{6,24}_+getriebe_[0-9a-z_]+(?: +[EF][0-9]{2}[a-z0-9]*)?", re.I)
PART = re.compile(
    r"(?<![A-Z0-9])([0-9A-Z]{3})(300|906|907|927)([0-9]{3})([A-Z0-9]{0,3})(?![A-Z0-9])",
    re.I)
# Some early headers put two revision digits directly before the part number.
DSG_PART = re.compile(r"(?:02E|0AM|0CW|0D9|0GC|0DL)(?:300|927)[0-9]{3}[A-Z]{0,3}", re.I)
TAGGED = re.compile(
    r"(?<![A-Z0-9])(?P<label>HW|HARDWARE|SW|SOFTWARE)"
    r"(?:[ _-]*(?:NO|NR|NUMBER|PART))?\s*[:=]\s*"
    r"(?P<value>[A-Z0-9][A-Z0-9._/-]{2,30})", re.I)
REVISION = re.compile(
    r"(?<![A-Z0-9])(?:SW[ _-]*(?:VER(?:SION)?|REV)|SOFTWARE[ _-]*VERSION)"
    r"\s*[:=]\s*([A-Z0-9][A-Z0-9._/-]{1,20})", re.I)
# Dataset-style marking: PART_VERSION_CODE, e.g. 0D9300041T_4514_OlJB.
DSG_DATASET = re.compile(
    r"(?<![A-Z])([0-9A-Z]{3}(?:300|906|907|927)[0-9]{3}[A-Z0-9]{0,3})"
    r"_([0-9]{3,5})_([A-Za-z0-9]{2,8})(?![A-Z0-9])", re.I)


def flash_identity(data):
    """Return identifiers observed in ASCII or UTF-16 strings in this buffer.

    Multiple markings are retained: a boot/default HW marking need not be the
    same as the installed HW. Unclassified part numbers stay in 'parts'.
    """
    data = bytes(data)
    result = {key: [] for key in
              ("hw", "sw", "version", "getriebe", "dataset", "ecu", "component", "maker", "parts")}

    def add(key, value):
        value = " ".join(value.split()).strip(" _")
        if value and value.casefold() not in {old.casefold() for old in result[key]}:
            result[key].append(value)

    strings = (match.group().decode("ascii")
               for match in re.finditer(rb"[\x20-\x7e]{4,}", data))
    wide_strings = (
        match.group().decode(encoding)
        for pattern, encoding in ((rb"(?:[\x20-\x7e]\x00){4,}", "utf-16-le"),
                                  (rb"(?:\x00[\x20-\x7e]){4,}", "utf-16-be"))
        for match in re.finditer(pattern, data))
    for text in chain(strings, wide_strings):
        for match in TAGGED.finditer(text):
            key = "hw" if match["label"].upper() in ("HW", "HARDWARE") else "sw"
            add(key, match["value"])
        for match in REVISION.finditer(text):
            add("version", match[1])
        for match in DATASET.finditer(text):
            dataset = match.group()
            add("dataset", dataset)
            getriebe = re.split(r"getriebe_", dataset, flags=re.I)[1].split()[0]
            getriebe = re.sub(r"_(?:sw|par)(?:_pfl)?$", "", getriebe, flags=re.I)
            add("getriebe", getriebe.replace("_", " "))
            revision = re.search(r" +([EF][0-9]{2}[a-z0-9]*)$", dataset, re.I)
            if revision:
                add("version", revision[1])
            if re.search(r"02e[ac]_", dataset, re.I):
                add("ecu", "DQ250")
            elif re.search(r"0am_", dataset, re.I):
                add("ecu", "DQ200")
        for match in DSG_DATASET.finditer(text):
            add("dataset", match.group())
            add("version", match[2])
        parts = [match.group().upper() for match in PART.finditer(text)]
        parts.extend(match.group().upper() for match in DSG_PART.finditer(text))
        for part in parts:
            if re.fullmatch(r"(?:02E|0AM|0CW|0D9|0GC|0DL)927770[A-Z]{0,3}", part):
                add("hw", part)
            elif part[3:6] in ("300", "906", "907"):
                add("sw", part)
            else:
                add("parts", part)
        for match in re.finditer(r"(?<![A-Z])(?:DQ[0-9]{3}(?:MQB)?|EV_TCM[A-Z0-9_]{3,32})(?![A-Z0-9_])", text, re.I):
            add("ecu", match.group())
        for match in re.finditer(r"\bGSG +DSG(?: +AG[0-9]+)? +DCT", text, re.I):
            add("component", match.group())
        for match in re.finditer(r"\b(?:Temic|Bosch|Siemens|Continental)\b", text, re.I):
            add("maker", match.group())
    # Do not repeat a tagged or classified part as an unclassified marking.
    classified = {value.casefold() for key in ("hw", "sw") for value in result[key]}
    result["parts"] = [value for value in result["parts"] if value.casefold() not in classified]
    return result


def identity_text(identity):
    def values(key):
        items = identity[key]
        text = " / ".join(items[:3]) or "—"
        return text + (f" (+{len(items) - 3})" if len(items) > 3 else "")

    lines = [f"HW: {values('hw')}    SW: {values('sw')}",
             f"Getriebe: {values('getriebe')}"]
    if identity["version"]:
        lines.append("SW-Version: " + values("version"))
    details = [("ECU", "ecu"), ("Component", "component"), ("Maker", "maker"), ("Part", "parts")]
    found = [f"{label}: {values(key)}" for label, key in details if identity[key]]
    if found:
        lines.append("    ".join(found))
    if identity["dataset"]:
        lines.append("Dataset: " + values("dataset"))
    return "\n".join(lines)
