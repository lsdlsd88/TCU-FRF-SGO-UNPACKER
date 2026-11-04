"""ctypes wrapper for sgo_fast.dll (hot loops), with graceful absence.

The DLL is optional: callers import this module and check `available()`, and
`sgo_frf` falls back to its pure-Python implementations when it is missing.
"""
import ctypes
import os
import sys
from pathlib import Path

_LIB = None
_TRIED = False


def _candidates():
    env = os.environ.get("SGO_FAST_DLL")
    if env:
        yield Path(env)
    here = Path(__file__).resolve().parent
    yield here / "sgo_fast.dll"
    bundle = getattr(sys, "_MEIPASS", None)
    if bundle:
        yield Path(bundle) / "sgo_fast.dll"
    yield Path.cwd() / "sgo_fast.dll"


def _configure(lib):
    lib.sgo_dsg_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                                    ctypes.c_char_p, ctypes.c_size_t]
    lib.sgo_dsg_decrypt.restype = None
    lib.sgo_lzss10.argtypes = [ctypes.c_char_p, ctypes.c_size_t,
                               ctypes.c_char_p, ctypes.c_size_t]
    lib.sgo_lzss10.restype = ctypes.c_long
    lib.sgo_lzz22.argtypes = [ctypes.c_char_p, ctypes.c_size_t,
                              ctypes.c_char_p, ctypes.c_size_t]
    lib.sgo_lzz22.restype = ctypes.c_long
    lib.sgo_table_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                                      ctypes.c_char_p, ctypes.c_size_t]
    lib.sgo_table_decrypt.restype = None
    lib.sgo_feedback.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                                 ctypes.c_char_p, ctypes.c_size_t]
    lib.sgo_feedback.restype = None


def load():
    """Load the DLL once; returns None when unavailable."""
    global _LIB, _TRIED
    if _TRIED:
        return _LIB[0] if _LIB else None
    _TRIED = True
    for path in _candidates():
        try:
            if not path.is_file():
                continue
            lib = ctypes.CDLL(str(path))
            _configure(lib)
            _LIB = (lib, str(path))
            break
        except (OSError, AttributeError):
            continue
    return _LIB[0] if _LIB else None


def available():
    return load() is not None


def path():
    load()
    return _LIB[1] if _LIB else None


def dsg_decrypt(key_bytes, data):
    lib = load()
    if lib is None:
        raise RuntimeError("sgo_fast.dll is not available")
    out = ctypes.create_string_buffer(len(data))
    lib.sgo_dsg_decrypt(bytes(key_bytes), bytes(data), out, len(data))
    return out.raw


def _decompress(name, data, size):
    lib = load()
    if lib is None:
        raise RuntimeError("sgo_fast.dll is not available")
    out = ctypes.create_string_buffer(size)
    produced = getattr(lib, name)(bytes(data), len(data), out, size)
    if produced < 0:
        raise ValueError(
            f"{name[4:]} stream corrupt: bad displacement (wrong key or garbage)")
    return out.raw[:produced]


def lzss10(data, uncompressed_size):
    return _decompress("sgo_lzss10", data, uncompressed_size)


def lzz22(data, uncompressed_size):
    return _decompress("sgo_lzz22", data, uncompressed_size)


def table_decrypt(table_bytes, data):
    """SGO format-1 PQ cipher (decrypt_table in sgo_unpack)."""
    lib = load()
    if lib is None:
        raise RuntimeError("sgo_fast.dll is not available")
    out = ctypes.create_string_buffer(len(data))
    lib.sgo_table_decrypt(bytes(table_bytes), bytes(data), out, len(data))
    return out.raw


def feedback(table_bytes, data):
    """Early 02EA byte-feedback cipher (decrypt_feedback in sgo_early)."""
    lib = load()
    if lib is None:
        raise RuntimeError("sgo_fast.dll is not available")
    out = ctypes.create_string_buffer(len(data))
    lib.sgo_feedback(bytes(table_bytes), bytes(data), out, len(data))
    return out.raw
