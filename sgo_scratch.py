"""Writable scratch directories.

tempfile.mkdtemp()/TemporaryDirectory() create the directory with mode 0700.
On hosts that map a POSIX mode onto a Windows DACL (the development sandbox
does), a 0700 directory can end up unreadable to the very process that made
it: stat succeeds, but listdir/open for write return ERROR_ACCESS_DENIED.
Creating the directory ourselves and widening only when 0700 is unusable keeps
the normal 0700 behaviour everywhere else.
"""
import contextlib
import shutil
import tempfile
import uuid
from pathlib import Path


def scratch_dir(prefix="sgo_"):
    base = Path(tempfile.gettempdir())
    error = None
    for mode in (0o700, 0o777):
        path = base / f"{prefix}{uuid.uuid4().hex[:10]}"
        path.mkdir(mode=mode)
        try:
            probe = path / ".probe"
            probe.write_bytes(b"")
            probe.unlink()
            return path
        except OSError as exc:
            error = exc
            shutil.rmtree(path, ignore_errors=True)
    raise OSError(f"no writable scratch directory in {base}: {error}")


@contextlib.contextmanager
def scratch(prefix="sgo_"):
    """Scratch directory that is removed on exit, like TemporaryDirectory."""
    path = scratch_dir(prefix)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
