"""Write a set of fixed-name output files inside one directory, all-or-nothing as far as possible.

Every target is checked (and every text encoded) before anything is written, so a planted symlink
at the second name or an unencodable string cannot leave the first file half-replaced. Each file is
written to a temporary name in the same directory and moved into place with ``os.replace``.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path


class UnsafeOutputError(RuntimeError):
    """An output target is unsafe to write, or the content cannot be encoded."""


def check_out_dir(out_dir: Path) -> None:
    if out_dir.is_symlink() or (out_dir.exists() and not out_dir.is_dir()):
        raise UnsafeOutputError(f"output path {out_dir} exists and is not a directory")


def write_files(
    out_dir: Path, files: dict[str, str], protected: tuple[Path, ...] = ()
) -> list[Path]:
    """Write ``{file name: text}`` as UTF-8 directly inside ``out_dir``; return the paths written.

    Refuses symlinks and non-regular files at any target, and any target that is one of the
    ``protected`` files (for example the input being enriched).
    """
    check_out_dir(out_dir)
    encoded: dict[Path, bytes] = {}
    protected_resolved = {p.resolve() for p in protected}
    for name, text in files.items():
        target = out_dir / name
        if target.is_symlink():
            raise UnsafeOutputError(f"refusing to write through symlink {target}")
        if target.exists() and not target.is_file():
            raise UnsafeOutputError(f"{target} exists and is not a regular file")
        if target.resolve() in protected_resolved:
            raise UnsafeOutputError(f"refusing to overwrite the input file {target}")
        try:
            encoded[target] = text.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise UnsafeOutputError(
                f"cannot write {name}: the content has a character that is not valid UTF-8 "
                "(for example an unpaired surrogate escape)"
            ) from exc
    out_dir.mkdir(parents=True, exist_ok=True)
    umask = os.umask(0)
    os.umask(umask)
    written = []
    for target, data in encoded.items():
        handle, temp_name = tempfile.mkstemp(dir=out_dir, prefix=f".{target.name}.", suffix=".tmp")
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(data)
            os.chmod(temp_name, 0o666 & ~umask)  # mkstemp creates 0600; match a normal write
            os.replace(temp_name, target)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(temp_name)
            raise
        written.append(target)
    return written
