"""Small cross-platform advisory file lock for local-file persistence."""

from __future__ import annotations

import importlib
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import Lock, RLock, local

_registry_guard = Lock()
_thread_locks: dict[str, RLock] = {}
_depth = local()


@contextmanager
def file_lock(path: Path, *, timeout: float = 10.0) -> Iterator[None]:
    """Serialize read/modify/write transactions across threads and processes."""
    key = str(path.resolve()).casefold() if os.name == "nt" else str(path.resolve())
    with _registry_guard:
        guard = _thread_locks.setdefault(key, RLock())
    if not guard.acquire(timeout=timeout):
        raise TimeoutError("Timed out acquiring local storage lock")
    depths = getattr(_depth, "values", {})
    _depth.values = depths
    try:
        if depths.get(key, 0):
            depths[key] += 1
            try:
                yield
            finally:
                depths[key] -= 1
        else:
            with _process_file_lock(path, timeout=timeout):
                depths[key] = 1
                try:
                    yield
                finally:
                    depths.pop(key, None)
    finally:
        guard.release()


@contextmanager
def _process_file_lock(path: Path, *, timeout: float) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+b")
    try:
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        deadline = time.monotonic() + timeout
        while True:
            try:
                if os.name == "nt":
                    import msvcrt

                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    fcntl = importlib.import_module("fcntl")
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except (BlockingIOError, OSError) as exc:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"Timed out acquiring storage lock: {path}") from exc
                time.sleep(0.01)
        try:
            yield
        finally:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl = importlib.import_module("fcntl")
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()
