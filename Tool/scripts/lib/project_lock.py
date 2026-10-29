"""Shared project transaction lock and portable, verified file storage.

The persistent lock file is intentional: unlinking it can split concurrent
writers onto different inodes. OS locks are released automatically on exit.
"""
from __future__ import annotations

import contextlib
import functools
import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
from pathlib import Path, PurePosixPath

_LOCKS: dict[str, threading.RLock] = {}
_GUARD = threading.Lock()
_HELD = threading.local()


def project_file(root: Path, relative: str) -> Path:
    text = str(relative).replace('\\', '/')
    ref = PurePosixPath(text)
    if not text or ref.is_absolute() or '..' in ref.parts or ':' in text:
        raise ValueError('project-relative file required: %s' % relative)
    path = root / ref
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('file escapes project: %s' % relative)
    return path


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def verify_file(root: Path, record: dict) -> Path:
    path = project_file(root, record.get('local_path', ''))
    if not record.get('sha256') or not isinstance(record.get('size'), int):
        raise ValueError('missing file fingerprint: %s' % path)
    if not path.is_file():
        raise FileNotFoundError('missing local file: %s' % path)
    if path.stat().st_size != record['size'] or digest(path) != record['sha256']:
        raise ValueError('local file fingerprint mismatch: %s' % path)
    return path


def atomic_copy(source: Path, destination: Path, sha256: str, size: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.seep-copy-', dir=destination.parent)
    try:
        with os.fdopen(fd, 'wb') as output, source.open('rb') as stream:
            shutil.copyfileobj(stream, output)
            output.flush()
            os.fsync(output.fileno())
        temporary = Path(name)
        if temporary.stat().st_size != size or digest(temporary) != sha256:
            raise ValueError('source changed during copy')
        os.replace(name, destination)
    finally:
        if os.path.exists(name):
            os.unlink(name)


@contextlib.contextmanager
def project_lock(root: Path, timeout: float = 20, *, recover: bool = False):
    root = root.resolve()
    key = os.path.normcase(str(root))
    with _GUARD:
        mutex = _LOCKS.setdefault(key, threading.RLock())
    deadline = time.monotonic() + timeout
    if not mutex.acquire(timeout=timeout):
        raise TimeoutError('project thread transaction lock timed out')
    try:
        held = getattr(_HELD, 'roots', None)
        if held is None:
            held = _HELD.roots = set()
        if key in held:
            # Only this thread can reuse its existing OS lock. Other threads
            # still wait on the RLock, and other processes wait on the file.
            yield
            return
        root.mkdir(parents=True, exist_ok=True)
        # a+b avoids truncation and supplies byte zero for Windows range locking.
        lock_path = project_file(root, '.project.lock')
        if lock_path.is_symlink():
            raise ValueError('project lock path invalid')
        with lock_path.open('a+b') as stream:
            stream.seek(0, os.SEEK_END)
            if not stream.tell():
                stream.write(b'\0')
                stream.flush()
            acquired = False
            while not acquired:
                try:
                    stream.seek(0)
                    if os.name == 'nt':
                        import msvcrt
                        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError('project transaction lock timed out')
                    time.sleep(0.05)
            held.add(key)
            try:
                journal = root / ".project-transaction.json"
                if journal.exists() or journal.is_symlink():
                    if not recover:
                        raise ValueError("interrupted project transaction; retry the interrupted command, or report generate/register, to recover")
                    from .project_transaction import recover as restore_transaction
                    restore_transaction(root)
                yield
            finally:
                held.remove(key)
                stream.seek(0)
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    finally:
        mutex.release()


def project_locked(argument: str, *, recover: bool = False):
    def decorate(function):
        @functools.wraps(function)
        def invoke(args):
            try:
                with project_lock(Path(getattr(args, argument)), recover=recover):
                    return function(args)
            except Exception as exc:
                print(json.dumps({'ok': False, 'blocked_at': function.__name__,
                                  'reason': '%s: %s' % (type(exc).__name__, exc)},
                                 ensure_ascii=False))
                return 2
        return invoke
    return decorate
