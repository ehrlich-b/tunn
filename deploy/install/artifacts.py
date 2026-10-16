#!/usr/bin/env python3
"""Offline, per-user artifact selection. Never calls a service manager or downloads."""

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile


HELP_MARKER = (
    b"Start\n  tunn login                          Sign in\n\n"
    b"Choose who gets in\n"
)


def regular(path, private=False):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"require a regular non-symlink file: {path}")
    if private and os.name != "nt" and stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError(f"require mode 0600: {path}")
    return path


def directory(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f"refusing symlink directory: {path}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir():
        raise ValueError(f"require directory: {path}")
    return path


def digest(path):
    with regular(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else _digest(stream)


def _digest(stream):
    result = hashlib.sha256()
    for chunk in iter(lambda: stream.read(65536), b""):
        result.update(chunk)
    return result.hexdigest()


def atomic_write(path, data, mode=0o600):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=".tunn-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def sync_directory(path):
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def write_json(path, data):
    atomic_write(path, (json.dumps(data, sort_keys=True, indent=2) + "\n").encode())


def read_json(path):
    return json.loads(regular(path, private=True).read_text())


def state(value):
    if not isinstance(value, dict) or set(value) != {"version", "current", "previous"} or type(value["version"]) is not int or value["version"] != 1:
        raise ValueError("unsupported installation state schema; require version 1")
    for key in ("current", "previous"):
        if value[key] is not None and (not isinstance(value[key], str) or not re.fullmatch(r"[0-9a-f]{64}", value[key])):
            raise ValueError("invalid artifact digest in installation state")
    return value


class Installation:
    def __init__(self, root, create=False):
        self.root = Path(root)
        if not self.root.is_absolute() or self.root == Path(self.root.anchor):
            raise ValueError("supply an absolute, dedicated installation root")
        # No alias may silently redirect an explicit installation root.
        if any(p.is_symlink() for p in (self.root, *self.root.parents)):
            raise ValueError("installation root must not traverse symlinks")
        self.marker = self.root / "install.json"
        self.pending = self.root / "pending.json"
        self.binary = self.root / "bin" / ("tunn.exe" if os.name == "nt" else "tunn")
        if create and not self.marker.exists():
            directory(self.root)
            if any(self.root.iterdir()):
                raise ValueError("refusing to adopt a nonempty unmarked installation root")
            # Exclusive creation prevents two first installs from replacing state.
            with self.marker.open("xb") as stream:
                os.chmod(self.marker, 0o600)
                stream.write(b'{"version":1,"current":null,"previous":null}\n')
                stream.flush()
                os.fsync(stream.fileno())
            sync_directory(self.root)

    @contextmanager
    def locked(self):
        state(read_json(self.marker))
        lock_path = self.root / ".lock"
        if lock_path.exists() or lock_path.is_symlink():
            regular(lock_path, private=True)
        with lock_path.open("a+b") as lock:
            os.chmod(lock_path, 0o600)
            if os.name == "nt":
                import msvcrt
                if lock.seek(0, 2) == 0:
                    lock.write(b"0")
                    lock.flush()
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                yield
            finally:
                if os.name == "nt":
                    lock.seek(0)
                    msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)

    def release(self, checksum):
        path = self.root / "releases" / checksum / self.binary.name
        if digest(path) != checksum:
            raise ValueError("retained artifact checksum changed; selection refused")
        return path

    def inspect(self):
        current = state(read_json(self.marker))
        if self.pending.exists():
            raise ValueError("interrupted selection; run reconcile before any further change")
        if current["current"] is None:
            if self.binary.exists() or self.binary.is_symlink():
                raise ValueError("untracked selected binary; refusing to overwrite it")
        elif digest(self.binary) != current["current"]:
            raise ValueError("selected binary differs from installation state")
        return current

    def select(self, checksum):
        directory(self.binary.parent)
        if checksum is None:
            if self.binary.exists() or self.binary.is_symlink():
                regular(self.binary)
                self.binary.unlink()
                sync_directory(self.binary.parent)
        else:
            source = self.release(checksum)
            if self.binary.exists() or self.binary.is_symlink():
                if digest(self.binary) == checksum:
                    return  # Don't replace a still-running Windows binary with itself.
            # Copy/rename rather than symlink: works without Windows symlink privileges.
            fd, temporary = tempfile.mkstemp(prefix=".tunn-", dir=self.binary.parent)
            try:
                with os.fdopen(fd, "wb") as stream, source.open("rb") as original:
                    shutil.copyfileobj(original, stream)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(temporary, 0o755)
                if digest(temporary) != checksum:
                    raise ValueError("artifact changed during selection")
                os.replace(temporary, self.binary)
                sync_directory(self.binary.parent)
            finally:
                Path(temporary).unlink(missing_ok=True)

    def transition(self, old, new, checkpoint=lambda _: None):
        write_json(self.pending, {"version": 1, "old": old, "new": new})
        try:
            checkpoint("journal")
            self.select(new["current"])
            checkpoint("selection")
            write_json(self.marker, new)
            checkpoint("state")
            self.pending.unlink()
            sync_directory(self.root)
        except Exception:
            # Ordinary failures restore the last committed selection. A killed
            # process leaves a durable journal for the explicit reconcile action.
            self.reconcile()
            raise

    def reconcile(self):
        if not self.pending.exists():
            return self.inspect()
        journal = read_json(self.pending)
        if not isinstance(journal, dict) or set(journal) != {"version", "old", "new"} or type(journal["version"]) is not int or journal["version"] != 1:
            raise ValueError("unsupported pending selection schema")
        old, new = state(journal["old"]), state(journal["new"])
        if state(read_json(self.marker)) not in (old, new):
            raise ValueError("journal does not match committed state")
        # Always return to the last committed artifact; no guessed completion.
        self.select(old["current"])
        write_json(self.marker, old)
        self.pending.unlink()
        sync_directory(self.root)
        return self.inspect()

    def install(self, source, checksum, checkpoint=lambda _: None):
        old = self.inspect()
        if not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise ValueError("supply the independently trusted SHA-256 digest")
        destination = directory(directory(self.root / "releases") / checksum) / self.binary.name
        if not destination.exists():
            regular(source)
            fd, temporary = tempfile.mkstemp(prefix=".candidate-", suffix=".exe" if os.name == "nt" else "", dir=destination.parent)
            try:
                with os.fdopen(fd, "wb") as stream, Path(source).open("rb") as original:
                    shutil.copyfileobj(original, stream)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(temporary, 0o755)
                if digest(temporary) != checksum:
                    raise ValueError("candidate checksum mismatch; prior selection retained")
                with tempfile.TemporaryFile(dir=self.root) as output:
                    result = subprocess.run([temporary, "--help"], stdin=subprocess.DEVNULL,
                                            stdout=output, stderr=output, timeout=10, cwd=self.root)
                    output.seek(0)
                    help_text = output.read(65536)
                if result.returncode != 0 or HELP_MARKER not in help_text:
                    raise ValueError("candidate is not a runnable tunn CLI; prior selection retained")
                os.chmod(temporary, 0o555)
                os.replace(temporary, destination)
                sync_directory(destination.parent)
            finally:
                if Path(temporary).exists():
                    os.chmod(temporary, 0o600)  # Clear Windows read-only before cleanup.
                Path(temporary).unlink(missing_ok=True)
        self.release(checksum)
        if old["current"] == checksum:
            return old
        new = {"version": 1, "current": checksum, "previous": old["current"]}
        self.transition(old, new, checkpoint)
        return self.inspect()

    def rollback(self):
        old = self.inspect()
        if old["previous"] is None:
            raise ValueError("no previous artifact; rollback refused")
        self.transition(old, {"version": 1, "current": old["previous"], "previous": old["current"]})
        return self.inspect()

    def remove(self):
        old = self.inspect()
        if old["current"] is not None:
            self.transition(old, {"version": 1, "current": None, "previous": old["current"]})
        return self.inspect()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "status", "reconcile", "rollback", "remove"))
    parser.add_argument("--root", required=True)
    parser.add_argument("--binary")
    parser.add_argument("--sha256")
    args = parser.parse_args()
    if args.action == "install" and (not args.binary or not args.sha256):
        parser.error("install requires --binary and --sha256; nothing is downloaded")
    installation = Installation(args.root, create=args.action == "install")
    if args.action in ("status", "remove") and not installation.root.exists():
        print("Selection absent; all config, credentials, databases and reserved names retained.")
        return
    with installation.locked():
        if args.action == "install":
            result = installation.install(args.binary, args.sha256)
        elif args.action == "status":
            result = installation.inspect()
        else:
            result = getattr(installation, args.action)()
    print(json.dumps(result, sort_keys=True))
    print("Config, credentials, databases and reserved names retained. Service managers were not called.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"install: {error}", file=sys.stderr)
        sys.exit(1)
