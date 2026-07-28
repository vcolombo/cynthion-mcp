"""Process- and host-wide ownership coordinator for Cynthion USB access."""
from __future__ import annotations

import fcntl
import os
import stat
import threading
from contextlib import contextmanager
from pathlib import Path

LOCK_DIR = Path.home() / ".cynthion-mcp"
LOCK_NAME = "hardware.lock"


class HardwareBusyError(RuntimeError):
    """A hardware operation conflicts with the active operation."""


class HardwareCoordinator:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._owner: str | None = None
        self._file_fd: int | None = None

    def _acquire_file_lock(self) -> int:
        LOCK_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = LOCK_DIR.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise HardwareBusyError("hardware lock directory is unsafe")
        directory_fd = os.open(LOCK_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fchmod(directory_fd, 0o700)
            file_fd = os.open(
                LOCK_NAME,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory_fd,
            )
        finally:
            os.close(directory_fd)
        try:
            os.fchmod(file_fd, 0o600)
            fcntl.flock(file_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return file_fd
        except (BlockingIOError, OSError) as exc:
            os.close(file_fd)
            raise HardwareBusyError("hardware is busy in another process") from exc

    def claim(self, owner: str) -> None:
        with self._lock:
            if self._owner is not None:
                raise HardwareBusyError(f"hardware is busy with {self._owner}")
            file_fd = self._acquire_file_lock()
            self._file_fd = file_fd
            self._owner = owner

    def release(self, owner: str) -> None:
        with self._lock:
            if self._owner != owner or self._file_fd is None:
                raise HardwareBusyError("hardware ownership mismatch")
            file_fd, self._file_fd = self._file_fd, None
            self._owner = None
            try:
                fcntl.flock(file_fd, fcntl.LOCK_UN)
            finally:
                os.close(file_fd)

    def assert_idle(self) -> None:
        with self._lock:
            if self._owner is not None:
                raise HardwareBusyError(f"hardware is busy with {self._owner}")

    @contextmanager
    def operation(self, owner: str):
        self.claim(owner)
        try:
            yield
        finally:
            self.release(owner)


HARDWARE_COORDINATOR = HardwareCoordinator()
