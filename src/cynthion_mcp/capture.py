"""Sniffer-mode capture lifecycle with descriptor-relative private storage."""
from __future__ import annotations

import hashlib
import logging
import os
import re
import stat
import subprocess
import threading
import time
import uuid
import fcntl
from contextlib import contextmanager
from itertools import islice
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Literal

import usb.core
import usb.util

from .coordinator import HARDWARE_COORDINATOR

log = logging.getLogger(__name__)
ANALYZER_VID, ANALYZER_PID = 0x1D50, 0x615B
BULK_ENDPOINT_ADDR, VENDOR_IFACE = 0x81, 0
CAPTURES_DIR = Path.home() / ".cynthion-mcp" / "captures"
CAPTURE_ID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$")
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_CAPTURE_SECONDS = 300
MAX_RAW_READ_BYTES = 64 * 1024
MAX_STORED_CAPTURES = 100
MAX_STORED_BYTES = 512 * 1024 * 1024
MAX_LIST_CAPTURES = 100
MAX_DIRECTORY_SCAN = 1_000
ID_RESERVATION_ATTEMPTS = 16
STORAGE_LOCK_NAME = ".storage.lock"
STARTUP_TIMEOUT_SECONDS = 5.0
STOP_TIMEOUT_SECONDS = 5.0
MAX_WAIT_SECONDS = 90.0


class CaptureError(RuntimeError):
    def __init__(self, code: str, message: str, next_action: str, recoverable: bool = True):
        super().__init__(message)
        self.code = code
        self.message = message
        self.next_action = next_action
        self.recoverable = recoverable

    def payload(self, tool: str) -> dict:
        return {
            "ok": False,
            "tool": tool,
            "error": self.code,
            "message": self.message,
            "recoverable": self.recoverable,
            "next_action": self.next_action,
        }


class VendorRequest(IntEnum):
    GET_STATE = 0
    SET_STATE = 1


class CaptureSpeed(IntEnum):
    HIGH, FULL, LOW, AUTO = 0, 1, 2, 3


SPEED_NAMES = {"auto": CaptureSpeed.AUTO, "high": CaptureSpeed.HIGH,
               "full": CaptureSpeed.FULL, "low": CaptureSpeed.LOW}


@dataclass
class CaptureSession:
    id: str
    speed: str
    started_at: float
    path: Path
    _partial_name: str = field(repr=False)
    _reservation_inode: int = field(repr=False)
    _reservation_device: int = field(repr=False)
    _started_monotonic: float = field(repr=False)
    _reservation_fd: int | None = field(default=None, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)
    _stop_flag: threading.Event = field(default_factory=threading.Event, repr=False)
    _ready: threading.Event = field(default_factory=threading.Event, repr=False)
    _dev: Any = field(default=None, repr=False)
    bytes_written: int = 0
    finished_at: float | None = None
    error: str | None = None
    error_code: str | None = None
    next_action: str | None = None
    recoverable: bool | None = None
    cleanup_confirmed: bool = False
    _ownership_released: bool = field(default=False, repr=False)
    _cleanup_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


_active: CaptureSession | None = None
_last_session: CaptureSession | None = None
_lock = threading.RLock()
_root_lock = threading.Lock()
_capture_root_identity: tuple[int, int] | None = None


def packetry_running() -> bool:
    for name in ("Packetry", "packetry"):
        try:
            result = subprocess.run(
                ["/usr/bin/pgrep", "-x", name],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"},
                timeout=1,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return True
        if result.returncode != 1:
            return True
    return False


def _set_session_error(
    session: CaptureSession,
    code: str,
    message: str,
    next_action: str,
    recoverable: bool = True,
) -> None:
    if session.error is None:
        session.error = message
        session.error_code = code
        session.next_action = next_action
        session.recoverable = recoverable


def _ensure_capture_dir() -> None:
    global _capture_root_identity
    state_dir = CAPTURES_DIR.parent
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    for directory in (state_dir, CAPTURES_DIR):
        if directory == CAPTURES_DIR and not directory.exists():
            directory.mkdir(mode=0o700)
        info = directory.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError("capture storage is unsafe")
        directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(directory_fd)
            if directory == CAPTURES_DIR:
                identity = (opened.st_dev, opened.st_ino)
                with _root_lock:
                    if _capture_root_identity is None:
                        _capture_root_identity = identity
                    elif _capture_root_identity != identity:
                        raise RuntimeError("capture storage identity changed")
            os.fchmod(directory_fd, 0o700)
        finally:
            os.close(directory_fd)


def _dirfd() -> int:
    _ensure_capture_dir()
    directory_fd = os.open(CAPTURES_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    opened = os.fstat(directory_fd)
    if _capture_root_identity != (opened.st_dev, opened.st_ino):
        os.close(directory_fd)
        raise RuntimeError("capture storage identity changed")
    return directory_fd


def _validate_id(capture_id: str) -> str:
    if not isinstance(capture_id, str) or not CAPTURE_ID_RE.fullmatch(capture_id):
        raise ValueError("invalid capture id")
    return capture_id


def _capture_path(capture_id: str, suffix: str) -> Path:
    _validate_id(capture_id)
    _ensure_capture_dir()
    return CAPTURES_DIR / f"{capture_id}{suffix}"


def _entry_regular(directory_fd: int, name: str) -> os.stat_result:
    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise FileNotFoundError("capture unavailable")
    return info


def open_capture_fd(capture_id: str, suffix: str = ".bin") -> tuple[int, os.stat_result]:
    name = f"{_validate_id(capture_id)}{suffix}"
    directory_fd = _dirfd()
    try:
        expected = _entry_regular(directory_fd, name)
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
    except OSError as exc:
        raise FileNotFoundError("capture unavailable") from exc
    finally:
        os.close(directory_fd)
    try:
        actual = os.fstat(fd)
        if not stat.S_ISREG(actual.st_mode) or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            raise FileNotFoundError("capture changed while opening")
        return fd, actual
    except Exception:
        os.close(fd)
        raise


def _capture_record(name: str) -> str:
    for suffix in (".pcap.json", ".partial", ".bin", ".pcap"):
        if name.endswith(suffix) and CAPTURE_ID_RE.fullmatch(name.removesuffix(suffix)):
            return name.removesuffix(suffix)
    parts = name.split(".")
    if (
        len(parts) == 6
        and not parts[0]
        and CAPTURE_ID_RE.fullmatch(parts[1])
        and parts[2] == "pcap"
        and parts[3].isdigit()
        and re.fullmatch(r"[0-9a-f]{32}", parts[4])
        and parts[5] == "partial"
    ):
        return parts[1]
    return name


def _stored_usage(directory_fd: int) -> tuple[int, int]:
    records: set[str] = set()
    total = 0
    for entry in os.scandir(directory_fd):
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        if entry.name == STORAGE_LOCK_NAME or not stat.S_ISREG(info.st_mode):
            continue
        records.add(_capture_record(entry.name))
        total += max(MAX_CAPTURE_BYTES, info.st_size) if entry.name.endswith(".partial") else info.st_size
    return len(records), total


@contextmanager
def storage_lock():
    """Serialize storage accounting and publication across processes."""
    directory_fd = _dirfd()
    lock_fd = None
    try:
        lock_fd = os.open(
            STORAGE_LOCK_NAME,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        os.fchmod(lock_fd, 0o600)
    finally:
        os.close(directory_fd)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def require_storage_capacity(additional_entries: int, additional_bytes: int, replacing: tuple[str, ...] = ()) -> None:
    directory_fd = _dirfd()
    try:
        count, total = _stored_usage(directory_fd)
        for name in replacing:
            try:
                info = _entry_regular(directory_fd, name)
            except OSError:
                continue
            total -= info.st_size
        if count + additional_entries > MAX_STORED_CAPTURES or total + additional_bytes > MAX_STORED_BYTES:
            raise CaptureError(
                "storage_quota",
                "Capture storage quota is full.",
                "Archive captures outside the managed directory, then retry.",
                False,
            )
    finally:
        os.close(directory_fd)


def _reserve_partial() -> tuple[str, str, int, os.stat_result]:
    with storage_lock():
        require_storage_capacity(1, MAX_CAPTURE_BYTES)
        directory_fd = _dirfd()
        try:
            for _ in range(ID_RESERVATION_ATTEMPTS):
                capture_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
                partial = f"{capture_id}.partial"
                try:
                    fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=directory_fd)
                except FileExistsError:
                    continue
                try:
                    os.fchmod(fd, 0o600)
                    return capture_id, partial, fd, os.fstat(fd)
                except Exception:
                    os.close(fd)
                    os.unlink(partial, dir_fd=directory_fd)
                    raise
            raise RuntimeError("could not reserve unique capture id")
        finally:
            os.close(directory_fd)


def _unlink_partial(name: str, device: int, inode: int) -> None:
    directory_fd = _dirfd()
    try:
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (device, inode):
            raise RuntimeError("reserved capture changed")
        os.unlink(name, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)


def _close_reservation(session: CaptureSession) -> None:
    if session._reservation_fd is not None:
        try:
            os.close(session._reservation_fd)
        except OSError:
            pass
        session._reservation_fd = None


def _release_session_ownership(session: CaptureSession) -> None:
    global _active
    with _lock:
        if _active is session:
            _active = None
        if not session._ownership_released:
            HARDWARE_COORDINATOR.release("capture")
            session._ownership_released = True


def _open_analyzer() -> usb.core.Device:
    if packetry_running():
        raise CaptureError(
            "packetry_busy",
            "Packetry is using the analyzer.",
            "Close Packetry, then run capture_preflight again.",
        )
    devices = list(usb.core.find(find_all=True, idVendor=ANALYZER_VID, idProduct=ANALYZER_PID) or [])
    if not devices:
        raise CaptureError(
            "hardware_missing",
            "Cynthion USB Analyzer is not connected.",
            "Connect Cynthion CONTROL, then run capture_preflight again.",
        )
    if len(devices) != 1:
        raise CaptureError(
            "hardware_ambiguous",
            "Multiple Cynthion analyzers are connected.",
            "Leave exactly one analyzer connected, then retry.",
        )
    device = devices[0]
    try:
        device.set_configuration()
    except usb.core.USBError:
        pass
    return device


def _set_state(dev: usb.core.Device, enable: bool, speed: CaptureSpeed) -> None:
    dev.ctrl_transfer(0x41, int(VendorRequest.SET_STATE), (1 if enable else 0) | (int(speed) << 1), VENDOR_IFACE, None, timeout=1000)


def _finalize_file(session: CaptureSession, clean: bool) -> None:
    if not clean:
        _unlink_partial(session._partial_name, session._reservation_device, session._reservation_inode)
        return
    with storage_lock():
        directory_fd = _dirfd()
        try:
            info = os.stat(session._partial_name, dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or (info.st_dev, info.st_ino) != (session._reservation_device, session._reservation_inode):
                raise RuntimeError("reserved capture changed")
            os.link(session._partial_name, f"{session.id}.bin", src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd, follow_symlinks=False)
            os.unlink(session._partial_name, dir_fd=directory_fd)
            os.fsync(directory_fd)
        except Exception:
            try:
                _unlink_partial(session._partial_name, session._reservation_device, session._reservation_inode)
            except Exception:
                pass
            raise
        finally:
            os.close(directory_fd)


def _cleanup_device(session: CaptureSession) -> bool:
    if session._dev is None:
        return True
    try:
        _set_state(session._dev, False, CaptureSpeed.AUTO)
    except Exception:
        _set_session_error(
            session,
            "cleanup_failed",
            "Capture cleanup failed.",
            "Retry capture_stop; do not start another capture.",
        )
        return False
    try:
        usb.util.dispose_resources(session._dev)
    except Exception:
        _set_session_error(
            session,
            "cleanup_failed",
            "Capture cleanup failed.",
            "Retry capture_stop; do not start another capture.",
        )
        return False
    session._dev = None
    return True


def start_capture(speed: Literal["auto", "high", "full", "low"] = "auto") -> CaptureSession:
    global _active, _last_session
    speed_norm = speed.lower()
    if speed_norm not in SPEED_NAMES:
        raise ValueError("unknown capture speed")
    with _lock:
        if _active is not None:
            raise CaptureError(
                "capture_active",
                "A capture is already active.",
                "Use capture_status, capture_wait, or capture_stop_and_convert.",
            )
        HARDWARE_COORDINATOR.claim("capture")
        session = None
        try:
            capture_id, partial_name, reservation_fd, reservation_info = _reserve_partial()
            session = CaptureSession(
                capture_id, speed_norm, time.time(), CAPTURES_DIR / f"{capture_id}.bin",
                partial_name, reservation_info.st_ino, reservation_info.st_dev,
                time.monotonic(), reservation_fd,
            )
            device = _open_analyzer()
            session._dev = device
            _active = session

            def drainer() -> None:
                global _last_session
                clean = False
                try:
                    fd, session._reservation_fd = session._reservation_fd, None
                    if fd is None:
                        raise RuntimeError("capture reservation unavailable")
                    with os.fdopen(fd, "wb", closefd=True) as output:
                        _set_state(device, True, SPEED_NAMES[speed_norm])
                        session._ready.set()
                        while not session._stop_flag.is_set():
                            if time.monotonic() - session._started_monotonic >= MAX_CAPTURE_SECONDS:
                                _set_session_error(
                                    session,
                                    "duration_limit",
                                    "Capture duration limit reached.",
                                    "Start a shorter capture; limit-ended data is not published.",
                                    False,
                                )
                                break
                            remaining = MAX_CAPTURE_BYTES - session.bytes_written
                            if remaining <= 0:
                                _set_session_error(
                                    session,
                                    "byte_limit",
                                    "Capture byte limit reached.",
                                    "Start a shorter capture; limit-ended data is not published.",
                                    False,
                                )
                                break
                            try:
                                chunk = device.read(BULK_ENDPOINT_ADDR, min(16384, remaining), timeout=200)
                            except usb.core.USBTimeoutError:
                                continue
                            if chunk:
                                output.write(chunk[:remaining])
                                session.bytes_written += min(len(chunk), remaining)
                                if len(chunk) >= remaining:
                                    _set_session_error(
                                        session,
                                        "byte_limit",
                                        "Capture byte limit reached.",
                                        "Start a shorter capture; limit-ended data is not published.",
                                        False,
                                    )
                                    break
                        output.flush()
                        os.fsync(output.fileno())
                    clean = session.error is None and session._stop_flag.is_set()
                except Exception as exc:
                    if isinstance(exc, usb.core.USBError):
                        startup = not session._ready.is_set()
                        _set_session_error(
                            session,
                            "usb_claim_failed" if startup else "usb_io_failed",
                            (
                                "The analyzer USB interface could not be claimed."
                                if startup
                                else "Analyzer USB I/O failed during capture."
                            ),
                            "Close Packetry, reconnect Cynthion CONTROL, and run capture_preflight.",
                        )
                    else:
                        _set_session_error(
                            session,
                            "capture_failed",
                            "Capture failed.",
                            "Run capture_preflight, then retry.",
                        )
                    session._ready.set()
                finally:
                    cleaned = _cleanup_device(session)
                    if cleaned:
                        try:
                            _finalize_file(session, clean)
                        except Exception:
                            _set_session_error(
                                session,
                                "artifact_publish_failed",
                                "Capture artifact could not be published.",
                                "Check capture storage, then retry.",
                            )
                        session.cleanup_confirmed = True
                        session.finished_at = time.time()
                        _last_session = session
                        _release_session_ownership(session)
                    else:
                        try:
                            _finalize_file(session, False)
                        except Exception:
                            _set_session_error(
                                session,
                                "cleanup_failed",
                                "Capture cleanup failed.",
                                "Retry capture_stop before starting another capture.",
                            )
                        session.finished_at = time.time()
                        _last_session = session

            session._thread = threading.Thread(target=drainer, daemon=False, name=f"capture-{capture_id}")
            session._thread.start()
        except Exception:
            if session is not None:
                if session._thread is not None and session._thread.ident is None:
                    session._thread = None
                _close_reservation(session)
                try:
                    _finalize_file(session, False)
                except Exception:
                    pass
            disposed = session is None or session._dev is None
            if session is not None and session._dev is not None:
                try:
                    usb.util.dispose_resources(session._dev)
                    session._dev = None
                    disposed = True
                except Exception:
                    _set_session_error(
                        session,
                        "cleanup_failed",
                        "Capture cleanup failed.",
                        "Retry capture_stop; do not start another capture.",
                    )
                    session.finished_at = time.time()
                    _last_session = session
            if disposed:
                _active = None
                HARDWARE_COORDINATOR.release("capture")
            raise
    session._ready.wait(STARTUP_TIMEOUT_SECONDS)
    if not session._ready.is_set() or session.error or not session._thread.is_alive():
        _set_session_error(
            session,
            "capture_start_failed",
            "Capture startup failed.",
            "Run capture_preflight, resolve its reported condition, then retry.",
        )
        session._stop_flag.set()
        session._thread.join(STOP_TIMEOUT_SECONDS)
        raise CaptureError(
            session.error_code or "capture_start_failed",
            session.error or "Capture startup failed.",
            session.next_action or "Run capture_preflight, then retry.",
            session.recoverable is not False,
        )
    return session


def stop_capture() -> CaptureSession:
    with _lock:
        if _active is None:
            raise CaptureError(
                "no_active_capture",
                "No capture is active.",
                "Run capture_start before stopping a capture.",
            )
        session = _active
        session._stop_flag.set()
    with session._cleanup_lock:
        if session._thread is not None:
            session._thread.join(STOP_TIMEOUT_SECONDS)
            if session._thread.is_alive():
                raise CaptureError(
                    "capture_stop_timeout",
                    "Capture did not stop before the timeout.",
                    "Retry capture_stop; do not start another capture.",
                )
        if not session.cleanup_confirmed:
            if not _cleanup_device(session):
                raise CaptureError(
                    "cleanup_failed",
                    "Capture cleanup is incomplete.",
                    "Retry capture_stop; do not start another capture.",
                )
            session.cleanup_confirmed = True
            try:
                _finalize_file(session, False)
            except Exception:
                _set_session_error(
                    session,
                    "artifact_publish_failed",
                    "Capture artifact could not be finalized.",
                    "Check capture storage, then run capture_preflight.",
                )
            finally:
                _release_session_ownership(session)
        if session.error:
            raise CaptureError(
                session.error_code or "capture_failed",
                session.error,
                session.next_action or "Run capture_preflight, then retry.",
                session.recoverable is not False,
            )
        return session


def list_captures() -> list[dict]:
    with storage_lock():
        directory_fd = _dirfd()
        try:
            result: list[dict] = []
            for entry in islice(os.scandir(directory_fd), MAX_DIRECTORY_SCAN):
                name = entry.name
                if not name.endswith(".bin") or not CAPTURE_ID_RE.fullmatch(name[:-4]):
                    continue
                try:
                    info = _entry_regular(directory_fd, name)
                except OSError:
                    continue
                result.append({"id": name[:-4], "size": info.st_size, "mtime": info.st_mtime})
                if len(result) >= MAX_LIST_CAPTURES:
                    break
            return result
        finally:
            os.close(directory_fd)


def read_capture_bytes(capture_id: str, offset: int = 0, length: int = 4096) -> bytes:
    if not isinstance(offset, int) or offset < 0 or not isinstance(length, int) or not 0 <= length <= MAX_RAW_READ_BYTES:
        raise ValueError("invalid capture read range")
    fd, _ = open_capture_fd(capture_id)
    try:
        os.lseek(fd, offset, os.SEEK_SET)
        return os.read(fd, length)
    finally:
        os.close(fd)


def _status(session: CaptureSession) -> dict:
    return {
        "id": session.id,
        "speed": session.speed,
        "started_at": session.started_at,
        "bytes_written": session.bytes_written,
        "finished_at": session.finished_at,
        "terminal": session.finished_at is not None,
        "cleanup_confirmed": session.cleanup_confirmed,
        "error": session.error,
        "error_code": session.error_code,
        "next_action": session.next_action,
        "recoverable": session.recoverable,
    }


def session_status() -> dict:
    with _lock:
        session = _active or _last_session
        return _status(session) if session is not None else {"terminal": True, "error": None}


def wait_for_capture(min_bytes: int = 1, timeout_seconds: float = 30.0) -> dict:
    if (
        isinstance(min_bytes, bool)
        or not isinstance(min_bytes, int)
        or not 1 <= min_bytes <= MAX_CAPTURE_BYTES
        or isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 <= timeout_seconds <= MAX_WAIT_SECONDS
    ):
        raise ValueError("invalid capture wait bounds")
    with _lock:
        session = _active
    if session is None:
        raise CaptureError(
            "no_active_capture",
            "No capture is active.",
            "Run capture_start before waiting for traffic.",
        )
    deadline = time.monotonic() + timeout_seconds
    while True:
        status = _status(session)
        status["traffic_seen"] = session.bytes_written >= min_bytes
        if status["traffic_seen"] or status["terminal"] or time.monotonic() >= deadline:
            return status
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))


def capture_file_sha256(capture_id: str, suffix: str) -> str:
    if suffix not in {".bin", ".pcap"}:
        raise ValueError("invalid capture suffix")
    fd, _ = open_capture_fd(capture_id, suffix)
    try:
        digest = hashlib.sha256()
        while chunk := os.read(fd, 64 * 1024):
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(fd)
