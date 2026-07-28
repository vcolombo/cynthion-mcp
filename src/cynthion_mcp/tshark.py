"""Capability-gated, bounded tshark helpers for completed captures."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import selectors
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from . import capture
from .decoder import MAX_PCAP_BYTES, ConversionResult, cynthion_bin_to_pcap

CAPTURES_DIR = capture.CAPTURES_DIR
MAX_TSHARK_PACKETS = 1_000
MAX_TSHARK_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_TSHARK_SECONDS = 15
_READ_CHUNK_BYTES = 64 * 1024
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 50_000
MAX_JSON_STRING_LENGTH = 16_384
MAX_JSON_KEY_LENGTH = 256
MAX_JSON_CONTAINER_ITEMS = 2_048
MAX_SUMMARY_TIME_SECONDS = 24 * 60 * 60



def _capture_paths(capture_id: str) -> tuple[Path, Path]:
    capture._validate_id(capture_id)
    capture.CAPTURES_DIR = CAPTURES_DIR
    status = capture.session_status()
    if not status["terminal"] and status.get("id") == capture_id:
        raise RuntimeError("capture is not complete")
    return capture._capture_path(capture_id, ".bin"), capture._capture_path(capture_id, ".pcap")


def _sha256_fd(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, _READ_CHUNK_BYTES):
        digest.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def _open_name(name: str) -> tuple[int, os.stat_result]:
    directory_fd = capture._dirfd()
    try:
        expected = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(expected.st_mode):
            raise FileNotFoundError(name)
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
    finally:
        os.close(directory_fd)
    actual = os.fstat(fd)
    if not stat.S_ISREG(actual.st_mode) or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
        os.close(fd)
        raise FileNotFoundError(name)
    return fd, actual


def _remove_legacy_metadata(capture_id: str) -> None:
    directory_fd = capture._dirfd()
    try:
        try:
            os.unlink(f"{capture._validate_id(capture_id)}.pcap.json", dir_fd=directory_fd)
        except FileNotFoundError:
            pass
    finally:
        os.close(directory_fd)


def ensure_pcap(capture_id: str, *, force: bool = False) -> ConversionResult:
    _, pcap_path = _capture_paths(capture_id)
    with capture.storage_lock():
        capture.require_storage_capacity(
            1,
            MAX_PCAP_BYTES,
            replacing=(f"{capture_id}.pcap",),
        )
        source_fd, source_stat = capture.open_capture_fd(capture_id)
        try:
            _remove_legacy_metadata(capture_id)
            return cynthion_bin_to_pcap(source_fd, pcap_path, source_stat=source_stat)
        finally:
            os.close(source_fd)


def _open_tshark_executable() -> int:
    executable = os.environ.get("CYNTHION_MCP_TSHARK")
    expected_hash = os.environ.get("CYNTHION_MCP_TSHARK_SHA256", "").lower()
    if not executable or not os.path.isabs(executable) or len(expected_hash) != 64 or any(character not in "0123456789abcdef" for character in expected_hash):
        raise RuntimeError("tshark is not explicitly configured")
    try:
        expected = os.lstat(executable)
        if stat.S_ISLNK(expected.st_mode) or not stat.S_ISREG(expected.st_mode) or not os.access(executable, os.X_OK):
            raise RuntimeError("configured tshark is unsafe")
        fd = os.open(executable, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise RuntimeError("configured tshark is unsafe") from exc
    try:
        actual = os.fstat(fd)
        if not stat.S_ISREG(actual.st_mode) or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            raise RuntimeError("configured tshark changed")
        if not hmac.compare_digest(_sha256_fd(fd), expected_hash):
            raise RuntimeError("configured tshark hash mismatch")
        return fd
    except Exception:
        os.close(fd)
        raise


def _fd_path(fd: int) -> str:
    return f"/dev/fd/{fd}" if sys.platform == "darwin" else f"/proc/self/fd/{fd}"


def _terminate_group(proc: Any) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (AttributeError, ProcessLookupError):
        pass
    try:
        proc.wait(timeout=0.25)
    except (subprocess.TimeoutExpired, TypeError):
        pass
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (AttributeError, ProcessLookupError):
            pass
        try:
            proc.wait(timeout=0.25)
        except (subprocess.TimeoutExpired, TypeError):
            pass


def _read_tshark_output(proc: Any) -> bytes:
    output = bytearray()
    deadline = time.monotonic() + MAX_TSHARK_SECONDS
    pipe_fd = proc.stdout.fileno()
    os.set_blocking(pipe_fd, False)
    selector = selectors.DefaultSelector()
    selector.register(pipe_fd, selectors.EVENT_READ)
    error = None
    eof = False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                error = "tshark timed out"
                break
            if not selector.select(remaining):
                error = "tshark timed out"
                break
            try:
                chunk = os.read(pipe_fd, _READ_CHUNK_BYTES)
            except BlockingIOError:
                continue
            if not chunk:
                eof = True
                break
            if len(output) + len(chunk) > MAX_TSHARK_OUTPUT_BYTES:
                error = "tshark output exceeded limit"
                break
            output.extend(chunk)
    finally:
        selector.close()
        proc.stdout.close()
    if eof and error is None:
        try:
            proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        except (subprocess.TimeoutExpired, TypeError):
            error = "tshark timed out"
    if error is not None:
        _terminate_group(proc)
    if error:
        raise RuntimeError(error)
    if proc.returncode != 0:
        raise RuntimeError("tshark failed")
    return bytes(output)


def _validate_json_value(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
    if budget is None:
        budget = [MAX_JSON_NODES]
    budget[0] -= 1
    if budget[0] < 0 or depth > MAX_JSON_DEPTH:
        raise ValueError("JSON complexity limit exceeded")
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, str):
        if len(value) > MAX_JSON_STRING_LENGTH:
            raise ValueError("JSON string limit exceeded")
        return
    if isinstance(value, float) and math.isfinite(value):
        return
    if isinstance(value, list):
        if len(value) > MAX_JSON_CONTAINER_ITEMS:
            raise ValueError("JSON container limit exceeded")
        for item in value:
            _validate_json_value(item, depth + 1, budget)
        return
    if isinstance(value, dict):
        if len(value) > MAX_JSON_CONTAINER_ITEMS:
            raise ValueError("JSON container limit exceeded")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > MAX_JSON_KEY_LENGTH:
                raise ValueError("invalid JSON key")
            _validate_json_value(item, depth + 1, budget)
        return
    raise ValueError("invalid JSON value")


def _validate_tshark_records(parsed: Any, limit: int) -> list[dict]:
    if not isinstance(parsed, list) or len(parsed) > limit:
        raise RuntimeError("tshark returned invalid record structure")
    try:
        _validate_json_value(parsed)
    except ValueError as exc:
        raise RuntimeError("tshark returned invalid record structure") from exc
    for record in parsed:
        layers = record.get("_source", {}).get("layers", {}) if isinstance(record, dict) else None
        if not isinstance(layers, dict) or not isinstance(layers.get("frame"), dict) or not isinstance(layers.get("usbll"), dict):
            raise RuntimeError("tshark returned invalid record structure")
    return parsed


def _run_tshark(pcap_path: Path, display_filter: str | None, limit: int) -> list[dict]:
    name = pcap_path.name
    pcap_fd, _ = _open_name(name)
    executable_fd = None
    try:
        executable_fd = _open_tshark_executable()
        executable_path = _fd_path(executable_fd)
        args = [executable_path, "-n", "-r", _fd_path(pcap_fd), "-T", "json", "-c", str(limit)]
        if display_filter: args.extend(["-Y", display_filter])
        try:
            proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    env={"PATH": "/usr/bin:/bin", "LANG": "C"}, pass_fds=(pcap_fd, executable_fd),
                                    executable=executable_path, start_new_session=True)
        except OSError as exc:
            raise RuntimeError("tshark failed to start") from exc
        os.close(executable_fd)
        executable_fd = None
        output = _read_tshark_output(proc)
    finally:
        if executable_fd is not None:
            os.close(executable_fd)
        os.close(pcap_fd)
    try:
        parsed = json.loads(output, parse_constant=lambda _: (_ for _ in ()).throw(ValueError())) if output.strip() else []
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("tshark returned invalid JSON") from exc
    return _validate_tshark_records(parsed, limit)


def run_tshark(pcap_path: Path, display_filter: str | None = None, limit: int | None = None) -> list[dict]:
    if limit is None or not isinstance(limit, int) or not 1 <= limit <= MAX_TSHARK_PACKETS:
        raise ValueError("invalid tshark packet limit")
    if display_filter is not None and (not isinstance(display_filter, str) or len(display_filter) > 512):
        raise ValueError("invalid display filter")
    return _run_tshark(pcap_path, display_filter, limit)


def run_tshark_with_truncation(pcap_path: Path, limit: int) -> tuple[list[dict], bool]:
    if not isinstance(limit, int) or not 1 <= limit <= MAX_TSHARK_PACKETS:
        raise ValueError("invalid tshark packet limit")
    records = _run_tshark(pcap_path, None, limit + 1)
    return records[:limit], len(records) > limit


def summarise_packet(packet: dict) -> dict:
    layers = packet.get("_source", {}).get("layers", {})
    frame, usbll = layers.get("frame", {}), layers.get("usbll", {})
    if not isinstance(frame, dict) or not isinstance(usbll, dict): raise ValueError("invalid packet fields")
    def number(mapping: dict, key: str, convert, minimum, maximum):
        value = mapping.get(key, 0)
        if isinstance(value, bool):
            raise ValueError("invalid tshark numeric field")
        try:
            parsed = convert(value)
        except (TypeError, ValueError, OverflowError):
            raise ValueError("invalid tshark numeric field") from None
        if not math.isfinite(parsed) or not minimum <= parsed <= maximum:
            raise ValueError("invalid tshark numeric field")
        return parsed
    pid = usbll.get("usbll.pid")
    return {"frame_number": number(frame, "frame.number", int, 0, 2**31 - 1), "time": number(frame, "frame.time_relative", float, 0, MAX_SUMMARY_TIME_SECONDS), "length": number(frame, "frame.len", int, 0, 1027), "pid": pid, "pid_name": PID_NAMES.get(pid, "UNKNOWN") if pid else None, "src": usbll.get("usbll.src"), "dst": usbll.get("usbll.dst"), "device": usbll.get("usbll.device_addr"), "endpoint": usbll.get("usbll.endp"), "sof_frame": usbll.get("usbll.sof.framenumber"), "extra": {key: value for key, value in usbll.items() if isinstance(key, str) and key not in {"usbll.pid", "usbll.src", "usbll.dst", "usbll.device_addr", "usbll.endp", "usbll.addr", "usbll.sof.framenumber", "usbll.crc5", "usbll.crc5.status"}}}


PID_NAMES = {"0xa5": "SOF", "0x2d": "SETUP", "0x69": "IN", "0xe1": "OUT", "0xc3": "DATA0", "0x4b": "DATA1", "0xd2": "ACK", "0x5a": "NAK", "0x1e": "STALL", "0x96": "NYET"}
