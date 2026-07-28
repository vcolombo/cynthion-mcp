"""Strict, atomic Cynthion native capture → PCAP converter."""
from __future__ import annotations

import os
import stat
import struct
import uuid
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

LINKTYPE_USB_2_0 = 288
MAX_CONVERSION_BYTES = 64 * 1024 * 1024
MAX_PCAP_BYTES = 128 * 1024 * 1024
MAX_PACKET_BYTES = 1027
USB_CLOCK_HZ = 60_000_000
PCAP_GLOBAL_HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_USB_2_0)
EVENT_NAMES = {0: "NONE", 1: "CAPTURE_STOP_NORMAL", 2: "CAPTURE_STOP_FULL", 3: "CAPTURE_STOP_ERROR", 4: "CAPTURE_START_HIGH_OR_AUTO", 5: "CAPTURE_START_FULL", 6: "CAPTURE_START_LOW", 7: "CAPTURE_START_AUTO", 8: "SPEED_DETECT_HIGH", 9: "SPEED_DETECT_FULL", 10: "SPEED_DETECT_LOW", 11: "SPEED_DETECT_AUTO", 12: "LINESTATE_SE0", 13: "LINESTATE_CHIRP_J", 14: "LINESTATE_CHIRP_K", 15: "LINESTATE_CHIRP_SE1", 16: "LINESTATE_LS_J", 17: "LINESTATE_LS_K", 18: "LINESTATE_FS_J", 19: "LINESTATE_FS_K", 20: "LINESTATE_SE1", 21: "VBUS_INVALID", 22: "VBUS_VALID", 23: "LS_ATTACH", 24: "FS_ATTACH", 25: "BUS_RESET", 26: "DEVICE_CHIRP_VALID", 27: "HOST_CHIRP_VALID", 28: "SUSPEND", 29: "RESUME", 30: "LS_KEEPALIVE"}


class CaptureFormatError(ValueError):
    """A corrupt or incomplete capture; ``offset`` is the last safe boundary."""
    def __init__(self, message: str, offset: int):
        super().__init__(f"{message} at offset {offset}")
        self.offset = offset


@dataclass
class ConversionResult:
    pcap_path: Path
    packets: int
    events: int
    bytes_consumed: int
    event_counts: dict[str, int]
    speed: str | None
    duration_us: float


def _read_exact(fp, size: int, offset: int) -> bytes:
    data = fp.read(size)
    if len(data) != size:
        raise CaptureFormatError("truncated capture", offset)
    return data


def _valid_pid(pid: int) -> bool:
    return ((pid & 0x0F) ^ (pid >> 4)) == 0x0F


def cynthion_bin_to_pcap(src: Path | int, dst: Path, *, source_stat: os.stat_result | None = None) -> ConversionResult:
    """Convert an already-opened capture descriptor or a local path atomically."""
    dst = Path(dst)
    owns_source = not isinstance(src, int)
    source_fd = None
    directory_fd = None
    output_fd = None
    temp_name = None
    try:
        source_fd = src if isinstance(src, int) else os.open(Path(src), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        actual_source = os.fstat(source_fd)
        if not stat.S_ISREG(actual_source.st_mode):
            raise ValueError("capture source is not a regular file")
        if source_stat is not None and (source_stat.st_dev, source_stat.st_ino, source_stat.st_size) != (actual_source.st_dev, actual_source.st_ino, actual_source.st_size):
            raise ValueError("capture source changed")
        src_stat = source_stat or actual_source
        if src_stat.st_size > MAX_CONVERSION_BYTES:
            raise ValueError("capture exceeds conversion limit")
        dst.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory_fd = os.open(dst.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        temp_name = f".{dst.name}.{os.getpid()}.{uuid.uuid4().hex}.partial"
        output_fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=directory_fd)
        os.fchmod(output_fd, 0o600)
        pos = cumulative_ticks = packets = events = 0
        output_bytes = len(PCAP_GLOBAL_HEADER)
        event_counts: Counter[str] = Counter()
        speed: str | None = None
        os.lseek(source_fd, 0, os.SEEK_SET)
        output = os.fdopen(output_fd, "wb")
        output_fd = None
        with os.fdopen(os.dup(source_fd), "rb") as inp, output as out:
            out.write(PCAP_GLOBAL_HEADER)
            while pos < src_stat.st_size:
                header = _read_exact(inp, 4, pos)
                if header[0] == 0xFF:
                    code, timestamp = header[1], (header[2] << 8) | header[3]
                    cumulative_ticks += timestamp
                    event_counts[EVENT_NAMES.get(code, f"UNKNOWN_{code:02x}")] += 1
                    events += 1
                    if code in (2, 3):
                        raise CaptureFormatError("capture reports non-normal stop", pos)
                    if code in (4, 5, 6, 7):
                        speed = {4: "high", 5: "full", 6: "low", 7: "auto"}[code]
                    pos += 4
                    continue
                size = (header[0] << 8) | header[1]
                if not 1 <= size <= MAX_PACKET_BYTES:
                    raise CaptureFormatError("invalid packet length", pos)
                payload = _read_exact(inp, size, pos + 4)
                if not _valid_pid(payload[0]):
                    raise CaptureFormatError("invalid USB PID", pos + 4)
                if size & 1:
                    _read_exact(inp, 1, pos + 4 + size)
                timestamp = (header[2] << 8) | header[3]
                cumulative_ticks += timestamp
                seconds, remainder = divmod(cumulative_ticks, USB_CLOCK_HZ)
                microseconds = remainder * 1_000_000 // USB_CLOCK_HZ
                output_bytes += 16 + size
                if output_bytes > MAX_PCAP_BYTES:
                    raise ValueError("pcap output exceeds conversion limit")
                out.write(struct.pack("<IIII", seconds, microseconds, size, size))
                out.write(payload)
                packets += 1
                pos += 4 + size + (size & 1)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp_name, dst.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        temp_name = None
        final_fd = os.open(dst.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
        try:
            os.fchmod(final_fd, 0o600)
        finally:
            os.close(final_fd)
        return ConversionResult(dst, packets, events, pos, dict(event_counts), speed, cumulative_ticks / USB_CLOCK_HZ * 1_000_000)
    finally:
        if output_fd is not None:
            os.close(output_fd)
        if temp_name is not None and directory_fd is not None:
            try:
                os.unlink(temp_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        if directory_fd is not None:
            os.close(directory_fd)
        if owns_source and source_fd is not None:
            os.close(source_fd)
