"""Passive-by-default MCP server entrypoint for capture and decoder operations."""
from __future__ import annotations

import functools
import inspect
import logging
import os
import re
import sys
from dataclasses import asdict
from importlib.metadata import PackageNotFoundError, version
from typing import Literal

from mcp.server.fastmcp import FastMCP

from . import capture, tshark as tshark_mod
from .coordinator import HardwareBusyError
from .decoder import CaptureFormatError, ConversionResult
from .hardware import Hardware

log = logging.getLogger("cynthion_mcp")
_ENABLED = frozenset(
    item.strip() for item in os.environ.get("CYNTHION_MCP_ENABLE", "").split(",") if item.strip()
)
_BUILD_RE = re.compile(r"^[0-9a-f]{7,40}$")
try:
    _VERSION = version("cynthion-mcp")
except PackageNotFoundError:
    _VERSION = "unknown"


def _error_payload(tool: str, exc: Exception) -> dict:
    if isinstance(exc, capture.CaptureError):
        return exc.payload(tool)
    if isinstance(exc, HardwareBusyError):
        return capture.CaptureError(
            "hardware_busy",
            "Cynthion is busy with another MCP operation.",
            "Wait for the active operation to finish, then retry.",
        ).payload(tool)
    if isinstance(exc, CaptureFormatError):
        return capture.CaptureError(
            "invalid_capture",
            "The capture is incomplete or invalid.",
            "Run a new capture and stop it cleanly before conversion.",
            False,
        ).payload(tool)
    if isinstance(exc, FileNotFoundError):
        return capture.CaptureError(
            "capture_not_found",
            "The requested capture is unavailable.",
            "Use list_captures and retry with an available capture ID.",
            False,
        ).payload(tool)
    if isinstance(exc, ValueError):
        return capture.CaptureError(
            "invalid_request",
            "The request arguments are invalid.",
            "Correct the arguments and retry.",
            False,
        ).payload(tool)
    return capture.CaptureError(
        "internal_error",
        "The operation failed safely.",
        "Check the MCP server log, then run capture_preflight.",
    ).payload(tool)


def _safe(fn):
    signature = inspect.signature(fn, eval_str=True)

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            log.error("tool %s failed with %s", fn.__name__, type(exc).__name__)
            return _error_payload(fn.__name__, exc)

    setattr(wrapper, "__signature__", signature)
    return wrapper


def _service_info() -> dict:
    commit = os.environ.get("CYNTHION_MCP_BUILD_COMMIT", "").lower()
    return {
        "version": _VERSION,
        "build_commit": commit if _BUILD_RE.fullmatch(commit) else "unknown",
        "capabilities": sorted(_ENABLED),
    }


def _conversion_payload(capture_id: str, result: ConversionResult) -> dict:
    return {
        "capture_id": capture_id,
        "pcap": f"{capture_id}.pcap",
        "packets": result.packets,
        "events": result.events,
        "speed": result.speed,
        "duration_s": result.duration_us / 1_000_000,
        "event_counts": result.event_counts,
        "raw_sha256": capture.capture_file_sha256(capture_id, ".bin"),
        "pcap_sha256": capture.capture_file_sha256(capture_id, ".pcap"),
    }


mcp = FastMCP(
    name="cynthion",
    instructions="Capture and decoder server. Emulator support is intentionally unavailable.",
)
_hw = Hardware()


def _tool(*capabilities: str):
    def decorate(fn):
        return mcp.tool()(fn) if not capabilities or all(item in _ENABLED for item in capabilities) else fn

    return decorate


@_tool()
@_safe
def get_status() -> dict:
    return {
        **asdict(_hw.get_status()),
        "service": _service_info(),
        "capture": capture.session_status(),
    }


@_tool("capture")
@_safe
def capture_preflight() -> dict:
    session = capture.session_status()
    if not session.get("terminal", True):
        return {
            "ready": False,
            "error": "capture_active",
            "message": "A capture is already active.",
            "next_action": "Use capture_status, capture_wait, or capture_stop_and_convert.",
            "capture": session,
        }
    if capture.packetry_running():
        return {
            "ready": False,
            "error": "packetry_busy",
            "message": "Packetry is running and may own the analyzer.",
            "next_action": "Close Packetry, then run capture_preflight again.",
        }
    board = asdict(_hw.get_status())
    if not board["connected"]:
        return {
            "ready": False,
            "error": "hardware_missing",
            "message": "Cynthion USB Analyzer is not connected.",
            "next_action": "Connect Cynthion CONTROL, then run capture_preflight again.",
        }
    if board["bitstream_name"] != "USB Analyzer":
        return {
            "ready": False,
            "error": "wrong_bitstream",
            "message": "Cynthion is not running the USB Analyzer bitstream.",
            "next_action": "Load USB Analyzer using an operator-controlled tool, then retry.",
            "board": board,
        }
    return {
        "ready": True,
        "message": "Cynthion is ready for a headless capture.",
        "next_action": "Run capture_start with the known bus speed.",
        "board": board,
    }


@_tool("capture")
@_safe
def capture_start(speed: Literal["auto", "high", "full", "low"] = "auto") -> dict:
    session = capture.start_capture(speed)
    return {
        "ok": True,
        "state": "armed",
        "id": session.id,
        "speed": session.speed,
        "started_at": session.started_at,
        "next_action": "Generate target traffic, then use capture_wait or capture_stop_and_convert.",
    }


@_tool("capture")
@_safe
def capture_wait(min_bytes: int = 1, timeout_seconds: float = 30.0) -> dict:
    return {"ok": True, **capture.wait_for_capture(min_bytes, timeout_seconds)}


@_tool("capture")
@_safe
def capture_stop() -> dict:
    session = capture.stop_capture()
    return {"ok": True, **capture._status(session)}


@_tool("capture", "native-converter")
@_safe
def capture_stop_and_convert() -> dict:
    session = capture.stop_capture()
    result = tshark_mod.ensure_pcap(session.id)
    return {"ok": True, **capture._status(session), **_conversion_payload(session.id, result)}


@_tool("capture")
@_safe
def capture_status() -> dict:
    return capture.session_status()


@_tool()
@_safe
def list_captures() -> list[dict]:
    return capture.list_captures()


@_tool("raw-read")
@_safe
def read_capture(capture_id: str, offset: int = 0, length: int = 4096) -> dict:
    data = capture.read_capture_bytes(capture_id, offset, length)
    return {
        "capture_id": capture_id,
        "offset": offset,
        "length_requested": length,
        "length_returned": len(data),
        "hex": data.hex(),
    }


@_tool("native-converter")
@_safe
def convert_to_pcap(capture_id: str) -> dict:
    return _conversion_payload(capture_id, tshark_mod.ensure_pcap(capture_id))


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("CYNTHION_MCP_LOG", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    mcp.run("stdio")


if __name__ == "__main__":
    main()
