"""Passive-by-default MCP server entrypoint for capture and decoder operations."""
from __future__ import annotations

import functools
import inspect
import logging
import os
import sys
from dataclasses import asdict
from typing import Literal

from mcp.server.fastmcp import FastMCP

from . import capture, tshark as tshark_mod
from .hardware import Hardware

log = logging.getLogger("cynthion_mcp")
_ENABLED = frozenset(item.strip() for item in os.environ.get("CYNTHION_MCP_ENABLE", "").split(",") if item.strip())


def _safe(fn):
    signature = inspect.signature(fn)

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception:
            log.exception("tool %s failed", fn.__name__)
            return {"error": "operation_failed", "tool": fn.__name__}

    wrapper.__signature__ = signature
    return wrapper


mcp = FastMCP(name="cynthion", instructions="Capture and decoder server. Emulator support is intentionally unavailable.")
_hw = Hardware()


def _tool(capability: str | None = None):
    def decorate(fn):
        return mcp.tool()(fn) if capability is None or capability in _ENABLED else fn
    return decorate


@_tool()
@_safe
def get_status() -> dict:
    return asdict(_hw.get_status())


@_tool("capture")
@_safe
def capture_start(speed: Literal["auto", "high", "full", "low"] = "auto") -> dict:
    session = capture.start_capture(speed)
    return {"id": session.id, "speed": session.speed, "started_at": session.started_at}


@_tool("capture")
@_safe
def capture_stop() -> dict:
    session = capture.stop_capture()
    return {"id": session.id, "speed": session.speed, "started_at": session.started_at,
            "finished_at": session.finished_at, "bytes_written": session.bytes_written,
            "error": session.error}


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
    return {"capture_id": capture_id, "offset": offset, "length_requested": length,
            "length_returned": len(data), "hex": data.hex()}


@_tool("native-converter")
@_safe
def convert_to_pcap(capture_id: str) -> dict:
    result = tshark_mod.ensure_pcap(capture_id)
    return {"capture_id": capture_id, "packets": result.packets, "events": result.events,
            "speed": result.speed, "duration_s": result.duration_us / 1_000_000,
            "event_counts": result.event_counts}


def main() -> None:
    logging.basicConfig(level=os.environ.get("CYNTHION_MCP_LOG", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    mcp.run("stdio")


if __name__ == "__main__":
    main()
