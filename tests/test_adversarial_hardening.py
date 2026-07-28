"""Mock-only adversarial hardening regression tests."""
from __future__ import annotations

import importlib
import inspect
import io
import os
import stat
import subprocess
import sys
import threading
import time
import types
import contextlib
from pathlib import Path

import pytest


def _install_dependency_stubs() -> None:
    usb = types.ModuleType("usb")
    core = types.ModuleType("usb.core")
    util = types.ModuleType("usb.util")
    core.USBError = type("USBError", (Exception,), {})
    core.USBTimeoutError = type("USBTimeoutError", (Exception,), {})
    core.find = lambda **kwargs: [] if kwargs.get("find_all") else None
    util.dispose_resources = lambda _device: None
    util.get_string = lambda *_args: None
    usb.core = core
    usb.util = util
    apollo = types.ModuleType("apollo_fpga")
    apollo.ApolloDebugger = object
    apollo.DebuggerNotFound = type("DebuggerNotFound", (Exception,), {})
    sys.modules.update({
        "usb": usb,
        "usb.core": core,
        "usb.util": util,
        "apollo_fpga": apollo,
    })


_install_dependency_stubs()


@pytest.fixture
def modules(monkeypatch, tmp_path):
    for name in list(sys.modules):
        if name.startswith("cynthion_mcp"):
            del sys.modules[name]
    capture = importlib.import_module("cynthion_mcp.capture")
    decoder = importlib.import_module("cynthion_mcp.decoder")
    tshark = importlib.import_module("cynthion_mcp.tshark")
    hardware = importlib.import_module("cynthion_mcp.hardware")
    coordinator = importlib.import_module("cynthion_mcp.coordinator")
    monkeypatch.setattr(coordinator, "LOCK_DIR", tmp_path / "state")
    monkeypatch.setattr(capture, "CAPTURES_DIR", tmp_path / "captures")
    return capture, decoder, tshark, hardware


def _valid_capture_id() -> str:
    return "20260728-123456-abcdef"


def _session(capture, capture_id: str, partial: str, fd: int, info: os.stat_result):
    return capture.CaptureSession(
        capture_id,
        "auto",
        time.time(),
        capture.CAPTURES_DIR / f"{capture_id}.bin",
        partial,
        info.st_ino,
        info.st_dev,
        time.monotonic(),
        fd,
    )


def test_reservation_closes_directory_fd_and_counts_all_artifacts(modules, monkeypatch):
    capture, _, _, _ = modules
    capture._ensure_capture_dir()
    original_dirfd = capture._dirfd
    original_close = capture.os.close
    opened: list[int] = []
    closed: list[int] = []

    def tracked_dirfd():
        fd = original_dirfd()
        opened.append(fd)
        return fd

    def tracked_close(fd):
        closed.append(fd)
        return original_close(fd)

    monkeypatch.setattr(capture, "_dirfd", tracked_dirfd)
    monkeypatch.setattr(capture.os, "close", tracked_close)
    monkeypatch.setattr(capture.time, "strftime", lambda _format: "20260728-123456")
    monkeypatch.setattr(capture.uuid, "uuid4", lambda: types.SimpleNamespace(hex="abcdef00"))
    capture_id, partial, fd, info = capture._reserve_partial()
    assert capture_id == _valid_capture_id()
    assert opened and all(directory_fd in closed for directory_fd in opened)
    capture.os.close(fd)
    capture._unlink_partial(partial, info.st_dev, info.st_ino)

    capture._ensure_capture_dir()
    (capture.CAPTURES_DIR / "artifact.pcap").write_bytes(b"x" * 8)
    monkeypatch.setattr(capture, "MAX_STORED_BYTES", capture.MAX_CAPTURE_BYTES + 7)
    with pytest.raises(RuntimeError, match="quota"):
        capture._reserve_partial()


def test_final_collision_never_overwrites_existing_capture(modules):
    capture, _, _, _ = modules
    capture._ensure_capture_dir()
    capture_id, partial, fd, info = capture._reserve_partial()
    os.write(fd, b"new")
    os.close(fd)
    session = _session(capture, capture_id, partial, -1, info)
    session._reservation_fd = None
    final = capture.CAPTURES_DIR / f"{capture_id}.bin"
    final.write_bytes(b"original")
    with pytest.raises(FileExistsError):
        capture._finalize_file(session, True)
    assert final.read_bytes() == b"original"
    assert not (capture.CAPTURES_DIR / partial).exists()


def test_reservation_permission_failure_closes_fd_and_unlinks_partial(modules, monkeypatch):
    capture, _, _, _ = modules
    capture._ensure_capture_dir()
    monkeypatch.setattr(capture, "storage_lock", lambda: contextlib.nullcontext())
    monkeypatch.setattr(
        capture,
        "_dirfd",
        lambda: os.open(capture.CAPTURES_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)),
    )
    monkeypatch.setattr(capture.os, "fchmod", lambda _fd, _mode: (_ for _ in ()).throw(OSError("denied")))
    with pytest.raises(OSError, match="denied"):
        capture._reserve_partial()
    assert not list(capture.CAPTURES_DIR.glob("*.partial"))


def test_initialization_cleanup_failure_preserves_retryable_ownership(modules, monkeypatch):
    capture, _, _, _ = modules

    class Device:
        def set_configuration(self):
            return None
        def ctrl_transfer(self, *_args, **_kwargs):
            return None

    class RefusingThread:
        ident = None
        def __init__(self, **_kwargs):
            pass
        def start(self):
            raise RuntimeError("thread unavailable")
        def join(self, _timeout):
            return None
        def is_alive(self):
            return False

    monkeypatch.setattr(capture, "_open_analyzer", lambda: Device())
    monkeypatch.setattr(capture.threading, "Thread", RefusingThread)
    monkeypatch.setattr(capture.usb.util, "dispose_resources", lambda _device: (_ for _ in ()).throw(OSError("busy")))
    with pytest.raises(RuntimeError, match="thread unavailable"):
        capture.start_capture()
    assert capture._active is not None
    with pytest.raises(Exception):
        capture.HARDWARE_COORDINATOR.claim("conflict")

    monkeypatch.setattr(capture.usb.util, "dispose_resources", lambda _device: None)
    with pytest.raises(RuntimeError, match="stopped with an error"):
        capture.stop_capture()
    capture.HARDWARE_COORDINATOR.claim("after-cleanup")
    capture.HARDWARE_COORDINATOR.release("after-cleanup")


def test_capture_uses_monotonic_limit_and_terminal_status(modules, monkeypatch):
    capture, _, _, _ = modules
    session = capture.CaptureSession(
        _valid_capture_id(), "auto", 10.0, Path("x"), "x.partial", 1, 1, 20.0,
        error="capture duration limit reached", finished_at=30.0, cleanup_confirmed=True,
    )
    capture._last_session = session
    assert capture.session_status()["terminal"] is True
    assert capture.session_status()["error"] == "capture duration limit reached"
    assert "_started_monotonic" in capture.CaptureSession.__dataclass_fields__


def test_startup_timeout_can_never_publish_clean_capture(modules, monkeypatch):
    capture, _, _, _ = modules

    class Device:
        def set_configuration(self):
            return None
        def ctrl_transfer(self, *_args, **_kwargs):
            time.sleep(0.03)
        def read(self, *_args, **_kwargs):
            return b""

    monkeypatch.setattr(capture, "_open_analyzer", lambda: Device())
    monkeypatch.setattr(capture, "STARTUP_TIMEOUT_SECONDS", 0.005)
    monkeypatch.setattr(capture, "STOP_TIMEOUT_SECONDS", 0.2)
    with pytest.raises(RuntimeError, match="startup failed"):
        capture.start_capture()
    assert not list(capture.CAPTURES_DIR.glob("*.bin"))
    assert capture.session_status()["error"] == "capture startup failed"


def test_listing_is_lazy_bounded_and_paths_are_confined(modules, monkeypatch):
    capture, _, _, _ = modules
    capture._ensure_capture_dir()
    valid = _valid_capture_id()
    target = capture.CAPTURES_DIR / "target"
    target.write_bytes(b"x")
    (capture.CAPTURES_DIR / f"{valid}.bin").symlink_to(target)
    with pytest.raises(FileNotFoundError):
        capture.open_capture_fd(valid)
    with pytest.raises(ValueError):
        capture.read_capture_bytes("../../secret")

    class Entry:
        name = "20260728-123456-aaaaaa.bin"
    class Iterator:
        def __init__(self):
            self.count = 0
        def __iter__(self):
            return self
        def __next__(self):
            self.count += 1
            if self.count > 1:
                raise AssertionError("listing was not bounded")
            return Entry()
        def close(self):
            pass
    monkeypatch.setattr(capture, "MAX_LIST_CAPTURES", 1)
    monkeypatch.setattr(capture.os, "scandir", lambda _fd: Iterator())
    monkeypatch.setattr(capture, "_entry_regular", lambda *_args: types.SimpleNamespace(st_size=1, st_mtime=1))
    assert len(capture.list_captures()) == 1


def test_decoder_fails_closed_cleans_temp_and_bounds_output(modules, tmp_path, monkeypatch):
    _, decoder, _, _ = modules
    src = tmp_path / "capture.bin"
    dst = tmp_path / "capture.pcap"
    dst.write_bytes(b"known-good")
    src.write_bytes(b"\x00\x00\x00\x00")
    with pytest.raises(decoder.CaptureFormatError):
        decoder.cynthion_bin_to_pcap(src, dst)
    assert dst.read_bytes() == b"known-good"
    assert not list(tmp_path.glob("*.partial"))

    src.write_bytes(b"\x00\x01\x00\x00\xd2\x00")
    monkeypatch.setattr(decoder, "MAX_PCAP_BYTES", len(decoder.PCAP_GLOBAL_HEADER))
    with pytest.raises(ValueError, match="pcap output"):
        decoder.cynthion_bin_to_pcap(src, dst)
    assert dst.read_bytes() == b"known-good"


def test_conversion_reprocesses_and_removes_legacy_metadata(modules, monkeypatch):
    capture, decoder, tshark, _ = modules
    assert "force" not in inspect.signature(tshark.ensure_pcap).parameters
    capture._ensure_capture_dir()
    capture_id = _valid_capture_id()
    raw = capture.CAPTURES_DIR / f"{capture_id}.bin"
    raw.write_bytes(b"\xff\x04\x00\x00")
    legacy = capture.CAPTURES_DIR / f"{capture_id}.pcap.json"
    legacy.write_text("forged")
    calls = []

    def convert(fd, dst, *, source_stat=None):
        calls.append(1)
        Path(dst).write_bytes(b"pcap")
        return decoder.ConversionResult(Path(dst), 0, 1, 4, {}, "high", 0)

    monkeypatch.setattr(tshark, "cynthion_bin_to_pcap", convert)
    tshark.ensure_pcap(capture_id)
    tshark.ensure_pcap(capture_id)
    assert len(calls) == 2
    assert not legacy.exists()


def test_tshark_requires_verified_executable_hash(modules, monkeypatch, tmp_path):
    _, _, tshark, _ = modules
    executable = tmp_path / "tshark"
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    monkeypatch.setenv("CYNTHION_MCP_TSHARK", str(executable))
    monkeypatch.setenv("CYNTHION_MCP_TSHARK_SHA256", "0" * 64)
    with pytest.raises(RuntimeError, match="hash mismatch"):
        tshark._open_tshark_executable()


def test_tshark_reader_has_one_deadline_and_reaps_group(modules, monkeypatch):
    _, _, tshark, _ = modules
    read_fd, write_fd = os.pipe()
    terminated = []

    class Process:
        pid = 123
        returncode = None
        stdout = os.fdopen(read_fd, "rb", buffering=0)

    monkeypatch.setattr(tshark, "MAX_TSHARK_SECONDS", 0.01)
    monkeypatch.setattr(tshark, "_terminate_group", lambda proc: terminated.append(proc.pid) or setattr(proc, "returncode", -15))
    with pytest.raises(RuntimeError, match="timed out"):
        tshark._read_tshark_output(Process())
    os.close(write_fd)
    assert terminated == [123]


def test_tshark_helpers_do_not_mutate_capture_root_or_exceed_packet_cap(modules, monkeypatch):
    capture, _, tshark, _ = modules
    original_root = capture.CAPTURES_DIR
    tshark._capture_paths(_valid_capture_id())
    assert capture.CAPTURES_DIR == original_root
    observed = []
    monkeypatch.setattr(
        tshark,
        "_run_tshark",
        lambda _path, _display_filter, limit: observed.append(limit) or [{}] * limit,
    )
    records, truncated = tshark.run_tshark_with_truncation(Path("capture.pcap"), tshark.MAX_TSHARK_PACKETS)
    assert observed == [tshark.MAX_TSHARK_PACKETS]
    assert len(records) == tshark.MAX_TSHARK_PACKETS and truncated is True


def test_json_complexity_and_numeric_summary_limits(modules, monkeypatch):
    _, _, tshark, _ = modules
    monkeypatch.setattr(tshark, "MAX_JSON_DEPTH", 2)
    with pytest.raises(ValueError, match="complexity"):
        tshark._validate_json_value([[[[1]]]])
    monkeypatch.setattr(tshark, "MAX_JSON_STRING_LENGTH", 3)
    with pytest.raises(ValueError, match="string"):
        tshark._validate_json_value("long")
    packet = {"_source": {"layers": {"frame": {"frame.number": "1", "frame.time_relative": "nan", "frame.len": "3"}, "usbll": {}}}}
    with pytest.raises(ValueError, match="numeric"):
        tshark.summarise_packet(packet)


def test_hardware_status_is_coordinated_and_multiple_boards_fail_closed(modules, monkeypatch):
    _, _, _, hardware = modules
    device = types.SimpleNamespace(idProduct=hardware.APOLLO_STUB_PID)
    monkeypatch.setattr(hardware.usb.core, "find", lambda **_kwargs: [device, device])
    with pytest.raises(RuntimeError, match="multiple"):
        hardware.Hardware()._find_gsg_device()
    hardware.HARDWARE_COORDINATOR.claim("capture")
    try:
        with pytest.raises(Exception):
            hardware.Hardware().get_status()
    finally:
        hardware.HARDWARE_COORDINATOR.release("capture")


def test_hardware_lock_blocks_a_second_process_coordinator(modules):
    import cynthion_mcp.coordinator as coordinator

    first = coordinator.HardwareCoordinator()
    second = coordinator.HardwareCoordinator()
    first.claim("capture")
    try:
        with pytest.raises(coordinator.HardwareBusyError, match="another process"):
            second.claim("status")
    finally:
        first.release("capture")


def _registered_tools(monkeypatch, enabled: str) -> tuple[list[str], object]:
    monkeypatch.setenv("CYNTHION_MCP_ENABLE", enabled)
    for name in list(sys.modules):
        if name == "cynthion_mcp.server" or name == "mcp" or name.startswith("mcp."):
            del sys.modules[name]
    recorded: list[str] = []
    class FakeMCP:
        def __init__(self, *_args, **_kwargs):
            pass
        def tool(self):
            return lambda function: recorded.append(function.__name__) or function
        def run(self, *_args):
            pass
    fast = types.ModuleType("mcp.server.fastmcp")
    fast.FastMCP = FakeMCP
    sys.modules.update({"mcp": types.ModuleType("mcp"), "mcp.server": types.ModuleType("mcp.server"), "mcp.server.fastmcp": fast})
    server = importlib.import_module("cynthion_mcp.server")
    return recorded, server


def test_server_registers_exact_default_and_enabled_tools(monkeypatch):
    default, server = _registered_tools(monkeypatch, "")
    assert default == ["get_status", "list_captures"]
    assert "switch_mode" not in server.__dict__
    assert "recover" not in server.__dict__
    assert "emulate_device" not in server.__dict__
    converter_only, _ = _registered_tools(monkeypatch, "native-converter")
    assert converter_only == ["get_status", "list_captures", "convert_to_pcap"]
    enabled, enabled_server = _registered_tools(monkeypatch, "capture,raw-read,native-converter,tshark-decoder")
    assert enabled == [
        "get_status", "capture_start", "capture_stop", "capture_status", "list_captures",
        "read_capture", "convert_to_pcap",
    ]
    assert "force" not in inspect.signature(enabled_server.convert_to_pcap).parameters
    enabled_server.capture.stop_capture = lambda: types.SimpleNamespace(
        id="capture", speed="auto", started_at=1, finished_at=2, bytes_written=3, error="failed"
    )
    stopped = enabled_server.capture_stop()
    assert stopped["error"] == "failed" and "terminal_error" not in stopped


def test_real_fastmcp_registers_enabled_tools():
    root = Path(__file__).parents[1]
    env = os.environ.copy()
    env["CYNTHION_MCP_ENABLE"] = "capture,raw-read,native-converter"
    env["PYTHONPATH"] = str(root / "src")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import cynthion_mcp.server as s; "
            "t=next(t for t in s.mcp._tool_manager.list_tools() if t.name=='capture_start'); "
            "print(','.join(t.parameters['properties']['speed']['enum']))",
        ],
        cwd=root,
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "auto,high,full,low"


def test_invalid_speed_is_rejected_before_hardware(modules, monkeypatch):
    capture, _, _, _ = modules
    monkeypatch.setattr(
        capture.HARDWARE_COORDINATOR,
        "claim",
        lambda _owner: (_ for _ in ()).throw(AssertionError("hardware touched")),
    )
    with pytest.raises(ValueError, match="unknown capture speed"):
        capture.start_capture("invalid")


def test_emulator_public_api_is_fail_closed():
    emulator = importlib.import_module("cynthion_mcp.emulator")
    with pytest.raises(emulator.EmulatorUnavailable):
        emulator.emulate_device()
    assert "facedancer" not in sys.modules


def test_reproducibility_and_documentation_contracts():
    root = Path(__file__).parents[1]
    assert (root / "uv.lock").is_file()
    assert "setuptools==82.0.1" in (root / "pyproject.toml").read_text()
    workflow = (root / ".github/workflows/test.yml").read_text()
    assert "uv sync --locked --extra test" in workflow
    assert "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in workflow
    readme = (root / "README.md").read_text()
    assert "CYNTHION_MCP_TSHARK_SHA256" in readme
    assert "intentionally unsupported" in readme
    assert "historical upstream evidence" in (root / "docs/HARDWARE-TEST-LOG.md").read_text()
