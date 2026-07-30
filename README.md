# cynthion-mcp

A hardened MCP surface for Cynthion USB capture storage and capability-gated decoding.

## Security profile

This branch is **capture/decoder-only**. Emulator support, descriptor cloning,
serial injection, and emulator diagnosis are intentionally unsupported. The
server does not register emulator tools, import Facedancer for emulator work,
or create emulator threads. A future emulator requires an isolated-process
architecture with its own review.

The default server exposes exactly `get_status` and `list_captures`. Operator
capabilities enable only their matching tools: `capture`, `raw-read`, and
`native-converter` (pure capture-to-PCAP conversion). The `capture` capability
adds preflight, start, bounded wait, stop, and status tools;
`capture_stop_and_convert` requires both `capture` and `native-converter`.
Mode switching, recovery, firmware, bitstream mutation, and tshark execution
are not exposed through MCP. Packetry or an operator-controlled local tshark
process can inspect exported PCAPs.

`capture_preflight` uses a fixed `/usr/bin/pgrep` invocation with no shell or
user-controlled arguments to report Packetry ownership before touching USB.
It never terminates Packetry and treats an unavailable/timed-out process probe
as busy. Tool failures return fixed redacted error codes, recoverability, and a
next action; raw USB exceptions are only reduced to coarse categories.

If an operator uses the optional host-side tshark helper directly, it requires
an absolute `CYNTHION_MCP_TSHARK` path and the lowercase SHA-256 digest of that
regular, non-symlink executable in `CYNTHION_MCP_TSHARK_SHA256`. The executable
is opened and hashed before it is run. This verifies file integrity; it is not
an operating-system sandbox, which is why tshark is not an MCP tool.

Capture files are private, descriptor-relative, no-follow operations. Captures
are not deleted to satisfy quotas: new captures are refused once aggregate
artifact count or byte limits are reached. PCAP conversion is deterministic on
every request; no persistent metadata cache is trusted.

## Reproducible setup

Use the committed lockfile and pinned build backend; do not install mutable
source clones or copy assets from a latest wheel:

```sh
uv sync --locked --extra test
PYTHONPATH=src uv run python -m pytest tests -q
```

The project pins direct dependencies and `setuptools==82.0.1`; setup and CI use
the committed `uv.lock` exclusively.

## Headless capture workflow

1. `capture_preflight`
2. `capture_start(speed="full")` when the bus speed is known
3. Generate target traffic; `capture_wait(min_bytes=4096, timeout_seconds=30)`
4. `capture_stop_and_convert`

The final call returns capture/PCAP names, packet and event counts, duration,
and SHA-256 digests for both artifacts. Physical cable changes, target power,
and target interactions remain operator actions.

## Hardware validation

A live headless capture/convert canary passed on the M4 control host for version
`0.1.0`. See `docs/HARDWARE-TEST-LOG.md` for the commit, counts, and artifact
hashes. Facedancer/emulation paths remain intentionally unvalidated and
unsupported.

## License and attribution

BSD 3-Clause — see `LICENSE`. This project preserves upstream Cynthion, LUNA,
and related-project attribution.
