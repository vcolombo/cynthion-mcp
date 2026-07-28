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
`native-converter` (pure capture-to-PCAP conversion). Mode switching, recovery,
firmware, bitstream mutation, and tshark execution are not exposed through MCP.
Packetry or an operator-controlled local tshark process can inspect exported PCAPs.

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

## Hardware validation

No current hardware validation is claimed by this hardened branch. See
`docs/HARDWARE-TEST-LOG.md` only as historical upstream evidence.

## License and attribution

BSD 3-Clause — see `LICENSE`. This project preserves upstream Cynthion, LUNA,
and related-project attribution.
