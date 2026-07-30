# Hardware validation

## Current hardened branch

Validated on 2026-07-30 UTC at commit
`64e9a67f4882746f452771ea2f12580a423c31d4` through the real FastMCP stdio
entrypoint over SSH to the M4 control host.

- Service version: `0.1.0`
- Registered tools: 10, including preflight, bounded wait, and atomic stop/convert
- Preflight: ready; `USB Analyzer` bitstream detected
- Requested speed: `auto`; detected speed: `full`
- Capture duration: 2.9264414666666667 seconds
- Native bytes: 344064
- USB packets: 8780
- Analyzer events: 69919
- Native SHA-256: `561a0675ca19c406ebab1ff5a88cb2fa4861537b2c30739f8dc16b4df8425763`
- PCAP SHA-256: `9f65e4dd44981e11da35eb9cb3b6c4a5b61448c5733711aa51d2bfc901d2bfc2`
- Cleanup confirmed: true
- Serial field absent from status output

The canary did not load firmware, change bitstreams, terminate Packetry, or use
Facedancer/emulation paths.

## Historical upstream evidence (commit `057b794`)

Historical observations at commit `057b794` are retained only for attribution
and context. They are not current validation of Facedancer emulation,
descriptor cloning, serial injection, or emulator diagnosis; those capabilities
remain intentionally unsupported by this hardened branch.
