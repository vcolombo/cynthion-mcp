"""Emulation is deliberately unavailable in this hardened capture/decoder build.

A future implementation must isolate Facedancer in a separately supervised
process.  These compatibility entry points fail closed: they do not import
Facedancer, open hardware, or create worker threads.
"""
from __future__ import annotations


class EmulatorUnavailable(RuntimeError):
    """Raised because this build intentionally has no emulator."""


class EmulatorLifecycleError(EmulatorUnavailable):
    pass


_UNSUPPORTED = "emulator is intentionally unsupported in this hardened build"


def _unsupported(*_args, **_kwargs):
    raise EmulatorUnavailable(_UNSUPPORTED)


probe_moondancer_responsive = _unsupported
emulate_device = _unsupported
emulate_from_descriptor = _unsupported
disconnect_device = _unsupported
inject_serial = _unsupported
