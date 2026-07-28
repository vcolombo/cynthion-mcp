"""Read-only Cynthion status discovery.

This hardened build deliberately contains no reset, firmware, or FPGA
reconfiguration path. The analyzer bitstream must already be loaded by an
operator-controlled tool before capture capability is enabled.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import usb.core
import usb.util

from .coordinator import HARDWARE_COORDINATOR

GSG_VID = 0x1D50
APOLLO_STUB_PID = 0x615B
APOLLO_MCU_PID = 0x615C


@dataclass
class BoardStatus:
    connected: bool
    mode: Literal["stub", "mcu_direct", "missing"]
    bitstream_name: str | None
    vendor_id: int | None
    product_id: int | None
    hardware: str | None
    serial_number: str | None
    firmware_version: str | None


class Hardware:
    def get_status(self) -> BoardStatus:
        """Read USB descriptors only, serialized against active captures."""
        with HARDWARE_COORDINATOR.operation("status"):
            device = self._find_gsg_device()
            if device is None:
                return BoardStatus(False, "missing", None, None, None, None, None, None)
            mode = "mcu_direct" if device.idProduct == APOLLO_MCU_PID else "stub"
            return BoardStatus(
                connected=True,
                mode=mode,
                bitstream_name=self._usb_string(device, getattr(device, "iProduct", 0)),
                vendor_id=device.idVendor,
                product_id=device.idProduct,
                hardware=None,
                serial_number=self._usb_string(device, getattr(device, "iSerialNumber", 0)),
                firmware_version=None,
            )

    def _find_gsg_device(self) -> usb.core.Device | None:
        devices = list(usb.core.find(find_all=True, idVendor=GSG_VID) or [])
        matches = [device for device in devices if device.idProduct in (APOLLO_STUB_PID, APOLLO_MCU_PID)]
        if len(matches) > 1:
            raise RuntimeError("multiple matching Cynthion devices detected")
        return matches[0] if matches else None

    @staticmethod
    def _usb_string(device, index: int) -> str | None:
        if not index:
            return None
        try:
            return usb.util.get_string(device, index)
        except Exception:
            return None
