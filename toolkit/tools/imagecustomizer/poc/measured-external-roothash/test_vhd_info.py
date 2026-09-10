#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import struct
import tempfile
import unittest
from pathlib import Path

import vhd_info


PAYLOAD_SIZE = vhd_info.ONE_MIB


def make_footer(
    *,
    disk_type: int = vhd_info.FIXED_DISK_TYPE,
    current_size: int = PAYLOAD_SIZE,
) -> bytes:
    footer = bytearray(vhd_info.FOOTER_SIZE)
    footer[:8] = b"conectix"
    struct.pack_into(">I", footer, 8, 2)
    struct.pack_into(">I", footer, 12, 0x00010000)
    struct.pack_into(">Q", footer, 16, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into(">QQ", footer, 40, current_size, current_size)
    struct.pack_into(">I", footer, 60, disk_type)
    footer[68:84] = bytes(range(16))
    checksum_footer = bytearray(footer)
    checksum_footer[64:68] = bytes(4)
    struct.pack_into(">I", footer, 64, (~sum(checksum_footer)) & 0xFFFFFFFF)
    return bytes(footer)


class VhdInfoTests(unittest.TestCase):
    def validate(self, data: bytes) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.vhd"
            path.write_bytes(data)
            vhd_info.validate_fixed_vhd(path)

    def test_accepts_valid_fixed_vhd(self):
        self.validate(bytes(PAYLOAD_SIZE) + make_footer())

    def test_rejects_dynamic_vhd_footer(self):
        with self.assertRaises(vhd_info.VhdInfoError):
            self.validate(bytes(PAYLOAD_SIZE) + make_footer(disk_type=3))

    def test_rejects_incorrect_virtual_size(self):
        with self.assertRaises(vhd_info.VhdInfoError):
            self.validate(
                bytes(PAYLOAD_SIZE) + make_footer(current_size=PAYLOAD_SIZE * 2)
            )

    def test_rejects_bad_checksum(self):
        data = bytearray(bytes(PAYLOAD_SIZE) + make_footer())
        data[-1] ^= 1
        with self.assertRaises(vhd_info.VhdInfoError):
            self.validate(bytes(data))


if __name__ == "__main__":
    unittest.main()
