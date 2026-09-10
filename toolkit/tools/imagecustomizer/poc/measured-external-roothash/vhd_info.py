#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Validate the fixed VHD container requirements used by Azure."""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path


FOOTER_SIZE = 512
ONE_MIB = 1024 * 1024
FIXED_DISK_TYPE = 2


class VhdInfoError(Exception):
    pass


def validate_fixed_vhd(path: Path) -> None:
    try:
        file_size = path.stat().st_size
        if file_size < FOOTER_SIZE:
            raise VhdInfoError("VHD is too small")
        with path.open("rb") as stream:
            stream.seek(-FOOTER_SIZE, 2)
            footer = stream.read(FOOTER_SIZE)
    except OSError as error:
        raise VhdInfoError(f"cannot read VHD: {error}") from error

    if len(footer) != FOOTER_SIZE or footer[:8] != b"conectix":
        raise VhdInfoError("missing VHD footer")

    data_offset = struct.unpack_from(">Q", footer, 16)[0]
    original_size, current_size = struct.unpack_from(">QQ", footer, 40)
    disk_type = struct.unpack_from(">I", footer, 60)[0]
    stored_checksum = struct.unpack_from(">I", footer, 64)[0]

    checksum_footer = bytearray(footer)
    checksum_footer[64:68] = bytes(4)
    expected_checksum = (~sum(checksum_footer)) & 0xFFFFFFFF

    payload_size = file_size - FOOTER_SIZE
    if data_offset != 0xFFFFFFFFFFFFFFFF or disk_type != FIXED_DISK_TYPE:
        raise VhdInfoError("VHD is not fixed-size")
    if original_size != payload_size or current_size != payload_size:
        raise VhdInfoError("VHD footer size does not match the file")
    if payload_size % ONE_MIB:
        raise VhdInfoError("Azure fixed VHD size must be a multiple of 1 MiB")
    if stored_checksum != expected_checksum:
        raise VhdInfoError("VHD footer checksum is invalid")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("vhd", type=Path)
    args = parser.parse_args()

    try:
        validate_fixed_vhd(args.vhd)
    except VhdInfoError as error:
        print(f"{parser.prog}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
