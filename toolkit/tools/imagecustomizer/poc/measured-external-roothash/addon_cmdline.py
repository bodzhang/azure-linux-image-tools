#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Build and validate the external command line from UKI addon sections."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


ROOT_HASH_RE = re.compile(r"(?:^|\s)roothash=([0-9A-Fa-f]{64})(?=\s|$)")
DATA_DEVICE_RE = re.compile(
    r"(?:^|\s)systemd\.verity_root_data=(\S+)(?=\s|$)"
)
HASH_DEVICE_RE = re.compile(
    r"(?:^|\s)systemd\.verity_root_hash=(\S+)(?=\s|$)"
)
REQUIRED_ARGUMENTS = (
    ("rd.systemd.verity=1", re.compile(r"(?:^|\s)rd\.systemd\.verity=1(?=\s|$)")),
    ("systemd.verity_root_options=", re.compile(
        r"(?:^|\s)systemd\.verity_root_options=\S+(?=\s|$)"
    )),
)


class CmdlineError(Exception):
    pass


def decode_section(data: bytes) -> str:
    data = data.rstrip(b"\0")
    if b"\0" in data:
        raise CmdlineError("UKI addon command line contains an interior NUL")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CmdlineError("UKI addon command line is not UTF-8") from error
    text = text.strip()
    if not text or "\n" in text or "\r" in text:
        raise CmdlineError("UKI addon command line must contain exactly one line")
    return text


def combine_sections(paths: list[Path]) -> tuple[str, str]:
    if not paths:
        raise CmdlineError("UKI has no command-line addon")
    fragments: list[str] = []
    for path in paths:
        try:
            fragments.append(decode_section(path.read_bytes()))
        except OSError as error:
            raise CmdlineError(f"cannot read {path}: {error}") from error

    cmdline = " ".join(fragments)
    root_hashes = ROOT_HASH_RE.findall(cmdline)
    if len(root_hashes) != 1:
        raise CmdlineError(
            "combined UKI addon command line must contain exactly one roothash="
        )
    for name, argument in REQUIRED_ARGUMENTS:
        if len(argument.findall(cmdline)) != 1:
            raise CmdlineError(
                f"combined UKI addon command line is missing or duplicates {name}"
            )
    for name, argument in (
        ("systemd.verity_root_data=", DATA_DEVICE_RE),
        ("systemd.verity_root_hash=", HASH_DEVICE_RE),
    ):
        if len(argument.findall(cmdline)) != 1:
            raise CmdlineError(
                f"combined UKI addon command line is missing or duplicates {name}"
            )
    return cmdline, root_hashes[0].lower()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cmdline-output", required=True, type=Path)
    parser.add_argument("--roothash-output", required=True, type=Path)
    parser.add_argument("--data-device-output", type=Path)
    parser.add_argument("--hash-device-output", type=Path)
    parser.add_argument("sections", nargs="+", type=Path)
    args = parser.parse_args()

    try:
        cmdline, root_hash = combine_sections(args.sections)
        args.cmdline_output.write_text(cmdline + "\n", encoding="utf-8")
        args.roothash_output.write_text(root_hash + "\n", encoding="ascii")
        if args.data_device_output:
            args.data_device_output.write_text(
                DATA_DEVICE_RE.findall(cmdline)[0] + "\n", encoding="ascii"
            )
        if args.hash_device_output:
            args.hash_device_output.write_text(
                HASH_DEVICE_RE.findall(cmdline)[0] + "\n", encoding="ascii"
            )
    except (OSError, CmdlineError) as error:
        print(f"{parser.prog}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
