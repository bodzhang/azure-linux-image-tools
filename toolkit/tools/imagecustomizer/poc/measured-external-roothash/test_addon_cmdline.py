#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import tempfile
import unittest
from pathlib import Path

import addon_cmdline


ROOT_HASH = "66edc2dedf7a1aecc608d49cb2185415be3c2ba8b075675f9cc8222b41a846f3"
VERITY_ARGS = (
    "rd.systemd.verity=1 "
    "systemd.verity_root_data=PARTUUID=data "
    "systemd.verity_root_hash=PARTUUID=hash "
    "systemd.verity_root_options=panic-on-corruption"
)


class AddonCmdlineTests(unittest.TestCase):
    def combine(self, contents: list[bytes]) -> tuple[str, str]:
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for index, content in enumerate(contents):
                path = Path(directory) / f"{index}.cmdline"
                path.write_bytes(content)
                paths.append(path)
            return addon_cmdline.combine_sections(paths)

    def test_combines_nul_padded_addon_sections(self):
        cmdline, root_hash = self.combine(
            [
                f"root=/dev/mapper/root {VERITY_ARGS}\0\0".encode(),
                f"roothash={ROOT_HASH}".encode(),
            ]
        )
        self.assertEqual(root_hash, ROOT_HASH)
        self.assertIn("root=/dev/mapper/root", cmdline)
        self.assertIn(f"roothash={ROOT_HASH}", cmdline)

    def test_rejects_duplicate_roothash(self):
        with self.assertRaises(addon_cmdline.CmdlineError):
            self.combine(
                [
                    f"{VERITY_ARGS} roothash={ROOT_HASH}".encode(),
                    f"roothash={ROOT_HASH}".encode(),
                ]
            )

    def test_rejects_interior_nul(self):
        with self.assertRaises(addon_cmdline.CmdlineError):
            self.combine([f"{VERITY_ARGS} roothash={ROOT_HASH}\0quiet".encode()])

    def test_rejects_missing_roothash(self):
        with self.assertRaises(addon_cmdline.CmdlineError):
            self.combine([VERITY_ARGS.encode()])

    def test_rejects_missing_systemd_verity_argument(self):
        with self.assertRaises(addon_cmdline.CmdlineError):
            self.combine(
                [
                    (
                        "rd.systemd.verity=1 "
                        "systemd.verity_root_data=PARTUUID=data "
                        "systemd.verity_root_hash=PARTUUID=hash "
                        f"roothash={ROOT_HASH}"
                    ).encode()
                ]
            )

    def test_extracts_verity_partition_identifiers(self):
        cmdline, _ = self.combine(
            [f"{VERITY_ARGS} roothash={ROOT_HASH}".encode()]
        )
        self.assertEqual(
            addon_cmdline.DATA_DEVICE_RE.findall(cmdline),
            ["PARTUUID=data"],
        )
        self.assertEqual(
            addon_cmdline.HASH_DEVICE_RE.findall(cmdline),
            ["PARTUUID=hash"],
        )


if __name__ == "__main__":
    unittest.main()
