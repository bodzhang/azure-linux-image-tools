#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import hashlib
import struct
import unittest

import verify


ROOT_HASH = "66edc2dedf7a1aecc608d49cb2185415be3c2ba8b075675f9cc8222b41a846f3"
CMDLINE = f"root=/dev/mapper/root roothash={ROOT_HASH} quiet"


def spec_event() -> bytes:
    data = (
        b"Spec ID Event03\0"
        + struct.pack("<I", 0)
        + bytes((0, 2, 0, 2))
        + struct.pack("<I", 2)
        + struct.pack("<HH", 0x0004, 20)
        + struct.pack("<HH", verify.TPM_ALG_SHA256, 32)
        + b"\0"
    )
    return (
        struct.pack("<II", 0, verify.EV_NO_ACTION)
        + bytes(20)
        + struct.pack("<I", len(data))
        + data
    )


def event2(pcr: int, event_type: int, data: bytes, measured: bytes | None = None) -> bytes:
    measured = data if measured is None else measured
    digest = hashlib.sha256(measured).digest()
    return (
        struct.pack("<IIIH", pcr, event_type, 1, verify.TPM_ALG_SHA256)
        + digest
        + struct.pack("<I", len(data))
        + data
    )


def make_log(
    root_hash: str = ROOT_HASH,
    corrupt_cmdline_digest: bool = False,
    cmdline: str | None = None,
) -> bytes:
    cmdline = cmdline or f"root=/dev/mapper/root roothash={root_hash} quiet"
    cmdline_data = (cmdline + "\0").encode("utf-16-le")
    measured = b"not the command line" if corrupt_cmdline_digest else None
    return (
        spec_event()
        + event2(4, 0x80000003, b"unrelated")
        + event2(12, verify.EV_IPL, cmdline_data, measured)
        + event2(12, verify.EV_IPL, cmdline_data)
        + event2(12, 0x00000006, b"separator")
    )


def make_quote(replayed_pcr12: bytes, pcr_select: bytes = b"\x00\x10\x00") -> bytes:
    composite = hashlib.sha256(replayed_pcr12).digest()
    return (
        struct.pack(">IH", verify.TPM_GENERATED_VALUE, verify.TPM_ST_ATTEST_QUOTE)
        + struct.pack(">H", 0)
        + struct.pack(">H", 4)
        + b"test"
        + bytes(17)
        + struct.pack(">Q", 1)
        + struct.pack(">IHB", 1, verify.TPM_ALG_SHA256, len(pcr_select))
        + pcr_select
        + struct.pack(">H", len(composite))
        + composite
    )


class VerifyTests(unittest.TestCase):
    def test_accepts_matching_quote_and_roothash(self):
        events = verify.parse_eventlog(make_log())
        replayed = verify.replay_pcr(events, 12, "sha256")
        verify.validate_quote_pcr12(make_quote(replayed), replayed)
        self.assertEqual(
            verify.validate_measured_cmdlines(events, CMDLINE, ROOT_HASH), 2
        )

    def test_rejects_changed_roothash_policy(self):
        events = verify.parse_eventlog(make_log("a" * 64))
        with self.assertRaises(verify.VerificationError):
            verify.validate_measured_cmdlines(events, CMDLINE, ROOT_HASH)

    def test_rejects_extra_security_sensitive_option(self):
        cmdline = CMDLINE + " systemd.verity=no init=/bin/sh"
        events = verify.parse_eventlog(make_log(cmdline=cmdline))
        with self.assertRaises(verify.VerificationError):
            verify.validate_measured_cmdlines(events, CMDLINE, ROOT_HASH)

    def test_rejects_additional_command_line_fragment(self):
        log = make_log() + event2(
            12, verify.EV_IPL, ("systemd.verity=no\0").encode("utf-16-le")
        )
        events = verify.parse_eventlog(log)
        with self.assertRaises(verify.VerificationError):
            verify.validate_measured_cmdlines(events, CMDLINE, ROOT_HASH)

    def test_rejects_non_ascii_command_line_without_crashing(self):
        cmdline = CMDLINE + " hostname=caf\u00e9"
        events = verify.parse_eventlog(make_log(cmdline=cmdline))
        with self.assertRaises(verify.VerificationError):
            verify.validate_measured_cmdlines(events, CMDLINE, ROOT_HASH)

    def test_rejects_tampered_event_log(self):
        events = verify.parse_eventlog(make_log())
        replayed = verify.replay_pcr(events, 12, "sha256")
        quote = make_quote(replayed)

        tampered = bytearray(make_log())
        # Change the digest of the final PCR 12 event, not only its description.
        tampered[-45] ^= 1
        tampered_events = verify.parse_eventlog(bytes(tampered))
        tampered_replay = verify.replay_pcr(tampered_events, 12, "sha256")
        with self.assertRaises(verify.VerificationError):
            verify.validate_quote_pcr12(quote, tampered_replay)

    def test_rejects_cmdline_digest_not_covering_event_data(self):
        events = verify.parse_eventlog(make_log(corrupt_cmdline_digest=True))
        self.assertEqual(
            verify.validate_measured_cmdlines(events, CMDLINE, ROOT_HASH), 1
        )

    def test_rejects_quote_selecting_another_pcr(self):
        events = verify.parse_eventlog(make_log())
        replayed = verify.replay_pcr(events, 12, "sha256")
        with self.assertRaises(verify.VerificationError):
            verify.validate_quote_pcr12(
                make_quote(replayed, b"\x00\x08\x00"), replayed
            )

    def test_no_action_event_is_not_extended(self):
        data = make_log()
        events = verify.parse_eventlog(data)
        baseline = verify.replay_pcr(events, 12, "sha256")
        no_action = event2(12, verify.EV_NO_ACTION, b"metadata")
        with_no_action = verify.parse_eventlog(data + no_action)
        self.assertEqual(verify.replay_pcr(with_no_action, 12, "sha256"), baseline)


if __name__ == "__main__":
    unittest.main()
