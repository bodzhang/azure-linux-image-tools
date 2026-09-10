#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Verify a systemd-stub external roothash against a PCR 12 TPM quote."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import hmac
import re
import struct
import sys
from pathlib import Path


EV_NO_ACTION = 0x00000003
EV_IPL = 0x0000000D
TPM_GENERATED_VALUE = 0xFF544347
TPM_ST_ATTEST_QUOTE = 0x8018
TPM_ALG_SHA256 = 0x000B
SHA256_SIZE = 32
PCR_INDEX = 12

ALG_NAMES = {
    0x0004: "sha1",
    TPM_ALG_SHA256: "sha256",
    0x000C: "sha384",
    0x000D: "sha512",
    0x0012: "sm3_256",
}

ROOT_HASH_RE = re.compile(r"(?:^|\s)roothash=([0-9A-Fa-f]+)(?=\s|$)")


class VerificationError(Exception):
    pass


class Reader:
    def __init__(self, data: bytes, endian: str):
        self.data = data
        self.endian = endian
        self.offset = 0

    def remaining(self) -> int:
        return len(self.data) - self.offset

    def take(self, size: int) -> bytes:
        if size < 0 or self.remaining() < size:
            raise VerificationError("truncated binary structure")
        start = self.offset
        self.offset += size
        return self.data[start : self.offset]

    def unpack(self, fmt: str):
        size = struct.calcsize(self.endian + fmt)
        values = struct.unpack(self.endian + fmt, self.take(size))
        return values[0] if len(values) == 1 else values

    def u8(self) -> int:
        return self.unpack("B")

    def u16(self) -> int:
        return self.unpack("H")

    def u32(self) -> int:
        return self.unpack("I")

    def u64(self) -> int:
        return self.unpack("Q")

    def sized_u16(self) -> bytes:
        return self.take(self.u16())


@dataclasses.dataclass(frozen=True)
class Event:
    pcr: int
    event_type: int
    digests: dict[str, bytes]
    data: bytes


def parse_spec_id(data: bytes) -> dict[int, int]:
    r = Reader(data, "<")
    signature = r.take(16).rstrip(b"\0")
    if signature != b"Spec ID Event03":
        raise VerificationError("unsupported TCG event log Spec ID")

    r.take(4)  # platformClass
    r.take(4)  # minor, major, errata, uintnSize
    count = r.u32()
    if count == 0 or count > 64:
        raise VerificationError("invalid Spec ID algorithm count")

    algorithms: dict[int, int] = {}
    for _ in range(count):
        algorithm = r.u16()
        digest_size = r.u16()
        if digest_size == 0 or digest_size > 128:
            raise VerificationError("invalid digest size in Spec ID")
        algorithms[algorithm] = digest_size

    vendor_size = r.u8()
    r.take(vendor_size)
    if r.remaining() != 0:
        raise VerificationError("trailing bytes in Spec ID event")
    if TPM_ALG_SHA256 not in algorithms:
        raise VerificationError("event log has no SHA-256 bank")
    return algorithms


def parse_eventlog(data: bytes) -> list[Event]:
    r = Reader(data, "<")
    if r.remaining() < 32:
        raise VerificationError("event log is too small")

    pcr = r.u32()
    event_type = r.u32()
    sha1_digest = r.take(20)
    event_data = r.take(r.u32())
    if event_type != EV_NO_ACTION:
        raise VerificationError("event log does not start with a Spec ID event")

    algorithms = parse_spec_id(event_data)
    events = [Event(pcr, event_type, {"sha1": sha1_digest}, event_data)]

    while r.remaining():
        if r.remaining() < 12:
            raise VerificationError("truncated TCG_PCR_EVENT2 header")
        pcr = r.u32()
        event_type = r.u32()
        digest_count = r.u32()
        if digest_count == 0 or digest_count > len(algorithms):
            raise VerificationError("invalid event digest count")

        digests: dict[str, bytes] = {}
        for _ in range(digest_count):
            algorithm = r.u16()
            digest_size = algorithms.get(algorithm)
            if digest_size is None:
                raise VerificationError(
                    f"event uses algorithm 0x{algorithm:04x} absent from Spec ID"
                )
            name = ALG_NAMES.get(algorithm, f"alg_{algorithm:04x}")
            if name in digests:
                raise VerificationError(f"duplicate {name} digest in event")
            digests[name] = r.take(digest_size)

        event_data = r.take(r.u32())
        events.append(Event(pcr, event_type, digests, event_data))

    return events


def replay_pcr(events: list[Event], pcr: int, bank: str) -> bytes:
    value = bytes(hashlib.new(bank).digest_size)
    count = 0
    for event in events:
        digest = event.digests.get(bank)
        if event.pcr != pcr or digest is None or event.event_type == EV_NO_ACTION:
            continue
        value = hashlib.new(bank, value + digest).digest()
        count += 1
    if count == 0:
        raise VerificationError(f"event log has no {bank} PCR {pcr} events")
    return value


def decode_systemd_cmdline(event: Event) -> str | None:
    if event.pcr != PCR_INDEX or event.event_type != EV_IPL:
        return None
    if len(event.data) < 2 or len(event.data) % 2:
        return None
    try:
        text = event.data.decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    digest = event.digests.get("sha256")
    if digest is None or hashlib.sha256(event.data).digest() != digest:
        # Other PCR 12 EV_IPL records describe data that differs from the
        # measured bytes. Only self-describing command-line events are policy
        # inputs.
        return None

    if "\0" in text:
        if not text.endswith("\0") or "\0" in text[:-1]:
            raise VerificationError("measured command line contains an interior NUL")
        text = text[:-1]
    return text


def validate_measured_cmdlines(
    events: list[Event], expected_cmdline: str, expected_roothash: str
) -> int:
    count = 0
    for event in events:
        cmdline = decode_systemd_cmdline(event)
        if cmdline is None:
            continue
        count += 1
        if not hmac.compare_digest(
            cmdline.encode("utf-8"), expected_cmdline.encode("utf-8")
        ):
            raise VerificationError(
                f"measured command line is not approved: {cmdline!r}"
            )
        values = ROOT_HASH_RE.findall(cmdline)
        if len(values) != 1:
            raise VerificationError(
                "a measured command line must contain exactly one roothash="
            )
        if not hmac.compare_digest(values[0].lower(), expected_roothash):
            raise VerificationError(
                f"measured roothash is not approved: {values[0].lower()}"
            )
    if count == 0:
        raise VerificationError("no systemd PCR 12 command-line event found")
    return count


def parse_quote_message(data: bytes) -> tuple[list[tuple[int, bytes]], bytes]:
    # tpm2_quote writes TPMS_ATTEST. Also accept a TPM2B_ATTEST prefix.
    if len(data) >= 2 and int.from_bytes(data[:2], "big") == len(data) - 2:
        data = data[2:]

    r = Reader(data, ">")
    if r.u32() != TPM_GENERATED_VALUE:
        raise VerificationError("quote has invalid TPM_GENERATED magic")
    if r.u16() != TPM_ST_ATTEST_QUOTE:
        raise VerificationError("attestation message is not a quote")

    r.sized_u16()  # qualifiedSigner
    r.sized_u16()  # extraData; freshness is checked by tpm2_checkquote
    r.take(17)  # TPMS_CLOCK_INFO
    r.u64()  # firmwareVersion

    selection_count = r.u32()
    if selection_count == 0 or selection_count > 16:
        raise VerificationError("invalid quote PCR selection count")

    selections: list[tuple[int, bytes]] = []
    for _ in range(selection_count):
        algorithm = r.u16()
        select = r.take(r.u8())
        selections.append((algorithm, select))

    pcr_digest = r.sized_u16()
    if r.remaining() != 0:
        raise VerificationError("trailing bytes in quote message")
    return selections, pcr_digest


def validate_quote_pcr12(quote: bytes, replayed_pcr12: bytes) -> None:
    selections, quoted_digest = parse_quote_message(quote)
    if len(selections) != 1 or selections[0][0] != TPM_ALG_SHA256:
        raise VerificationError(
            "quote must select exactly SHA-256 PCR 12"
        )
    selected = selections[0][1]
    selected_pcrs = {
        byte_index * 8 + bit
        for byte_index, byte in enumerate(selected)
        for bit in range(8)
        if byte & (1 << bit)
    }
    if selected_pcrs != {PCR_INDEX}:
        raise VerificationError("quote must select exactly SHA-256 PCR 12")
    if len(quoted_digest) != SHA256_SIZE:
        raise VerificationError("quote has an invalid SHA-256 PCR digest size")

    expected_digest = hashlib.sha256(replayed_pcr12).digest()
    if not hmac.compare_digest(quoted_digest, expected_digest):
        raise VerificationError(
            "event-log replay does not match the PCR 12 composite in the quote"
        )


def valid_roothash(value: str) -> str:
    value = value.lower()
    if len(value) not in (64, 96, 128) or not re.fullmatch(r"[0-9a-f]+", value):
        raise argparse.ArgumentTypeError(
            "root hash must be 64, 96, or 128 hexadecimal characters"
        )
    return value


def read_expected_cmdline(path: Path) -> str:
    try:
        value = path.read_text(encoding="utf-8")
    except OSError as error:
        raise VerificationError(f"cannot read command-line policy: {error}") from error
    if value.endswith("\n"):
        value = value[:-1]
    if not value or "\n" in value or "\r" in value or "\0" in value:
        raise VerificationError("command-line policy must contain exactly one line")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--eventlog", required=True, type=Path)
    parser.add_argument("--quote-message", required=True, type=Path)
    parser.add_argument("--expected-roothash", required=True, type=valid_roothash)
    parser.add_argument("--expected-cmdline-file", required=True, type=Path)
    args = parser.parse_args()

    try:
        expected_cmdline = read_expected_cmdline(args.expected_cmdline_file)
        events = parse_eventlog(args.eventlog.read_bytes())
        replayed = replay_pcr(events, PCR_INDEX, "sha256")
        validate_quote_pcr12(args.quote_message.read_bytes(), replayed)
        validate_measured_cmdlines(events, expected_cmdline, args.expected_roothash)
    except (OSError, VerificationError) as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1

    print(
        "verification succeeded: quote, PCR 12 replay, and measured roothash match"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
