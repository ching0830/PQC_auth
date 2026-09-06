#!/usr/bin/env python3
"""Strict codec and public-surface tests for conditional opening."""

from __future__ import annotations

import unittest
from dataclasses import replace

import pq_rbbc.opening as opening
from pq_rbbc.opening.request import (
    MAX_REQUEST_BYTES,
    MAX_TICKET_BYTES,
    OPENING_REQUEST_MAGIC,
    OpeningCodecError,
    OpeningRequest,
)
from pq_rbbc.opening.shares import OPEN_SHARE_MAGIC, OpenShare
from pq_rbbc.opening.shares import MAX_OPEN_SHARE_BYTES, MAX_SHARE_VALUE_BYTES

from tests.system_modules.opening._fixtures import honest_share, reference_request


def field_offsets(encoded: bytes, magic: bytes) -> list[int]:
    count = int.from_bytes(encoded[len(magic) + 2 : len(magic) + 4], "little")
    offset = len(magic) + 4
    result: list[int] = []
    for _index in range(count):
        result.append(offset)
        length = int.from_bytes(encoded[offset + 1 : offset + 5], "little")
        offset += 5 + length
    return result


class OpeningRequestCodecTests(unittest.TestCase):
    def test_request_round_trip_and_digests_are_deterministic(self) -> None:
        request = reference_request()
        encoded = request.encode()
        self.assertEqual(OpeningRequest.decode(encoded), request)
        self.assertEqual(len(request.ticket_digest), 32)
        self.assertEqual(len(request.request_digest), 32)
        self.assertEqual(len(request.replay_key), 32)

    def test_unknown_protocol_version_rejects(self) -> None:
        with self.assertRaises(OpeningCodecError):
            replace(reference_request(), protocol_version=2).encode()

    def test_request_parser_rejects_malformed_encodings(self) -> None:
        encoded = reference_request().encode()
        offsets = field_offsets(encoded, OPENING_REQUEST_MAGIC)
        duplicate = bytearray(encoded)
        duplicate[offsets[1]] = duplicate[offsets[0]]
        wrong_order = bytearray(encoded)
        wrong_order[offsets[0]] = 2
        unknown_schema = bytearray(encoded)
        unknown_schema[len(OPENING_REQUEST_MAGIC)] = 2
        oversized_ticket = bytearray(encoded)
        oversized_ticket[offsets[1] + 1 : offsets[1] + 5] = (
            MAX_TICKET_BYTES + 1
        ).to_bytes(4, "little")
        cases = {
            "wrong_magic": bytes([encoded[0] ^ 1]) + encoded[1:],
            "unknown_schema": bytes(unknown_schema),
            "wrong_order": bytes(wrong_order),
            "duplicate": bytes(duplicate),
            "truncated": encoded[:-1],
            "oversized_field": bytes(oversized_ticket),
            "oversized_message": b"x" * (MAX_REQUEST_BYTES + 1),
            "trailing": encoded + b"\x00",
        }
        for name, candidate in cases.items():
            with self.subTest(name=name), self.assertRaises(OpeningCodecError):
                OpeningRequest.decode(candidate)


class OpenShareCodecTests(unittest.TestCase):
    def test_share_round_trip(self) -> None:
        share = honest_share(1)
        self.assertEqual(OpenShare.decode(share.encode()), share)

    def test_share_parser_rejects_malformed_encodings(self) -> None:
        encoded = honest_share(1).encode()
        offsets = field_offsets(encoded, OPEN_SHARE_MAGIC)
        duplicate = bytearray(encoded)
        duplicate[offsets[1]] = duplicate[offsets[0]]
        wrong_order = bytearray(encoded)
        wrong_order[offsets[0]] = 2
        unknown_schema = bytearray(encoded)
        unknown_schema[len(OPEN_SHARE_MAGIC)] = 2
        oversized_value = bytearray(encoded)
        oversized_value[offsets[7] + 1 : offsets[7] + 5] = (
            MAX_SHARE_VALUE_BYTES + 1
        ).to_bytes(4, "little")
        cases = {
            "wrong_magic": bytes([encoded[0] ^ 1]) + encoded[1:],
            "unknown_schema": bytes(unknown_schema),
            "wrong_order": bytes(wrong_order),
            "duplicate": bytes(duplicate),
            "truncated": encoded[:-1],
            "oversized_field": bytes(oversized_value),
            "oversized_message": b"x" * (MAX_OPEN_SHARE_BYTES + 1),
            "trailing": encoded + b"\x00",
        }
        for name, candidate in cases.items():
            with self.subTest(name=name), self.assertRaises(OpeningCodecError):
                OpenShare.decode(candidate)

    def test_package_exposes_no_bare_partial_decrypt_api(self) -> None:
        public = set(opening.__all__)
        self.assertFalse(any("decrypt" in name.lower() for name in public))
        service_methods = {
            name
            for name in dir(opening.OpenShareService)
            if not name.startswith("_")
        }
        self.assertEqual(service_methods, {"open_share"})


if __name__ == "__main__":
    unittest.main()
