from __future__ import annotations

import unittest

from pq_sat_auth.v2.framing import (
    FRAME_HEADER_BYTES,
    FrameTypeV2,
    ProtocolEncodingError,
    decode_frame_v2,
    decode_opaque_v2,
    encode_frame_v2,
    encode_opaque_v2,
)


class FrameV2Tests(unittest.TestCase):
    def test_empty_request_vector_is_frozen(self) -> None:
        encoded = encode_frame_v2(FrameTypeV2.ACCESS_REQUEST, b"")
        self.assertEqual(
            encoded.hex(),
            "50515341542d41320002010100000000",
        )
        self.assertEqual(FRAME_HEADER_BYTES, 16)
        self.assertEqual(decode_frame_v2(encoded).body, b"")

    def test_every_type_round_trips_exactly(self) -> None:
        for msg_type in FrameTypeV2:
            with self.subTest(msg_type=msg_type):
                body = bytes((int(msg_type) & 0xFF, 0, 255))
                decoded = decode_frame_v2(encode_frame_v2(msg_type, body))
                self.assertEqual(decoded.msg_type, msg_type)
                self.assertEqual(decoded.body, body)
                self.assertEqual(decoded.version, 2)

    def test_v1_and_noncanonical_frames_are_rejected(self) -> None:
        honest = bytearray(encode_frame_v2(FrameTypeV2.ACCESS_REQUEST, b"abc"))
        cases: list[bytes] = []

        wrong_magic = honest.copy()
        wrong_magic[-len(honest)] ^= 1
        cases.append(bytes(wrong_magic))

        v1_magic_and_version = honest.copy()
        v1_magic_and_version[7] = ord("1")
        v1_magic_and_version[8:10] = (1).to_bytes(2, "big")
        cases.append(bytes(v1_magic_and_version))

        unknown_type = honest.copy()
        unknown_type[10:12] = b"\xff\xff"
        cases.append(bytes(unknown_type))

        short_length = honest.copy()
        short_length[12:16] = (2).to_bytes(4, "big")
        cases.append(bytes(short_length))

        long_length = honest.copy()
        long_length[12:16] = (4).to_bytes(4, "big")
        cases.append(bytes(long_length))

        cases.append(bytes(honest) + b"\x00")
        cases.append(bytes(honest[:15]))

        for encoded in cases:
            with self.subTest(encoded=encoded.hex()):
                with self.assertRaises(ProtocolEncodingError):
                    decode_frame_v2(encoded)

    def test_frame_encoder_rejects_implicit_types_and_nonbytes(self) -> None:
        with self.assertRaises(TypeError):
            encode_frame_v2(0x0101, b"")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            encode_frame_v2(
                FrameTypeV2.ACCESS_REQUEST,
                bytearray(),  # type: ignore[arg-type]
            )


class OpaqueV2Tests(unittest.TestCase):
    def test_multiple_opaque_fields_round_trip(self) -> None:
        body = (
            encode_opaque_v2(b"first")
            + encode_opaque_v2(b"")
            + encode_opaque_v2(b"x")
        )
        first, offset = decode_opaque_v2(body)
        second, offset = decode_opaque_v2(body, offset)
        third, offset = decode_opaque_v2(body, offset)
        self.assertEqual((first, second, third), (b"first", b"", b"x"))
        self.assertEqual(offset, len(body))

    def test_opaque_rejects_truncation_and_limits(self) -> None:
        with self.assertRaises(ProtocolEncodingError):
            decode_opaque_v2(b"\x00\x00\x00")
        with self.assertRaises(ProtocolEncodingError):
            decode_opaque_v2(b"\x00\x00\x00\x02x")
        with self.assertRaises(ProtocolEncodingError):
            decode_opaque_v2(b"\x00\x00\x00\x02xy", max_length=1)
        with self.assertRaises(ValueError):
            encode_opaque_v2(b"xy", max_length=1)


if __name__ == "__main__":
    unittest.main()
