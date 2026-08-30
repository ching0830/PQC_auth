from __future__ import annotations

import unittest

from pq_sat_auth.framing import (
    FRAME_HEADER_BYTES,
    FrameType,
    ProtocolEncodingError,
    decode_frame,
    decode_opaque,
    encode_frame,
    encode_opaque,
)


class FrameV1Tests(unittest.TestCase):
    def test_empty_init_vector_is_frozen(self) -> None:
        encoded = encode_frame(FrameType.ACCESS_INIT, b"")
        self.assertEqual(
            encoded.hex(),
            "50515341542d41310001000100000000",
        )
        self.assertEqual(FRAME_HEADER_BYTES, 16)
        self.assertEqual(decode_frame(encoded).body, b"")

    def test_every_type_round_trips_exactly(self) -> None:
        for msg_type in FrameType:
            with self.subTest(msg_type=msg_type):
                body = bytes((int(msg_type), 0, 255))
                decoded = decode_frame(encode_frame(msg_type, body))
                self.assertEqual(decoded.msg_type, msg_type)
                self.assertEqual(decoded.body, body)
                self.assertEqual(decoded.version, 1)

    def test_noncanonical_frames_are_rejected(self) -> None:
        honest = bytearray(encode_frame(FrameType.ACCESS_INIT, b"abc"))
        cases: list[bytes] = []

        wrong_magic = honest.copy()
        wrong_magic[0] ^= 1
        cases.append(bytes(wrong_magic))

        wrong_version = honest.copy()
        wrong_version[9] = 2
        cases.append(bytes(wrong_version))

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
                    decode_frame(encoded)

    def test_frame_encoder_rejects_implicit_types_and_nonbytes(self) -> None:
        with self.assertRaises(TypeError):
            encode_frame(1, b"")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            encode_frame(FrameType.ACCESS_INIT, bytearray())  # type: ignore[arg-type]


class OpaqueV1Tests(unittest.TestCase):
    def test_multiple_opaque_fields_round_trip(self) -> None:
        body = encode_opaque(b"first") + encode_opaque(b"") + encode_opaque(b"x")
        first, offset = decode_opaque(body)
        second, offset = decode_opaque(body, offset)
        third, offset = decode_opaque(body, offset)
        self.assertEqual((first, second, third), (b"first", b"", b"x"))
        self.assertEqual(offset, len(body))

    def test_opaque_rejects_truncation_and_limits(self) -> None:
        with self.assertRaises(ProtocolEncodingError):
            decode_opaque(b"\x00\x00\x00")
        with self.assertRaises(ProtocolEncodingError):
            decode_opaque(b"\x00\x00\x00\x02x")
        with self.assertRaises(ProtocolEncodingError):
            decode_opaque(b"\x00\x00\x00\x02xy", max_length=1)
        with self.assertRaises(ValueError):
            encode_opaque(b"xy", max_length=1)


if __name__ == "__main__":
    unittest.main()
