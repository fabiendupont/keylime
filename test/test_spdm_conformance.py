"""
Conformance tests for the keylime.spdm parser against the DMTF DSP0274 wire format.

The vectors below are synthetic but structurally faithful, and the layout was
validated against DMTF's own tooling (libspdm reference implementation and the
spdm-dump parser, into which the real Lenovo GB300 NVL72 / Microchip CEC173x
capture was fed via a crafted MCTP pcap):

- MeasurementRecordLength is a 3-byte uint24 in every published DSP0274 version
  (1.0 through 1.4); libspdm encodes and decodes it as uint24 unconditionally
- The OpaqueDataLength field follows the nonce in every version
- SPDM 1.3+ responses carry an 8-byte requester context after the opaque data

Measurement blocks are two-level in every version, per DSP0274:

    Index(1) MeasurementSpecification(1) MeasurementSize(2)
    DMTFSpecMeasurementValueType(1) ValueSize(2) Value(var)   [MeasurementSize == 3 + ValueSize]

The CEC173x vector mirrors the shape of a real Lenovo GB300 NVL72 capture (64
blocks, indices 1..N, ECDSA-P384 signature over request || response in raw
r||s form) with synthetic values, so that no real device identifiers are
committed to the repository.
"""

import struct
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from keylime.spdm import (
    MeasurementBlock,
    SpdmError,
    find_request_nonce,
    locate_measurements_message,
    parse_measurements,
    verify_signature,
)

SPDM_GET_MEASUREMENTS = 0xE0
SPDM_MEASUREMENTS = 0x60
SPDM_REQ_CONTEXT_SIZE = 8


def _block(index, value_type, value, spec=0x01):
    """Encode one DSP0274 MeasurementBlock (two-level, DMTF measurement spec)."""
    measurement = struct.pack("<BH", value_type, len(value)) + value
    return struct.pack("<BBH", index, spec, len(measurement)) + measurement


def _response(version, blocks, nonce, opaque=b"", opaque_field=True):
    """Encode a MEASUREMENTS response (without signature) for the given SPDM version.

    Follows the layout common to all DSP0274 versions: uint24
    MeasurementRecordLength, nonce, OpaqueDataLength + OpaqueData, and (for
    SPDM 1.3+) the 8-byte requester context. Pass opaque_field=False to build
    the non-conformant variant that omits the OpaqueDataLength field (used by
    negative tests only).
    """
    record = b"".join(_block(b.index, b.value_type, b.value, b.measurement_spec) for b in blocks)
    message = struct.pack("<BBBBB", version, SPDM_MEASUREMENTS, 0x00, 0x00, len(blocks))
    message += len(record).to_bytes(3, "little")
    message += record + nonce
    if opaque_field:
        message += struct.pack("<H", len(opaque)) + opaque
    if version >= 0x13:
        message += b"\x00" * SPDM_REQ_CONTEXT_SIZE
    return message


def _request(version, nonce, param1=0x01, slot=0x00):
    """Encode a GET_MEASUREMENTS request: version, code, param1, param2, nonce(32), slot(1)."""
    return struct.pack("<BBBB", version, SPDM_GET_MEASUREMENTS, param1, 0x00) + nonce + bytes([slot])


BLOCKS = [
    MeasurementBlock(index=1, measurement_spec=0x01, value_type=0x03, value=b"\x01\x00\x04\x02"),
    MeasurementBlock(index=2, measurement_spec=0x01, value_type=0x83, value=b"HMC\x00"),
    MeasurementBlock(index=3, measurement_spec=0x01, value_type=0x01, value=bytes(range(48))),
    MeasurementBlock(index=4, measurement_spec=0x01, value_type=0x02, value=b"\xab" * 48),
    MeasurementBlock(index=5, measurement_spec=0x01, value_type=0x82, value=b"\x0d\x0e\x0a\x0d"),
]

REQUESTER_NONCE = bytes(range(32))
RESPONDER_NONCE = bytes(range(32, 64))


class TestSpecConformantVectors(unittest.TestCase):
    """Positive vectors: every supported SPDM version must parse and round-trip."""

    def _roundtrip(self, version, opaque=b""):
        message = _response(version, BLOCKS, RESPONDER_NONCE, opaque=opaque)
        blocks, nonce, opaque_length = parse_measurements(message)

        self.assertEqual(len(blocks), len(BLOCKS))
        for parsed, expected in zip(blocks, BLOCKS):
            self.assertEqual(parsed.index, expected.index)
            self.assertEqual(parsed.measurement_spec, expected.measurement_spec)
            self.assertEqual(parsed.value_type, expected.value_type)
            self.assertEqual(parsed.value, expected.value)
        self.assertEqual(nonce, RESPONDER_NONCE)
        self.assertEqual(opaque_length, len(opaque))

    def test_spdm_10(self):
        self._roundtrip(0x10)

    def test_spdm_11_cec173x_layout(self):
        # The CEC173x (GB300 rack eRoT) wire format: SPDM 1.1, uint24 record
        # length, OpaqueDataLength present — fully DSP0274-conformant
        self._roundtrip(0x11)

    def test_spdm_11_with_opaque_data(self):
        self._roundtrip(0x11, opaque=b"\xde\xad\xbe\xef")

    def test_spdm_12(self):
        self._roundtrip(0x12)

    def test_spdm_12_with_opaque_data(self):
        self._roundtrip(0x12, opaque=b"\x01\x02\x03")

    def test_spdm_13(self):
        # SPDM 1.3 adds the 8-byte requester context after the opaque data
        self._roundtrip(0x13)

    def test_empty_value_block(self):
        # A DMTF measurement with an empty value is legal (MeasurementSize == 3)
        message = _response(0x12, [MeasurementBlock(1, 0x01, 0x02, b"")], RESPONDER_NONCE)
        blocks, _, _ = parse_measurements(message)
        self.assertEqual(blocks[0].value, b"")


class TestLocateAndRequestNonce(unittest.TestCase):
    """Locating the response in a signed transcript and extracting the request nonce."""

    def _locate(self, version):
        response = _response(version, BLOCKS, RESPONDER_NONCE)
        prefix = b"\x12\xe2\x00\x00\x00\xff" + b"\x00" * 16  # stand-in VCA, opaque to the verifier
        request = _request(version, REQUESTER_NONCE)
        transcript = prefix + request + response

        offset = locate_measurements_message(transcript)
        self.assertEqual(offset, len(prefix) + len(request))

        blocks, nonce, _ = parse_measurements(transcript[offset:])
        self.assertEqual(len(blocks), len(BLOCKS))
        self.assertEqual(nonce, RESPONDER_NONCE)

        self.assertEqual(find_request_nonce(transcript[:offset]), REQUESTER_NONCE)

    def test_locate_spdm_11(self):
        self._locate(0x11)

    def test_locate_spdm_12(self):
        self._locate(0x12)

    def test_locate_spdm_13(self):
        self._locate(0x13)

    def test_locate_bare_response(self):
        response = _response(0x12, BLOCKS, RESPONDER_NONCE)
        self.assertEqual(locate_measurements_message(response), 0)

    def test_find_request_nonce_absent(self):
        self.assertIsNone(find_request_nonce(b"\x00" * 64))
        self.assertIsNone(find_request_nonce(_response(0x12, BLOCKS, RESPONDER_NONCE)))

    def test_locate_rejects_trailing_data(self):
        response = _response(0x12, BLOCKS, RESPONDER_NONCE)
        with self.assertRaises(SpdmError):
            locate_measurements_message(response + b"\x00")

    def test_locate_rejects_garbage(self):
        with self.assertRaises(SpdmError):
            locate_measurements_message(b"\x00" * 64)


class TestCec173xFidelityVector(unittest.TestCase):
    """A signed statement shaped like a real GB300 NVL72 capture (synthetic values).

    Transcript layout, as emitted by the rack's CEC173x eRoTs and parsed by NVIDIA's
    Attestation SDK: GET_MEASUREMENTS request (37 bytes) || SPDM 1.1 MEASUREMENTS response
    (3-byte record length, 64 blocks, OpaqueDataLength=0) || ECDSA-P384 signature in raw
    r||s form over request || response.
    """

    @classmethod
    def setUpClass(cls):
        cls.device_key = ec.generate_private_key(ec.SECP384R1())
        cls.device_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-erot")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-erot")]))
            .public_key(cls.device_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(__import__("datetime").datetime.now(__import__("datetime").timezone.utc))
            .not_valid_after(__import__("datetime").datetime(2049, 12, 31))
            .sign(cls.device_key, hashes.SHA384())
        )

        # 64 blocks with index range and value-type mix mirroring the real capture
        cls.blocks = [
            MeasurementBlock(
                index=i + 1,
                measurement_spec=0x01,
                value_type=[0x03, 0x83, 0x01, 0x02, 0x81, 0x82][i % 6],
                value=bytes([(i * 7) % 256]) * (4 if i % 6 in (0, 1, 4) else 48),
            )
            for i in range(64)
        ]
        cls.request = _request(0x11, REQUESTER_NONCE)
        cls.response = _response(0x11, cls.blocks, RESPONDER_NONCE, opaque_field=True)
        cls.transcript = cls.request + cls.response

        der_sig = cls.device_key.sign(cls.transcript, ec.ECDSA(hashes.SHA384()))
        r, s = decode_dss_signature(der_sig)
        cls.signature = r.to_bytes(48, "big") + s.to_bytes(48, "big")

    def test_locate_finds_response_after_request(self):
        self.assertEqual(locate_measurements_message(self.transcript), len(self.request))

    def test_parse_all_blocks(self):
        blocks, nonce, opaque_length = parse_measurements(self.transcript[len(self.request) :])

        self.assertEqual(len(blocks), 64)
        self.assertEqual([b.index for b in blocks], list(range(1, 65)))
        self.assertEqual(nonce, RESPONDER_NONCE)
        self.assertNotEqual(nonce, REQUESTER_NONCE)  # the responder nonce is its own
        self.assertEqual(opaque_length, 0)

    def test_request_nonce_in_transcript(self):
        self.assertEqual(find_request_nonce(self.transcript), REQUESTER_NONCE)

    def test_signature_verifies_over_transcript(self):
        verify_signature(self.transcript, self.signature, self.device_cert, "sha384")

    def test_signature_rejects_tampering(self):
        tampered = bytearray(self.transcript)
        tampered[-1] ^= 0xFF
        with self.assertRaises(SpdmError):
            verify_signature(bytes(tampered), self.signature, self.device_cert, "sha384")


class TestMalformedVectors(unittest.TestCase):
    """Negative vectors: every malformed condition must be rejected, never mis-parsed."""

    def _message(self, **kwargs):
        return _response(kwargs.get("version", 0x12), BLOCKS, RESPONDER_NONCE, **kwargs)

    def test_rejects_unsupported_version(self):
        message = bytearray(self._message())
        message[0] = 0x0F
        with self.assertRaises(SpdmError):
            parse_measurements(bytes(message))

    def test_rejects_wrong_message_code(self):
        message = bytearray(self._message())
        message[1] = 0x61
        with self.assertRaises(SpdmError):
            parse_measurements(bytes(message))

    def test_rejects_truncated_header(self):
        with self.assertRaises(SpdmError):
            parse_measurements(b"\x12\x60\x00\x00")

    def test_rejects_record_length_exceeding_message(self):
        message = bytearray(self._message())
        message[5:8] = (0xFFFFFF).to_bytes(3, "little")
        with self.assertRaises(SpdmError):
            parse_measurements(bytes(message))

    def test_rejects_uint32_style_record_length(self):
        # A 4-byte MeasurementRecordLength (a common misreading of DSP0274 1.2)
        # shifts the nonce by one byte and must be rejected: the field is a
        # uint24 in every version, per libspdm
        record = b"".join(_block(b.index, b.value_type, b.value) for b in BLOCKS)
        message = (
            struct.pack("<BBBBB", 0x12, SPDM_MEASUREMENTS, 0, 0, len(BLOCKS))
            + struct.pack("<I", len(record))
            + record
            + RESPONDER_NONCE
            + struct.pack("<H", 0)
        )
        with self.assertRaises(SpdmError):
            parse_measurements(message)

    def test_rejects_block_count_mismatch(self):
        message = bytearray(self._message())
        message[4] = len(BLOCKS) + 1
        with self.assertRaises(SpdmError):
            parse_measurements(bytes(message))

    def test_rejects_measurement_exceeding_record(self):
        # Claim a MeasurementSize that runs past the end of the record
        block = _block(1, 0x02, b"\xaa" * 48)
        record = struct.pack("<BBH", 1, 0x01, 1000) + block[4:]
        message = (
            struct.pack("<BBBBB", 0x12, SPDM_MEASUREMENTS, 0, 0, 1)
            + struct.pack("<I", len(record))
            + record
            + RESPONDER_NONCE
            + struct.pack("<H", 0)
        )
        with self.assertRaises(SpdmError):
            parse_measurements(message)

    def test_rejects_inner_size_mismatch(self):
        # MeasurementSize != 3 + ValueSize must be rejected (strict DSP0274)
        measurement = struct.pack("<BH", 0x02, 48) + b"\xaa" * 40  # claims 48, provides 40
        record = struct.pack("<BBH", 1, 0x01, len(measurement) + 8) + measurement  # and lies again
        message = (
            struct.pack("<BBBBB", 0x12, SPDM_MEASUREMENTS, 0, 0, 1)
            + struct.pack("<I", len(record))
            + record
            + RESPONDER_NONCE
            + struct.pack("<H", 0)
        )
        with self.assertRaises(SpdmError):
            parse_measurements(message)

    def test_rejects_measurement_too_short(self):
        # MeasurementSize < 3: no room for ValueType + ValueSize
        record = struct.pack("<BBH", 1, 0x01, 2) + b"\x02\x00"
        message = (
            struct.pack("<BBBBB", 0x12, SPDM_MEASUREMENTS, 0, 0, 1)
            + struct.pack("<I", len(record))
            + record
            + RESPONDER_NONCE
            + struct.pack("<H", 0)
        )
        with self.assertRaises(SpdmError):
            parse_measurements(message)

    def test_rejects_missing_opaque_length(self):
        # OpaqueDataLength is part of the MEASUREMENTS layout in every version;
        # a message ending at the nonce is malformed (rejected by spdm-dump too)
        message = self._message()
        message = message[:-2]
        with self.assertRaises(SpdmError):
            parse_measurements(message)

    def test_rejects_spdm_13_missing_requester_context(self):
        # SPDM 1.3 responses carry an 8-byte requester context after the opaque data
        message = _response(0x13, BLOCKS, RESPONDER_NONCE)
        with self.assertRaises(SpdmError):
            parse_measurements(message[:-SPDM_REQ_CONTEXT_SIZE])

    def test_rejects_trailing_data_after_opaque(self):
        with self.assertRaises(SpdmError):
            parse_measurements(self._message() + b"\x00")

    def test_rejects_spdm_11_stray_bytes_after_nonce(self):
        # A 1.1 message with no well-formed OpaqueDataLength field
        message = _response(0x11, BLOCKS, RESPONDER_NONCE, opaque_field=False)
        with self.assertRaises(SpdmError):
            parse_measurements(message + b"\xff\xff\xff")

    def test_rejects_truncated_before_nonce(self):
        message = self._message()
        with self.assertRaises(SpdmError):
            parse_measurements(message[: len(message) - 40])


if __name__ == "__main__":
    unittest.main()
