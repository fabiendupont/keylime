"""
Unit tests for the keylime.spdm module (out-of-band SPDM evidence parsing and verification)
"""

# pylint: disable=protected-access

import datetime
import struct
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from keylime.spdm import (
    MeasurementBlock,
    SpdmError,
    chain_blob_from_pem,
    locate_measurements_message,
    parse_cert_chain,
    parse_measurements,
    signature_length,
    split_signed_message,
    verify_cert_chain,
    verify_signature,
)


def _make_key(curve=ec.SECP384R1()):
    return ec.generate_private_key(curve)


def _make_cert(key, issuer_key=None, issuer_cert=None, cn="Test Device"):
    issuer_key = issuer_key or key
    issuer_cert_subject = issuer_cert.subject if issuer_cert else None

    subject = issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    if issuer_cert is not None:
        issuer_name = issuer_cert_subject

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .sign(issuer_key, hashes.SHA384())
    )


def _chain_blob(certs):
    """Serialise certificates into an SPDM certificate chain blob (length-prefixed)."""
    body = b""
    for cert in certs:
        der = cert.public_bytes(serialization.Encoding.DER)
        body += struct.pack("<H", len(der)) + der
    return struct.pack("<H", len(body)) + body


def _make_measurements_message(nonce, blocks=None, opaque=b"", version=0x12, opaque_field=None):
    """Build a spec-conformant (DSP0274) MEASUREMENTS response.

    Measurement blocks use the two-level form Index(1) MeasurementSpecification(1)
    MeasurementSize(2) wrapping DMTFSpecMeasurementValueType(1) ValueSize(2) Value. The
    MeasurementRecordLength field is 3 bytes for SPDM 1.0/1.1 and 4 bytes from 1.2 on. By default the
    OpaqueDataLength field is emitted for SPDM 1.2+ only (strict 1.0/1.1 layout); pass
    opaque_field=True to emulate the de-facto CEC173x 1.1 variant that includes it anyway.
    """
    if blocks is None:
        blocks = [
            MeasurementBlock(index=1, measurement_spec=0x01, value_type=0x02, value=b"\xaa" * 48),
            MeasurementBlock(index=2, measurement_spec=0x01, value_type=0x03, value=b"\xbb" * 48),
        ]

    record = b""
    for block in blocks:
        measurement = struct.pack("<BH", block.value_type, len(block.value)) + block.value
        record += struct.pack("<BBH", block.index, block.measurement_spec, len(measurement)) + measurement

    message = struct.pack("<BBBBB", version, 0x60, 0x00, 0x00, len(blocks))
    if version <= 0x11:
        message += len(record).to_bytes(3, "little")
    else:
        message += struct.pack("<I", len(record))
    message += record
    message += nonce
    if opaque_field if opaque_field is not None else version >= 0x12:
        message += struct.pack("<H", len(opaque)) + opaque
    return message


class TestCertChain(unittest.TestCase):
    def test_parse_roundtrip(self):
        device_key = _make_key()
        root_key = _make_key()
        device_cert = _make_cert(device_key, issuer_key=root_key, cn="Device")
        root_cert = _make_cert(root_key, cn="Root")

        blob = _chain_blob([device_cert, root_cert])
        certs = parse_cert_chain(blob)

        self.assertEqual(len(certs), 2)
        self.assertEqual(certs[0].subject, device_cert.subject)

    def test_parse_rejects_short_blob(self):
        with self.assertRaises(SpdmError):
            parse_cert_chain(b"\x00")

    def test_parse_rejects_bad_total_length(self):
        device_cert = _make_cert(_make_key())
        blob = _chain_blob([device_cert])
        with self.assertRaises(SpdmError):
            parse_cert_chain(blob + b"\xff\xff\xff")

    def test_verify_chain(self):
        device_key = _make_key()
        root_key = _make_key()
        root_cert = _make_cert(root_key, cn="Root")
        device_cert = _make_cert(device_key, issuer_key=root_key, issuer_cert=root_cert, cn="Device")

        # Use the test's own root certificate as the trust store anchor
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as store:
            with open(os.path.join(store, "root.pem"), "wb") as f:
                f.write(root_cert.public_bytes(serialization.Encoding.PEM))

            verify_cert_chain([device_cert, root_cert], store)

    def test_verify_chain_rejects_untrusted_root(self):
        device_key = _make_key()
        root_key = _make_key()
        root_cert = _make_cert(root_key, cn="Root")
        device_cert = _make_cert(device_key, issuer_key=root_key, issuer_cert=root_cert, cn="Device")

        other_root = _make_cert(_make_key(), cn="Other Root")

        import os
        import tempfile

        with tempfile.TemporaryDirectory() as store:
            with open(os.path.join(store, "other.pem"), "wb") as f:
                f.write(other_root.public_bytes(serialization.Encoding.PEM))

            with self.assertRaises(SpdmError):
                verify_cert_chain([device_cert, root_cert], store)


class TestMeasurements(unittest.TestCase):
    def test_parse_roundtrip(self):
        nonce = b"\x11" * 32
        message = _make_measurements_message(nonce)

        blocks, parsed_nonce, opaque_length = parse_measurements(message)

        self.assertEqual(len(blocks), 2)
        self.assertEqual(blocks[0].index, 1)
        self.assertEqual(blocks[0].value, b"\xaa" * 48)
        self.assertEqual(blocks[1].index, 2)
        self.assertEqual(parsed_nonce, nonce)
        self.assertEqual(opaque_length, 0)

    def test_parse_rejects_wrong_message_code(self):
        nonce = b"\x00" * 32
        message = _make_measurements_message(nonce)
        message = bytes([message[0], 0x61]) + message[2:]

        with self.assertRaises(SpdmError):
            parse_measurements(message)

    def test_parse_rejects_truncated_message(self):
        with self.assertRaises(SpdmError):
            parse_measurements(b"\x12\x60\x00\x00")

    def test_parse_rejects_bad_block_count(self):
        nonce = b"\x00" * 32
        message = bytearray(_make_measurements_message(nonce))
        message[4] = 3  # claim three blocks but only two present

        with self.assertRaises(SpdmError):
            parse_measurements(bytes(message))


class TestSignature(unittest.TestCase):
    def test_verify_valid_signature(self):
        device_key = _make_key()
        device_cert = _make_cert(device_key)
        nonce = b"\x22" * 32
        message = _make_measurements_message(nonce)

        signature = device_key.sign(message, ec.ECDSA(hashes.SHA384()))
        verify_signature(message, signature, device_cert, "sha384")

    def test_verify_rejects_bad_signature(self):
        device_key = _make_key()
        other_key = _make_key()
        device_cert = _make_cert(device_key)
        nonce = b"\x22" * 32
        message = _make_measurements_message(nonce)

        signature = other_key.sign(message, ec.ECDSA(hashes.SHA384()))

        with self.assertRaises(SpdmError):
            verify_signature(message, signature, device_cert, "sha384")

    def test_verify_rejects_tampered_message(self):
        device_key = _make_key()
        device_cert = _make_cert(device_key)
        nonce = b"\x22" * 32
        message = _make_measurements_message(nonce)

        signature = device_key.sign(message, ec.ECDSA(hashes.SHA384()))
        tampered = message[:-1] + bytes([message[-1] ^ 0xFF])

        with self.assertRaises(SpdmError):
            verify_signature(tampered, signature, device_cert, "sha384")

    def test_verify_accepts_raw_spdm_signature(self):
        # SPDM conveys ECDSA signatures in raw r||s form, not DER
        device_key = _make_key()
        device_cert = _make_cert(device_key)
        nonce = b"\x22" * 32
        message = _make_measurements_message(nonce)

        der_signature = device_key.sign(message, ec.ECDSA(hashes.SHA384()))
        r, s = decode_dss_signature(der_signature)
        raw_signature = r.to_bytes(48, "big") + s.to_bytes(48, "big")

        verify_signature(message, raw_signature, device_cert, "sha384")

    def test_signature_length(self):
        self.assertEqual(signature_length("TPM_ALG_ECDSA_ECC_NIST_P384"), 96)
        self.assertEqual(signature_length("TPM_ALG_ECDSA_ECC_NIST_P256"), 64)
        self.assertEqual(signature_length("TPM_ALG_RSAPSS_3072"), 384)

        with self.assertRaises(SpdmError):
            signature_length("TPM_ALG_UNKNOWN")

    def test_split_signed_message(self):
        message = b"\x12\x60\x00\x00" + b"\x00" * 100
        signature = b"\x99" * 96
        blob = message + signature

        split_message, split_signature = split_signed_message(blob, 96)
        self.assertEqual(split_message, message)
        self.assertEqual(split_signature, signature)

    def test_chain_blob_from_pem(self):
        from cryptography.hazmat.primitives import serialization

        device_key = _make_key()
        root_key = _make_key()
        root_cert = _make_cert(root_key, cn="Root")
        device_cert = _make_cert(device_key, issuer_key=root_key, issuer_cert=root_cert, cn="Device")

        pem = (
            device_cert.public_bytes(serialization.Encoding.PEM).decode()
            + root_cert.public_bytes(serialization.Encoding.PEM).decode()
        )

        blob = chain_blob_from_pem(pem)
        certs = parse_cert_chain(blob)

        self.assertEqual(len(certs), 2)
        self.assertEqual(certs[0].subject, device_cert.subject)
        self.assertEqual(certs[1].subject, root_cert.subject)

    def test_chain_blob_from_pem_rejects_empty(self):
        with self.assertRaises(SpdmError):
            chain_blob_from_pem("not a pem at all")

    def test_locate_measurements_message_bare_response(self):
        nonce = b"\x00" * 32
        message = _make_measurements_message(nonce)

        # A bare (transcript-less) response is located at offset 0
        self.assertEqual(locate_measurements_message(message), 0)

    def test_locate_measurements_message_in_transcript(self):
        nonce = b"\x22" * 32
        response = _make_measurements_message(nonce)

        # L2 transcript: VCA || GET_MEASUREMENTS request || MEASUREMENTS response.
        # The VCA and request are opaque to the verifier (only included in the signature);
        # the request carries the nonce, the response is the only 0x60-coded message.
        vca = bytes.fromhex("12e2000000ff") + b"\x00" * 16
        request = bytes([0x12, 0xE0, 0x01, 0x00]) + nonce + b"\x00"
        transcript = vca + request + response

        offset = locate_measurements_message(transcript)
        self.assertEqual(offset, len(vca) + len(request))

        blocks, parsed_nonce, _ = parse_measurements(transcript[offset:])
        self.assertEqual(parsed_nonce, nonce)
        self.assertEqual(len(blocks), 2)

    def test_locate_measurements_message_rejects_garbage(self):
        with self.assertRaises(SpdmError):
            locate_measurements_message(b"\x00" * 64)


if __name__ == "__main__":
    unittest.main()
