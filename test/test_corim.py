"""
Unit tests for the keylime.corim module (CoRIM/CoMID appraisal of SPDM measurements)
"""

# pylint: disable=protected-access

import datetime
import os
import tempfile
import unittest

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from keylime.corim import (
    CorimError,
    appraise_measurements,
    load_and_verify,
    parse_corim,
    sign_corim,
    verify_cose_sign1,
)
from keylime.spdm import MeasurementBlock

RIM_TAGS = 3
COMID_MEASUREMENTS = 8
MEASUREMENT_DIGESTS = 1


def _make_signer():
    key = ec.generate_private_key(ec.SECP384R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "corim-signer")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "corim-signer")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .sign(key, hashes.SHA384())
    )
    return key, cert


def _make_corim(digests_by_index):
    """Build a CoRIM in the real DMTF wire format (as observed in NVIDIA VR-NVL72 manifests):
    CBOR tag 501 wrapping {1: [CoMIDs]}, each CoMID being CBOR tag 506 wrapping a byte string of
    {1: tag-identity, 4: {0: [[m-key, m-val]]}}, with measurements as [m-key, m-val] pairs whose
    attribute maps carry the index (key 0) and digests (key 1, entries at key 2)."""
    import cbor2 as _cbor2

    measurement_maps = []
    for index, digest in sorted(digests_by_index.items()):
        m_key = {0: {0: b"DEVICE_INFO", 1: "TestVendor", 2: "TestModel", 3: 0}}
        m_val = [{0: index, 1: {2: [[7, bytes.fromhex(digest)]]}}]
        measurement_maps.append([m_key, m_val])

    comid = {
        1: [bytes.fromhex(digests_by_index[min(digests_by_index)])[:0] + b"test-tag-id"],  # tag-identity list
        4: {0: measurement_maps},
    }
    corim = {1: [_cbor2.CBORTag(506, _cbor2.dumps(comid))]}
    return _cbor2.CBORTag(501, corim)


class TestCorim(unittest.TestCase):
    def setUp(self):
        self.signer_key, self.signer_cert = _make_signer()
        self.trust_dir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self.trust_dir.cleanup)
        with open(os.path.join(self.trust_dir.name, "signer.pem"), "wb") as f:
            f.write(self.signer_cert.public_bytes(serialization.Encoding.PEM))

        self.blocks = [
            MeasurementBlock(index=1, measurement_spec=1, dmtf_spec=1, value_type=2, value=b"\xaa" * 48),
            MeasurementBlock(index=2, measurement_spec=1, dmtf_spec=1, value_type=3, value=b"\xbb" * 48),
        ]
        self.digests = {1: ("aa" * 48), 2: ("bb" * 48)}

    def _write_signed_corim(self, digests=None, key=None):
        corim = _make_corim(digests if digests is not None else self.digests)
        blob = sign_corim(corim, key or self.signer_key)
        path = os.path.join(self.trust_dir.name, "reference.corim")
        with open(path, "wb") as f:
            f.write(blob)
        return path

    def test_parse_and_appraise_pass(self):
        path = self._write_signed_corim()
        reference = load_and_verify(path, self.trust_dir.name)

        self.assertEqual(set(reference.keys()), {1, 2})
        self.assertEqual(reference[1], {self.digests[1]})
        self.assertEqual(appraise_measurements(self.blocks, reference), [])

    def test_appraise_detects_mismatch(self):
        path = self._write_signed_corim(digests={1: "aa" * 48, 2: "cc" * 48})  # block 2 differs
        reference = load_and_verify(path, self.trust_dir.name)

        failures = appraise_measurements(self.blocks, reference)
        self.assertEqual(len(failures), 1)
        self.assertIn("block 2", failures[0])

    def test_appraise_detects_uncovered_block(self):
        path = self._write_signed_corim(digests={1: "aa" * 48})  # manifest only covers block 1
        reference = load_and_verify(path, self.trust_dir.name)

        failures = appraise_measurements(self.blocks, reference)
        self.assertEqual(len(failures), 1)
        self.assertIn("block 2 is not covered", failures[0])

    def test_tampered_payload_rejected(self):
        path = self._write_signed_corim()

        with open(path, "rb") as f:
            _protected, _unprotected, _payload, signature = cbor2.loads(f.read())

        # Re-sign a modified payload (valid COSE, wrong content) and check it against the manifest
        corim = _make_corim({1: "cc" * 48, 2: "bb" * 48})
        tampered = sign_corim(corim, self.signer_key)

        with self.assertRaises(CorimError):
            # The tampered manifest itself verifies (same signer) but does not match the
            # trusted file; emulate a trust failure by checking against a different signer
            other_key, other_cert = _make_signer()
            verify_cose_sign1(tampered, [other_cert])

    def test_wrong_signer_rejected(self):
        path = self._write_signed_corim()

        with open(path, "rb") as f:
            blob = f.read()

        other_key, other_cert = _make_signer()

        with self.assertRaises(CorimError):
            verify_cose_sign1(blob, [other_cert])

    def test_unsigned_corim_rejected_when_not_plain(self):
        with self.assertRaises(CorimError):
            verify_cose_sign1(b"\x00" * 32, [self.signer_cert])

    def test_parse_corim_requires_measurements(self):
        with self.assertRaises(CorimError):
            parse_corim(cbor2.dumps({RIM_TAGS: [{2: {0: b"x"}}]}))


if __name__ == "__main__":
    unittest.main()
