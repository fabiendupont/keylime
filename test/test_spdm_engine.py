"""
Unit tests for keylime.verification.spdm_engine module
"""

# pylint: disable=protected-access,attribute-defined-outside-init
# Testing requires access to protected methods and dynamic test attributes

import base64
import datetime
import os
import struct
import unittest
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from keylime.failure import Component, Failure
from keylime.spdm import MeasurementBlock
from keylime.verification.spdm_engine import SPDMEngine


def _make_cert(key, cn="Test Device"):
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .sign(key, hashes.SHA384())
    )


def _make_chain_blob(cert):
    der = cert.public_bytes(serialization.Encoding.DER)
    body = struct.pack("<H", len(der)) + der
    return struct.pack("<H", len(body)) + body


def _make_signed_message(device_key, nonce, responder_nonce=None, include_transcript=False):
    """Build a signed MEASUREMENTS statement in the DSP0274 wire format.

    By default a bare response whose responder nonce is the given nonce (legacy collector behavior).
    With include_transcript=True, builds a full L2 transcript: GET_MEASUREMENTS request carrying the
    requester's (verifier's) nonce, followed by a response with an independently generated responder
    nonce — the conformant flow, where freshness rests on the signed request.
    """
    block = MeasurementBlock(index=1, measurement_spec=1, value_type=2, value=b"\xaa" * 48)
    measurement = struct.pack("<BH", block.value_type, len(block.value)) + block.value
    record = struct.pack("<BBH", block.index, block.measurement_spec, len(measurement)) + measurement

    response = struct.pack("<BBBBB", 0x12, 0x60, 0x00, 0x00, 1)
    response += struct.pack("<I", len(record)) + record
    response += responder_nonce or nonce
    response += struct.pack("<H", 0)

    message = b""
    if include_transcript:
        # GET_MEASUREMENTS request: version, code(0xE0), param1, param2, nonce(32), slot(1)
        message += struct.pack("<BBBB", 0x12, 0xE0, 0x01, 0x00) + nonce + b"\x00"
    message += response

    signature = device_key.sign(message, ec.ECDSA(hashes.SHA384()))
    return message, signature


class TestSPDMEngine(unittest.TestCase):
    def setUp(self):
        self.device_key = ec.generate_private_key(ec.SECP384R1())
        self.device_cert = _make_cert(self.device_key)
        self.chain_blob = _make_chain_blob(self.device_cert)
        self.chain_b64 = base64.b64encode(self.chain_blob).decode("utf-8")
        self.nonce = b"\x33" * 32

        message, signature = _make_signed_message(self.device_key, self.nonce)

        # Mock attestation and evidence item
        self.mock_item = MagicMock()
        self.mock_item.data.message = message
        self.mock_item.data.signature = signature
        self.mock_item.data.meta = {"spdm_cert_chain": self.chain_b64}
        self.mock_item.chosen_parameters.hash_algorithm = "sha384"
        self.mock_item.chosen_parameters.challenge = self.nonce
        self.mock_item.results.meta = {}

        mock_view = MagicMock()
        mock_view.filter.return_value = mock_view
        mock_view.result.return_value = [self.mock_item]
        mock_view.to_list.return_value = [self.mock_item]

        self.mock_evidence = MagicMock()
        self.mock_evidence.view.return_value = mock_view

        self.mock_attestation = MagicMock()
        self.mock_attestation.agent_id = "test-agent-123"
        self.mock_attestation.index = 0
        self.mock_attestation.evaluation = "pending"
        self.mock_attestation.failure_reason = None
        self.mock_attestation.evidence = self.mock_evidence

        self.engine = SPDMEngine(self.mock_attestation)

    def _trust_store(self, *_args):
        import tempfile

        store = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(store.cleanup)
        with open(os.path.join(store.name, "device.pem"), "wb") as f:
            f.write(self.device_cert.public_bytes(serialization.Encoding.PEM))
        return store.name

    def test_verify_evidence_pass(self):
        with patch.object(self.engine, "_trust_store", self._trust_store):
            self.engine.verify_evidence()

        self.assertEqual(self.mock_attestation.evaluation, "pass")
        self.assertFalse(self.mock_attestation.failure_reason)
        self.assertIn("measurements", self.mock_item.results.meta)

    def test_verify_evidence_pass_transcript_freshness(self):
        # Conformant flow: the responder generates its own nonce; freshness rests on the signed
        # GET_MEASUREMENTS request carrying the verifier's challenge
        message, signature = _make_signed_message(
            self.device_key, self.nonce, responder_nonce=b"\x55" * 32, include_transcript=True
        )
        self.mock_item.data.message = message
        self.mock_item.data.signature = signature

        with patch.object(self.engine, "_trust_store", self._trust_store):
            self.engine.verify_evidence()

        self.assertEqual(self.mock_attestation.evaluation, "pass")
        self.assertFalse(self.mock_attestation.failure_reason)

    def test_verify_evidence_stale_transcript(self):
        # Transcript present but the request carries a nonce other than the verifier's challenge
        message, signature = _make_signed_message(
            self.device_key, b"\x66" * 32, responder_nonce=b"\x55" * 32, include_transcript=True
        )
        self.mock_item.data.message = message
        self.mock_item.data.signature = signature

        with patch.object(self.engine, "_trust_store", self._trust_store):
            self.engine.verify_evidence()

        self.assertEqual(self.mock_attestation.evaluation, "fail")
        self.assertEqual(self.mock_attestation.failure_reason, "broken_evidence_chain")

    def test_verify_evidence_bad_signature(self):
        message, _ = _make_signed_message(self.device_key, self.nonce)
        _, bad_signature = _make_signed_message(ec.generate_private_key(ec.SECP384R1()), self.nonce)
        self.mock_item.data.signature = bad_signature

        with patch.object(self.engine, "_trust_store", self._trust_store):
            self.engine.verify_evidence()

        self.assertEqual(self.mock_attestation.evaluation, "fail")
        self.assertEqual(self.mock_attestation.failure_reason, "broken_evidence_chain")

    def test_verify_evidence_nonce_mismatch(self):
        message, signature = _make_signed_message(self.device_key, b"\x44" * 32)
        self.mock_item.data.message = message
        self.mock_item.data.signature = signature

        with patch.object(self.engine, "_trust_store", self._trust_store):
            self.engine.verify_evidence()

        self.assertEqual(self.mock_attestation.evaluation, "fail")
        self.assertEqual(self.mock_attestation.failure_reason, "broken_evidence_chain")

    def test_verify_evidence_untrusted_chain(self):
        with patch.object(self.engine, "_trust_store", side_effect=lambda *_: "/nonexistent/trust/store"):
            self.engine.verify_evidence()

        self.assertEqual(self.mock_attestation.evaluation, "fail")
        self.assertEqual(self.mock_attestation.failure_reason, "broken_evidence_chain")

    def test_verify_evidence_policy_violation(self):
        import json
        import tempfile

        policy_file = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)  # pylint: disable=consider-using-with
        self.addCleanup(os.unlink, policy_file.name)
        json.dump({"1": "0x" + "bb" * 48}, policy_file)  # expected value differs from the signed measurement
        policy_file.close()

        def json_config_get(section, option, fallback=None):
            if option == "spdm_measurement_policy":
                return policy_file.name
            return fallback

        with patch.object(self.engine, "_trust_store", self._trust_store), patch(
            "keylime.verification.spdm_engine.config.get", side_effect=json_config_get
        ):
            self.engine.verify_evidence()

        self.assertEqual(self.mock_attestation.evaluation, "fail")
        self.assertEqual(self.mock_attestation.failure_reason, "policy_violation")

    def test_verify_evidence_corim_appraisal_pass(self):
        import tempfile

        from cryptography.hazmat.primitives.serialization import Encoding

        from keylime.corim import sign_corim

        signer_key = ec.generate_private_key(ec.SECP384R1())
        signer_cert = _make_cert(signer_key, cn="corim-signer")

        # CoRIM in the real DMTF wire format, declaring the digest of measurement block 1 (0xaa * 48)
        import cbor2 as _cbor2
        m_key = {0: {0: b"DEVICE_INFO", 1: "TestVendor", 2: "TestModel", 3: 0}}
        m_val = [{0: 1, 1: {2: [[7, b"\xaa" * 48]]}}]
        comid = {1: [b"test-tag-id"], 4: {0: [[m_key, m_val]]}}
        corim = _cbor2.CBORTag(501, {1: [_cbor2.CBORTag(506, _cbor2.dumps(comid))]})
        blob = sign_corim(corim, signer_key)

        corim_file = tempfile.NamedTemporaryFile(suffix=".corim", delete=False)  # pylint: disable=consider-using-with
        self.addCleanup(os.unlink, corim_file.name)
        corim_file.write(blob)
        corim_file.close()

        signer_dir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(signer_dir.cleanup)
        with open(os.path.join(signer_dir.name, "signer.pem"), "wb") as f:
            f.write(signer_cert.public_bytes(Encoding.PEM))

        def fake_config_get(section, option, fallback=None):
            if option == "spdm_corim":
                return corim_file.name
            if option == "spdm_corim_signers":
                return signer_dir.name
            return fallback

        with patch.object(self.engine, "_trust_store", self._trust_store), patch(
            "keylime.verification.spdm_engine.config.get", side_effect=fake_config_get
        ):
            self.engine.verify_evidence()

        self.assertEqual(self.mock_attestation.evaluation, "pass")

    def test_verify_evidence_corim_appraisal_fail(self):
        import tempfile

        from cryptography.hazmat.primitives.serialization import Encoding

        from keylime.corim import sign_corim

        signer_key = ec.generate_private_key(ec.SECP384R1())
        signer_cert = _make_cert(signer_key, cn="corim-signer")

        # Manifest declares a digest that does NOT match the signed measurement block
        import cbor2 as _cbor2
        m_key = {0: {0: b"DEVICE_INFO", 1: "TestVendor", 2: "TestModel", 3: 0}}
        m_val = [{0: 1, 1: {2: [[7, b"\xcc" * 48]]}}]
        comid = {1: [b"test-tag-id"], 4: {0: [[m_key, m_val]]}}
        corim = _cbor2.CBORTag(501, {1: [_cbor2.CBORTag(506, _cbor2.dumps(comid))]})
        blob = sign_corim(corim, signer_key)

        corim_file = tempfile.NamedTemporaryFile(suffix=".corim", delete=False)  # pylint: disable=consider-using-with
        self.addCleanup(os.unlink, corim_file.name)
        corim_file.write(blob)
        corim_file.close()

        signer_dir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(signer_dir.cleanup)
        with open(os.path.join(signer_dir.name, "signer.pem"), "wb") as f:
            f.write(signer_cert.public_bytes(Encoding.PEM))

        def fake_config_get(section, option, fallback=None):
            if option == "spdm_corim":
                return corim_file.name
            if option == "spdm_corim_signers":
                return signer_dir.name
            return fallback

        with patch.object(self.engine, "_trust_store", self._trust_store), patch(
            "keylime.verification.spdm_engine.config.get", side_effect=fake_config_get
        ):
            self.engine.verify_evidence()

        self.assertEqual(self.mock_attestation.evaluation, "fail")
        self.assertEqual(self.mock_attestation.failure_reason, "policy_violation")

    def test_pass_does_not_override_prior_failure(self):
        # Dual-factor attestation: another engine has already recorded a failure
        self.mock_attestation.evaluation = "fail"

        with patch.object(self.engine, "_trust_store", self._trust_store):
            self.engine.verify_evidence()

        self.assertEqual(self.mock_attestation.evaluation, "fail")

    def test_register_callbacks(self):
        from keylime.verification.base import EngineDriver

        self.assertIn(SPDMEngine, EngineDriver.get_evidence_evaluators("spdm_measurements"))
        self.assertIn(SPDMEngine, EngineDriver.get_parameter_mutators("spdm_measurements"))


if __name__ == "__main__":
    unittest.main()
