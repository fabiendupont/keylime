"""
End-to-end test of the out-of-band SPDM attestation path:

    vbmc-rs (Redfish service + SPDM responder)  ->  OOB collection flow  ->  SPDM engine

vbmc-rs is the GB300 stand-in BMC: a real Redfish service with an SPDM responder
whose MEASUREMENTS responses are validated by DMTF's Responder Validator. This
test drives the same code path the production collector uses (Redfish discovery,
SPDMGetSignedMeasurements with a freshness challenge, Certificate resource
retrieval, message/signature splitting) and feeds the result to the verifier's
SPDMEngine — so any wire-format drift between vbmc and the Keylime parser fails
here rather than in the field.

Requires the vbmc-rs binary. The test is skipped unless VBMC_BINARY is set or
the binary exists at the default checkout path.
"""

import base64
import datetime
import os
import socket
import struct
import subprocess
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from keylime.oob.redfish import RedfishClient, RedfishError
from keylime.spdm import chain_blob_from_pem, signature_length, split_signed_message
from keylime.verification.spdm_engine import SPDMEngine

VBMC_BINARY = os.environ.get(
    "VBMC_BINARY",
    os.path.expanduser("~/Code/github.com/fabiendupont/vbmc-rs/target/release/vbmc-rs"),
)


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _make_cert(key, cn):
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .sign(key, hashes.SHA384())
    )


class TestOOBEndToEnd(unittest.TestCase):
    """Full round trip: Redfish collection from a live vbmc-rs into the SPDM engine."""

    @classmethod
    def setUpClass(cls):
        if not os.access(VBMC_BINARY, os.X_OK):
            raise unittest.SkipTest(f"vbmc-rs binary not available at {VBMC_BINARY} (set VBMC_BINARY)")

        cls.workdir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        cls.addClassCleanup(cls.workdir.cleanup)
        work = cls.workdir.name

        # SPDM device identity: EC P-384 key + self-signed cert in the DSP0274 chain-blob format
        cls.device_key = ec.generate_private_key(ec.SECP384R1())
        cls.device_cert = _make_cert(cls.device_key, "vbmc-e2e-spdm-device")
        key_path = os.path.join(work, "device-key.pem")
        with open(key_path, "wb") as f:
            f.write(cls.device_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
        der = cls.device_cert.public_bytes(serialization.Encoding.DER)
        chain_path = os.path.join(work, "device-chain.blob")
        with open(chain_path, "wb") as f:
            body = struct.pack("<H", len(der)) + der
            f.write(struct.pack("<H", len(body)) + body)

        # TLS server identity for the Redfish service
        tls_key = ec.generate_private_key(ec.SECP384R1())
        tls_cert = _make_cert(tls_key, "localhost")
        tls_cert_path = os.path.join(work, "tls.crt")
        tls_key_path = os.path.join(work, "tls.key")
        with open(tls_cert_path, "wb") as f:
            f.write(tls_cert.public_bytes(serialization.Encoding.PEM))
        with open(tls_key_path, "wb") as f:
            f.write(tls_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))

        cls.port = _free_port()
        config_path = os.path.join(work, "vbmc.toml")
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(
                f"""
backend = "cloud_hypervisor"

[server]
bind_address = "127.0.0.1"
port = {cls.port}
tls_cert = "{tls_cert_path}"
tls_key = "{tls_key_path}"

[auth]
enabled = false

[defaults]
firmware_path = "/usr/share/OVMF/OVMF_CODE.fd"
boot_source = "Hdd"

[metrics]
enabled = false

[systems.vm1]
name = "E2E Test VM"
socket_path = "{work}/nonexistent.sock"

[systems.vm1.hardware]
cpu_count = 2
memory_mib = 1024

# GB300 (Microchip CEC173x) fidelity: SPDM 1.1
[systems.vm1.spdm]
private_key = "{key_path}"
cert_chain = "{chain_path}"
spdm_versions = ["1.1"]
collection_delay_ms = 0
"""
            )

        cls.vbmc_log = open(os.path.join(work, "vbmc.log"), "wb")  # pylint: disable=consider-using-with
        cls.addClassCleanup(cls.vbmc_log.close)
        cls.vbmc = subprocess.Popen(
            [VBMC_BINARY, "-c", config_path],
            stdout=cls.vbmc_log,
            stderr=subprocess.STDOUT,
        )
        cls.addClassCleanup(cls._stop_vbmc, cls)

        cls.base_url = f"https://127.0.0.1:{cls.port}"
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if cls.vbmc.poll() is not None:
                cls.fail(f"vbmc-rs exited during startup (see {cls.vbmc_log.name})")
            try:
                if requests.get(f"{cls.base_url}/redfish/v1", verify=False, timeout=2).ok:
                    break
            except requests.RequestException:
                pass
            time.sleep(0.2)
        else:
            cls.fail(f"vbmc-rs did not become ready (see {cls.vbmc_log.name})")

    @staticmethod
    def _stop_vbmc(cls):
        cls.vbmc.terminate()
        try:
            cls.vbmc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            cls.vbmc.kill()

    def setUp(self):
        self.client = RedfishClient(f"127.0.0.1:{self.port}", "test", "test", verify_tls=False, timeout=10)
        self.addCleanup(self.client.close)

        # Trust store holding the device's self-signed certificate
        self.trust_dir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self.trust_dir.cleanup)
        with open(os.path.join(self.trust_dir.name, "device.pem"), "wb") as f:
            f.write(self.device_cert.public_bytes(serialization.Encoding.PEM))

    def _collect_evidence(self, nonce):
        """Run the collector's evidence-gathering flow and return (message, signature, chain blob)."""
        components = self.client.get_component_integrity()
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]["ComponentIntegrityType"], "SPDM")

        measurement = self.client.get_signed_measurements(components[0], nonce.hex())

        signed_b64 = measurement.get("SignedMeasurements")
        signing_algorithm = measurement.get("SigningAlgorithm")
        self.assertTrue(signed_b64, "SPDMGetSignedMeasurements returned no SignedMeasurements")
        self.assertEqual(signing_algorithm, "TPM_ALG_ECDSA_ECC_NIST_P384")

        # Certificate chain via the schema-conformant Certificate link, as the collector prefers
        certificate_link = measurement.get("Certificate")
        self.assertIsInstance(certificate_link, dict, "action response lacks a Certificate link")
        pem = self.client.get_certificate_chain_pem(certificate_link)
        chain_blob = chain_blob_from_pem(pem)

        signed_blob = base64.b64decode(signed_b64)
        message, signature = split_signed_message(signed_blob, signature_length(signing_algorithm))
        return message, signature, chain_blob

    def _verify(self, message, signature, chain_blob, challenge):
        """Run the SPDM engine over collected evidence (same mock harness as test_spdm_engine)."""
        item = MagicMock()
        item.data.message = message
        item.data.signature = signature
        item.data.meta = {"spdm_cert_chain": base64.b64encode(chain_blob).decode("utf-8")}
        item.chosen_parameters.hash_algorithm = "sha384"
        item.chosen_parameters.challenge = challenge
        item.results.meta = {}

        mock_view = MagicMock()
        mock_view.filter.return_value = mock_view
        mock_view.result.return_value = [item]
        mock_view.to_list.return_value = [item]

        mock_evidence = MagicMock()
        mock_evidence.view.return_value = mock_view

        attestation = MagicMock()
        attestation.agent_id = "oob-e2e-agent"
        attestation.index = 0
        attestation.evaluation = "pending"
        attestation.failure_reason = None
        attestation.evidence = mock_evidence

        engine = SPDMEngine(attestation)
        with patch.object(engine, "_trust_store", lambda *_: self.trust_dir.name):
            engine.verify_evidence()

        return attestation, item

    def test_attestation_pass(self):
        nonce = os.urandom(32)
        message, signature, chain_blob = self._collect_evidence(nonce)

        attestation, item = self._verify(message, signature, chain_blob, challenge=nonce)

        self.assertEqual(attestation.evaluation, "pass")
        self.assertFalse(attestation.failure_reason)
        # Parsed measurements must be recorded for auditability
        self.assertIn("measurements", item.results.meta)
        self.assertGreater(len(item.results.meta["measurements"]), 0)

    def test_replayed_evidence_fails_freshness(self):
        """Evidence collected for one challenge must not verify against a different challenge."""
        nonce = os.urandom(32)
        message, signature, chain_blob = self._collect_evidence(nonce)

        attestation, _ = self._verify(message, signature, chain_blob, challenge=os.urandom(32))

        self.assertEqual(attestation.evaluation, "fail")
        self.assertEqual(attestation.failure_reason, "broken_evidence_chain")

    def test_tampered_evidence_fails(self):
        nonce = os.urandom(32)
        message, signature, chain_blob = self._collect_evidence(nonce)

        tampered = bytearray(message)
        tampered[-1] ^= 0xFF

        attestation, _ = self._verify(bytes(tampered), signature, chain_blob, challenge=nonce)

        self.assertEqual(attestation.evaluation, "fail")
        self.assertEqual(attestation.failure_reason, "broken_evidence_chain")


if __name__ == "__main__":
    unittest.main()
