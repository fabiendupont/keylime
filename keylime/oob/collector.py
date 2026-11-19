"""Out-of-band SPDM attestation collector.

Polls a BMC's Redfish ComponentIntegrity endpoints and submits signed SPDM
measurements to the Keylime verifier as `spdm_measurements` evidence, using the
verifier's v3 push-mode attestation protocol:

    1. POST   /v3/agents/:agent_id/attestations      (capabilities negotiation)
    2.         -> verifier responds with freshness challenges (nonces)
    3.         -> collector triggers SPDMGetSignedMeasurements on the BMC
    4. PATCH  /v3/agents/:agent_id/attestations/latest (evidence submission)

Verification failures cause the verifier to broadcast revocation events
through its existing ZeroMQ/webhook framework, which downstream consumers
(e.g., OpenShift node controllers) may use to quarantine the node.
"""

import argparse
import base64
import json
import sys
import time
from typing import Optional

import requests
import urllib3

from keylime import config, keylime_logging
from keylime.oob.redfish import RedfishClient, RedfishError
from keylime.oob.tpm_identity import SwtpmIdentity, TpmIdentityError
from keylime.spdm import SpdmError, chain_blob_from_pem, signature_length, split_signed_message

logger = keylime_logging.init_logging("oob_collector")

API_VERSION = 3


class OOBCollector:
    def __init__(
        self,
        agent_id: str,
        bmc: RedfishClient,
        verifier_base_url: str,
        cert_chain_b64: Optional[str] = None,
        tls_cert: Optional[str] = None,
        tls_key: Optional[str] = None,
        tls_ca_cert: Optional[str] = None,
        registrar_base_url: Optional[str] = None,
        tpm: Optional[SwtpmIdentity] = None,
    ):
        self.agent_id = agent_id
        self.bmc = bmc
        self.verifier_base_url = verifier_base_url.rstrip("/")
        self.cert_chain_b64 = cert_chain_b64
        self.registrar_base_url = registrar_base_url.rstrip("/") if registrar_base_url else None
        self.tpm = tpm
        self.token: Optional[str] = None

        self.http = requests.Session()

        if tls_cert and tls_key:
            self.http.cert = (tls_cert, tls_key)

        self.http.verify = tls_ca_cert if tls_ca_cert else True

    def _json_api(self, attributes):
        return {"data": {"type": "attestation", "attributes": attributes}}

    def _json_api_headers(self):
        return {"Content-Type": "application/vnd.api+json"}

    def register_with_registrar(self):
        """Register the device identity with the Keylime registrar.

        When a TPM identity is available (swtpm), performs the full v2 registration protocol: EK/AK submission,
        AK activation via MakeCredential/ActivateCredential. The SPDM certificate chain, if known, is included in
        the same registration. Otherwise registers the SPDM certificate chain alone.
        """
        if not self.registrar_base_url:
            return

        if self.tpm:
            body = {
                "ek_tpm": base64.b64encode(self.tpm.ek_tpm).decode("utf-8"),
                "aik_tpm": base64.b64encode(self.tpm.ak_tpm).decode("utf-8"),
            }
        elif self.cert_chain_b64:
            body = {"spdm_cert_chain": self.cert_chain_b64}
        else:
            return

        if self.cert_chain_b64:
            body["spdm_cert_chain"] = self.cert_chain_b64

        response = self.http.post(f"{self.registrar_base_url}/v2/agents/{self.agent_id}", json=body)

        if response.status_code not in (200, 201):
            logger.error(
                "Registrar registration failed for agent '%s' with status %s: %s",
                self.agent_id,
                response.status_code,
                response.text[:200],
            )
            return

        logger.info("Registered identity for agent '%s' with registrar", self.agent_id)

        # Activate the AK by decrypting the registrar's challenge and returning its HMAC
        if self.tpm:
            blob = (response.json().get("results") or {}).get("blob")
            if not blob:
                logger.error("Registrar did not return an AK challenge blob for agent '%s'", self.agent_id)
                return

            try:
                auth_tag = self.tpm.activate_credential(base64.b64decode(blob), self.agent_id)
            except TpmIdentityError as e:
                logger.error("AK activation failed for agent '%s': %s", self.agent_id, e)
                return

            response = self.http.post(
                f"{self.registrar_base_url}/v2/agents/{self.agent_id}/activate", json={"auth_tag": auth_tag}
            )

            if response.status_code == 200:
                logger.info("Activated AK for agent '%s' with registrar", self.agent_id)
            else:
                logger.error(
                    "AK activation rejected for agent '%s' (status %s): %s",
                    self.agent_id,
                    response.status_code,
                    response.text[:200],
                )

    def enroll_with_verifier(self):
        """Enroll the agent with the verifier (v2 API, requires an admin TLS client certificate)."""
        if not self.tpm:
            logger.warning("Verifier enrollment requires a TPM identity (--swtpm-socket)")
            return

        body = {
            "v": None,
            "verifier_ip": None,
            "verifier_port": None,
            "tpm_policy": json.dumps({}),
            "runtime_policy": "",
            "runtime_policy_name": "",
            "runtime_policy_key": "",
            "mb_policy": None,
            "mb_policy_name": "",
            "ima_sign_verification_keys": "",
            "metadata": json.dumps({}),
            "revocation_key": "",
            "accept_tpm_hash_algs": ["sha256", "sha384"],
            "accept_tpm_encryption_algs": ["rsa", "ecc"],
            "accept_tpm_signing_algs": ["rsassa", "rsapss", "ecdsa"],
            "ak_tpm": base64.b64encode(self.tpm.ak_tpm).decode("utf-8"),
            "mtls_cert": None,
            "supported_version": "2.0",
        }

        response = self.http.post(f"{self.verifier_base_url}/v2/agents/{self.agent_id}", json=body)

        if response.status_code in (200, 201):
            logger.info("Enrolled agent '%s' with verifier", self.agent_id)
        elif response.status_code == 409:
            logger.info("Agent '%s' already enrolled with verifier", self.agent_id)
        else:
            logger.error(
                "Verifier enrollment failed for agent '%s' (status %s): %s",
                self.agent_id,
                response.status_code,
                response.text[:300],
            )

    def authenticate(self):
        """Obtain a bearer token from the verifier by proving possession of the AK (tpm_pop)."""
        if not self.tpm:
            return

        response = self.http.post(
            f"{self.verifier_base_url}/v3/sessions",
            json={
                "data": {
                    "type": "session",
                    "attributes": {
                        "agent_id": self.agent_id,
                        "authentication_supported": [
                            {"authentication_class": "pop", "authentication_type": "tpm_pop"}
                        ],
                    },
                }
            },
            headers=self._json_api_headers(),
        )

        if response.status_code not in (200, 201):
            logger.error(
                "Session creation failed for agent '%s' (status %s): %s",
                self.agent_id,
                response.status_code,
                response.text[:300],
            )
            return

        attributes = response.json()["data"]["attributes"]
        session_id = response.json()["data"]["id"]
        auth_requested = attributes.get("authentication_requested", [])
        challenge = auth_requested[0].get("chosen_parameters", {}).get("challenge")

        if not challenge:
            logger.error("Verifier did not provide a session challenge for agent '%s'", self.agent_id)
            return

        nonce = base64.b64decode(challenge)
        attest, signature = self.tpm.certify(nonce)

        response = self.http.patch(
            f"{self.verifier_base_url}/v3/sessions/{session_id}",
            json={
                "data": {
                    "type": "session",
                    "id": session_id,
                    "attributes": {
                        "agent_id": self.agent_id,
                        "authentication_provided": [
                            {
                                "authentication_class": "pop",
                                "authentication_type": "tpm_pop",
                                "data": {
                                    "message": base64.b64encode(attest).decode("utf-8"),
                                    "signature": base64.b64encode(signature).decode("utf-8"),
                                },
                            }
                        ],
                    },
                }
            },
            headers=self._json_api_headers(),
        )

        attributes = response.json().get("data", {}).get("attributes", {})

        if response.status_code == 200 and attributes.get("evaluation") == "pass":
            self.token = attributes.get("token")
            logger.info("Authenticated agent '%s' with verifier (session token obtained)", self.agent_id)
        else:
            logger.error(
                "Session PoP failed for agent '%s' (status %s): %s",
                self.agent_id,
                response.status_code,
                response.text[:300],
            )

    def _auth_headers(self):
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def _resolve_cert_chain(self, measurement):
        """Resolve the SPDM device certificate chain as Base64 of the DMTF DSP0274 blob, in order of
        preference: the action response's 'Certificate' link (Redfish Certificate resource with a PEM
        chain), the non-standard inline 'CertificateChain' property, or the collector's --cert-chain
        fallback. Returns None when no source is available."""
        certificate_link = measurement.get("Certificate")

        if isinstance(certificate_link, dict) and certificate_link.get("@odata.id"):
            try:
                pem = self.bmc.get_certificate_chain_pem(certificate_link)
                return base64.b64encode(chain_blob_from_pem(pem)).decode("utf-8")
            except (RedfishError, SpdmError) as e:
                logger.warning(
                    "Could not fetch certificate chain from the linked Certificate resource, falling back to "
                    "inline/--cert-chain: %s",
                    e,
                )

        return measurement.get("CertificateChain") or self.cert_chain_b64

    def attest_once(self):
        """Run a single attestation cycle. Returns True if evidence was submitted successfully."""
        components = self.bmc.get_component_integrity()

        if not components:
            logger.warning("No SPDM-capable ComponentIntegrity resources found on BMC")
            return False

        # Phase 1: negotiate capabilities for one spdm_measurements evidence item per component
        capabilities = [
            {
                "evidence_class": "certification",
                "evidence_type": "spdm_measurements",
                "capabilities": {
                    "component_version": "1.3",
                    "signature_schemes": ["ecdsa"],
                    "hash_algorithms": ["sha384"],
                    "certification_keys": [
                        {
                            "key_class": "asymmetric",
                            "key_algorithm": "ec",
                            "key_size": 384,
                            "server_identifier": "spdm_device",
                        }
                    ],
                },
            }
            for _ in components
        ]

        # The verifier's schema requires a boot time. An out-of-band attested node has no guest OS to report a
        # boot time from, so the collector reports the time of the attestation itself.
        from datetime import datetime, timezone  # pylint: disable=import-outside-toplevel

        boot_time = datetime.now(timezone.utc).isoformat()

        response = self.http.post(
            f"{self.verifier_base_url}/v{API_VERSION}/agents/{self.agent_id}/attestations",
            json=self._json_api({"evidence_supported": capabilities, "system_info": {"boot_time": boot_time}}),
            headers={**self._json_api_headers(), **self._auth_headers()},
        )

        if response.status_code == 401 and self.tpm:
            self.authenticate()
            response = self.http.post(
                f"{self.verifier_base_url}/v{API_VERSION}/agents/{self.agent_id}/attestations",
                json=self._json_api({"evidence_supported": capabilities, "system_info": {"boot_time": boot_time}}),
                headers={**self._json_api_headers(), **self._auth_headers()},
            )

        if response.status_code not in (200, 201):
            logger.error(
                "Could not create attestation for agent '%s' (status %s): %s",
                self.agent_id,
                response.status_code,
                response.text[:300],
            )
            return False

        attestation = response.json()["data"]["attributes"]
        evidence_requested = attestation.get("evidence_requested", [])

        if len(evidence_requested) != len(components):
            logger.error(
                "Verifier requested %s evidence items but %s SPDM components were discovered",
                len(evidence_requested),
                len(components),
            )
            return False

        # Phase 2: collect signed measurements using the verifier's freshness challenges
        evidence_collected = []

        for item, component in zip(evidence_requested, components):
            challenge = (item.get("chosen_parameters") or {}).get("challenge")

            if not challenge:
                logger.error("Verifier did not provide a challenge for spdm_measurements evidence")
                return False

            # The challenge is Base64-encoded in the JSON:API response; SPDM expects a hex nonce
            nonce_hex = base64.b64decode(challenge).hex()

            try:
                measurement = self.bmc.get_signed_measurements(component, nonce_hex)
            except RedfishError as e:
                logger.error("Could not collect signed measurements from '%s': %s", component["_uri"], e)
                return False

            signed_blob_b64 = measurement.get("SignedMeasurements")
            signing_algorithm = measurement.get("SigningAlgorithm")
            hash_algorithm = measurement.get("HashingAlgorithm") or "sha384"

            # Resolve the device certificate chain, in order of preference: the schema-conformant
            # 'Certificate' link to a Redfish Certificate resource (as served by SPDM-capable BMCs), the
            # non-standard inline 'CertificateChain' blob, or the collector's --cert-chain fallback
            cert_chain_b64 = self._resolve_cert_chain(measurement)

            if not signed_blob_b64 or not signing_algorithm:
                logger.error(
                    "Redfish response for '%s' did not include SignedMeasurements and SigningAlgorithm",
                    component["_uri"],
                )
                return False

            if not cert_chain_b64:
                logger.error(
                    "No SPDM certificate chain available for '%s' (neither in the Redfish response nor via "
                    "--cert-chain)",
                    component["_uri"],
                )
                return False

            # The Redfish action returns the full signed statement (message plus trailing SPDM signature) as a
            # single Base64 blob; split it so the verifier's SPDM engine receives message and signature separately
            try:
                signed_blob = base64.b64decode(signed_blob_b64)
                sig_length = signature_length(signing_algorithm)
                message, signature = split_signed_message(signed_blob, sig_length)
            except SpdmError as e:
                logger.error("Could not process signed measurements from '%s': %s", component["_uri"], e)
                return False

            evidence_collected.append(
                {
                    "evidence_class": "certification",
                    "evidence_type": "spdm_measurements",
                    "data": {
                        "message": base64.b64encode(message).decode("utf-8"),
                        "signature": base64.b64encode(signature).decode("utf-8"),
                        "meta": {
                            "spdm_cert_chain": cert_chain_b64,
                            "hash_algorithm": hash_algorithm,
                            "component_id": component["id"],
                        },
                    },
                }
            )

        response = self.http.patch(
            f"{self.verifier_base_url}/v{API_VERSION}/agents/{self.agent_id}/attestations/latest",
            json=self._json_api({"evidence_collected": evidence_collected}),
            headers={**self._json_api_headers(), **self._auth_headers()},
        )

        if response.status_code not in (200, 202):
            logger.error(
                "Could not submit evidence for agent '%s' (status %s): %s",
                self.agent_id,
                response.status_code,
                response.text[:300],
            )
            return False

        logger.info("Submitted SPDM evidence for agent '%s'; verifier will appraise it asynchronously", self.agent_id)
        return True

    def run(self, interval, enroll=False):
        self.register_with_registrar()

        if enroll:
            self.enroll_with_verifier()

        self.authenticate()

        while True:
            try:
                self.attest_once()
            except Exception as e:  # pylint: disable=broad-except
                logger.error("Attestation cycle for agent '%s' failed: %s", self.agent_id, e)

            if interval <= 0:
                break

            time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="Keylime out-of-band SPDM attestation collector")
    parser.add_argument("-a", "--agent-uuid", required=True, help="UUID of the agent (node) to attest")
    parser.add_argument("-b", "--bmc-host", required=True, help="hostname or IP of the BMC's Redfish interface")
    parser.add_argument("-u", "--bmc-user", default=config.get("oob", "bmc_username", fallback="root"))
    parser.add_argument("-p", "--bmc-password", default=config.get("oob", "bmc_password", fallback=""))
    parser.add_argument(
        "--bmc-ca-cert",
        default=config.get("oob", "bmc_ca_cert", fallback=""),
        help="CA certificate to verify the BMC's TLS certificate (disables verification if empty)",
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=int,
        default=config.getint("oob", "interval", fallback=1800),
        help="polling interval in seconds (0 for a single cycle; default 1800 = 30 minutes)",
    )
    parser.add_argument("--verifier-host", default=config.get("verifier", "ip", fallback="127.0.0.1"))
    parser.add_argument("--verifier-port", type=int, default=config.getint("verifier", "port", fallback=8881))
    parser.add_argument(
        "--tls-cert", default=config.get("oob", "tls_cert", fallback=""), help="client certificate for verifier mTLS"
    )
    parser.add_argument("--tls-key", default=config.get("oob", "tls_key", fallback=""))
    parser.add_argument("--tls-ca-cert", default=config.get("oob", "tls_ca_cert", fallback=""))
    parser.add_argument(
        "--registrar-host",
        default=config.get("registrar", "ip", fallback=""),
        help="register the SPDM certificate chain with the registrar at this host (optional)",
    )
    parser.add_argument("--registrar-port", type=int, default=config.getint("registrar", "port", fallback=8889))
    parser.add_argument(
        "--cert-chain",
        default=config.get("oob", "spdm_cert_chain", fallback=""),
        help="path to the device's SPDM certificate chain blob (raw or Base64-encoded)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="do not verify the TLS certificates of the BMC (use only for testing)",
    )
    parser.add_argument(
        "--swtpm-socket",
        default=config.get("oob", "swtpm_socket", fallback=""),
        help="unix socket of a swtpm instance providing the collector's TPM identity (enables registrar "
        "registration, verifier enrollment and session authentication)",
    )
    parser.add_argument(
        "--enroll",
        action="store_true",
        help="enroll the agent with the verifier (requires --swtpm-socket and an admin TLS client certificate)",
    )

    args = parser.parse_args()

    cert_chain_b64 = None

    if args.cert_chain:
        with open(args.cert_chain, "rb") as f:
            blob = f.read()

        try:
            base64.b64decode(blob, validate=True)
            cert_chain_b64 = blob.decode("utf-8")
        except Exception:
            cert_chain_b64 = base64.b64encode(blob).decode("utf-8")

    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    bmc = RedfishClient(
        args.bmc_host,
        args.bmc_user,
        args.bmc_password,
        verify_tls=args.bmc_ca_cert if args.bmc_ca_cert else not args.insecure,
    )

    scheme = "https" if args.tls_ca_cert or args.tls_cert else "http"
    verifier_base_url = f"{scheme}://{args.verifier_host}:{args.verifier_port}"

    registrar_base_url = None
    if args.registrar_host:
        registrar_base_url = f"http://{args.registrar_host}:{args.registrar_port}"

    tpm = None
    if args.swtpm_socket:
        tpm = SwtpmIdentity(args.swtpm_socket)
        try:
            tpm.initialize()
        except TpmIdentityError as e:
            logger.error("Could not establish swtpm TPM identity: %s", e)
            sys.exit(1)

    collector = OOBCollector(
        agent_id=args.agent_uuid,
        bmc=bmc,
        verifier_base_url=verifier_base_url,
        cert_chain_b64=cert_chain_b64,
        tls_cert=args.tls_cert or None,
        tls_key=args.tls_key or None,
        tls_ca_cert=args.tls_ca_cert or None,
        registrar_base_url=registrar_base_url,
        tpm=tpm,
    )

    try:
        collector.run(args.interval, enroll=args.enroll)
    except KeyboardInterrupt:
        logger.info("Shutting down OOB collector for agent '%s'", args.agent_uuid)
        bmc.close()
        sys.exit(0)


if __name__ == "__main__":
    main()
