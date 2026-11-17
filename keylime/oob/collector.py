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
import sys
import time
from typing import Optional

import requests
import urllib3

from keylime import config, keylime_logging
from keylime.oob.redfish import RedfishClient, RedfishError
from keylime.spdm import SpdmError, signature_length, split_signed_message

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
    ):
        self.agent_id = agent_id
        self.bmc = bmc
        self.verifier_base_url = verifier_base_url.rstrip("/")
        self.cert_chain_b64 = cert_chain_b64
        self.registrar_base_url = registrar_base_url.rstrip("/") if registrar_base_url else None

        self.http = requests.Session()
        self.http.headers.update({"Content-Type": "application/vnd.api+json"})

        if tls_cert and tls_key:
            self.http.cert = (tls_cert, tls_key)

        self.http.verify = tls_ca_cert if tls_ca_cert else True

    def _json_api(self, attributes):
        return {"data": {"type": "attestation", "attributes": attributes}}

    def register_with_registrar(self):
        """Register the device's SPDM certificate chain with the Keylime registrar."""
        if not self.registrar_base_url or not self.cert_chain_b64:
            return

        response = self.http.post(
            f"{self.registrar_base_url}/v2/agents",
            json={"agent_id": self.agent_id, "spdm_cert_chain": self.cert_chain_b64},
        )

        if response.status_code not in (200, 201):
            logger.error(
                "Registrar registration failed for agent '%s' with status %s: %s",
                self.agent_id,
                response.status_code,
                response.text[:200],
            )
        else:
            logger.info("Registered SPDM certificate chain for agent '%s' with registrar", self.agent_id)

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
                        {"key_class": "asymmetric", "key_algorithm": "ec", "key_size": 384}
                    ],
                },
            }
            for _ in components
        ]

        response = self.http.post(
            f"{self.verifier_base_url}/v{API_VERSION}/agents/{self.agent_id}/attestations",
            json=self._json_api({"evidence_supported": capabilities, "system_info": {}}),
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
            cert_chain_b64 = measurement.get("CertificateChain") or self.cert_chain_b64

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
                        "meta": {"spdm_cert_chain": cert_chain_b64, "hash_algorithm": hash_algorithm},
                    },
                }
            )

        response = self.http.patch(
            f"{self.verifier_base_url}/v{API_VERSION}/agents/{self.agent_id}/attestations/latest",
            json=self._json_api({"evidence_collected": evidence_collected}),
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

    def run(self, interval):
        self.register_with_registrar()

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

    collector = OOBCollector(
        agent_id=args.agent_uuid,
        bmc=bmc,
        verifier_base_url=verifier_base_url,
        cert_chain_b64=cert_chain_b64,
        tls_cert=args.tls_cert or None,
        tls_key=args.tls_key or None,
        tls_ca_cert=args.tls_ca_cert or None,
        registrar_base_url=registrar_base_url,
    )

    try:
        collector.run(args.interval)
    except KeyboardInterrupt:
        logger.info("Shutting down OOB collector for agent '%s'", args.agent_uuid)
        bmc.close()
        sys.exit(0)


if __name__ == "__main__":
    main()
