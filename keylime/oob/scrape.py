"""Rack attestation-surface scraper.

Automates the bring-up capture of a rack's SPDM attestation surface (e.g. an NVIDIA GB300
NVL72): for every tray BMC it discovers all ComponentIntegrity resources, fetches their
certificate chains and firmware inventory, optionally challenges each SPDM responder with a
fresh nonce (the full 202-Task -> poll -> /data flow), and saves every artifact for offline
analysis.

    python3 -m keylime.oob.scrape --bmc 10.0.0.42 [--bmc 10.0.0.43 ...] [--outdir capture]

Output layout (one directory per BMC):

    capture/
      manifest.json                       summary incl. per-component validation results
      <bmc>/
        service-root.json
        firmware-inventory.json           + firmware-inventory/<Id>.json
        component-integrity/
          <Id>.json                       the ComponentIntegrity resource
          <Id>-chain.pem                  the SPDM certificate chain
          <Id>-task.json                  the SPDMGetSignedMeasurements Task
          <Id>-measurement.json           the measurement payload from /data
          <Id>-signed.bin                 the raw signed statement (Base64-decoded)
          <Id>-nonce.hex                  the challenge nonce used, for replay validation

Every captured component is validated inline against the keylime SPDM appraisal code
(transcript location, nonce freshness, signature over the captured chain), and the results
are recorded in the manifest — so on bring-up day, assumption mismatches surface per
component instead of as a verifier failure.
"""

import argparse
import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from keylime import config, keylime_logging
from keylime.oob.redfish import RedfishClient, RedfishError
from keylime.spdm import (
    SpdmError,
    chain_blob_from_pem,
    locate_measurements_message,
    parse_cert_chain,
    parse_measurements,
    signature_length,
    split_signed_message,
    verify_signature,
)

logger = keylime_logging.init_logging("oob_scrape")


class BmcScraper:
    def __init__(self, host, outdir, challenge=True, timeout=30, insecure=False, ca_cert="", components=None):
        self.host = host
        self.challenge = challenge
        # Optional allowlist of ComponentIntegrity IDs to capture (default: all)
        self.component_filter = set(components) if components else None
        self.client = RedfishClient(
            host, config.get("oob", "bmc_username", fallback="root"), "", verify_tls=(ca_cert or not insecure),
            timeout=timeout,
        )
        self.outdir = Path(outdir) / host.replace(":", "_")
        self.cidir = self.outdir / "component-integrity"
        self.warnings = []

    def scrape(self):
        """Scrape one BMC. Returns the per-host manifest section."""
        self.outdir.mkdir(parents=True, exist_ok=True)
        self.cidir.mkdir(exist_ok=True)

        result = {"host": self.host, "components": [], "warnings": self.warnings}

        result.update(self._scrape_service_root())
        result["firmware_inventory"] = self._scrape_firmware_inventory()
        result["components"] = self._scrape_components()

        return result

    def _scrape_service_root(self):
        try:
            root = self.client.get_json("/redfish/v1")
        except RedfishError as e:
            self.warnings.append(f"service root unavailable: {e}")
            root = {}
        self._save("service-root.json", root)
        return {"uuid": root.get("UUID"), "redfish_version": root.get("RedfishVersion")}

    def _scrape_firmware_inventory(self):
        try:
            inventory = self.client.get_json("/redfish/v1/UpdateService/FirmwareInventory")
        except RedfishError as e:
            self.warnings.append(f"firmware inventory unavailable: {e}")
            return None

        self._save("firmware-inventory.json", inventory)

        members = inventory.get("Members") or []
        fwdir = self.outdir / "firmware-inventory"
        fwdir.mkdir(exist_ok=True)
        count = 0

        for member in members:
            uri = member.get("@odata.id")
            if not uri:
                continue
            try:
                entry = self.client.get_json(uri)
                fw_id = entry.get("Id", f"member{count}").replace("/", "_")
                self._save(f"firmware-inventory/{fw_id}.json", entry)
                count += 1
            except RedfishError as e:
                self.warnings.append(f"firmware inventory member {uri} unavailable: {e}")

        return {"count": len(members), "saved": count}

    def _scrape_components(self):
        components = []

        try:
            collection = self.client.get_json("/redfish/v1/ComponentIntegrity")
        except RedfishError as e:
            self.warnings.append(f"ComponentIntegrity collection unavailable: {e}")
            return components

        for member in collection.get("Members") or []:
            uri = member.get("@odata.id")
            if not uri:
                continue

            component = {"uri": uri, "id": uri.rstrip("/").split("/")[-1]}

            if self.component_filter and component["id"] not in self.component_filter:
                continue

            try:
                components.append(self._scrape_component(component))
            except (RedfishError, SpdmError) as e:
                component["error"] = str(e)
                components.append(component)

        return components

    def _scrape_component(self, component):
        cid = component["id"]
        resource = self.client.get_json(component["uri"])
        self._save(f"component-integrity/{cid}.json", resource)
        component["type"] = resource.get("ComponentIntegrityType")

        # Certificate chain: prefer the resource's ComponentCertificate link, then the
        # Chassis Certificates convention used by NVIDIA BMCs
        chain_pem = None
        for link in [
            resource.get("SPDM", {}).get("IdentityAuthentication", {}).get("ResponderAuthentication", {}).get(
                "ComponentCertificate"
            ),
            f"/redfish/v1/Chassis/{cid}/Certificates/CertChain",
        ]:
            uri = link.get("@odata.id") if isinstance(link, dict) else link
            if not uri:
                continue
            try:
                chain_pem = self.client.get_certificate_chain_pem(uri)
                component["chain_source"] = uri
                break
            except RedfishError:
                continue

        if chain_pem:
            self._save(f"component-integrity/{cid}-chain.pem", chain_pem, binary=False)

        if not self.challenge:
            component["challenged"] = False
            return component

        component["challenged"] = True

        # Fresh nonce per component, saved for replay validation
        import secrets

        nonce_hex = secrets.token_hex(32)
        self._save(f"component-integrity/{cid}-nonce.hex", nonce_hex + "\n", binary=False)
        component["nonce"] = nonce_hex

        try:
            measurement = self.client.get_signed_measurements(resource, nonce_hex)
        except RedfishError as e:
            component["challenge_error"] = str(e)
            return component

        self._save(f"component-integrity/{cid}-measurement.json", measurement)

        blob_b64 = measurement.get("SignedMeasurements")
        signing_algorithm = measurement.get("SigningAlgorithm")

        # Chain may also arrive via the action response's Certificate link
        if chain_pem is None and isinstance(measurement.get("Certificate"), dict):
            try:
                chain_pem = self.client.get_certificate_chain_pem(measurement["Certificate"])
                self._save(f"component-integrity/{cid}-chain.pem", chain_pem, binary=False)
                component["chain_source"] = measurement["Certificate"]["@odata.id"]
            except RedfishError as e:
                self.warnings.append(f"{cid}: certificate link fetch failed: {e}")

        if blob_b64:
            blob = base64.b64decode(blob_b64)
            self._save(f"component-integrity/{cid}-signed.bin", blob)
            component["validation"] = self._validate(blob, signing_algorithm, chain_pem, nonce_hex)
        else:
            component["challenge_error"] = "measurement payload contained no SignedMeasurements"

        return component

    def _validate(self, blob, signing_algorithm, chain_pem, nonce_hex):
        """Run the keylime SPDM appraisal over the captured artifacts and report the outcome."""
        validation = {}

        try:
            if not chain_pem:
                raise SpdmError("no certificate chain captured")
            if not signing_algorithm:
                raise SpdmError("no SigningAlgorithm in the measurement payload")

            certs = parse_cert_chain(chain_blob_from_pem(chain_pem))
            validation["chain_certs"] = len(certs)
            validation["leaf_subject"] = certs[0].subject.rfc4514_string()

            message, signature = split_signed_message(blob, signature_length(signing_algorithm))
            offset = locate_measurements_message(message)
            blocks, nonce, _ = parse_measurements(message[offset:])

            validation["transcript_offset"] = offset
            validation["blocks"] = len(blocks)
            validation["block_indices"] = [b.index for b in blocks]
            validation["nonce_match"] = nonce.hex() == nonce_hex

            verify_signature(message, signature, certs[0], "sha384")
            validation["signature_valid"] = True
            validation["verdict"] = "pass"
        except (SpdmError, ValueError) as e:
            validation["signature_valid"] = False
            validation["verdict"] = "fail"
            validation["error"] = str(e)

        return validation

    def _save(self, name, content, binary=True):
        path = self.outdir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if binary and not isinstance(content, bytes):
            content = json.dumps(content, indent=2).encode()
        elif not binary and isinstance(content, bytes):
            content = content.decode()
        elif not binary and not isinstance(content, str):
            content = json.dumps(content, indent=2)
        with open(path, "wb") as f:
            f.write(content if isinstance(content, bytes) else content.encode())


def main():
    parser = argparse.ArgumentParser(description="Scrape the SPDM attestation surface of one or more BMCs")
    parser.add_argument("--bmc", action="append", required=True, help="BMC host[:port] (repeatable)")
    parser.add_argument("--bmc-user", default=config.get("oob", "bmc_username", fallback="root"))
    parser.add_argument("--bmc-password", default=config.get("oob", "bmc_password", fallback=""))
    parser.add_argument("--bmc-ca-cert", default=config.get("oob", "bmc_ca_cert", fallback=""))
    parser.add_argument("--insecure", action="store_true", help="do not verify BMC TLS certificates")
    parser.add_argument("--outdir", default="capture", help="output directory (default ./capture)")
    parser.add_argument(
        "--no-challenge",
        action="store_true",
        help="passive scrape only: no SPDMGetSignedMeasurements requests (Phase 1 discovery)",
    )
    parser.add_argument(
        "--component",
        action="append",
        help="restrict capture to the given ComponentIntegrity ID (repeatable; default: all). Use for the "
        "first active challenge of a component before sweeping the full rack.",
    )
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "challenge": not args.no_challenge,
        "hosts": [],
    }

    failed = False
    for host in args.bmc:
        logger.info("Scraping %s", host)
        scraper = BmcScraper(
            host,
            outdir,
            challenge=not args.no_challenge,
            timeout=args.timeout,
            insecure=args.insecure,
            ca_cert=args.bmc_ca_cert,
            components=args.component,
        )
        scraper.client.session.auth = (args.bmc_user, args.bmc_password)
        try:
            result = scraper.scrape()
            manifest["hosts"].append(result)
            components = result.get("components") or []
            validated = [c for c in components if c.get("validation")]
            passed = [c for c in validated if c["validation"].get("verdict") == "pass"]
            logger.info(
                "%s: %d component(s), %d validated, %d passed appraisal", host, len(components), len(validated),
                len(passed),
            )
            failed = failed or (validated and len(passed) != len(validated))
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("%s: scrape failed: %s", host, e)
            manifest["hosts"].append({"host": host, "error": str(e)})
            failed = True

    with open(outdir / "manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    logger.info("Manifest written to %s", outdir / "manifest.json")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
