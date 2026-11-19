# pyright: reportAttributeAccessIssue=false
# Uses ORM models with dynamically-created attributes from metaclasses
import base64
import json
import os
from typing import Optional
from typing import TYPE_CHECKING, Any

from keylime import config, keylime_logging
from keylime.corim import (
    CorimError,
    appraise_measurements as appraise_against_corim,
    load_and_verify,
    parse_corim_devices,
)
from keylime.failure import Component, Failure
from keylime.spdm import (
    find_request_nonce,
    locate_measurements_message,
    parse_cert_chain,
    parse_measurements,
    verify_cert_chain,
    verify_signature,
)
from keylime.verification.base import EngineDriver, VerificationEngine

if TYPE_CHECKING:
    from keylime.models.verifier import Attestation

logger = keylime_logging.init_logging("verifier")


class SPDMEngine(VerificationEngine):
    """Verification engine for out-of-band SPDM measurement evidence.

    Evidence of type ``spdm_measurements`` (evidence class ``certification``) carries a signed DMTF DSP0274
    MEASUREMENTS response produced by a peripheral's hardware root of trust and collected out-of-band via Redfish
    (DSP0268 ComponentIntegrity). Verification comprises:

    1. parsing and trust-validating the SPDM device certificate chain accompanying the evidence;
    2. verifying the device's signature over the measurements statement;
    3. establishing freshness from transcript coverage: the signed statement includes the
       GET_MEASUREMENTS request carrying the verifier's challenge (SPDM responders generate their
       own nonce and never echo the requester's);
    4. appraising the measurement blocks against a reference policy, if one is configured.

    When an agent supplies both ``tpm_quote`` and ``spdm_measurements`` evidence, both engines must pass for the
    attestation to succeed (dual-factor attestation).
    """

    @classmethod
    def register_callbacks(cls) -> None:
        EngineDriver.register_parameter_mutator(cls, "spdm_measurements")
        EngineDriver.register_evidence_evaluator(cls, "spdm_measurements")

    def __init__(self, attestation: "Attestation") -> None:
        super().__init__(attestation)

    def _select_spdm_item(self) -> Any:
        # pylint: disable=protected-access
        spdm_items = self.attestation.evidence.view().filter(  # type: ignore[attr-defined]
            evidence_class="certification", evidence_type="spdm_measurements"
        )

        if not spdm_items.result():
            return None

        return spdm_items.to_list()[0]

    def _trust_store(self) -> str:
        return config.get("registrar", "spdm_cert_store", fallback=config.SPDM_CERT_STORE)

    def process_capabilities(self, evidence_requested: Any) -> None:
        item = self._select_spdm_item()

        if not item:
            return

        item.validate_required(["capabilities"])

        if item.capabilities:
            item.capabilities.validate_required(["signature_schemes"])

            if not item.capabilities.certification_keys:
                item.capabilities._add_error(
                    "certification_keys", "is required for spdm_measurements evidence"
                )
                return

        # Select the first signature scheme and hash algorithm offered by the collector
        item.initialise_parameters()
        item.chosen_parameters.signature_scheme = item.capabilities.signature_schemes[0]
        item.chosen_parameters.hash_algorithm = (item.capabilities.hash_algorithms or ["sha384"])[0]

        # Generate the freshness challenge. The collector relays it as the nonce of the GET_MEASUREMENTS
        # request, which the responder signs as part of the measurement transcript (DSP0274 responders
        # generate their own response nonce, so freshness rests on the signed request). SPDM nonces are
        # 32 bytes, so the challenge is 256 bits rather than the 128 bits used by other evidence types
        item.generate_challenge(256)

        evidence_requested.append(item)

    def process_evidence(self) -> None:
        item = self._select_spdm_item()

        if not item:
            return

        item.validate_required(["data"])

        if item.data:
            item.data.validate_required(["message", "signature"])

            if not item.data.meta.get("spdm_cert_chain"):
                item.data._add_error("meta", "must contain 'spdm_cert_chain' for spdm_measurements evidence")

    def _load_reference_policy(self):
        """Load the reference policy for measurement appraisal.

        In order of preference:

        1. `verifier/spdm_corim` — a signed CoRIM/CoMID manifest (DMTF CoRIM, RATS RFC 9334), verified against
           the signer certificates in `verifier/spdm_corim_signers`. This is the vendor-manifest appraisal
           mechanism intended for production. Per-device references are extracted so that SPDM measurement
           indices (which collide across devices — every eRoT has indices 1..N) are matched against the
           correct device's digests.
        2. `verifier/spdm_measurement_policy` — a simple JSON file mapping measurement block indexes to
           expected hex values.

        If neither is configured, only the signature, freshness and trust of the evidence are checked.
        """
        corim_path = config.get("verifier", "spdm_corim", fallback="")

        if corim_path:
            signer_dir = config.get(
                "verifier", "spdm_corim_signers", fallback="/var/lib/keylime/corim_signers"
            )
            devices = parse_corim_devices(load_and_verify(corim_path, signer_dir))
            return ("corim", devices)

        path = config.get("verifier", "spdm_measurement_policy", fallback="")

        if not path or not os.path.isfile(path):
            return None

        with open(path, encoding="utf-8") as f:
            return ("json", json.load(f))

    @staticmethod
    def _match_corim_device(devices: dict, device_hint: str) -> Optional[str]:
        """Match a ComponentIntegrity identity hint against CoRIM device names.

        CoRIM devices are identified as 'vendor/model[instance]' (e.g. 'NVIDIA/CEC1736 ERoT[1]'), while the
        collector knows the Redfish ComponentIntegrity ID (e.g. 'HGX_ERoT_BMC_0'). The matching is
        substring-based: a CoRIM device matches when its model name appears in the hint (case-insensitive),
        covering the common pattern where the ComponentIntegrity ID embeds the device model.
        """
        if not device_hint:
            return None

        hint_lower = device_hint.lower()

        # Exact match first
        if device_hint in devices:
            return device_hint

        # Substring match: CoRIM model name appears in the ComponentIntegrity ID
        for device_name in devices:
            # Extract the model part (between '/' and '[')
            parts = device_name.split("/")
            if len(parts) < 2:
                continue
            model = parts[1].split("[")[0].strip()
            if model and model.lower() in hint_lower:
                return device_name

        return None

    def verify_evidence(self) -> None:
        # pylint: disable=protected-access
        item = self._select_spdm_item()

        if not item:
            return

        logger.info("Starting SPDM verification of attestation %s for agent '%s'...", self.index, self.agent_id)

        failure = Failure(Component.SPDM)
        hash_algorithm = item.chosen_parameters.hash_algorithm or "sha384"

        try:
            chain_blob = item.data.meta.get("spdm_cert_chain")

            if isinstance(chain_blob, str):
                chain_blob = base64.b64decode(chain_blob)

            certs = parse_cert_chain(chain_blob)
            verify_cert_chain(certs, self._trust_store())
        except Exception as e:
            failure.add_event(
                "invalid_cert_chain",
                {"message": "SPDM device certificate chain could not be validated", "error": str(e)},
                False,
            )
            self._process_results(failure)
            return

        message = item.data.message
        signature = item.data.signature

        try:
            verify_signature(message, signature, certs[0], hash_algorithm)
        except Exception as e:
            failure.add_event(
                "invalid_signature",
                {"message": "signature over SPDM measurements is invalid", "error": str(e)},
                False,
            )
            self._process_results(failure)
            return

        # Locate the MEASUREMENTS response within the signed statement. SPDM-capable BMCs sign the full L2
        # transcript (VCA + GET_MEASUREMENTS request + response); the signature is verified over the whole
        # statement, while the measurements and nonce are parsed from the located response
        try:
            response_offset = locate_measurements_message(message)
            blocks, nonce, _opaque_length = parse_measurements(message[response_offset:])
        except Exception as e:
            failure.add_event(
                "invalid_measurements", {"message": "SPDM measurements could not be parsed", "error": str(e)}, False
            )
            self._process_results(failure)
            return

        # Freshness: per DSP0274 the responder generates its own nonce and never echoes the requester's.
        # Freshness therefore rests on transcript coverage — the signed statement includes the
        # GET_MEASUREMENTS request carrying the verifier's challenge. Bare (transcript-less) responses
        # are accepted only when the challenge appears as the responder nonce, which still proves the
        # signer saw the challenge after it was issued.
        challenge = item.chosen_parameters.challenge
        fresh = False
        if challenge:
            challenge = bytes(challenge)
            if response_offset > 0:
                fresh = find_request_nonce(message[:response_offset]) == challenge
            else:
                fresh = bytes(nonce) == challenge

        if not fresh:
            failure.add_event(
                "nonce_mismatch",
                {
                    "message": "verifier challenge not covered by the signed SPDM statement: "
                    "no GET_MEASUREMENTS request carrying it was found in the transcript"
                    if response_offset > 0
                    else "responder nonce does not match the challenge issued by the verifier"
                },
                False,
            )
            self._process_results(failure)
            return

        # Appraisal: compare measurement blocks against the reference policy, if configured
        policy = self._load_reference_policy()

        if policy is not None:
            policy_kind, reference = policy

            if policy_kind == "corim":
                # reference is a per-device mapping: {device_name: {index: {digest_hex, ...}}}
                # Determine which device's reference to use from the evidence metadata
                device_hint = item.data.meta.get("spdm_device") or item.data.meta.get("component_id", "")
                matched_device = self._match_corim_device(reference, device_hint)

                if matched_device:
                    device_ref = reference[matched_device]
                    logger.info(
                        "Appraising SPDM measurements for agent '%s' against CoRIM device '%s' "
                        "(%d indexed reference values)",
                        self.agent_id,
                        matched_device,
                        len(device_ref),
                    )
                    for failure_message in appraise_against_corim(blocks, device_ref):
                        failure.add_event("measurement_mismatch", {"message": failure_message}, True)
                else:
                    # No device match: appraise against all devices' references (any match passes)
                    # This handles the single-component case where device identification is not yet wired
                    all_failures = []
                    for device_name, device_ref in reference.items():
                        device_failures = appraise_against_corim(blocks, device_ref)
                        if not device_failures:
                            logger.info(
                                "SPDM measurements for agent '%s' match CoRIM device '%s'",
                                self.agent_id,
                                device_name,
                            )
                            all_failures = []
                            break
                        all_failures = device_failures

                    for failure_message in all_failures:
                        failure.add_event("measurement_mismatch", {"message": failure_message}, True)
            else:
                for block in blocks:
                    expected = reference.get(str(block.index))

                    if expected is None:
                        failure.add_event(
                            "unexpected_measurement",
                            {
                                "message": f"SPDM measurement block {block.index} is not covered by the reference policy",
                            },
                            True,
                        )
                    elif block.value.hex() != expected.removeprefix("0x"):
                        failure.add_event(
                            "measurement_mismatch",
                            {
                                "message": f"SPDM measurement block {block.index} does not match the reference value",
                                "expected": expected,
                                "got": f"0x{block.value.hex()}",
                            },
                            True,
                        )

        # Record parsed measurements in the evidence results for auditability. Assign a new dict (rather than
        # mutating in place) so the change is tracked by the model layer and persisted with the verification
        # results
        item.results.meta = {
            **(item.results.meta or {}),
            "measurements": [
                {
                    "index": block.index,
                    "value_type": block.value_type,
                    "value": f"0x{block.value.hex()}",
                }
                for block in blocks
            ],
        }

        self._process_results(failure)

    def _process_results(self, failure: Failure) -> None:
        # pylint: disable=protected-access
        if failure:
            self.attestation.evaluation = "fail"
            self.attestation.failure_reason = "broken_evidence_chain" if not failure.recoverable else "policy_violation"
            logger.warning(
                "Attestation %s for agent '%s' failed SPDM verification (see above)", self.index, self.agent_id
            )
            return

        # Dual-factor attestation: only pass if no other engine (e.g., TPM) has already recorded a failure
        if self.attestation.evaluation != "fail":
            self.attestation.evaluation = "pass"

        logger.info("Attestation %s for agent '%s' successfully passed SPDM verification", self.index, self.agent_id)
