"""Minimal CoRIM/CoMID support for SPDM measurement appraisal (DMTF CoRIM, RATS RFC 9334).

This module implements just enough of the Concise Reference Integrity Manifest format to
appraise SPDM measurements against signed vendor manifests:

* parsing of a COSE_Sign1-wrapped CoRIM (RFC 9052) and its CoMID measurement maps;
* verification of the COSE signature against a trusted signer certificate; and
* appraisal of SPDM measurement blocks against the digests declared in the manifest's
  measurement maps.

The supported subset is: a CoRIM map whose 'tags' member (label 3) contains CoMID maps;
each CoMID's 'measurements' member (label 8) contains measurement maps keyed by
measurement index (matching SPDM measurement block indices); each measurement value
carries 'digests' (label 1), a list of {alg-id, digest} entries (labels 1/2 or 2-element
arrays are accepted). Signatures may use ES256/ES384/ES512 or PS256/PS384/PS512, with the
signer certificate carried in the COSE 'x5chain' protected header or pinned out of band.
"""

import hashlib
import os
from typing import Any, Optional, Union

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import load_pem_x509_certificate

from keylime import keylime_logging

logger = keylime_logging.init_logging("corim")

# CoRIM map labels
RIM_TAGS = 3

# CoMID map labels
COMID_MEASUREMENTS = 8

# Measurement value labels
MEASUREMENT_DIGESTS = 1

# COSE common header parameters and algorithms
COSE_ALG = 1
COSE_X5CHAIN = 33
COSE_ALGS = {
    -7: ("ecdsa", "sha256"),
    -35: ("ecdsa", "sha384"),
    -36: ("ecdsa", "sha512"),
    -257: ("rsassa", "sha256"),
    -258: ("rsassa", "sha384"),
    -259: ("rsassa", "sha512"),
}


class CorimError(Exception):
    """Raised when a CoRIM cannot be parsed or its signature verified."""


def _digest_hex(digest_entry: Any) -> Optional[str]:
    """Extract a digest as a hex string from a CoMID digest entry, which may be a map
    ({alg-id: int, digest: bytes}, in either label order) or a 2-element array."""
    if isinstance(digest_entry, dict):
        if 2 in digest_entry and isinstance(digest_entry[2], bytes):
            return digest_entry[2].hex()
        if 1 in digest_entry and isinstance(digest_entry[1], bytes):
            return digest_entry[1].hex()
        for value in digest_entry.values():
            if isinstance(value, bytes):
                return value.hex()
    elif isinstance(digest_entry, (list, tuple)) and len(digest_entry) == 2:
        if isinstance(digest_entry[1], bytes):
            return digest_entry[1].hex()
    return None


def parse_corim(cbor_bytes: bytes) -> dict[int, set[str]]:
    """Parse the measurement maps out of a CoRIM (already unwrapped from COSE, if any).

    Returns a mapping of measurement index (int) to the set of acceptable digest values
    (hex strings)."""
    corim = cbor2.loads(cbor_bytes)

    if not isinstance(corim, dict):
        raise CorimError("CoRIM is not a CBOR map")

    tags = corim.get(RIM_TAGS)

    if not isinstance(tags, list):
        raise CorimError("CoRIM does not contain a 'tags' member with CoMIDs")

    measurements: dict[int, set[str]] = {}

    for tag in tags:
        if not isinstance(tag, dict):
            continue

        measurement_maps = tag.get(COMID_MEASUREMENTS)

        if not isinstance(measurement_maps, list):
            continue

        for measurement_map in measurement_maps:
            if not isinstance(measurement_map, dict):
                continue

            for key, value in measurement_map.items():
                if not isinstance(value, dict):
                    continue

                digests = value.get(MEASUREMENT_DIGESTS)
                if not isinstance(digests, list):
                    continue

                acceptable = set()
                for entry in digests:
                    digest = _digest_hex(entry)
                    if digest:
                        acceptable.add(digest)

                if acceptable and isinstance(key, int):
                    measurements.setdefault(key, set()).update(acceptable)

    if not measurements:
        raise CorimError("CoRIM contains no usable CoMID measurement maps")

    return measurements


def _load_certs_from_dir(trust_dir: str) -> list[x509.Certificate]:
    certs = []

    if not os.path.isdir(trust_dir):
        raise CorimError(f"CoRIM signer trust store '{trust_dir}' is not a directory")

    for name in sorted(os.listdir(trust_dir)):
        if not name.endswith(".pem") and not name.endswith(".crt") and not name.endswith(".cer"):
            continue
        with open(os.path.join(trust_dir, name), "rb") as f:
            certs.append(load_pem_x509_certificate(f.read()))

    if not certs:
        raise CorimError(f"CoRIM signer trust store '{trust_dir}' contains no certificates")

    return certs


def verify_cose_sign1(blob: bytes, trusted_signers: list[x509.Certificate]) -> bytes:
    """Verify a COSE_Sign1-wrapped CoRIM and return its payload.

    The signer certificate must either be carried in the protected 'x5chain' header and
    match (by DER bytes) one of the trusted signers, or be pinned entirely out of band
    (each trusted signer is tried against the signature).
    """
    try:
        protected, _unprotected, payload, signature = cbor2.loads(blob)
    except Exception as e:
        raise CorimError(f"blob is not a well-formed COSE_Sign1 structure: {e}") from e

    try:
        protected_headers = cbor2.loads(protected)
    except Exception as e:
        raise CorimError(f"COSE protected header is not valid CBOR: {e}") from e

    alg = protected_headers.get(COSE_ALG)

    if alg not in COSE_ALGS:
        raise CorimError(f"unsupported COSE algorithm '{alg}' in CoRIM signature")

    _family, hash_name = COSE_ALGS[alg]
    hash_alg = getattr(hashes, hash_name.upper(), None)

    if hash_alg is None:
        raise CorimError(f"unsupported hash algorithm '{hash_name}' for CoRIM signature")

    # Candidates for the signing key: certificates pinned out of band, or an x5chain in
    # the protected header that matches a trusted signer
    candidates: list[x509.Certificate] = list(trusted_signers)

    x5chain = protected_headers.get(COSE_X5CHAIN)
    if x5chain is not None:
        chain = x5chain if isinstance(x5chain, list) else [x5chain]
        carried = []
        for cert_bytes in chain:
            if not isinstance(cert_bytes, bytes):
                continue
            try:
                carried.append(x509.load_der_x509_certificate(cert_bytes))
            except ValueError:
                continue

        # Only trust a carried certificate if it is identical to one of the trusted ones
        trusted_ders = {c.public_bytes(Encoding.DER) for c in trusted_signers}
        for cert in carried:
            if cert.public_bytes(Encoding.DER) in trusted_ders:
                candidates.insert(0, cert)

    # COSE signature structure: ["Signature1", protected, external_aad, payload]
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])

    last_error = None
    for cert in candidates:
        public_key = cert.public_key()
        try:
            if isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(signature, sig_structure, ec.ECDSA(hash_alg()))
            elif isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(signature, sig_structure, padding.PKCS1v15(), hash_alg())
            else:
                continue
            return payload
        except Exception as e:  # pylint: disable=broad-exception-caught
            last_error = e

    raise CorimError(f"CoRIM signature does not verify against any trusted signer ({last_error})")


def load_and_verify(path: str, trust_dir: str) -> dict[int, set[str]]:
    """Load, verify and parse a CoRIM file (COSE_Sign1-wrapped or plain CBOR).

    Plain (unsigned) CoRIMs are only accepted for testing and log a loud warning; set
    allow_unsigned on the appraisal call site only in test code."""
    with open(path, "rb") as f:
        blob = f.read()

    trusted = _load_certs_from_dir(trust_dir)

    try:
        payload = verify_cose_sign1(blob, trusted)
    except CorimError as e:
        if _looks_like_plain_corim(blob):
            logger.warning("Loading UNSIGNED CoRIM from %s — this must never happen in production", path)
            payload = blob
        else:
            raise CorimError(f"CoRIM '{path}' could not be verified: {e}") from e

    return parse_corim(payload)


def _looks_like_plain_corim(blob: bytes) -> bool:
    try:
        parsed = cbor2.loads(blob)
        return isinstance(parsed, dict) and RIM_TAGS in parsed
    except Exception:
        return False


def appraise_measurements(
    blocks: list[Any], reference: dict[Union[int, str], set[str]]
) -> list[str]:
    """Appraise SPDM measurement blocks against a parsed CoRIM (or JSON) reference.

    Each block must match a measurement index in the reference with the same digest
    value. Returns a list of human-readable failure descriptions (empty when the
    measurements conform)."""
    failures = []
    provided = set()
    matched = set()

    for block in blocks:
        provided.add(block.index)
        acceptable = reference.get(block.index)

        if acceptable is None:
            failures.append(f"measurement block {block.index} is not covered by the reference integrity manifest")
            continue

        digest = block.value.hex()

        if digest in acceptable:
            matched.add(block.index)
        else:
            failures.append(
                f"measurement block {block.index} does not match any digest in the reference integrity manifest"
            )

    for index in sorted(set(reference.keys()) - provided):
        failures.append(f"reference integrity manifest expects measurement block {index} which was not provided")

    return failures


def sign_corim(corim: dict, private_key, alg: int = -35) -> bytes:
    """Sign a CoRIM with a COSE_Sign1 envelope. Intended for tests and tooling, not for
    the verifier path."""
    payload = cbor2.dumps(corim)
    protected = cbor2.dumps({COSE_ALG: alg})

    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])

    if alg in (-7, -35, -36):
        hash_alg = {-7: hashes.SHA256, -35: hashes.SHA384, -36: hashes.SHA512}[alg]
        signature = private_key.sign(sig_structure, ec.ECDSA(hash_alg()))
    else:
        hash_alg = {-257: hashes.SHA256, -258: hashes.SHA384, -259: hashes.SHA512}[alg]
        signature = private_key.sign(sig_structure, padding.PKCS1v15(), hash_alg())

    return cbor2.dumps([protected, {}, payload, signature])


def digest_of(data: bytes, hash_name: str = "sha384") -> str:
    """Utility: hex digest of arbitrary bytes, for building CoRIM fixtures."""
    return hashlib.new(hash_name, data).hexdigest()
