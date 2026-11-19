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
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509 import load_pem_x509_certificate

from keylime import keylime_logging

logger = keylime_logging.init_logging("corim")

# CBOR tags (IANA / DMTF CoRIM specification)
COSE_SIGN1_TAG = 18
CORIM_TAG = 501
COMID_TAG = 506

# CoRIM map labels
RIM_TAGS = 1

# CoMID map labels
COMID_TAG_IDENTITY = 1
COMID_MEASUREMENTS = 4

# Measurement value labels
MEASUREMENT_INDEX = 0
MEASUREMENT_DIGESTS = 1
MEASUREMENT_DIGEST_LIST = 2

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


def _unwrap_cose(cbor_bytes: bytes) -> bytes:
    """If the input is a COSE_Sign1 envelope (CBOR tag 18), return its payload; otherwise return the
    input unchanged, assuming it is already an unwrapped CoRIM payload."""
    try:
        decoded = cbor2.loads(cbor_bytes)
    except Exception as e:  # pylint: disable=broad-exception-caught
        raise CorimError(f"input is not valid CBOR: {e}") from e

    if isinstance(decoded, cbor2.CBORTag) and decoded.tag == COSE_SIGN1_TAG:
        _protected, _unprotected, payload, _signature = decoded.value
        return payload

    return cbor_bytes


def _decode_tagged(value: Any, tag: int) -> Any:
    """Decode a CBOR-tagged value, tolerating double encoding (tag wrapping a bstr of the CBOR bytes),
    which is how CoMIDs appear inside real manifests. Returns the tagged content, decoded."""
    for _ in range(2):  # tolerate both [tag, content] and [tag, bstr(tagged content)]
        if isinstance(value, cbor2.CBORTag):
            if value.tag != tag:
                raise CorimError(f"expected CBOR tag {tag}, got {value.tag}")
            value = value.value
        elif isinstance(value, bytes):
            value = cbor2.loads(value)
        else:
            break
    return value


def _normalize_measurement_maps(measurements: Any) -> list:
    """The CoMID 'measurements' member appears either as a list of measurement maps or as a map keyed by
    an integer (typically 0) containing that list; normalize to the list."""
    if isinstance(measurements, dict):
        for value in measurements.values():
            if isinstance(value, list):
                return value
        raise CorimError("CoMID measurements map does not contain a list of measurement maps")
    if isinstance(measurements, list):
        return measurements
    raise CorimError("CoMID measurements member has an unexpected type")


def _measurement_key_components(m_key: Any) -> Optional[dict]:
    """Extract the device identity components (environment class, vendor, model, instance) from a
    measurement-map key."""
    if not isinstance(m_key, dict) or 0 not in m_key:
        return None
    env = m_key[0]
    if not isinstance(env, dict):
        return None
    class_id = env.get(0)
    if isinstance(class_id, cbor2.CBORTag):
        class_id = class_id.value
    if isinstance(class_id, bytes):
        try:
            class_id = class_id.decode("utf-8", errors="replace")
        except Exception:  # pylint: disable=broad-exception-caught
            return None
    return {
        "class": class_id,
        "vendor": env.get(1),
        "model": env.get(2),
        "instance": env.get(3),
    }


def _measurement_digests(m_val: Any) -> list[str]:
    """Extract the digest values (hex strings) from a measurement-map value. The value is a list of attribute
    maps; digest attributes are keyed MEASUREMENT_DIGESTS and hold either a versioned digest container
    ({0: version, 2: entries}) or an algorithm-tagged one ({1: cose-alg, 2: entries}), where each entry is a
    2-element array whose final element is the digest bytes."""
    digests: list[str] = []

    if not isinstance(m_val, list):
        return digests

    for attrs in m_val:
        if not isinstance(attrs, dict):
            continue

        digest_container = attrs.get(MEASUREMENT_DIGESTS)
        if not isinstance(digest_container, dict):
            continue

        entries = digest_container.get(MEASUREMENT_DIGEST_LIST)
        if not isinstance(entries, list):
            continue

        for entry in entries:
            digest = _digest_hex(entry)
            if digest:
                digests.append(digest)

    return digests


def _indexed_digests(m_val: Any) -> list[tuple[int, list[str]]]:
    """Extract (measurement index, digests) pairs from a measurement-map value.

    The value is a list of attribute maps. Index and digests may appear in the same attribute map
    ({index: ..., digests: ...}, as in the NVIDIA CEC1736 measurements) or in adjacent maps (an index
    attribute followed by a digest attribute, as in the MCXN556 measurements); both forms are handled
    by tracking the most recent index seen.
    """
    results: list[tuple[int, list[str]]] = []
    current_index: Optional[int] = None

    if not isinstance(m_val, list):
        return results

    for attrs in m_val:
        if not isinstance(attrs, dict):
            continue

        index = attrs.get(MEASUREMENT_INDEX)
        if isinstance(index, int):
            current_index = index

        digest_container = attrs.get(MEASUREMENT_DIGESTS)
        if isinstance(digest_container, dict):
            entries = digest_container.get(MEASUREMENT_DIGEST_LIST)
            if isinstance(entries, list):
                digests = [d for d in (_digest_hex(e) for e in entries) if d]
                if digests and current_index is not None:
                    results.append((current_index, digests))

    return results


def parse_corim(cbor_bytes: bytes) -> dict[int, set[str]]:
    """Parse the measurement maps out of a CoRIM payload (already unwrapped from COSE, if any).

    Returns a mapping of measurement index (int) to the set of acceptable digest values (hex strings).
    Follows the DMTF CoRIM wire format as observed in real vendor manifests (NVIDIA VR-NVL72): a CBOR
    tag 501 wrapping a map with 'tags' (label 1) containing CoMIDs (CBOR tag 506, possibly double
    encoded as a byte string), each CoMID carrying 'measurements' (label 4). A COSE_Sign1-wrapped
    input (CBOR tag 18) is unwrapped automatically.
    """
    corim = _decode_tagged(_unwrap_cose(cbor_bytes), CORIM_TAG)

    if not isinstance(corim, dict):
        raise CorimError("CoRIM is not a CBOR map")

    tags = corim.get(RIM_TAGS)

    if not isinstance(tags, list):
        raise CorimError("CoRIM does not contain a 'tags' member with CoMIDs")

    measurements: dict[int, set[str]] = {}

    for tag in tags:
        comid = _decode_tagged(tag, COMID_TAG)
        if not isinstance(comid, dict):
            continue

        measurement_maps = _normalize_measurement_maps(comid.get(COMID_MEASUREMENTS))

        for measurement_map in measurement_maps:
            # Measurement maps appear either as [m-key, m-val] arrays or as {m-key: m-val} dicts
            if isinstance(measurement_map, dict):
                pairs = measurement_map.items()
            elif isinstance(measurement_map, list) and len(measurement_map) == 2:
                pairs = [(measurement_map[0], measurement_map[1])]
            else:
                continue

            for _m_key, m_val in pairs:
                for index, digests in _indexed_digests(m_val):
                    measurements.setdefault(index, set()).update(digests)

    if not measurements:
        raise CorimError("CoRIM contains no usable CoMID measurement maps")

    return measurements


def parse_corim_devices(cbor_bytes: bytes) -> dict[str, dict[int, set[str]]]:
    """Parse a CoRIM payload into per-device measurement references.

    Returns a mapping of device identity ("vendor/model[instance]") to a mapping of measurement index to
    the set of acceptable digests. This is the reference structure needed for multi-component appraisal,
    where SPDM measurement indices collide across devices (every eRoT has indices 1..N). A
    COSE_Sign1-wrapped input (CBOR tag 18) is unwrapped automatically.
    """
    corim = _decode_tagged(_unwrap_cose(cbor_bytes), CORIM_TAG)

    if not isinstance(corim, dict):
        raise CorimError("CoRIM is not a CBOR map")

    tags = corim.get(RIM_TAGS)
    if not isinstance(tags, list):
        raise CorimError("CoRIM does not contain a 'tags' member with CoMIDs")

    devices: dict[str, dict[int, set[str]]] = {}

    for tag in tags:
        comid = _decode_tagged(tag, COMID_TAG)
        if not isinstance(comid, dict):
            continue

        measurement_maps = _normalize_measurement_maps(comid.get(COMID_MEASUREMENTS))

        for measurement_map in measurement_maps:
            if isinstance(measurement_map, dict):
                pairs = measurement_map.items()
            elif isinstance(measurement_map, list) and len(measurement_map) == 2:
                pairs = [(measurement_map[0], measurement_map[1])]
            else:
                continue

            for m_key, m_val in pairs:
                identity = _measurement_key_components(m_key)
                if identity is None:
                    continue

                device = f"{identity['vendor']}/{identity['model']}[{identity['instance']}]"

                for index, digests in _indexed_digests(m_val):
                    devices.setdefault(device, {}).setdefault(index, set()).update(digests)

    if not devices:
        raise CorimError("CoRIM contains no usable device measurement maps")

    return devices


def _cose_ecdsa_signature(signature: bytes, curve_bits: int) -> bytes:
    """Convert a COSE raw r||s ECDSA signature (per RFC 9052) to the DER encoding expected by
    python-cryptography."""
    coordinate_size = (curve_bits + 7) // 8
    raw_size = 2 * coordinate_size

    if len(signature) == raw_size:
        r = int.from_bytes(signature[:coordinate_size], "big")
        s = int.from_bytes(signature[coordinate_size:], "big")
        return encode_dss_signature(r, s)

    return signature


def _cert_signed_by(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Return True when child's signature verifies under issuer's public key."""
    public_key = issuer.public_key()
    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), child.signature_hash_algorithm
            )
        else:
            return False
        return True
    except Exception:  # pylint: disable=broad-exception-caught
        return False


def _chains_to_anchor(leaf: x509.Certificate, pool: list[x509.Certificate]) -> bool:
    """Return True when the leaf chains, through certificates in the pool, to a self-signed certificate that is
    itself part of the pool (the trust anchor). Real vendor CoRIMs are signed by per-product leaves several
    levels below the root (e.g. NVIDIA's L4 product signers under L1/L2/L3 intermediates), so direct
    leaf-vs-anchor verification is insufficient."""
    anchors = [c for c in pool if c.subject == c.issuer]
    current = leaf
    seen = set()

    while True:
        if current.public_bytes(Encoding.DER) in seen:
            return False
        seen.add(current.public_bytes(Encoding.DER))

        if any(current.public_bytes(Encoding.DER) == a.public_bytes(Encoding.DER) for a in anchors):
            return True

        issuer = next((c for c in pool if c.subject == current.issuer and _cert_signed_by(current, c)), None)
        if issuer is None:
            return False
        current = issuer


def verify_cose_sign1(blob: bytes, trusted_signers: list[x509.Certificate]) -> bytes:
    """Verify a COSE_Sign1-wrapped CoRIM and return its payload.

    The signer certificate must either be carried in the protected 'x5chain' header and
    match (by DER bytes) one of the trusted signers, or be pinned entirely out of band
    (each trusted signer is tried against the signature).
    """
    try:
        envelope = cbor2.loads(blob)
        # COSE_Sign1 is CBOR tag 18; tolerate both the tagged form (as used by real vendor manifests)
        # and the bare 4-element array
        if isinstance(envelope, cbor2.CBORTag):
            if envelope.tag != COSE_SIGN1_TAG:
                raise CorimError(f"expected COSE_Sign1 (CBOR tag 18), got tag {envelope.tag}")
            envelope = envelope.value
        protected, _unprotected, payload, signature = envelope
    except CorimError:
        raise
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
                der_sig = _cose_ecdsa_signature(signature, public_key.curve.key_size)
                public_key.verify(der_sig, sig_structure, ec.ECDSA(hash_alg()))
            elif isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(signature, sig_structure, padding.PKCS1v15(), hash_alg())
            else:
                continue
        except Exception as e:  # pylint: disable=broad-exception-caught
            last_error = e
            continue

        # The signature verifies under this certificate's key; it is only trusted if the certificate
        # chains to a self-signed anchor in the trusted pool
        if _chains_to_anchor(cert, trusted_signers):
            return payload
        last_error = CorimError(f"signer '{cert.subject.rfc4514_string()}' does not chain to a trust anchor")

    raise CorimError(f"CoRIM signature does not verify against any trusted signer ({last_error})")


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
