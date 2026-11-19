"""Minimal DMTF SPDM (DSP0274) helpers for out-of-band hardware attestation.

This module provides just enough SPDM support for Keylime to appraise
SPDM measurement evidence collected out-of-band via Redfish
(DSP0268 ComponentIntegrity / SPDMGetSignedMeasurements). It is
deliberately not a full SPDM protocol stack: the BMC acts as the SPDM
requester and this code only consumes the signed MEASUREMENTS response
produced by the peripheral's hardware root of trust.

Structures follow the DMTF DSP0274 wire format:

    MEASUREMENTS response (with signature):
        SPDMVersion(1) SPDMMessageCode(1) Param1(1) Param2(1)
        NumberOfBlocks(1) MeasurementRecordLength(3 in SPDM 1.0/1.1, 4 from 1.2 on)
        MeasurementRecord(var)
        Nonce(32)
        OpaqueDataLength(2) OpaqueData(var)    [SPDM 1.2+]
        Signature(var)

    Each measurement block in the record is two-level (all SPDM versions):
        Index(1) MeasurementSpecification(1) MeasurementSize(2)
        DMTFSpecMeasurementValueType(1) ValueSize(2) Value(var)
    where MeasurementSize covers the inner DMTF measurement, i.e.
    MeasurementSize == 3 + ValueSize.

    Note on SPDM 1.1: DSP0274 1.1 defines no OpaqueDataLength field in the
    MEASUREMENTS response (the signature follows the nonce directly). Some
    SPDM 1.1 responders — notably Microchip CEC173x eRoTs found in NVIDIA
    HGX racks — emit a 1.2-style OpaqueDataLength anyway. Both layouts are
    accepted for 1.0/1.1 messages.

    Certificate chain (SPDM CERTIFICATE response body):
        TotalLength(2) then, for each certificate, Length(2) + CertificateData(var)
"""

import base64
import re
import struct
from dataclasses import dataclass
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509 import load_der_x509_certificate

from keylime import keylime_logging

logger = keylime_logging.init_logging("spdm")

SPDM_MEASUREMENTS = 0x60
SPDM_GET_MEASUREMENTS = 0xE0
SPDM_NONCE_SIZE = 32
SPDM_VERSIONS = (0x10, 0x11, 0x12, 0x13)


class SpdmError(Exception):
    """Raised when SPDM evidence cannot be parsed or verified."""


@dataclass(frozen=True)
class MeasurementBlock:
    """A single SPDM measurement block (DSP0274 MeasurementBlock, DMTF measurement spec)."""

    index: int
    measurement_spec: int
    value_type: int
    value: bytes


def _record_length_size(version: int) -> int:
    """Size in bytes of the MeasurementRecordLength field for the given SPDM version.

    DSP0274 defines the field as uint24 in SPDM 1.0/1.1 and widens it to uint32 from SPDM 1.2 on.
    """
    return 3 if version <= 0x11 else 4


def parse_cert_chain(blob: bytes) -> list[x509.Certificate]:
    """Parse an SPDM certificate chain blob into a list of X.509 certificates (root first)."""
    if not blob or len(blob) < 4:
        raise SpdmError("SPDM certificate chain is too short")

    total_length = struct.unpack_from("<H", blob, 0)[0]
    if total_length + 2 != len(blob):
        raise SpdmError("SPDM certificate chain total length does not match blob size")

    certs = []
    offset = 2
    while offset < total_length + 2:
        if offset + 2 > total_length + 2:
            raise SpdmError("truncated certificate length field in SPDM certificate chain")
        cert_length = struct.unpack_from("<H", blob, offset)[0]
        offset += 2
        if cert_length == 0 or offset + cert_length > total_length + 2:
            raise SpdmError("invalid certificate length in SPDM certificate chain")
        try:
            certs.append(load_der_x509_certificate(blob[offset : offset + cert_length]))
        except ValueError as e:
            raise SpdmError(f"certificate in SPDM chain could not be parsed: {e}") from e
        offset += cert_length

    if not certs:
        raise SpdmError("SPDM certificate chain contains no certificates")

    return certs


def verify_cert_chain(certs: list[x509.Certificate], trust_store: str) -> None:
    """Verify each certificate in an SPDM chain is signed by the next, and that the chain roots in the given trust
    store directory. Raises SpdmError on failure."""
    # Imported lazily: cert_utils pulls pyasn1_modules.rfc4108, which is absent from the system
    # pyasn1_modules on some distributions (e.g. DGX OS / Ubuntu 22.04), and is not needed by the
    # OOB tooling until chains are actually verified
    from keylime import cert_utils  # pylint: disable=import-outside-toplevel

    for i, cert in enumerate(certs[:-1]):
        issuer = certs[i + 1]
        if cert.issuer != issuer.subject:
            raise SpdmError(f"certificate {i} in SPDM chain is not issued by certificate {i + 1}")
        issuer_pub = issuer.public_key()
        try:
            if isinstance(issuer_pub, rsa.RSAPublicKey):
                issuer_pub.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
            elif isinstance(issuer_pub, ec.EllipticCurvePublicKey):
                issuer_pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
            else:
                raise SpdmError(f"unsupported key type in SPDM chain certificate {i + 1}")
        except Exception as e:
            raise SpdmError(f"signature by certificate {i + 1} over certificate {i} in SPDM chain is invalid: {e}")

    if not cert_utils.verify_cert(certs[-1], trust_store, "SPDM device"):
        raise SpdmError("root of SPDM certificate chain is not issued by a CA present in the SPDM trust store")


def parse_measurements(message: bytes) -> tuple[list[MeasurementBlock], bytes, int]:
    """Parse the (unsigned portion of an) SPDM MEASUREMENTS response.

    Returns a tuple of (measurement blocks, nonce, opaque data length). The
    signature itself must be stripped by the caller before calling this. The
    message must end exactly at the end of the opaque data (or the nonce, for
    strict SPDM 1.0/1.1 responses without the OpaqueDataLength field).

    Conforms to DMTF DSP0274 for all versions:

    - SPDM 1.0/1.1: MeasurementRecordLength is a 3-byte uint24; the message
      ends at the nonce. The de-facto variant implemented by Microchip
      CEC173x responders (see note in the module docstring), which appends a
      1.2-style OpaqueDataLength field, is also accepted.
    - SPDM 1.2+: MeasurementRecordLength is a 4-byte uint32 and is followed,
      after the nonce, by OpaqueDataLength and OpaqueData.
    - Measurement blocks are two-level in all versions:
      Index(1) MeasurementSpecification(1) MeasurementSize(2), wrapping the
      DMTF measurement DMTFSpecMeasurementValueType(1) ValueSize(2) Value,
      with MeasurementSize == 3 + ValueSize enforced.
    """
    if len(message) < 8:
        raise SpdmError("SPDM measurements message is too short")

    version, code, _param1, _param2 = struct.unpack_from("<BBBB", message, 0)
    if version not in SPDM_VERSIONS:
        raise SpdmError(f"unsupported SPDM version 0x{version:02x} in measurements message")
    if code != SPDM_MEASUREMENTS:
        raise SpdmError(f"message code 0x{code:02x} is not an SPDM MEASUREMENTS response")

    number_of_blocks = message[4]
    length_size = _record_length_size(version)
    if len(message) < 5 + length_size:
        raise SpdmError("SPDM measurements message is truncated before measurement record length")

    record_length = int.from_bytes(message[5 : 5 + length_size], "little")
    offset = 5 + length_size

    if offset + record_length > len(message):
        raise SpdmError("SPDM measurement record length exceeds message size")

    record_end = offset + record_length
    blocks: list[MeasurementBlock] = []

    while offset < record_end:
        # MeasurementBlock: Index(1) MeasurementSpecification(1) MeasurementSize(2)
        if offset + 4 > record_end:
            raise SpdmError("truncated measurement block in SPDM measurements message")
        index = message[offset]
        measurement_spec = message[offset + 1]
        measurement_size = struct.unpack_from("<H", message, offset + 2)[0]
        offset += 4

        if offset + measurement_size > record_end:
            raise SpdmError("measurement block exceeds measurement record length")
        measurement = message[offset : offset + measurement_size]
        offset += measurement_size

        # DMTF measurement: DMTFSpecMeasurementValueType(1) ValueSize(2) Value
        if measurement_size < 3:
            raise SpdmError(f"measurement block {index} is too short to contain a DMTF measurement")
        value_type = measurement[0]
        value_size = struct.unpack_from("<H", measurement, 1)[0]
        if 3 + value_size != measurement_size:
            raise SpdmError(
                f"measurement block {index} inner size {value_size} is inconsistent with "
                f"MeasurementSize {measurement_size}"
            )
        value = measurement[3:]

        blocks.append(
            MeasurementBlock(
                index=index,
                measurement_spec=measurement_spec,
                value_type=value_type,
                value=value,
            )
        )

    if len(blocks) != number_of_blocks:
        raise SpdmError(
            f"SPDM measurements message reports {number_of_blocks} blocks but {len(blocks)} could be parsed"
        )

    # Nonce (responder-generated; the requester's nonce is never echoed — see find_request_nonce)
    nonce_end = record_end + SPDM_NONCE_SIZE
    if nonce_end > len(message):
        raise SpdmError("SPDM measurements message is truncated before nonce")
    nonce = message[record_end:nonce_end]

    if version >= 0x12:
        # SPDM 1.2+: OpaqueDataLength + OpaqueData, and the message ends exactly there
        if nonce_end + 2 > len(message):
            raise SpdmError("SPDM measurements message is truncated before opaque data length")
        opaque_length = struct.unpack_from("<H", message, nonce_end)[0]
        if nonce_end + 2 + opaque_length != len(message):
            raise SpdmError("SPDM measurements message has trailing data after opaque data")
    elif nonce_end == len(message):
        # Strict DSP0274 1.0/1.1: the message ends at the nonce
        opaque_length = 0
    else:
        # De-facto SPDM 1.1 (Microchip CEC173x): a 1.2-style OpaqueDataLength field is present
        if nonce_end + 2 > len(message):
            raise SpdmError("SPDM measurements message is truncated before opaque data length")
        opaque_length = struct.unpack_from("<H", message, nonce_end)[0]
        if nonce_end + 2 + opaque_length != len(message):
            raise SpdmError("SPDM measurements message has trailing data after opaque data")

    return blocks, nonce, opaque_length


def locate_measurements_message(transcript: bytes) -> int:
    """Locate the SPDM MEASUREMENTS response within a signed statement.

    SPDM-capable BMCs sign the measurement transcript — the GET_MEASUREMENTS request followed by the
    MEASUREMENTS response. The `SignedMeasurements` blob conveyed by Redfish is that transcript with
    the signature appended.

    This function scans for the MEASUREMENTS response (the only message with code 0x60 in the transcript)
    and returns its offset. A bare (transcript-less) response is simply found at offset 0. The located
    message must end exactly at the end of the buffer: the MEASUREMENTS response is always the last
    message of the transcript, immediately preceding the signature.

    Handles the version-dependent layouts described in the module docstring: 3-byte
    MeasurementRecordLength with or without the OpaqueDataLength field (SPDM 1.0/1.1), and 4-byte
    MeasurementRecordLength with OpaqueDataLength (SPDM 1.2+).

    :raises SpdmError: no well-formed MEASUREMENTS response ending at the buffer end was found
    """
    if len(transcript) < 9:
        raise SpdmError("signed SPDM statement is too short to contain a MEASUREMENTS response")

    for offset in range(0, len(transcript) - 7):
        # SPDM message header: version(1) code(1) param1(1) param2(1)
        if transcript[offset + 1] != SPDM_MEASUREMENTS:
            continue

        spdm_version = transcript[offset]
        if spdm_version not in SPDM_VERSIONS:
            continue

        length_size = _record_length_size(spdm_version)
        if offset + 5 + length_size > len(transcript):
            continue

        # Candidate: validate the internal structure and require an exact fit to the buffer end
        record_length = int.from_bytes(transcript[offset + 5 : offset + 5 + length_size], "little")
        nonce_end = offset + 5 + length_size + record_length + SPDM_NONCE_SIZE
        if nonce_end > len(transcript):
            continue

        if spdm_version >= 0x12:
            # SPDM 1.2+: Nonce || OpaqueDataLength(2) || OpaqueData
            if nonce_end + 2 > len(transcript):
                continue
            opaque_length = struct.unpack_from("<H", transcript, nonce_end)[0]
            if nonce_end + 2 + opaque_length != len(transcript):
                continue
        elif nonce_end == len(transcript):
            # Strict DSP0274 1.0/1.1: the message ends at the nonce
            pass
        elif nonce_end + 2 <= len(transcript):
            # De-facto SPDM 1.1 (Microchip CEC173x): Nonce || OpaqueDataLength(2) || OpaqueData
            opaque_length = struct.unpack_from("<H", transcript, nonce_end)[0]
            if nonce_end + 2 + opaque_length != len(transcript):
                continue
        else:
            continue

        # A candidate that structurally fits is the response; validate it fully by parsing
        try:
            parse_measurements(transcript[offset:])
            return offset
        except SpdmError:
            continue

    raise SpdmError("could not locate a MEASUREMENTS response ending at the end of the signed statement")


def chain_blob_from_pem(pem: str) -> bytes:
    """Convert a PEM certificate chain (concatenated BEGIN/END CERTIFICATE blocks, leaf first), as served by
    Redfish Certificate resources, into the DMTF DSP0274 chain blob format (2-byte total length, then
    2-byte length-prefixed DER certificates)."""
    certs = []

    for match in re.finditer(
        r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem, re.DOTALL
    ):
        b64_body = "".join(match.group(1).split())
        try:
            certs.append(base64.b64decode(b64_body))
        except Exception as e:
            raise SpdmError(f"certificate in PEM chain is not valid Base64: {e}") from e

    if not certs:
        raise SpdmError("no certificates found in PEM chain")

    body = b"".join(struct.pack("<H", len(der)) + der for der in certs)
    return struct.pack("<H", len(body)) + body


def signature_length(signing_algorithm: str) -> int:
    """Return the length in bytes of an SPDM signature produced with the given signing algorithm.

    SPDM conveys ECDSA signatures in raw r||s form (DER encoding is not used), so the length is fixed by the
    curve; RSA signatures are of the key size.
    """
    lengths = {
        "TPM_ALG_ECDSA_ECC_NIST_P256": 64,
        "TPM_ALG_ECDSA_ECC_NIST_P384": 96,
        "TPM_ALG_ECDSA_ECC_NIST_P521": 132,
        "TPM_ALG_RSAPSS_2048": 256,
        "TPM_ALG_RSAPSS_3072": 384,
        "TPM_ALG_RSAPSS_4096": 512,
        "TPM_ALG_RSASSA_2048": 256,
        "TPM_ALG_RSASSA_3072": 384,
        "TPM_ALG_RSASSA_4096": 512,
    }

    try:
        return lengths[signing_algorithm]
    except KeyError as e:
        raise SpdmError(f"unsupported SPDM signing algorithm '{signing_algorithm}'") from e


def verify_signature(
    message: bytes, signature: bytes, cert: x509.Certificate, hash_algorithm: str = "sha384"
) -> None:
    """Verify the signature over an SPDM MEASUREMENTS message using the leaf certificate of the device chain.

    The hash algorithm is the SPDM base hash algorithm negotiated for the session (defaulting to SHA-384, the
    most common choice on modern accelerator roots of trust).
    """
    public_key = cert.public_key()
    hash_alg = getattr(hashes, hash_algorithm.upper(), None)
    if hash_alg is None:
        raise SpdmError(f"unsupported hash algorithm '{hash_algorithm}' for SPDM signature verification")

    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, message, padding.PKCS1v15(), hash_alg())
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            # SPDM conveys ECDSA signatures in raw r||s form; convert to the DER encoding expected by
            # python-cryptography (falling back to DER if the signature is already in that form)
            sig = _decode_ecdsa_signature(signature, public_key.curve)
            public_key.verify(sig, message, ec.ECDSA(hash_alg()))
        else:
            raise SpdmError("unsupported key type in SPDM device certificate")
    except SpdmError:
        raise
    except Exception as e:
        raise SpdmError(f"signature over SPDM measurements message is invalid: {e}")


def _decode_ecdsa_signature(signature: bytes, curve: ec.EllipticCurve) -> bytes:
    """Convert a raw r||s SPDM ECDSA signature to DER encoding. Signatures already in DER form are returned
    unchanged."""
    coordinate_size = (curve.key_size + 7) // 8
    raw_size = 2 * coordinate_size

    if len(signature) == raw_size:
        r = int.from_bytes(signature[:coordinate_size], "big")
        s = int.from_bytes(signature[coordinate_size:], "big")
        return encode_dss_signature(r, s)

    # Already DER-encoded
    return signature


def find_request_nonce(transcript: bytes) -> Optional[bytes]:
    """Return the nonce carried by the GET_MEASUREMENTS request in a signed SPDM transcript.

    DSP0274 never echoes the requester's nonce in the MEASUREMENTS response — the responder
    generates its own. Freshness of the evidence therefore rests on transcript coverage: the
    GET_MEASUREMENTS request containing the requester's (verifier's) nonce is part of the signed
    statement. This function locates that request and extracts its nonce.

    The GET_MEASUREMENTS request is: version(1) code(0xE0) param1(1) param2(1) nonce(32) slot(1).

    :returns: the 32-byte request nonce, or None if no GET_MEASUREMENTS request is present
    """
    for offset in range(0, max(0, len(transcript) - 4 - SPDM_NONCE_SIZE) + 1):
        if transcript[offset] in SPDM_VERSIONS and transcript[offset + 1] == SPDM_GET_MEASUREMENTS:
            return transcript[offset + 4 : offset + 4 + SPDM_NONCE_SIZE]
    return None


def find_nonce_offset(message: bytes) -> int:
    """Return the offset of the nonce field within an SPDM MEASUREMENTS message."""
    _blocks, _nonce, _opaque = parse_measurements(message)
    version = message[0]
    record_length = int.from_bytes(message[5 : 5 + _record_length_size(version)], "little")
    return 5 + _record_length_size(version) + record_length


def split_signed_message(response: bytes, signature_length: Optional[int] = None) -> tuple[bytes, bytes]:
    """Split a signed SPDM MEASUREMENTS response into (message, signature).

    The signature covers the entire response up to and including the opaque
    data. If signature_length is None it is derived from the leaf certificate
    key size where possible; otherwise it must be provided by the caller.
    """
    if signature_length is None:
        raise SpdmError("signature length must be provided to split a signed SPDM message")
    if len(response) < signature_length:
        raise SpdmError("SPDM response is shorter than the expected signature")
    return response[:-signature_length], response[-signature_length:]
