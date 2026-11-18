"""Minimal DMTF SPDM (DSP0274) helpers for out-of-band hardware attestation.

This module provides just enough SPDM support for Keylime to appraise
SPDM measurement evidence collected out-of-band via Redfish
(DSP0268 ComponentIntegrity / SPDMGetSignedMeasurements). It is
deliberately not a full SPDM protocol stack: the BMC acts as the SPDM
requester and this code only consumes the signed MEASUREMENTS response
produced by the peripheral's hardware root of trust.

Structures follow the SPDM 1.x wire format:

    MEASUREMENTS response (with signature):
        SPDMVersion(1) SPDMMessageCode(1) Param1(1) Param2(1)
        NumberOfBlocks(1) MeasurementRecordLength(4)
        MeasurementRecord(var)
        Nonce(32)
        OpaqueDataLength(2) OpaqueData(var)
        Signature(var)

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

from keylime import cert_utils, keylime_logging

logger = keylime_logging.init_logging("spdm")

SPDM_MEASUREMENTS = 0x60
SPDM_NONCE_SIZE = 32


class SpdmError(Exception):
    """Raised when SPDM evidence cannot be parsed or verified."""


@dataclass(frozen=True)
class MeasurementBlock:
    """A single SPDM measurement block (DMTF measurement spec)."""

    index: int
    measurement_spec: int
    dmtf_spec: int
    value_type: int
    value: bytes


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
    signature itself must be stripped by the caller before calling this.
    """
    if len(message) < 8:
        raise SpdmError("SPDM measurements message is too short")

    version, code, _param1, _param2 = struct.unpack_from("<BBBB", message, 0)
    if version not in (0x10, 0x11, 0x12, 0x13):
        raise SpdmError(f"unsupported SPDM version 0x{version:02x} in measurements message")
    if code != SPDM_MEASUREMENTS:
        raise SpdmError(f"message code 0x{code:02x} is not an SPDM MEASUREMENTS response")

    number_of_blocks = message[4]
    record_length = struct.unpack_from("<I", message, 5)[0]
    offset = 9

    if offset + record_length > len(message):
        raise SpdmError("SPDM measurement record length exceeds message size")

    record_end = offset + record_length
    blocks: list[MeasurementBlock] = []

    while offset < record_end:
        if offset + 6 > record_end:
            raise SpdmError("truncated measurement block in SPDM measurements message")
        index, measurement_spec, dmtf_spec, value_type = struct.unpack_from("<BBBB", message, offset)
        value_size = struct.unpack_from("<H", message, offset + 4)[0]
        offset += 6
        if offset + value_size > record_end:
            raise SpdmError("measurement block value exceeds measurement record length")
        value = message[offset : offset + value_size]
        offset += value_size
        blocks.append(
            MeasurementBlock(
                index=index,
                measurement_spec=measurement_spec,
                dmtf_spec=dmtf_spec,
                value_type=value_type,
                value=value,
            )
        )

    if len(blocks) != number_of_blocks:
        raise SpdmError(
            f"SPDM measurements message reports {number_of_blocks} blocks but {len(blocks)} could be parsed"
        )

    if record_end + SPDM_NONCE_SIZE + 2 > len(message):
        raise SpdmError("SPDM measurements message is truncated before nonce")

    nonce = message[record_end : record_end + SPDM_NONCE_SIZE]
    opaque_length = struct.unpack_from("<H", message, record_end + SPDM_NONCE_SIZE)[0]

    return blocks, nonce, opaque_length


def locate_measurements_message(transcript: bytes) -> int:
    """Locate the SPDM MEASUREMENTS response within a signed statement.

    SPDM-capable BMCs sign the full L2 measurement transcript — VCA (the version/capabilities/algorithms
    negotiation) followed by the GET_MEASUREMENTS request and the MEASUREMENTS response. The `SignedMeasurements`
    blob conveyed by Redfish is that transcript with the signature appended.

    This function scans for the MEASUREMENTS response (the only message with code 0x60 in the transcript)
    and returns its offset. A bare (transcript-less) response is simply found at offset 0. The located
    message must end exactly at the end of the buffer: the MEASUREMENTS response is always the last
    message of the transcript, immediately preceding the signature.

    :raises SpdmError: no well-formed MEASUREMENTS response ending at the buffer end was found
    """
    if len(transcript) < 9:
        raise SpdmError("signed SPDM statement is too short to contain a MEASUREMENTS response")

    for offset in range(0, len(transcript) - 8):
        # SPDM message header: version(1) code(1) param1(1) param2(1)
        if transcript[offset + 1] != SPDM_MEASUREMENTS:
            continue

        # Candidate: validate the internal structure and require an exact fit to the buffer end
        record_length = struct.unpack_from("<I", transcript, offset + 5)[0]
        nonce_end = offset + 9 + record_length + SPDM_NONCE_SIZE
        if nonce_end + 2 > len(transcript):
            continue

        opaque_length = struct.unpack_from("<H", transcript, nonce_end)[0]
        message_end = nonce_end + 2 + opaque_length

        if message_end != len(transcript):
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


def find_nonce_offset(message: bytes) -> int:
    """Return the offset of the nonce field within an SPDM MEASUREMENTS message."""
    _blocks, _nonce, _opaque = parse_measurements(message)
    record_length = struct.unpack_from("<I", message, 5)[0]
    return 9 + record_length


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
