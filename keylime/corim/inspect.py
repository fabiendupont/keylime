"""CoRIM inspection tooling.

Pretty-prints the CBOR structure of a CoRIM file (COSE_Sign1-wrapped or plain) with the
known DMTF label names resolved, and reports whether the current keylime CoRIM subset can
appraise against it. Intended for bring-up against real vendor manifests, e.g. the NVIDIA
DGX GB300 NVL72 per-component CoRIMs shipped in the firmware bundles:

    python3 -m keylime.corim.inspect <file.corim> [--signers <dir>]

Use this to compare a real manifest's structure against the supported subset before
wiring it into the verifier's spdm_corim configuration.
"""

import argparse
import sys
from typing import Any

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from keylime import keylime_logging
from keylime.corim.corim import COSE_ALG, COSE_ALGS, COSE_X5CHAIN, verify_cose_sign1

logger = keylime_logging.init_logging("corim_inspect")

LABEL_NAMES = {
    # CoRIM
    0: "rim-format",
    1: "rim-tag",
    2: "profile-name / rim-profile?",
    3: "tags",
    # CoMID
    0: "comid-vnd-id?",
    1: "language?",
    2: "tag-identity",
    3: "entities?",
    4: "linked-tags?",
    8: "measurements?",
    9: "dev-identities?",
    10: "trip-counters?",
    # tag-identity-map
    0: "tag-id",
    1: "tag-version?",
    # entity-map
    0: "entity-name",
    1: "reg-id",
    2: "role",
    # measurement-value
    0: "m-key?",
    1: "digests?",
    2: "authorized-by?",
    3: "crypto-keys?",
    4: "mac-addr?",
    5: "serial-numbers?",
    6: "ueid?",
    7: "uuids?",
    8: "version?",
    9: "svn?",
    10: "measurement-values?",
    # COSE
    1: "alg",
    3: "content-type",
    4: "kid",
    33: "x5chain",
}


def _label(key: Any) -> str:
    if isinstance(key, int) and key in LABEL_NAMES:
        return f"{key} ({LABEL_NAMES[key]})"
    if isinstance(key, bytes):
        return f"bstr[{len(key)}] {key[:24].hex()}{'...' if len(key) > 24 else ''}"
    return repr(key)


def _dump(value: Any, indent: int = 0, max_depth: int = 8) -> None:
    pad = "  " * indent
    if indent > max_depth:
        print(f"{pad}…")
        return
    if isinstance(value, dict):
        for key, val in value.items():
            if isinstance(val, (dict, list)) and val:
                print(f"{pad}{_label(key)}:")
                _dump(val, indent + 1, max_depth)
            else:
                print(f"{pad}{_label(key)}: {_brief(val)}")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            if isinstance(item, (dict, list)) and item:
                print(f"{pad}[{i}]:")
                _dump(item, indent + 1, max_depth)
            else:
                print(f"{pad}[{i}]: {_brief(item)}")
    else:
        print(f"{pad}{_brief(value)}")


def _brief(value: Any) -> str:
    if isinstance(value, bytes):
        return f"bstr[{len(value)}] {value[:24].hex()}{'...' if len(value) > 24 else ''}"
    if isinstance(value, str):
        return repr(value[:80]) + ("…" if len(value) > 80 else "")
    return repr(value)


def inspect(path: str, signers_dir: str | None = None) -> int:
    with open(path, "rb") as f:
        blob = f.read()

    print(f"== {path} ({len(blob)} bytes) ==")

    # Try COSE_Sign1 first (bare array or CBOR tag 18, as used by real vendor manifests)
    payload = None
    try:
        decoded = cbor2.loads(blob)
        if isinstance(decoded, cbor2.CBORTag):
            if decoded.tag != 18:
                raise ValueError(f"CBOR tag {decoded.tag}")
            decoded = decoded.value
        protected, unprotected, cose_payload, signature = decoded
        if isinstance(protected, bytes) and isinstance(cose_payload, bytes):
            print("Envelope: COSE_Sign1")
            headers = cbor2.loads(protected)
            alg = headers.get(COSE_ALG)
            print(f"  alg: {alg} ({COSE_ALGS.get(alg, 'UNSUPPORTED')})")
            x5chain = headers.get(COSE_X5CHAIN)
            if x5chain is not None:
                chain = x5chain if isinstance(x5chain, list) else [x5chain]
                print(f"  x5chain: {len(chain)} certificate(s) carried")
                for cert_bytes in chain:
                    if isinstance(cert_bytes, bytes):
                        try:
                            cert = x509.load_der_x509_certificate(cert_bytes)
                            print(f"    - {cert.subject.rfc4514_string()} (valid until {cert.not_valid_after_utc.date()})")
                        except ValueError:
                            print("    - <unparseable>")
            payload = cose_payload
            if signers_dir:
                _try_verify(blob, signers_dir)
    except Exception:  # pylint: disable=broad-exception-caught
        print("Envelope: none (plain CBOR)")

    if payload is None:
        payload = blob

    print("\n== Structure ==")
    try:
        decoded = cbor2.loads(payload)
        _dump(decoded)
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"  not decodable as CBOR: {e}")
        return 1

    print("\n== keylime subset compatibility ==")
    from keylime.corim import parse_corim, parse_corim_devices

    try:
        devices = parse_corim_devices(payload)
        total = sum(len(m) for m in devices.values())
        print(f"  parse_corim_devices: OK — {len(devices)} device(s), {total} indexed measurement(s)")
        for dev, meas in sorted(devices.items()):
            print(f"    {dev}: indices {sorted(meas.keys())}")
        print("  appraiseable: yes")
        return 0
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"  parse_corim: FAILED — {e}")
        print("  appraiseable: no — the parser needs extending for this manifest's structure")
        print("  (compare the structure dump above against keylime/corim/corim.py)")
        return 2


def _try_verify(blob: bytes, signers_dir: str) -> None:
    from keylime.corim.corim import _load_certs_from_dir

    try:
        trusted = _load_certs_from_dir(signers_dir)
        verify_cose_sign1(blob, trusted)
        print(f"  signature: VALID against a signer in {signers_dir}")
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"  signature: FAILED — {e}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect a CoRIM file and check keylime parser compatibility")
    parser.add_argument("corim", help="path to the CoRIM file")
    parser.add_argument("--signers", help="directory of trusted signer certificates (PEM)", default=None)
    args = parser.parse_args()

    return inspect(args.corim, args.signers)


if __name__ == "__main__":
    sys.exit(main())
