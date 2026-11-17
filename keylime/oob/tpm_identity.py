"""swtpm-backed TPM identity for the out-of-band attestation collector.

The OOB collector cannot run inside the tenant OS (that would defeat the point
of agentless attestation), but the verifier's authentication model requires a
TPM proof of possession. The collector therefore holds a *software* TPM
(swtpm) as its identity device: the TPM provides the identity/authentication
channel (EK/AK registration, session PoP), while the SPDM measurements
collected from the BMC provide the actual attestation evidence.

This module drives tpm2-tools against a swtpm instance over its unix socket.
Keys are persisted at fixed permanent handles so they survive across collector
restarts (and swtpm restarts, as the TPM state is on disk):

    0x81010000  EK (endorsement-restricted primary)
    0x81010001  owner storage primary (parent of the AK)
    0x81010002  AK (restricted signing key)

The AK is deliberately created under the owner hierarchy rather than as a
child of the EK: the registrar binds the AK to the EK via
MakeCredential/ActivateCredential (which only requires matching names, not
parentage), and owner-hierarchy keys avoid the EK policy session quirks of
some swtpm profiles.
"""

import base64
import hmac
import hashlib
import os
import subprocess
import tempfile
from typing import Optional, Tuple

from keylime import keylime_logging

logger = keylime_logging.init_logging("oob_tpm")

EK_HANDLE = "0x81010000"
OWNER_PRIMARY_HANDLE = "0x81010001"
AK_HANDLE = "0x81010002"

EK_ATTRS = "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt"
AK_ATTRS = "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign"


class TpmIdentityError(Exception):
    """Raised when the swtpm-backed TPM identity cannot be established or used."""


class SwtpmIdentity:
    def __init__(self, socket_path: str, workdir: Optional[str] = None):
        self.socket_path = socket_path
        self._workdir = workdir or tempfile.mkdtemp(prefix="keylime-oob-tpm-")
        self._env = {**os.environ, "TPM2TOOLS_TCTI": f"swtpm:path={socket_path}"}
        self._ek_tpm: Optional[bytes] = None
        self._ak_tpm: Optional[bytes] = None

    def _run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        result = subprocess.run(  # pylint: disable=subprocess-run-check
            list(args), env=self._env, cwd=self._workdir, capture_output=True, text=True, timeout=30
        )
        if check and result.returncode != 0:
            raise TpmIdentityError(f"command {' '.join(args)} failed: {result.stderr.strip()[:200]}")
        return result

    def _path(self, name: str) -> str:
        return os.path.join(self._workdir, name)

    def _persistent_handles(self) -> set[str]:
        result = self._run("tpm2_getcap", "handles-persistent")
        return {line.strip().lstrip("- ") for line in result.stdout.splitlines() if "0x" in line}

    def _create_keys(self) -> None:
        handles = self._persistent_handles()

        if EK_HANDLE not in handles:
            self._run(
                "tpm2_createprimary", "-C", "e", "-g", "sha256", "-G", "rsa2048", "-a", EK_ATTRS,
                "-c", self._path("ek.ctx"),
            )
            self._run("tpm2_evictcontrol", "-c", self._path("ek.ctx"), EK_HANDLE)
            self._run("tpm2_flushcontext", "-t", check=False)
            logger.info("Created EK at persistent handle %s", EK_HANDLE)

        if OWNER_PRIMARY_HANDLE not in handles:
            self._run(
                "tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "rsa2048", "-a", EK_ATTRS,
                "-c", self._path("o.ctx"),
            )
            self._run("tpm2_evictcontrol", "-c", self._path("o.ctx"), OWNER_PRIMARY_HANDLE)
            self._run("tpm2_flushcontext", "-t", check=False)
            logger.info("Created owner primary at persistent handle %s", OWNER_PRIMARY_HANDLE)

        if AK_HANDLE not in handles:
            self._run(
                "tpm2_create", "-C", OWNER_PRIMARY_HANDLE, "-G", "rsa:rsassa:null", "-g", "sha256",
                "-u", self._path("ak.pub"), "-r", self._path("ak.priv"), "-a", AK_ATTRS,
            )
            self._run(
                "tpm2_load", "-C", OWNER_PRIMARY_HANDLE, "-u", self._path("ak.pub"),
                "-r", self._path("ak.priv"), "-c", self._path("ak.ctx"),
            )
            self._run("tpm2_evictcontrol", "-c", self._path("ak.ctx"), AK_HANDLE)
            self._run("tpm2_flushcontext", "-t", check=False)
            logger.info("Created AK at persistent handle %s", AK_HANDLE)

    def initialize(self) -> None:
        """Ensure the swtpm is started up and the EK/AK exist. Reads the public blobs."""
        # A freshly started swtpm needs TPM2_Startup; ignore errors if already started
        self._run("tpm2_startup", "-c", check=False)
        self._create_keys()

        self._run("tpm2_readpublic", "-c", EK_HANDLE, "-f", "tss", "-o", self._path("ek.tss"))
        self._run("tpm2_readpublic", "-c", AK_HANDLE, "-f", "tss", "-o", self._path("ak.tss"))

        self._ek_tpm = open(self._path("ek.tss"), "rb").read()
        self._ak_tpm = open(self._path("ak.tss"), "rb").read()

    @property
    def ek_tpm(self) -> bytes:
        if self._ek_tpm is None:
            raise TpmIdentityError("TPM identity has not been initialized")
        return self._ek_tpm

    @property
    def ak_tpm(self) -> bytes:
        if self._ak_tpm is None:
            raise TpmIdentityError("TPM identity has not been initialized")
        return self._ak_tpm

    def certify(self, nonce: bytes) -> Tuple[bytes, bytes]:
        """Produce a TPM2_Certify of the AK over the given nonce (the session proof of possession).

        Returns the (attest, signature) blobs as expected by the verifier's tpm_pop verification.
        """
        nonce_hex = nonce.hex()
        self._run(
            "tpm2_certify", "-c", AK_HANDLE, "-C", AK_HANDLE, "-q", nonce_hex, "-g", "sha256",
            "-o", self._path("certify.msg"), "-s", self._path("certify.sig"),
        )
        attest = open(self._path("certify.msg"), "rb").read()
        signature = open(self._path("certify.sig"), "rb").read()
        return attest, signature

    def activate_credential(self, credential_blob: bytes, agent_id: str) -> str:
        """Activate a registrar AK challenge and return the auth tag (HMAC-SHA384 of the agent ID)."""
        with open(self._path("cred.blob"), "wb") as f:
            f.write(credential_blob)

        self._run(
            "tpm2_activatecredential", "-c", AK_HANDLE, "-C", EK_HANDLE,
            "-i", self._path("cred.blob"), "-o", self._path("cred.secret"),
        )
        secret = open(self._path("cred.secret"), "rb").read()

        # Mirror RegistrarAgent.verify_ak_response / crypto.do_hmac: the HMAC key is the Base64 encoding of
        # the recovered challenge secret, as stored by the registrar
        key = base64.b64encode(secret)
        return hmac.new(key, msg=agent_id.encode("utf-8"), digestmod=hashlib.sha384).hexdigest()
