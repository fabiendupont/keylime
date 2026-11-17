"""Minimal Redfish client for out-of-band SPDM attestation.

Implements just the subset of DMTF DSP0268 (Redfish) needed to collect signed
SPDM measurements out-of-band: session establishment and discovery of
ComponentIntegrity resources exposing SPDM actions.
"""

import requests

from keylime import keylime_logging

logger = keylime_logging.init_logging("oob_redfish")


class RedfishError(Exception):
    """Raised when a Redfish request fails or returns an unexpected response."""


class RedfishClient:
    def __init__(self, host, username, password, verify_tls=True, timeout=30):
        self.base_url = f"https://{host}"
        self.timeout = timeout
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.verify = verify_tls
        self.session.headers.update({"Content-Type": "application/json", "Accept": "application/json"})
        self._xauth_token = None

    def _headers(self):
        headers = {}
        if self._xauth_token:
            headers["X-Auth-Token"] = self._xauth_token
        return headers

    def _request(self, method, path, **kwargs):
        url = f"{self.base_url}{path}"
        try:
            response = self.session.request(
                method, url, timeout=self.timeout, headers=self._headers(), **kwargs
            )
        except requests.RequestException as e:
            raise RedfishError(f"could not {method} {url}: {e}") from e

        if response.status_code == 401:
            # Session may have expired; re-authenticate once and retry
            self._xauth_token = None
            self._establish_session()
            response = self.session.request(
                method, url, timeout=self.timeout, headers=self._headers(), **kwargs
            )

        if not response.ok:
            raise RedfishError(f"{method} {url} failed with status {response.status_code}: {response.text[:200]}")

        return response

    def _establish_session(self):
        response = self._request(
            "POST",
            "/redfish/v1/SessionService/Sessions",
            json={"UserName": self.session.auth[0], "Password": self.session.auth[1]},
        )
        self._xauth_token = response.headers.get("X-Auth-Token")

    def get_component_integrity(self):
        """Return the list of ComponentIntegrity resources (as dicts) which provide SPDM capabilities."""
        collection = self._request("GET", "/redfish/v1/ComponentIntegrity").json()
        members = collection.get("Members", [])

        resources = []
        for member in members:
            uri = member.get("@odata.id")
            if not uri:
                continue

            resource = self._request("GET", uri).json()

            if resource.get("ComponentIntegrityType") != "SPDM":
                continue

            resource["_uri"] = uri
            resources.append(resource)

        return resources

    def get_signed_measurements(self, component_integrity, nonce_hex):
        """Trigger an SPDMGetSignedMeasurements action on a ComponentIntegrity resource.

        The nonce (a 32-byte value given as a hex string) becomes the SPDM challenge nonce which the device must
        include in its signed measurements response. Returns the response as a JSON dict containing, per the
        ComponentIntegrity schema, at least 'SignedMeasurements' (Base64 of the signed statement, signature
        included), 'SigningAlgorithm' and 'HashingAlgorithm'.
        """
        actions = component_integrity.get("Actions", {})
        action = actions.get("#ComponentIntegrity.SPDMGetSignedMeasurements")

        if not action or not action.get("target"):
            raise RedfishError(
                f"ComponentIntegrity resource '{component_integrity['_uri']}' does not expose SPDMGetSignedMeasurements"
            )

        payload = {
            "Nonce": nonce_hex,
            "SlotId": 0,
            "MeasurementIndices": [255],
        }

        return self._request("POST", action["target"], json=payload).json()

    def close(self):
        self.session.close()
