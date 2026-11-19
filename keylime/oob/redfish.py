"""Minimal Redfish client for out-of-band SPDM attestation.

Implements just the subset of DMTF DSP0268 (Redfish) needed to collect signed
SPDM measurements out-of-band: session establishment and discovery of
ComponentIntegrity resources exposing SPDM actions.
"""

import time

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
        include in its signed measurements response.

        Handles both response styles: synchronous services return the measurement payload directly, while
        SPDM-capable BMCs such as the NVIDIA GB300 NVL72 trays return HTTP 202 with a Task (gathering the
        measurements means traversing MCTP to the device's root of trust, which is slow). For the task style,
        the task is polled until completion and the payload is retrieved from the action's `/data` endpoint.
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

        response = self._request("POST", action["target"], json=payload)
        body = self._json_or_empty(response)

        if self._is_task(body):
            return self._wait_for_measurement_task(action["target"], body)

        return body

    @staticmethod
    def _json_or_empty(response):
        try:
            return response.json()
        except ValueError:
            return {}

    @staticmethod
    def _is_task(body):
        odata_type = str(body.get("@odata.type", ""))
        return "TaskState" in body or "Task" in odata_type

    def _wait_for_measurement_task(self, action_target, task_body, timeout=60.0, poll_interval=0.2):
        """Poll a Redfish task until completion, then fetch the measurement payload from the action's
        `/data` endpoint (the convention used by SPDM-capable BMCs)."""
        task_uri = task_body.get("@odata.id")

        if not task_uri:
            raise RedfishError("SPDM measurement task response did not include a task URI")

        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            task = self._json_or_empty(self._request("GET", task_uri))
            state = task.get("TaskState")

            if state == "Completed":
                return self._json_or_empty(self._request("GET", f"{action_target}/data"))

            if state in ("Exception", "Killed", "Cancelled"):
                messages = task.get("Messages", [])
                raise RedfishError(f"SPDM measurement task failed with state '{state}': {messages}")

            time.sleep(poll_interval)

        raise RedfishError(f"SPDM measurement task did not complete within {timeout} seconds")

    def get_json(self, path):
        """GET an arbitrary Redfish resource and return it as a dict (None on no-content)."""
        return self._json_or_empty(self._request("GET", path))

    def get_certificate_chain_pem(self, link):
        """Fetch a Redfish Certificate resource (given as a URI or a `{"@odata.id": ...}` link) and return its
        `CertificateString`: the device's SPDM certificate chain as concatenated PEM."""
        uri = link.get("@odata.id") if isinstance(link, dict) else link

        if not uri:
            raise RedfishError("certificate link did not include a URI")

        certificate = self._json_or_empty(self._request("GET", uri))
        pem = certificate.get("CertificateString")

        if not pem:
            raise RedfishError(f"certificate resource '{uri}' did not include a CertificateString")

        return pem

    def close(self):
        self.session.close()
