"""REST client for Dell OpenManage Enterprise with session-based auth."""

import logging
import ssl
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Severity and status code maps
SEVERITY_MAP = {
    "critical": 16,
    "warning": 8,
    "info": 2,
    "normal": 4,
}

STATUS_MAP = {
    "unack": 2000,
    "ack": 1000,
}

HEALTH_NAMES = {
    1000: "Normal",
    2000: "Unknown",
    3000: "Warning",
    4000: "Critical",
    5000: "Information",
}


class OmeClient:
    """OpenManage Enterprise REST API client with session-based auth.

    Creates an X-Auth-Token session on init, uses it for all requests,
    and cleans up on close. SSL verification is disabled (self-signed certs).
    """

    def __init__(self, host: str, username: str, password: str) -> None:
        self.base_url = f"https://{host}"
        self.username = username
        self.password = password
        self.token: str | None = None
        self.session_id: str | None = None

        # Disable SSL verification for self-signed OME certs
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        self._http = httpx.Client(
            base_url=self.base_url,
            timeout=30.0,
            verify=ssl_ctx,
        )
        self._authenticate()

    def _authenticate(self) -> None:
        """Create an OME session and store the X-Auth-Token."""
        resp = self._http.post(
            "/api/SessionService/Sessions",
            json={
                "UserName": self.username,
                "Password": self.password,
                "SessionType": "API",
            },
        )
        resp.raise_for_status()
        self.token = resp.headers.get("X-Auth-Token")
        body = resp.json()
        self.session_id = body.get("Id")
        if not self.token:
            raise RuntimeError("No X-Auth-Token in OME session response")
        logger.info("OME session created (ID: %s)", self.session_id)

    def close(self) -> None:
        """Delete the OME session (best-effort)."""
        if self.token and self.session_id:
            try:
                self._http.delete(
                    f"/api/SessionService/Sessions('{self.session_id}')",
                    headers={"X-Auth-Token": self.token},
                )
                logger.info("OME session deleted")
            except Exception:
                pass
        self._http.close()

    def get(
        self, path: str, params: dict[str, str] | None = None, top: int | None = None
    ) -> dict[str, Any]:
        """GET with token auth. Handles OData pagination.

        Follows @odata.nextLink to fetch all pages unless top is set.
        OData $ params are passed as literal (not URL-encoded) because
        OME rejects percent-encoded parameter names.
        """
        # Build URL with OData params
        url = path
        qp = dict(params) if params else {}
        if top:
            qp["$top"] = str(top)

        all_values: list[dict] = []
        first_response: dict | None = None

        while url:
            resp = self._http.get(
                url,
                params=qp if not url.startswith("http") else None,
                headers={"X-Auth-Token": self.token},
            )
            resp.raise_for_status()
            body = resp.json()

            if first_response is None:
                first_response = body

            if "value" in body:
                all_values.extend(body["value"])
                next_link = body.get("@odata.nextLink")
                # When $top is set, don't follow nextLink
                if next_link and not top:
                    if next_link.startswith("http"):
                        url = next_link
                    else:
                        url = next_link
                    qp = {}  # nextLink includes its own params
                else:
                    url = None
            else:
                return body

        result = dict(first_response)
        result["value"] = all_values
        result.pop("@odata.nextLink", None)
        return result

    def post(self, path: str, data: Any = None) -> tuple[int, Any]:
        """POST with token auth. Returns (status_code, response_body)."""
        resp = self._http.post(
            path,
            json=data,
            headers={"X-Auth-Token": self.token},
        )
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        return resp.status_code, body
