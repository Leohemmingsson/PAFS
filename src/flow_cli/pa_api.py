"""Power Automate API client for flow management."""

import json
import urllib.error
import urllib.request

BASE_URL = "https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple"
API_VERSION = "2016-11-01"


def _make_request(
    access_token: str, method: str, endpoint: str, body: dict | None = None
) -> dict:
    """Make a request to the Flow API."""
    url = f"{BASE_URL}{endpoint}?api-version={API_VERSION}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")

    request = urllib.request.Request(url, headers=headers, method=method, data=data)

    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode("utf-8"))


def get_flow(access_token: str, environment_id: str, flow_id: str) -> dict:
    """GET - Fetch flow details."""
    endpoint = f"/environments/{environment_id}/flows/{flow_id}"
    return _make_request(access_token, "GET", endpoint)


def update_flow(
    access_token: str, flow_definition: dict, environment_id: str, flow_id: str
) -> dict:
    """PATCH - Update an existing flow."""
    endpoint = f"/environments/{environment_id}/flows/{flow_id}"
    return _make_request(access_token, "PATCH", endpoint, flow_definition)
