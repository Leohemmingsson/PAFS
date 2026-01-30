"""Power Automate API client for flow management."""

import json
import urllib.error
import urllib.parse
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


def get_environment(access_token: str, environment_id: str) -> dict:
    """GET - Fetch environment info including Dataverse URL.

    Returns environment data with properties.linkedEnvironmentMetadata.instanceUrl
    containing the Dataverse URL.
    """
    url = f"{BASE_URL}/environments/{environment_id}?api-version=2020-06-01"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    request = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode("utf-8"))


def get_solution_flows(access_token: str, dataverse_url: str, solution_id: str) -> list[dict]:
    """Get all flows in a solution via Dataverse API.

    Args:
        access_token: Bearer token for authentication
        dataverse_url: The Dataverse instance URL (e.g., https://org.crm.dynamics.com)
        solution_id: The solution GUID

    Returns:
        List of flow objects with msdyn_displayname and msdyn_objectid
    """
    # Ensure URL doesn't have trailing slash
    dataverse_url = dataverse_url.rstrip("/")

    # Query for solution components that are workflows (includes cloud flows)
    # Filter by componentlogicalname which is the entity type
    filter_query = (
        f"msdyn_solutionid eq '{solution_id}' "
        f"and msdyn_componentlogicalname eq 'workflow'"
    )
    encoded_filter = urllib.parse.quote(filter_query)

    url = f"{dataverse_url}/api/data/v9.0/msdyn_solutioncomponentsummaries?$filter={encoded_filter}"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "OData-MaxVersion": "4.0",
        "OData-Version": "4.0",
    }

    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request) as response:
            data = json.loads(response.read().decode("utf-8"))
            return data.get("value", [])
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        raise RuntimeError(f"Dataverse API error {e.code}: {error_body}") from e


def get_solutions(access_token: str, dataverse_url: str) -> list[dict]:
    """Get all visible solutions from Dataverse.

    Args:
        access_token: Bearer token for authentication
        dataverse_url: The Dataverse instance URL (e.g., https://org.crm.dynamics.com)

    Returns:
        List of solution objects with solutionid, friendlyname, uniquename, version
    """
    # Ensure URL doesn't have trailing slash
    dataverse_url = dataverse_url.rstrip("/")

    # Query for visible solutions, ordered by creation date (newest first)
    filter_query = "(isvisible eq true)"
    orderby_query = "createdon desc"
    url = (
        f"{dataverse_url}/api/data/v9.0/solutions"
        f"?$expand=publisherid"
        f"&$filter={urllib.parse.quote(filter_query)}"
        f"&$orderby={urllib.parse.quote(orderby_query)}"
    )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "OData-MaxVersion": "4.0",
        "OData-Version": "4.0",
    }

    request = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(request) as response:
        data = json.loads(response.read().decode("utf-8"))
        return data.get("value", [])
