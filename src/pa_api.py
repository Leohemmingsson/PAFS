"""Power Automate API client for flow management."""

import json
import urllib.error
import urllib.parse
import urllib.request

BASE_URL = "https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple"
API_VERSION = "2016-11-01"


class PAFSAPIError(Exception):
    """Custom exception for Power Automate API errors.

    Preserves HTTP status code for proper 401 handling in auth layer.
    """

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


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

    try:
        with urllib.request.urlopen(request) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # Try to extract error message from response body
        try:
            error_body = json.loads(e.read().decode("utf-8"))
            message = error_body.get("error", {}).get("message", str(e))
        except (json.JSONDecodeError, UnicodeDecodeError):
            message = str(e)
        raise PAFSAPIError(message, status_code=e.code) from e


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
    try:
        with urllib.request.urlopen(request) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            error_body = json.loads(e.read().decode("utf-8"))
            message = error_body.get("error", {}).get("message", str(e))
        except (json.JSONDecodeError, UnicodeDecodeError):
            message = str(e)
        raise PAFSAPIError(message, status_code=e.code) from e


def get_solution_flows(access_token: str, dataverse_url: str, solution_id: str) -> list[dict]:
    """Get cloud flows in a solution via Dataverse API.

    Only returns cloud flows (category=5), excluding desktop flows and other workflow types.

    Args:
        access_token: Bearer token for authentication
        dataverse_url: The Dataverse instance URL (e.g., https://org.crm.dynamics.com)
        solution_id: The solution GUID

    Returns:
        List of flow objects with msdyn_displayname and msdyn_objectid
    """
    dataverse_url = dataverse_url.rstrip("/")

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "OData-MaxVersion": "4.0",
        "OData-Version": "4.0",
    }

    # Step 1: Get workflow IDs from solution components
    filter_query = (
        f"msdyn_solutionid eq '{solution_id}' "
        f"and msdyn_componentlogicalname eq 'workflow'"
    )
    url = f"{dataverse_url}/api/data/v9.0/msdyn_solutioncomponentsummaries?$filter={urllib.parse.quote(filter_query)}"

    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request) as response:
            data = json.loads(response.read().decode("utf-8"))
            solution_workflows = data.get("value", [])
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        raise PAFSAPIError(f"Dataverse API error: {error_body}", status_code=e.code) from e

    if not solution_workflows:
        return []

    # Step 2: Query workflows entity to filter for cloud flows only (category=5)
    # Batch queries to avoid URL length limits (50 IDs per batch)
    workflow_ids = [w.get("msdyn_objectid") for w in solution_workflows if w.get("msdyn_objectid")]

    if not workflow_ids:
        return []

    BATCH_SIZE = 50
    cloud_flow_ids: set[str] = set()

    for i in range(0, len(workflow_ids), BATCH_SIZE):
        batch_ids = workflow_ids[i : i + BATCH_SIZE]

        # Build filter: (workflowid eq 'id1' or workflowid eq 'id2' ...) and category eq 5
        id_filters = " or ".join(f"workflowid eq '{wid}'" for wid in batch_ids)
        workflow_filter = f"({id_filters}) and category eq 5"

        workflow_url = f"{dataverse_url}/api/data/v9.2/workflows?$filter={urllib.parse.quote(workflow_filter)}&$select=workflowid"

        request = urllib.request.Request(workflow_url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request) as response:
                data = json.loads(response.read().decode("utf-8"))
                batch_flows = data.get("value", [])
                cloud_flow_ids.update(f.get("workflowid") for f in batch_flows if f.get("workflowid"))
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8")
            raise PAFSAPIError(f"Dataverse API error: {error_body}", status_code=e.code) from e

    # Step 3: Return only solution workflows that are cloud flows
    return [w for w in solution_workflows if w.get("msdyn_objectid") in cloud_flow_ids]


def create_flow(access_token: str, environment_id: str, flow_definition: dict) -> dict:
    """POST - Create a new flow."""
    endpoint = f"/environments/{environment_id}/flows"
    return _make_request(access_token, "POST", endpoint, flow_definition)


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
    try:
        with urllib.request.urlopen(request) as response:
            data = json.loads(response.read().decode("utf-8"))
            return data.get("value", [])
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        raise PAFSAPIError(f"Dataverse API error: {error_body}", status_code=e.code) from e
