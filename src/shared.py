"""Shared utilities for PAFS."""

import json
import re
from pathlib import Path

# Constants
SETTINGS_DIR = Path(".pafs")
FLOWS_FILE = SETTINGS_DIR / "flows.json"
SOLUTIONS_FILE = SETTINGS_DIR / "solutions.json"
TOKEN_FILE = SETTINGS_DIR / "token.json"
BROWSER_DATA_DIR = SETTINGS_DIR / "browser-data"


# Token functions
def load_flow_token() -> str | None:
    """Load saved Flow API token from .pafs/token.json.

    Supports both old format ({"token": "..."}) and new format
    ({"flow_token": "...", "dataverse_token": "..."}) for backward compatibility.
    """
    if not TOKEN_FILE.exists():
        return None
    try:
        data = json.loads(TOKEN_FILE.read_text())
        # Try new format first, fall back to old format
        return data.get("flow_token") or data.get("token")
    except (json.JSONDecodeError, KeyError):
        return None


def load_dataverse_token() -> str | None:
    """Load saved Dataverse API token from .pafs/token.json."""
    if not TOKEN_FILE.exists():
        return None
    try:
        data = json.loads(TOKEN_FILE.read_text())
        return data.get("dataverse_token")
    except (json.JSONDecodeError, KeyError):
        return None


def save_tokens(flow_token: str | None, dataverse_token: str | None) -> None:
    """Save both Flow and Dataverse tokens to .pafs/token.json."""
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    token_data = {}
    if flow_token:
        token_data["flow_token"] = flow_token
    if dataverse_token:
        token_data["dataverse_token"] = dataverse_token
    TOKEN_FILE.write_text(json.dumps(token_data, indent=2) + "\n")


def clear_token() -> None:
    """Clear the saved token."""
    if TOKEN_FILE.exists():
        TOKEN_FILE.unlink()


# Flow registry functions
def load_flows() -> dict:
    """Load the flows registry from .pafs/flows.json."""
    if not FLOWS_FILE.exists():
        return {}
    try:
        return json.loads(FLOWS_FILE.read_text())
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON in {FLOWS_FILE}: {e}") from e


def save_flows(flows: dict) -> None:
    """Save the flows registry to .pafs/flows.json."""
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    FLOWS_FILE.write_text(json.dumps(flows, indent=2) + "\n")


# Solutions registry functions
def load_solutions() -> dict:
    """Load solutions registry from .pafs/solutions.json.

    Returns a dict mapping solution_id to solution info:
    {
        "solution-uuid": {
            "environment_id": "env-uuid",
            "name": "My Solution",
            "ignored": ["flow-uuid-1", "flow-uuid-2"]
        }
    }
    """
    if not SOLUTIONS_FILE.exists():
        return {}
    try:
        return json.loads(SOLUTIONS_FILE.read_text())
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON in {SOLUTIONS_FILE}: {e}") from e


def save_solutions(solutions: dict) -> None:
    """Save solutions registry to .pafs/solutions.json."""
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    SOLUTIONS_FILE.write_text(json.dumps(solutions, indent=2) + "\n")


# URL utilities
def parse_flow_url(url: str) -> tuple[str, str, str | None]:
    """Parse a Power Automate URL to extract environment_id, flow_id, and optional solution_id.

    Supported URL formats:
    - https://make.powerautomate.com/environments/<env_id>/flows/<flow_id>/details
    - https://make.powerautomate.com/environments/<env_id>/solutions/<solution_id>/flows/<flow_id>/details

    Returns:
        Tuple of (environment_id, flow_id, solution_id or None)
    """
    # Pattern with optional solution capture
    pattern = r"https://make\.powerautomate\.com/environments/([^/]+)/(?:solutions/([^/]+)/)?flows/([^/]+)"
    match = re.match(pattern, url)
    if not match:
        raise ValueError(f"Invalid Power Automate flow URL format: {url}")
    env_id = match.group(1)
    solution_id = match.group(2)  # None if not present
    flow_id = match.group(3)
    return env_id, flow_id, solution_id


def parse_solution_url(url: str) -> tuple[str, str]:
    """Parse a Power Automate solution URL to extract environment_id and solution_id.

    Supported URL formats:
    - https://make.powerautomate.com/environments/<env_id>/solutions/<solution_id>
    - https://make.powerautomate.com/environments/<env_id>/solutions/<solution_id>/...

    Returns:
        Tuple of (environment_id, solution_id)
    """
    pattern = r"https://make\.powerautomate\.com/environments/([^/]+)/solutions/([^/]+)"
    match = re.match(pattern, url)
    if not match:
        # Check if URL is missing solution ID
        if re.match(r"https://make\.powerautomate\.com/environments/[^/]+/solutions/?$", url):
            raise ValueError("URL is missing solution ID. Open a specific solution and copy its URL")
        raise ValueError(f"Invalid Power Automate solution URL format: {url}")
    return match.group(1), match.group(2)


def detect_url_type(url: str) -> str:
    """Detect if a Power Automate URL points to a flow, solution, or environment.

    Returns:
        'flow' if the URL contains /flows/
        'solution' if the URL contains /solutions/<solution_id>
        'environment' if the URL ends with /solutions (no solution ID)
    """
    if "/flows/" in url:
        return "flow"
    elif "/solutions" in url:
        # Check if URL ends with /solutions (with optional trailing slash)
        if re.match(r"https://make\.powerautomate\.com/environments/[^/]+/solutions/?$", url):
            return "environment"
        return "solution"
    else:
        raise ValueError(f"Cannot detect URL type (expected flow or solution URL): {url}")


def parse_environment_url(url: str) -> str:
    """Parse a Power Automate environment URL to extract environment_id.

    Supported URL formats:
    - https://make.powerautomate.com/environments/<env_id>/solutions
    - https://make.powerautomate.com/environments/<env_id>/solutions/

    Returns:
        environment_id
    """
    pattern = r"https://make\.powerautomate\.com/environments/([^/]+)/solutions/?$"
    match = re.match(pattern, url)
    if not match:
        raise ValueError(f"Invalid Power Automate environment URL format: {url}")
    return match.group(1)


def sanitize_label(display_name: str) -> str:
    """Convert a flow display name to a valid file name label.

    - Converts to lowercase
    - Replaces spaces and special characters with hyphens
    - Preserves underscores
    - Removes consecutive hyphens
    - Strips leading/trailing hyphens and underscores
    """
    # Convert to lowercase and replace spaces/special chars with hyphens (preserve underscores)
    label = re.sub(r"[^a-zA-Z0-9_]+", "-", display_name.lower())
    # Remove consecutive hyphens
    label = re.sub(r"-+", "-", label)
    # Strip leading/trailing hyphens and underscores
    label = label.strip("-_")
    return label or "unnamed-flow"


def build_flow_url(environment_id: str, flow_id: str) -> str:
    """Build a Power Automate URL from environment_id and flow_id."""
    return f"https://make.powerautomate.com/environments/{environment_id}/flows/{flow_id}/details"
