"""Shared utilities for PAFS."""

import json
import re
import subprocess
import sys
from pathlib import Path

from playwright.sync_api import Request, sync_playwright

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


def _ensure_playwright_browsers() -> None:
    """Install Playwright Chromium browser if not already installed."""
    result = subprocess.run(
        [sys.executable, "-m", "playwright", "install", "--dry-run", "chromium"],
        capture_output=True,
        text=True,
    )
    if "chromium" in result.stdout.lower() or result.returncode != 0:
        subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            check=True,
            capture_output=True,
        )


def _is_login_page(url: str) -> bool:
    """Check if the URL is a Microsoft login page."""
    login_hosts = [
        "login.microsoftonline.com",
        "login.microsoft.com",
        "login.live.com",
        "account.microsoft.com",
    ]
    return any(host in url for host in login_hosts)


def capture_token_via_browser(
    url: str = "https://make.powerautomate.com/",
    timeout_seconds: int = 300,
) -> tuple[str | None, str | None]:
    """Open a browser to capture Bearer tokens from Power Automate.

    Captures tokens for both the Flow API (api.flow.microsoft.com) and
    Dataverse API (*.dynamics.com).

    Args:
        url: The URL to navigate to for authentication.
        timeout_seconds: Maximum time to wait for authentication.

    Returns:
        Tuple of (flow_token, dataverse_token). Either may be None if not captured.

    Raises:
        RuntimeError: If no tokens were captured before timeout.
    """
    _ensure_playwright_browsers()

    captured_flow_token: str | None = None
    captured_dataverse_token: str | None = None

    def on_request(request: Request) -> None:
        nonlocal captured_flow_token, captured_dataverse_token
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return

        token = auth_header.removeprefix("Bearer ")

        if "api.flow.microsoft.com" in request.url and captured_flow_token is None:
            captured_flow_token = token
        elif ".dynamics.com" in request.url and captured_dataverse_token is None:
            captured_dataverse_token = token

    BROWSER_DATA_DIR.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=str(BROWSER_DATA_DIR),
            headless=False,
        )

        page = context.pages[0]
        page.on("request", on_request)
        context.on("page", lambda new_page: new_page.on("request", on_request))

        page.goto(url, wait_until="commit")

        poll_interval_ms = 500
        max_polls = (timeout_seconds * 1000) // poll_interval_ms

        for _ in range(max_polls):
            # Wait until we have the flow token (required)
            # Dataverse token is optional since not all pages trigger Dataverse requests
            if captured_flow_token:
                break
            try:
                page.wait_for_timeout(poll_interval_ms)
            except Exception:
                break

        context.close()

    if not captured_flow_token:
        raise RuntimeError("Failed to capture authentication token")

    save_tokens(captured_flow_token, captured_dataverse_token)
    return captured_flow_token, captured_dataverse_token


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
    - Removes consecutive hyphens
    - Strips leading/trailing hyphens
    """
    # Convert to lowercase and replace spaces/special chars with hyphens
    label = re.sub(r"[^a-zA-Z0-9]+", "-", display_name.lower())
    # Remove consecutive hyphens
    label = re.sub(r"-+", "-", label)
    # Strip leading/trailing hyphens
    label = label.strip("-")
    return label or "unnamed-flow"


def build_flow_url(environment_id: str, flow_id: str) -> str:
    """Build a Power Automate URL from environment_id and flow_id."""
    return f"https://make.powerautomate.com/environments/{environment_id}/flows/{flow_id}/details"


# Git utilities
def is_git_initialized() -> bool:
    """Check if git is initialized in the current directory."""
    result = subprocess.run(
        ["git", "rev-parse", "--git-dir"],
        capture_output=True,
    )
    return result.returncode == 0


def _ensure_gitignore_has_pafs() -> bool:
    """Ensure .pafs is in .gitignore. Returns True if file was modified."""
    gitignore = Path(".gitignore")
    pafs_entry = ".pafs"

    if gitignore.exists():
        content = gitignore.read_text()
        # Check if .pafs is already in gitignore (as its own line)
        lines = content.splitlines()
        if pafs_entry in lines:
            return False
        # Append .pafs
        if content and not content.endswith("\n"):
            content += "\n"
        content += f"{pafs_entry}\n"
        gitignore.write_text(content)
    else:
        gitignore.write_text(f"{pafs_entry}\n")

    return True
