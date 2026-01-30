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
TOKEN_FILE = SETTINGS_DIR / "token.json"
BROWSER_DATA_DIR = SETTINGS_DIR / "browser-data"


# Token functions
def load_token() -> str | None:
    """Load saved token from .pafs/token.json."""
    if not TOKEN_FILE.exists():
        return None
    try:
        data = json.loads(TOKEN_FILE.read_text())
        return data.get("token")
    except (json.JSONDecodeError, KeyError):
        return None


def save_token(token: str) -> None:
    """Save token to .pafs/token.json."""
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    TOKEN_FILE.write_text(json.dumps({"token": token}, indent=2) + "\n")


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
) -> str:
    """Open a browser to capture a Bearer token from Power Automate.

    Args:
        url: The URL to navigate to for authentication.
        timeout_seconds: Maximum time to wait for authentication.

    Returns:
        The captured Bearer token.

    Raises:
        RuntimeError: If token capture fails or times out.
    """
    _ensure_playwright_browsers()

    captured_token: str | None = None

    def on_request(request: Request) -> None:
        nonlocal captured_token
        if "api.flow.microsoft.com" in request.url:
            auth_header = request.headers.get("authorization", "")
            if auth_header.startswith("Bearer ") and captured_token is None:
                captured_token = auth_header.removeprefix("Bearer ")

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
            if captured_token:
                break
            try:
                page.wait_for_timeout(poll_interval_ms)
            except Exception:
                break

        context.close()

    if not captured_token:
        raise RuntimeError("Failed to capture authentication token")

    save_token(captured_token)
    return captured_token


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
        raise ValueError(f"Invalid Power Automate solution URL format: {url}")
    return match.group(1), match.group(2)


def detect_url_type(url: str) -> str:
    """Detect if a Power Automate URL points to a flow or solution.

    Returns:
        'flow' if the URL contains /flows/
        'solution' if the URL contains /solutions/ but not /flows/
    """
    if "/flows/" in url:
        return "flow"
    elif "/solutions/" in url:
        return "solution"
    else:
        raise ValueError(f"Cannot detect URL type (expected flow or solution URL): {url}")


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
