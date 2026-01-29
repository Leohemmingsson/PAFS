"""Shared utilities for PAFS."""

import json
import re
import subprocess
from pathlib import Path

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
def parse_flow_url(url: str) -> tuple[str, str]:
    """Parse a Power Automate URL to extract environment_id and flow_id.

    URL format: https://make.powerautomate.com/environments/<env_id>/flows/<flow_id>/details
    """
    pattern = r"https://make\.powerautomate\.com/environments/([^/]+)/flows/([^/]+)"
    match = re.match(pattern, url)
    if not match:
        raise ValueError(f"Invalid Power Automate URL format: {url}")
    return match.group(1), match.group(2)


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
