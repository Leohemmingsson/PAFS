"""MCP server for PAFS - allows LLM clients to manage Power Automate flows."""

import json
import subprocess
import urllib.error
from pathlib import Path

from fastmcp import FastMCP

from .pa_api import get_flow, update_flow
from .shared import (
    _ensure_gitignore_has_pafs,
    build_flow_url,
    clear_token,
    is_git_initialized,
    load_flows,
    load_token,
    parse_flow_url,
    save_flows,
)

mcp = FastMCP(name="pafs")

AUTH_ERROR = "Authentication required. Please run 'pafs auth' in a terminal first."


def _get_token_or_error() -> str:
    """Get the saved token or raise an error."""
    token = load_token()
    if not token:
        raise RuntimeError(AUTH_ERROR)
    return token


def _api_request(func, *args, **kwargs):
    """Make an API request with token, returning error on 401."""
    token = _get_token_or_error()
    try:
        return func(token, *args, **kwargs)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            clear_token()
            raise RuntimeError(f"Token expired. {AUTH_ERROR}") from e
        raise


@mcp.tool
def init() -> dict:
    """Initialize git repo and add .pafs to .gitignore."""
    git_initialized = is_git_initialized()
    gitignore_has_pafs = (
        Path(".gitignore").exists()
        and ".pafs" in Path(".gitignore").read_text().splitlines()
    )

    if git_initialized and gitignore_has_pafs:
        return {"status": "already_initialized", "message": "Already initialized"}

    messages = []

    if not git_initialized:
        subprocess.run(["git", "init"], check=True, capture_output=True)
        messages.append("Initialized git repository")

    gitignore_modified = _ensure_gitignore_has_pafs()
    if gitignore_modified:
        messages.append("Added .pafs to .gitignore")

    files_to_commit = []
    if gitignore_modified:
        files_to_commit.append(".gitignore")

    flows = load_flows()
    for label in flows:
        file_path = Path(f"{label}.json")
        if file_path.exists():
            files_to_commit.append(str(file_path))

    if files_to_commit:
        subprocess.run(["git", "add"] + files_to_commit, check=True, capture_output=True)
        result = subprocess.run(["git", "diff", "--cached", "--quiet"])
        if result.returncode != 0:
            subprocess.run(
                ["git", "commit", "-m", "Initial pafs commit"],
                check=True,
                capture_output=True,
            )
            messages.append(f"Committed {len(files_to_commit)} file(s)")

    return {"status": "initialized", "messages": messages}


@mcp.tool
def list_flows() -> dict:
    """List all registered flows."""
    flows = load_flows()
    if not flows:
        return {"flows": [], "message": "No flows registered"}

    flow_list = []
    for label, info in flows.items():
        flow_list.append({
            "label": label,
            "environment_id": info["environment_id"],
            "flow_id": info["flow_id"],
            "url": build_flow_url(info["environment_id"], info["flow_id"]),
        })

    return {"flows": flow_list}


@mcp.tool
def add_flow(label: str, url: str) -> dict:
    """Register a new flow.

    Args:
        label: A friendly name for the flow (used as filename)
        url: The Power Automate URL for the flow
    """
    try:
        environment_id, flow_id = parse_flow_url(url)
    except ValueError as e:
        return {"status": "error", "message": str(e)}

    flows = load_flows()
    flows[label] = {
        "environment_id": environment_id,
        "flow_id": flow_id,
    }
    save_flows(flows)

    return {
        "status": "added",
        "label": label,
        "environment_id": environment_id,
        "flow_id": flow_id,
    }


@mcp.tool
def remove_flow(label: str) -> dict:
    """Remove a flow from the registry and delete its local JSON file.

    Args:
        label: The label of the flow to remove
    """
    flows = load_flows()

    if label not in flows:
        return {"status": "error", "message": f"Flow '{label}' not found"}

    del flows[label]
    save_flows(flows)

    file_deleted = False
    flow_file = Path(f"{label}.json")
    if flow_file.exists():
        flow_file.unlink()
        file_deleted = True

    return {
        "status": "removed",
        "label": label,
        "file_deleted": file_deleted,
    }


@mcp.tool
def sync_flows(labels: str | None = None) -> dict:
    """Download flows from Power Automate to local JSON files.

    Args:
        labels: Comma-separated list of flow labels to sync (default: all)
    """
    flows = load_flows()

    if not flows:
        return {"status": "error", "message": "No flows registered"}

    # Parse labels
    if labels:
        label_list = [l.strip() for l in labels.split(",") if l.strip()]
        to_sync = {l: flows[l] for l in label_list if l in flows}
        missing = [l for l in label_list if l not in flows]
    else:
        to_sync = flows
        missing = []

    if not to_sync:
        return {"status": "error", "message": "No matching flows to sync"}

    synced = []
    errors = []

    for label, flow_info in to_sync.items():
        env_id = flow_info["environment_id"]
        flow_id = flow_info["flow_id"]

        try:
            flow_data = _api_request(get_flow, env_id, flow_id)
            file_path = Path(f"{label}.json")
            file_path.write_text(json.dumps(flow_data, indent=2) + "\n")
            synced.append(label)
        except RuntimeError as e:
            # Auth error - propagate immediately
            raise
        except Exception as e:
            errors.append({"label": label, "error": str(e)})

    # Git commit if successful
    if synced and is_git_initialized():
        files = [f"{l}.json" for l in synced]
        subprocess.run(["git", "add"] + files, check=True, capture_output=True)
        result = subprocess.run(["git", "diff", "--cached", "--quiet"])
        if result.returncode != 0:
            subprocess.run(
                ["git", "commit", "-m", "Synced from Power Automate"],
                check=True,
                capture_output=True,
            )

    return {
        "status": "synced",
        "synced": synced,
        "errors": errors,
        "missing": missing,
    }


@mcp.tool
def push_flows(labels: str | None = None) -> dict:
    """Upload local flow JSON files to Power Automate.

    Args:
        labels: Comma-separated list of flow labels to push (default: all)
    """
    flows = load_flows()

    if not flows:
        return {"status": "error", "message": "No flows registered"}

    # Parse labels
    if labels:
        label_list = [l.strip() for l in labels.split(",") if l.strip()]
        to_push = {l: flows[l] for l in label_list if l in flows}
        missing = [l for l in label_list if l not in flows]
    else:
        to_push = flows
        missing = []

    if not to_push:
        return {"status": "error", "message": "No matching flows to push"}

    pushed = []
    errors = []
    skipped = []

    for label, flow_info in to_push.items():
        file_path = Path(f"{label}.json")
        if not file_path.exists():
            skipped.append({"label": label, "reason": "file not found"})
            continue

        try:
            flow_data = json.loads(file_path.read_text())
        except json.JSONDecodeError as e:
            errors.append({"label": label, "error": f"Invalid JSON: {e}"})
            continue

        env_id = flow_info["environment_id"]
        flow_id = flow_info["flow_id"]

        try:
            _api_request(update_flow, flow_data, env_id, flow_id)
            pushed.append(label)
        except RuntimeError as e:
            # Auth error - propagate immediately
            raise
        except Exception as e:
            errors.append({"label": label, "error": str(e)})

    # Git commit if successful
    if pushed and is_git_initialized():
        files = [f"{l}.json" for l in pushed]
        subprocess.run(["git", "add"] + files, check=True, capture_output=True)
        result = subprocess.run(["git", "diff", "--cached", "--quiet"])
        if result.returncode != 0:
            subprocess.run(
                ["git", "commit", "-m", "Pushed to Power Automate"],
                check=True,
                capture_output=True,
            )

    return {
        "status": "pushed",
        "pushed": pushed,
        "errors": errors,
        "skipped": skipped,
        "missing": missing,
    }


def main():
    """Entry point for the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
