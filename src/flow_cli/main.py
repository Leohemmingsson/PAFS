
import argparse
import importlib.metadata
import json
import subprocess
import sys
import urllib.error
from pathlib import Path

from playwright.sync_api import Request, sync_playwright

from .pa_api import get_flow, update_flow
from .shared import (
    BROWSER_DATA_DIR,
    SETTINGS_DIR,
    _ensure_gitignore_has_pafs,
    build_flow_url,
    clear_token,
    is_git_initialized,
    load_flows,
    load_token,
    parse_flow_url,
    save_flows,
    save_token,
)


def ensure_playwright_browsers() -> None:
    """Install Playwright Chromium browser if not already installed."""
    # Use sys.executable to run playwright from the same venv as pafs
    result = subprocess.run(
        [sys.executable, "-m", "playwright", "install", "--dry-run", "chromium"],
        capture_output=True,
        text=True,
    )

    # If dry-run shows browsers need to be installed, install them
    if "chromium" in result.stdout.lower() or result.returncode != 0:
        print("Installing browser (first run)...")
        subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], check=True)
        print("Browser installed")


def _is_login_page(url: str) -> bool:
    """Check if the URL is a Microsoft login page."""
    login_hosts = [
        "login.microsoftonline.com",
        "login.microsoft.com",
        "login.live.com",
        "account.microsoft.com",
    ]
    return any(host in url for host in login_hosts)


def get_token(flow_url: str, timeout_seconds: int = 300) -> str:
    """Get Bearer token, using saved token or capturing a new one via browser.

    If the user is redirected to a Microsoft login page, waits patiently for
    them to complete authentication before capturing the token.

    Args:
        flow_url: The Power Automate URL to navigate to.
        timeout_seconds: Maximum time to wait for authentication (default: 5 minutes).
    """
    # Try to use saved token first
    saved_token = load_token()
    if saved_token:
        return saved_token

    # Ensure browser is installed before launching
    ensure_playwright_browsers()

    captured_token: str | None = None

    def on_request(request: Request) -> None:
        nonlocal captured_token
        if "api.flow.microsoft.com" in request.url:
            auth_header = request.headers.get("authorization", "")
            if auth_header.startswith("Bearer ") and captured_token is None:
                captured_token = auth_header.removeprefix("Bearer ")
                print("Token captured")

    BROWSER_DATA_DIR.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=str(BROWSER_DATA_DIR),
            headless=False,
        )

        page = context.pages[0]
        page.on("request", on_request)
        context.on("page", lambda new_page: new_page.on("request", on_request))

        print("Opening browser...")
        page.goto(flow_url, wait_until="commit")

        # Poll until we capture a token or timeout
        login_prompt_shown = False
        poll_interval_ms = 500
        max_polls = (timeout_seconds * 1000) // poll_interval_ms

        for _ in range(max_polls):
            if captured_token:
                break

            try:
                current_url = page.url
                if _is_login_page(current_url):
                    if not login_prompt_shown:
                        print("Login required - complete authentication in browser")
                        login_prompt_shown = True
                page.wait_for_timeout(poll_interval_ms)
            except Exception:
                # Page might have been closed, check if we got a token
                break

        context.close()

    if not captured_token:
        raise RuntimeError("Failed to capture authentication token")

    # Save the token for future use
    save_token(captured_token)
    print("Token saved")
    return captured_token


def api_request_with_auth(func, flow_url: str, *args, **kwargs):
    """Wrapper that handles 401 errors by refreshing the token."""
    # Try with saved token first
    saved_token = load_token()
    if saved_token:
        try:
            return func(saved_token, *args, **kwargs)
        except urllib.error.HTTPError as e:
            if e.code != 401:
                raise
            print("Token expired, refreshing...")
            clear_token()

    # Get new token and retry
    token = get_token(flow_url)
    return func(token, *args, **kwargs)


def git_commit_files(files: list[str], message: str) -> None:
    """Add and commit files to git. Shows warning if git is not initialized."""
    if not is_git_initialized():
        print("Git not initialized. Run 'pafs init' to enable git tracking")
        return

    subprocess.run(["git", "add"] + files, check=True)
    # Only commit if there are staged changes
    result = subprocess.run(["git", "diff", "--cached", "--quiet"])
    if result.returncode != 0:
        subprocess.run(["git", "commit", "-m", message], check=True)
        print("Committed to git")
    else:
        print("No changes to commit")


def cmd_init() -> None:
    """Initialize git repo and commit any existing flow JSON files."""
    git_initialized = is_git_initialized()
    gitignore_has_pafs = Path(".gitignore").exists() and ".pafs" in Path(".gitignore").read_text().splitlines()

    # Already fully initialized
    if git_initialized and gitignore_has_pafs:
        print("Already initialized")
        return

    print("Initializing...")

    # Initialize git if needed
    if not git_initialized:
        subprocess.run(["git", "init"], check=True)

    # Ensure .pafs is in .gitignore
    gitignore_modified = _ensure_gitignore_has_pafs()

    # Collect files to commit
    files_to_commit = []

    if gitignore_modified:
        files_to_commit.append(".gitignore")

    # Find flows that have JSON files on disk
    flows = load_flows()
    for label in flows:
        file_path = Path(f"{label}.json")
        if file_path.exists():
            files_to_commit.append(str(file_path))

    if files_to_commit:
        subprocess.run(["git", "add"] + files_to_commit, check=True)
        result = subprocess.run(["git", "diff", "--cached", "--quiet"])
        if result.returncode != 0:
            subprocess.run(["git", "commit", "-m", "Initial pafs commit"], check=True)
            print("Committed to git")
        else:
            print("No changes to commit")
    else:
        print("No files to commit")


def cmd_add(label: str, url: str) -> None:
    """Add a flow to the registry."""
    environment_id, flow_id = parse_flow_url(url)

    flows = load_flows()
    flows[label] = {
        "environment_id": environment_id,
        "flow_id": flow_id,
    }
    save_flows(flows)

    print(f"Added flow '{label}':")
    print(f"  Environment: {environment_id}")
    print(f"  Flow ID: {flow_id}")


def cmd_del(label: str) -> None:
    """Remove a flow from the registry and delete its JSON file."""
    flows = load_flows()

    if label not in flows:
        print(f"Flow '{label}' not found")
        return

    del flows[label]
    save_flows(flows)
    print(f"Removed '{label}'")

    # Delete the JSON file if it exists
    flow_file = Path(f"{label}.json")
    if flow_file.exists():
        flow_file.unlink()
        print(f"Deleted {flow_file}")


def cmd_list() -> None:
    """List all registered flows."""
    flows = load_flows()

    if not flows:
        print("No flows registered. Run 'pafs add <label> <url>' to add one")
        return

    for label in flows:
        print(label)


def cmd_sync(labels: list[str] | None) -> None:
    """Sync flows from Power Automate to local JSON files."""
    flows = load_flows()

    if not flows:
        print("No flows registered. Run 'pafs add <label> <url>' to add one")
        return

    # Determine which flows to sync
    if labels:
        to_sync = {l: flows[l] for l in labels if l in flows}
        missing = [l for l in labels if l not in flows]
        if missing:
            print(f"Flows not found: {', '.join(missing)}")
    else:
        to_sync = flows

    if not to_sync:
        print("Nothing to sync")
        return

    synced_files = []

    for label, flow_info in to_sync.items():
        env_id = flow_info["environment_id"]
        flow_id = flow_info["flow_id"]
        flow_url = build_flow_url(env_id, flow_id)

        print(f"Syncing '{label}'...")
        flow_data = api_request_with_auth(get_flow, flow_url, env_id, flow_id)

        file_path = Path(f"{label}.json")
        file_path.write_text(json.dumps(flow_data, indent=2) + "\n")
        synced_files.append(str(file_path))
        print(f"  Saved {file_path}")

    if synced_files:
        git_commit_files(synced_files, "Synced from Power Automate")


def cmd_push(labels: list[str] | None, message: str) -> None:
    """Push local JSON files to Power Automate."""
    flows = load_flows()

    if not flows:
        print("No flows registered. Run 'pafs add <label> <url>' to add one")
        return

    # Determine which flows to push
    if labels:
        to_push = {l: flows[l] for l in labels if l in flows}
        missing = [l for l in labels if l not in flows]
        if missing:
            print(f"Flows not found: {', '.join(missing)}")
    else:
        to_push = flows

    if not to_push:
        print("Nothing to push")
        return

    pushed_files = []

    for label, flow_info in to_push.items():
        file_path = Path(f"{label}.json")
        if not file_path.exists():
            print(f"Skipping '{label}': {file_path} not found")
            continue

        env_id = flow_info["environment_id"]
        flow_id = flow_info["flow_id"]
        flow_url = build_flow_url(env_id, flow_id)

        print(f"Pushing '{label}'...")
        try:
            flow_data = json.loads(file_path.read_text())
        except json.JSONDecodeError:
            print(f"Skipping '{label}': invalid JSON in {file_path}")
            continue

        api_request_with_auth(update_flow, flow_url, flow_data, env_id, flow_id)
        pushed_files.append(str(file_path))
        print(f"  Pushed {file_path}")

    if pushed_files:
        git_commit_files(pushed_files, message)


def cmd_auth() -> None:
    """Authenticate with Power Automate by opening a browser to capture a token."""
    # Clear any existing token to force re-authentication
    clear_token()
    print("Cleared existing token")

    # Use a generic Power Automate URL to trigger authentication
    auth_url = "https://make.powerautomate.com/"

    # Ensure browser is installed before launching
    ensure_playwright_browsers()

    captured_token: str | None = None

    def on_request(request: Request) -> None:
        nonlocal captured_token
        if "api.flow.microsoft.com" in request.url:
            auth_header = request.headers.get("authorization", "")
            if auth_header.startswith("Bearer ") and captured_token is None:
                captured_token = auth_header.removeprefix("Bearer ")
                print("Token captured")

    BROWSER_DATA_DIR.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=str(BROWSER_DATA_DIR),
            headless=False,
        )

        page = context.pages[0]
        page.on("request", on_request)
        context.on("page", lambda new_page: new_page.on("request", on_request))

        print("Opening browser for authentication...")
        page.goto(auth_url, wait_until="commit")

        # Poll until we capture a token or timeout
        timeout_seconds = 300
        login_prompt_shown = False
        poll_interval_ms = 500
        max_polls = (timeout_seconds * 1000) // poll_interval_ms

        for _ in range(max_polls):
            if captured_token:
                break

            try:
                current_url = page.url
                if _is_login_page(current_url):
                    if not login_prompt_shown:
                        print("Login required - complete authentication in browser")
                        login_prompt_shown = True
                page.wait_for_timeout(poll_interval_ms)
            except Exception:
                break

        context.close()

    if not captured_token:
        raise RuntimeError("Failed to capture authentication token")

    save_token(captured_token)
    print("Token saved successfully")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="pafs",
        description="Manage Power Automate flows with automatic token handling",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {importlib.metadata.version('pafs')}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init
    subparsers.add_parser("init", help="Initialize git repo for flow tracking")

    # auth
    subparsers.add_parser("auth", help="Authenticate with Power Automate")

    # add
    add_parser = subparsers.add_parser("add", help="Add a flow to the registry")
    add_parser.add_argument("label", help="Label for the flow")
    add_parser.add_argument("url", help="Power Automate flow URL")

    # del
    del_parser = subparsers.add_parser("del", help="Remove a flow from the registry")
    del_parser.add_argument("label", help="Label of the flow to remove")

    # list
    subparsers.add_parser("list", help="List all registered flows")

    # sync
    sync_parser = subparsers.add_parser("sync", help="Sync flows from Power Automate")
    sync_parser.add_argument(
        "labels",
        nargs="?",
        help="Comma-separated labels to sync (default: all)",
    )

    # push
    push_parser = subparsers.add_parser("push", help="Push flows to Power Automate")
    push_parser.add_argument(
        "labels",
        nargs="?",
        help="Comma-separated labels to push (default: all)",
    )
    push_parser.add_argument(
        "-m",
        "--message",
        default="Pushed to Power Automate",
        help="Git commit message",
    )

    args = parser.parse_args()

    # Parse comma-separated labels if provided
    def parse_labels(labels_str: str | None) -> list[str] | None:
        if labels_str is None:
            return None
        return [l.strip() for l in labels_str.split(",") if l.strip()]

    if args.command == "init":
        cmd_init()
    elif args.command == "auth":
        cmd_auth()
    elif args.command == "add":
        cmd_add(args.label, args.url)
    elif args.command == "del":
        cmd_del(args.label)
    elif args.command == "list":
        cmd_list()
    elif args.command == "sync":
        cmd_sync(parse_labels(args.labels))
    elif args.command == "push":
        cmd_push(parse_labels(args.labels), args.message)


if __name__ == "__main__":
    main()
