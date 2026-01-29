
import argparse
import json
import re
import subprocess
import urllib.error
from pathlib import Path

from playwright.sync_api import Request, sync_playwright

from .pa_api import get_flow, update_flow

SETTINGS_DIR = Path(".pafs")
FLOWS_FILE = SETTINGS_DIR / "flows.json"
TOKEN_FILE = SETTINGS_DIR / "token.json"
BROWSER_DATA_DIR = SETTINGS_DIR / "browser-data"


def load_token() -> str | None:
    """Load saved token from .settings/token.json."""
    if not TOKEN_FILE.exists():
        return None
    try:
        data = json.loads(TOKEN_FILE.read_text())
        return data.get("token")
    except (json.JSONDecodeError, KeyError):
        return None


def save_token(token: str) -> None:
    """Save token to .settings/token.json."""
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    TOKEN_FILE.write_text(json.dumps({"token": token}, indent=2) + "\n")


def clear_token() -> None:
    """Clear the saved token."""
    if TOKEN_FILE.exists():
        TOKEN_FILE.unlink()


def load_flows() -> dict:
    """Load the flows registry from .settings/flows.json."""
    if not FLOWS_FILE.exists():
        return {}
    try:
        return json.loads(FLOWS_FILE.read_text())
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON in {FLOWS_FILE}: {e}") from e


def save_flows(flows: dict) -> None:
    """Save the flows registry to .settings/flows.json."""
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    FLOWS_FILE.write_text(json.dumps(flows, indent=2) + "\n")


def parse_flow_url(url: str) -> tuple[str, str]:
    """Parse a Power Automate URL to extract environment_id and flow_id.

    URL format: https://make.powerautomate.com/environments/<env_id>/flows/<flow_id>/details
    """
    pattern = r"https://make\.powerautomate\.com/environments/([^/]+)/flows/([^/]+)"
    match = re.match(pattern, url)
    if not match:
        raise ValueError(f"Invalid Power Automate URL format: {url}")
    return match.group(1), match.group(2)


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

    captured_token: str | None = None

    def on_request(request: Request) -> None:
        nonlocal captured_token
        if "api.flow.microsoft.com" in request.url:
            auth_header = request.headers.get("authorization", "")
            if auth_header.startswith("Bearer ") and captured_token is None:
                captured_token = auth_header.removeprefix("Bearer ")
                print(f"[+] Captured token from: {request.url[:80]}...")

    BROWSER_DATA_DIR.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=str(BROWSER_DATA_DIR),
            headless=False,
        )

        page = context.pages[0]
        page.on("request", on_request)
        context.on("page", lambda new_page: new_page.on("request", on_request))

        print("Opening browser to capture token...")
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
                        print("[*] Login required. Please complete authentication in the browser...")
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
    print("[+] Token saved for future use")
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
            print("[!] Token expired, refreshing...")
            clear_token()

    # Get new token and retry
    token = get_token(flow_url)
    return func(token, *args, **kwargs)


def build_flow_url(environment_id: str, flow_id: str) -> str:
    """Build a Power Automate URL from environment_id and flow_id."""
    return f"https://make.powerautomate.com/environments/{environment_id}/flows/{flow_id}/details"


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
        print(f"Flow '{label}' not found in registry")
        return

    del flows[label]
    save_flows(flows)
    print(f"Removed '{label}' from registry")

    # Delete the JSON file if it exists
    flow_file = Path(f"{label}.json")
    if flow_file.exists():
        flow_file.unlink()
        print(f"Deleted {flow_file}")


def cmd_list() -> None:
    """List all registered flows."""
    flows = load_flows()

    if not flows:
        print("No flows registered. Use 'flow add <label> <url>' first.")
        return

    for label in flows:
        print(label)


def cmd_sync(labels: list[str] | None) -> None:
    """Sync flows from Power Automate to local JSON files."""
    flows = load_flows()

    if not flows:
        print("No flows registered. Use 'flow add <label> <url>' first.")
        return

    # Determine which flows to sync
    if labels:
        to_sync = {l: flows[l] for l in labels if l in flows}
        missing = [l for l in labels if l not in flows]
        if missing:
            print(f"Warning: flows not found: {', '.join(missing)}")
    else:
        to_sync = flows

    if not to_sync:
        print("No flows to sync")
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
        print(f"  Saved to {file_path}")

    if synced_files:
        subprocess.run(["git", "add"] + synced_files, check=True)
        # Only commit if there are staged changes
        result = subprocess.run(["git", "diff", "--cached", "--quiet"])
        if result.returncode != 0:
            subprocess.run(
                ["git", "commit", "-m", "Synced from Power Automate"],
                check=True,
            )
            print("Git commit created")
        else:
            print("No changes to commit")


def cmd_push(labels: list[str] | None, message: str) -> None:
    """Push local JSON files to Power Automate."""
    flows = load_flows()

    if not flows:
        print("No flows registered. Use 'flow add <label> <url>' first.")
        return

    # Determine which flows to push
    if labels:
        to_push = {l: flows[l] for l in labels if l in flows}
        missing = [l for l in labels if l not in flows]
        if missing:
            print(f"Warning: flows not found: {', '.join(missing)}")
    else:
        to_push = flows

    if not to_push:
        print("No flows to push")
        return

    pushed_files = []

    for label, flow_info in to_push.items():
        file_path = Path(f"{label}.json")
        if not file_path.exists():
            print(f"Warning: {file_path} not found, skipping '{label}'")
            continue

        env_id = flow_info["environment_id"]
        flow_id = flow_info["flow_id"]
        flow_url = build_flow_url(env_id, flow_id)

        print(f"Pushing '{label}'...")
        try:
            flow_data = json.loads(file_path.read_text())
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in {file_path}: {e}")
            continue

        api_request_with_auth(update_flow, flow_url, flow_data, env_id, flow_id)
        pushed_files.append(str(file_path))
        print(f"  Uploaded from {file_path}")

    if pushed_files:
        subprocess.run(["git", "add"] + pushed_files, check=True)
        # Only commit if there are staged changes
        result = subprocess.run(["git", "diff", "--cached", "--quiet"])
        if result.returncode != 0:
            subprocess.run(["git", "commit", "-m", message], check=True)
            print("Git commit created")
        else:
            print("No changes to commit")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="flow",
        description="Manage Power Automate flows with automatic token handling",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

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

    if args.command == "add":
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
