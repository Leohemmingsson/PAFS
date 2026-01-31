"""Authentication module for PAFS - handles token capture and refresh."""

import re
import subprocess
import sys
import urllib.error

from playwright.sync_api import Request, sync_playwright

from .constants import LOGIN_HOSTS, TIMEOUT_SECONDS
from .shared import (
    BROWSER_DATA_DIR,
    clear_token,
    load_dataverse_token,
    load_flow_token,
    save_tokens,
)


def ensure_playwright_browsers() -> None:
    """Install Playwright Chromium browser if not already installed."""
    result = subprocess.run(
        [sys.executable, "-m", "playwright", "install", "--dry-run", "chromium"],
        capture_output=True,
        text=True,
    )

    if "chromium" in result.stdout.lower() or result.returncode != 0:
        print("Installing browser (first run)...")
        subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], check=True)
        print("Browser installed")


def _is_login_page(url: str) -> bool:
    """Check if the URL is a Microsoft login page."""
    return any(host in url for host in LOGIN_HOSTS)


def get_tokens(
    auth_url: str,
    timeout_seconds: int = TIMEOUT_SECONDS,
    require_dataverse_token: bool = False,
) -> tuple[str, str | None]:
    """Get Bearer tokens, using saved tokens or capturing new ones via browser.

    Captures tokens for both the Flow API and Dataverse API.

    If the user is redirected to a Microsoft login page, waits patiently for
    them to complete authentication before capturing the tokens.

    Args:
        auth_url: The Power Automate URL to navigate to for authentication.
        timeout_seconds: Maximum time to wait for authentication (default: 5 minutes).
        require_dataverse_token: If True, wait until Dataverse token is also captured.

    Returns:
        Tuple of (flow_token, dataverse_token). Dataverse token may be None unless required.
    """
    # Try to use saved tokens first
    saved_flow_token = load_flow_token()
    saved_dataverse_token = load_dataverse_token()
    if saved_flow_token and (not require_dataverse_token or saved_dataverse_token):
        return saved_flow_token, saved_dataverse_token

    # Ensure browser is installed before launching
    ensure_playwright_browsers()

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
            print("Flow API token captured")
        elif ".dynamics.com" in request.url and captured_dataverse_token is None:
            captured_dataverse_token = token
            print("Dataverse API token captured")

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
        page.goto(auth_url, wait_until="commit")

        # Poll until we capture required tokens or timeout
        login_prompt_shown = False
        poll_interval_ms = 500
        max_polls = (timeout_seconds * 1000) // poll_interval_ms

        for _ in range(max_polls):
            # Check if we have all required tokens
            have_required = captured_flow_token and (
                not require_dataverse_token or captured_dataverse_token
            )
            if have_required:
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

    if not captured_flow_token:
        raise RuntimeError("Failed to capture authentication token")

    # Save the tokens for future use
    save_tokens(captured_flow_token, captured_dataverse_token)
    print("Tokens saved")
    return captured_flow_token, captured_dataverse_token


def _build_solutions_url(auth_url: str) -> str:
    """Build a solutions page URL from an auth URL to trigger Dataverse requests.

    If auth_url contains an environment ID, navigates to its solutions page.
    Otherwise, uses a generic Power Automate home page.
    """
    match = re.search(r"/environments/([^/]+)", auth_url)
    if match:
        env_id = match.group(1)
        return f"https://make.powerautomate.com/environments/{env_id}/solutions"
    return auth_url


def api_request_with_auth(func, auth_url: str, *args, use_dataverse_token: bool = False, **kwargs):
    """Wrapper that handles 401 errors by refreshing the token.

    Args:
        func: The API function to call (first argument should be the token).
        auth_url: URL to navigate to if token refresh is needed.
        *args: Additional positional arguments for the API function.
        use_dataverse_token: If True, use the Dataverse token instead of Flow token.
        **kwargs: Additional keyword arguments for the API function.
    """
    # Try with saved token first
    if use_dataverse_token:
        saved_token = load_dataverse_token()
    else:
        saved_token = load_flow_token()

    if saved_token:
        try:
            return func(saved_token, *args, **kwargs)
        except urllib.error.HTTPError as e:
            if e.code != 401:
                raise
            print("Token expired, refreshing...")
            clear_token()

    # Determine which URL to use for authentication
    # For Dataverse, navigate to solutions page to ensure Dataverse token is captured
    if use_dataverse_token:
        target_url = _build_solutions_url(auth_url)
    else:
        target_url = auth_url

    # Get new tokens (require Dataverse token if needed)
    flow_token, dataverse_token = get_tokens(
        target_url, require_dataverse_token=use_dataverse_token
    )

    if use_dataverse_token:
        if not dataverse_token:
            raise RuntimeError(
                "Failed to capture Dataverse token. "
                "Make sure you have access to the environment's solutions."
            )
        return func(dataverse_token, *args, **kwargs)
    else:
        return func(flow_token, *args, **kwargs)
