from playwright.sync_api import sync_playwright, Request
import os

USER_DATA_DIR = os.path.expanduser("~/.config/ethos-permobil/browser-data")

captured_token: str | None = None


def on_request(request: Request):
    global captured_token
    if "api.flow.microsoft.com" in request.url:
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer ") and captured_token is None:
            captured_token = auth_header.removeprefix("Bearer ")
            print(f"\n[+] Captured token from: {request.url[:80]}...")
            print(f"[+] Token: {captured_token[:50]}...{captured_token[-20:]}")


def main():
    global captured_token
    os.makedirs(USER_DATA_DIR, exist_ok=True)

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=USER_DATA_DIR,
            headless=False,
        )

        page = context.pages[0]
        page.on("request", on_request)

        # Also listen on any new pages
        context.on("page", lambda new_page: new_page.on("request", on_request))

        page.goto("https://make.powerautomate.com/environments/Default-8ecb77bf-8d29-4cde-b294-6abc3940beee/flows/40c78062-ac7d-4703-b53b-eac04e991f8b/details")

        print("Browser opened. Listening for api.flow.microsoft.com requests...")
        page.wait_for_load_state("networkidle")

        if captured_token:
            print(f"\n{'='*60}")
            print("CAPTURED TOKEN:")
            print(f"{'='*60}")
            print(captured_token)
            print(f"{'='*60}\n")
        else:
            print("No token captured. Make sure to navigate to a flow.")

        input("Press Enter to close the browser...")
        context.close()


if __name__ == "__main__":
    main()
