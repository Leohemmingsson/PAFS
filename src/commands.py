"""Command implementations for PAFS CLI."""

import json
import subprocess
from pathlib import Path

from .auth import api_request_with_auth, ensure_playwright_browsers, get_tokens
from .git import ensure_gitignore_has_pafs, git_commit_files, is_git_initialized
from .pa_api import get_environment, get_flow, get_solution_flows, get_solutions, update_flow
from .shared import (
    build_flow_url,
    clear_token,
    detect_url_type,
    load_flows,
    load_solutions,
    parse_environment_url,
    parse_flow_url,
    parse_solution_url,
    sanitize_label,
    save_flows,
    save_solutions,
)


def select_from_menu(options: list[str], title: str) -> int | None:
    """Show interactive menu for selection. Returns index or None if cancelled.

    Uses simple-term-menu for interactive selection with built-in search (press /).
    Falls back to numbered list with input() if the terminal doesn't support it.
    """
    try:
        from simple_term_menu import TerminalMenu

        menu = TerminalMenu(
            options,
            title=title,
            search_key="/",
            show_search_hint=True,
        )
        return menu.show()
    except Exception:
        # Fallback for non-interactive terminals or import issues
        print(title)
        for i, option in enumerate(options, 1):
            print(f"  {i}. {option}")
        print("  0. Cancel")
        print()

        while True:
            try:
                choice = input("Enter number: ").strip()
                if not choice:
                    continue
                num = int(choice)
                if num == 0:
                    return None
                if 1 <= num <= len(options):
                    return num - 1
                print(f"Please enter a number between 0 and {len(options)}")
            except ValueError:
                print("Please enter a valid number")
            except (KeyboardInterrupt, EOFError):
                print()
                return None


def _get_unique_label(base_label: str, existing_labels: set[str]) -> str:
    """Generate a unique label by appending a number if needed."""
    if base_label not in existing_labels:
        return base_label
    counter = 2
    while f"{base_label}-{counter}" in existing_labels:
        counter += 1
    return f"{base_label}-{counter}"


def _add_single_flow(
    flows: dict,
    env_id: str,
    flow_id: str,
    label: str,
    solution_id: str | None = None,
) -> bool:
    """Add a single flow to the registry. Returns True if added, False if skipped."""
    # Check for duplicate flow_id
    for existing_label, info in flows.items():
        if info["flow_id"] == flow_id:
            if existing_label == label:
                print(f"Flow '{label}' already exists, skipping")
            else:
                print(f"Warning: Flow ID {flow_id} already exists as '{existing_label}'")
            return False

    flow_entry = {
        "environment_id": env_id,
        "flow_id": flow_id,
    }
    if solution_id:
        flow_entry["solution_id"] = solution_id

    flows[label] = flow_entry
    return True


def _discover_solution_flows(flows: dict) -> list[str]:
    """Discover new flows in tracked solutions. Returns list of newly added labels."""
    solutions_registry = load_solutions()
    if not solutions_registry:
        return []

    # Get existing flow_ids for quick lookup
    existing_flow_ids = {info["flow_id"] for info in flows.values()}
    existing_labels = set(flows.keys())
    added_labels = []

    for solution_id, sol_info in solutions_registry.items():
        env_id = sol_info["environment_id"]
        ignored = set(sol_info.get("ignored", []))

        auth_url = f"https://make.powerautomate.com/environments/{env_id}"

        try:
            # Get Dataverse URL
            env_data = api_request_with_auth(get_environment, auth_url, env_id)
            dataverse_url = env_data.get("properties", {}).get("linkedEnvironmentMetadata", {}).get("instanceUrl")

            if not dataverse_url:
                continue

            # Get flows in solution (uses Dataverse API)
            solution_flows = api_request_with_auth(
                get_solution_flows, auth_url, dataverse_url, solution_id,
                use_dataverse_token=True
            )

            for flow_info in solution_flows:
                flow_id = flow_info.get("msdyn_objectid")

                # Skip if already tracked, or if in ignored list
                if not flow_id or flow_id in existing_flow_ids or flow_id in ignored:
                    continue

                display_name = flow_info.get("msdyn_displayname", "unnamed-flow")
                label = sanitize_label(display_name)
                label = _get_unique_label(label, existing_labels)

                flows[label] = {
                    "environment_id": env_id,
                    "flow_id": flow_id,
                    "solution_id": solution_id,
                }
                existing_flow_ids.add(flow_id)
                existing_labels.add(label)
                added_labels.append(label)
                print(f"Discovered new flow: '{label}'")

        except Exception as e:
            print(f"Warning: Could not check solution {solution_id}: {e}")

    return added_labels


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
    gitignore_modified = ensure_gitignore_has_pafs()

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


def cmd_auth() -> None:
    """Authenticate with Power Automate by opening a browser to capture tokens."""
    clear_token()
    print("Cleared existing tokens")
    get_tokens("https://make.powerautomate.com/", require_dataverse_token=False)


def cmd_add(url: str, label: str | None = None) -> None:
    """Add a flow or all flows from a solution to the registry."""
    try:
        url_type = detect_url_type(url)
    except ValueError as e:
        print(f"Error: {e}")
        return

    flows = load_flows()
    added_labels = []

    if url_type == "flow":
        try:
            env_id, flow_id, solution_id = parse_flow_url(url)
        except ValueError as e:
            print(f"Error: {e}")
            return

        # Get display name from API if no label provided
        if label is None:
            flow_url = build_flow_url(env_id, flow_id)
            print("Fetching flow info...")
            flow_data = api_request_with_auth(get_flow, flow_url, env_id, flow_id)
            display_name = flow_data.get("properties", {}).get("displayName", "unnamed-flow")
            label = sanitize_label(display_name)
            label = _get_unique_label(label, set(flows.keys()))

        # Don't pass solution_id for single flow adds - only track the specific flow
        if _add_single_flow(flows, env_id, flow_id, label):
            added_labels.append(label)
            print(f"Added flow '{label}'")

            # Remove from any solution's ignored list
            solutions = load_solutions()
            modified = False
            for sol_info in solutions.values():
                if flow_id in sol_info.get("ignored", []):
                    sol_info["ignored"].remove(flow_id)
                    modified = True
            if modified:
                save_solutions(solutions)

    elif url_type == "environment":
        # Environment URL without solution ID - let user select a solution
        try:
            env_id = parse_environment_url(url)
        except ValueError as e:
            print(f"Error: {e}")
            return

        # Get environment info to find Dataverse URL
        print("Fetching environment info...")
        auth_url = f"https://make.powerautomate.com/environments/{env_id}"
        env_data = api_request_with_auth(get_environment, auth_url, env_id)

        dataverse_url = env_data.get("properties", {}).get("linkedEnvironmentMetadata", {}).get("instanceUrl")
        if not dataverse_url:
            print("Error: Could not find Dataverse URL for this environment")
            print("This environment may not have Dataverse enabled")
            return

        # Fetch solutions list (uses Dataverse API)
        print("Fetching solutions...")
        solutions = api_request_with_auth(
            get_solutions, auth_url, dataverse_url, use_dataverse_token=True
        )

        if not solutions:
            print("No solutions found in this environment")
            return

        # Build menu options
        menu_options = []
        for sol in solutions:
            name = sol.get("friendlyname", sol.get("uniquename", "Unknown"))
            version = sol.get("version", "")
            if version:
                menu_options.append(f"{name} (v{version})")
            else:
                menu_options.append(name)

        print(f"Found {len(solutions)} solution(s)")
        print()

        # Show interactive menu
        selected_index = select_from_menu(
            menu_options,
            "Select a solution (/ to search, Enter to select, q to cancel):",
        )

        if selected_index is None:
            print("Cancelled")
            return

        solution_id = solutions[selected_index].get("solutionid")
        if not solution_id:
            print("Error: Selected solution has no ID")
            return

        selected_name = solutions[selected_index].get("friendlyname", "Unknown")
        print(f"\nSelected: {selected_name}")

        # Now fetch flows from the selected solution (uses Dataverse API)
        print("Fetching flows from solution...")
        solution_flows = api_request_with_auth(
            get_solution_flows, auth_url, dataverse_url, solution_id,
            use_dataverse_token=True
        )

        if not solution_flows:
            print("No flows found in solution")
            return

        print(f"Found {len(solution_flows)} flow(s) in solution")

        # Save solution to solutions.json for auto-discovery
        solutions_registry = load_solutions()
        if solution_id not in solutions_registry:
            solutions_registry[solution_id] = {
                "environment_id": env_id,
                "name": selected_name,
                "ignored": []
            }
            save_solutions(solutions_registry)

        existing_labels = set(flows.keys())
        for flow_info in solution_flows:
            display_name = flow_info.get("msdyn_displayname", "unnamed-flow")
            flow_id = flow_info.get("msdyn_objectid")

            if not flow_id:
                continue

            flow_label = sanitize_label(display_name)
            flow_label = _get_unique_label(flow_label, existing_labels)

            if _add_single_flow(flows, env_id, flow_id, flow_label, solution_id):
                added_labels.append(flow_label)
                existing_labels.add(flow_label)
                print(f"Added flow '{flow_label}'")

    elif url_type == "solution":
        try:
            env_id, solution_id = parse_solution_url(url)
        except ValueError as e:
            print(f"Error: {e}")
            return

        # Get environment info to find Dataverse URL
        print("Fetching environment info...")
        # Use a generic URL for auth since we don't have a specific flow
        auth_url = f"https://make.powerautomate.com/environments/{env_id}"
        env_data = api_request_with_auth(get_environment, auth_url, env_id)

        dataverse_url = env_data.get("properties", {}).get("linkedEnvironmentMetadata", {}).get("instanceUrl")
        if not dataverse_url:
            print("Error: Could not find Dataverse URL for this environment")
            print("This environment may not have Dataverse enabled")
            return

        # Get all flows in the solution (uses Dataverse API)
        print("Fetching flows from solution...")
        solution_flows = api_request_with_auth(
            get_solution_flows, auth_url, dataverse_url, solution_id,
            use_dataverse_token=True
        )

        if not solution_flows:
            print("No flows found in solution")
            return

        print(f"Found {len(solution_flows)} flow(s) in solution")

        # Save solution to solutions.json for auto-discovery
        solutions_registry = load_solutions()
        if solution_id not in solutions_registry:
            solutions_registry[solution_id] = {
                "environment_id": env_id,
                "name": "Unknown",  # Solution name not available from URL
                "ignored": []
            }
            save_solutions(solutions_registry)

        existing_labels = set(flows.keys())
        for flow_info in solution_flows:
            display_name = flow_info.get("msdyn_displayname", "unnamed-flow")
            flow_id = flow_info.get("msdyn_objectid")

            if not flow_id:
                continue

            flow_label = sanitize_label(display_name)
            flow_label = _get_unique_label(flow_label, existing_labels)

            if _add_single_flow(flows, env_id, flow_id, flow_label, solution_id):
                added_labels.append(flow_label)
                existing_labels.add(flow_label)
                print(f"Added flow '{flow_label}'")

    if added_labels:
        save_flows(flows)
        # Pull newly added flows
        print(f"\nPulling {len(added_labels)} flow(s)...")
        cmd_pull(added_labels)
    else:
        print("No flows were added")


def cmd_del(label: str) -> None:
    """Remove a flow from the registry and delete its JSON file."""
    flows = load_flows()

    if label not in flows:
        print(f"Flow '{label}' not found")
        return

    flow_info = flows[label]
    solution_id = flow_info.get("solution_id")

    # Add to solution's ignored list if flow is from a tracked solution
    if solution_id:
        solutions = load_solutions()
        if solution_id in solutions:
            ignored = solutions[solution_id].setdefault("ignored", [])
            if flow_info["flow_id"] not in ignored:
                ignored.append(flow_info["flow_id"])
            save_solutions(solutions)

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
        print("No flows registered. Run 'pafs add <url>' to add one")
        return

    for label in flows:
        print(label)


def cmd_pull(labels: list[str] | None) -> None:
    """Pull flows from Power Automate to local JSON files."""
    flows = load_flows()

    if not flows:
        print("No flows registered. Run 'pafs add <url>' to add one")
        return

    # Auto-discover new flows in tracked solutions when pulling all
    if labels is None:
        discovered = _discover_solution_flows(flows)
        if discovered:
            save_flows(flows)
            print(f"Discovered {len(discovered)} new flow(s)")

    # Determine which flows to pull
    if labels:
        to_pull = {l: flows[l] for l in labels if l in flows}
        missing = [l for l in labels if l not in flows]
        if missing:
            print(f"Flows not found: {', '.join(missing)}")
    else:
        to_pull = flows

    if not to_pull:
        print("Nothing to pull")
        return

    pulled_files = []

    for label, flow_info in to_pull.items():
        env_id = flow_info["environment_id"]
        flow_id = flow_info["flow_id"]
        flow_url = build_flow_url(env_id, flow_id)

        print(f"Pulling '{label}'...")
        flow_data = api_request_with_auth(get_flow, flow_url, env_id, flow_id)

        file_path = Path(f"{label}.json")
        file_path.write_text(json.dumps(flow_data, indent=2) + "\n")
        pulled_files.append(str(file_path))
        print(f"  Saved {file_path}")

    if pulled_files:
        git_commit_files(pulled_files, "Pulled from Power Automate")


def cmd_push(labels: list[str] | None, message: str) -> None:
    """Push local JSON files to Power Automate."""
    flows = load_flows()

    if not flows:
        print("No flows registered. Run 'pafs add <url>' to add one")
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
