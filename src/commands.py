"""Command implementations for PAFS CLI - thin adapter over services."""

from .services import (
    ServiceResult,
    add_flow,
    add_solution_flows,
    clear_auth,
    create_flow_service,
    delete_flow,
    get_available_solutions,
    get_dataverse_url,
    get_unique_label,
    init_repo,
    list_flows_service,
    prune_flows_service,
    pull_flows_service,
    push_flows_service,
)
from .shared import detect_url_type, parse_environment_url, parse_solution_url


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


def _print_result(result: ServiceResult) -> None:
    """Print messages and errors from a service result."""
    for msg in result.messages:
        print(msg)
    for err in result.errors:
        print(f"Error: {err}")


def cmd_init() -> None:
    """Initialize git repo and commit any existing flow JSON files."""
    result = init_repo()
    _print_result(result)


def cmd_auth() -> None:
    """Authenticate with Power Automate by opening a browser to capture tokens."""
    result = clear_auth()
    _print_result(result)


def cmd_add(url: str, label: str | None = None) -> None:
    """Add a flow or all flows from a solution to the registry."""
    try:
        url_type = detect_url_type(url)
    except ValueError as e:
        print(f"Error: {e}")
        return

    if url_type == "environment":
        # Environment URL without solution ID - let user select a solution interactively
        try:
            env_id = parse_environment_url(url)
        except ValueError as e:
            print(f"Error: {e}")
            return

        # Get available solutions
        print("Fetching environment info...")
        solutions_result = get_available_solutions(env_id)
        if not solutions_result.success:
            _print_result(solutions_result)
            return

        solutions = solutions_result.data.get("solutions", [])
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

        # Add the solution's flows
        from .shared import load_flows, save_flows

        flows = load_flows()
        auth_url = solutions_result.data["auth_url"]
        dataverse_url = solutions_result.data["dataverse_url"]

        sol_result = add_solution_flows(
            flows, env_id, solution_id, selected_name, auth_url, dataverse_url
        )
        _print_result(sol_result)

        added_labels = sol_result.data.get("added_labels", [])
        if added_labels:
            save_flows(flows)
            # Pull newly added flows
            print(f"\nPulling {len(added_labels)} flow(s)...")
            cmd_pull(added_labels)
        else:
            print("No flows were added")
    else:
        # Flow or solution URL - use service directly
        result = add_flow(url, label, url_type=url_type)
        _print_result(result)

        added_labels = result.data.get("added_labels", [])
        if added_labels:
            # Pull newly added flows
            print(f"\nPulling {len(added_labels)} flow(s)...")
            cmd_pull(added_labels)


def cmd_create(target: str, name: str, from_label: str | None = None) -> None:
    """Create a new flow in Power Automate."""
    result = create_flow_service(target, name, from_label)
    _print_result(result)


def cmd_del(label: str) -> None:
    """Remove a flow from the registry and delete its JSON file."""
    result = delete_flow(label)
    _print_result(result)


def cmd_list() -> None:
    """List all registered flows and solutions."""
    result = list_flows_service()

    flows = result.data.get("flows", [])
    solutions = result.data.get("solutions", [])

    if not flows and not solutions:
        print("No flows or solutions registered. Run 'pafs add <url>' to add one")
        return

    if flows:
        print("Flows:")
        for flow in flows:
            print(f"  * {flow['label']}")

    if solutions:
        if flows:
            print()
        print("Solutions:")
        for sol in solutions:
            print(f"  * {sol['label']}")


def cmd_prune() -> None:
    """Remove flows that no longer exist in Power Automate."""
    result = prune_flows_service()
    _print_result(result)


def cmd_pull(labels: list[str] | None, force: bool = False) -> None:
    """Pull flows from Power Automate to local JSON files."""
    result = pull_flows_service(labels, force)
    _print_result(result)


def cmd_push(labels: list[str] | None, message: str) -> None:
    """Push local JSON files to Power Automate."""
    result = push_flows_service(labels, message)
    _print_result(result)
