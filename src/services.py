"""Service layer for PAFS - core business logic shared by CLI and MCP."""

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .auth import api_request_with_auth, get_tokens
from .git import ensure_gitignore_has_pafs, git_commit_files, is_git_initialized
from .pa_api import (
    create_flow as api_create_flow,
    get_environment,
    get_flow,
    get_solution_flows,
    get_solutions,
    update_flow,
)
from .shared import (
    build_flow_url,
    clear_token,
    find_solution_by_id,
    load_flows,
    load_solutions,
    parse_environment_url,
    parse_flow_url,
    parse_solution_url,
    sanitize_label,
    save_flows,
    save_solutions,
)


@dataclass
class ServiceResult:
    """Standard return type for all service functions."""

    success: bool
    data: dict = field(default_factory=dict)
    messages: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# =============================================================================
# Helper Functions
# =============================================================================


def get_unique_label(base_label: str, existing_labels: set[str]) -> str:
    """Generate a unique label by appending a number if needed."""
    if base_label not in existing_labels:
        return base_label
    counter = 2
    while f"{base_label}-{counter}" in existing_labels:
        counter += 1
    return f"{base_label}-{counter}"


def add_single_flow(
    flows: dict,
    env_id: str,
    flow_id: str,
    label: str,
    solution_id: str | None = None,
) -> tuple[bool, str | None]:
    """Add a single flow to the registry.

    Returns: (was_added, message)
    """
    # Check for duplicate flow_id
    for existing_label, info in flows.items():
        if info["flow_id"] == flow_id:
            if existing_label == label:
                return False, f"Flow '{label}' already exists, skipping"
            else:
                return False, f"Warning: Flow ID {flow_id} already exists as '{existing_label}'"

    flow_entry = {
        "environment_id": env_id,
        "flow_id": flow_id,
    }
    if solution_id:
        flow_entry["solution_id"] = solution_id

    flows[label] = flow_entry
    return True, None


def get_dataverse_url(env_id: str) -> tuple[str, str, str | None] | tuple[None, None, str]:
    """Get the Dataverse URL for an environment.

    Returns: (auth_url, dataverse_url, None) on success
             (None, None, error_message) on failure
    """
    auth_url = f"https://make.powerautomate.com/environments/{env_id}"
    env_data = api_request_with_auth(get_environment, auth_url, env_id)

    dataverse_url = (
        env_data.get("properties", {})
        .get("linkedEnvironmentMetadata", {})
        .get("instanceUrl")
    )
    if not dataverse_url:
        return None, None, "Could not find Dataverse URL. This environment may not have Dataverse enabled."

    return auth_url, dataverse_url, None


def add_solution_flows(
    flows: dict,
    env_id: str,
    solution_id: str,
    solution_name: str | None,
    auth_url: str,
    dataverse_url: str,
) -> ServiceResult:
    """Fetch flows from a solution and add them to the registry.

    If solution_name is None, it will be fetched from the API.
    """
    result = ServiceResult(success=True)

    # Fetch flows from solution
    result.messages.append("Fetching flows from solution...")
    solution_flows = api_request_with_auth(
        get_solution_flows,
        auth_url,
        dataverse_url,
        solution_id,
        use_dataverse_token=True,
    )

    if not solution_flows:
        result.messages.append("No flows found in solution")
        result.data["added_labels"] = []
        return result

    result.messages.append(f"Found {len(solution_flows)} flow(s) in solution")

    # Register solution for auto-discovery
    solutions_registry = load_solutions()
    existing_entry = find_solution_by_id(solutions_registry, solution_id)
    if not existing_entry:
        # Get solution name from API if not provided
        if solution_name is None:
            all_solutions = api_request_with_auth(
                get_solutions, auth_url, dataverse_url, use_dataverse_token=True
            )
            solution_name = "unknown-solution"
            for sol in all_solutions:
                if sol.get("solutionid") == solution_id:
                    solution_name = sol.get(
                        "friendlyname", sol.get("uniquename", "unknown-solution")
                    )
                    break

        sol_label = sanitize_label(solution_name)
        sol_label = get_unique_label(sol_label, set(solutions_registry.keys()))
        solutions_registry[sol_label] = {
            "solution_id": solution_id,
            "environment_id": env_id,
            "ignored": [],
        }
        save_solutions(solutions_registry)

    # Add flows to registry
    added_labels = []
    existing_labels = set(flows.keys())
    for flow_info in solution_flows:
        display_name = flow_info.get("msdyn_displayname", "unnamed-flow")
        flow_id = flow_info.get("msdyn_objectid")

        if not flow_id:
            continue

        flow_label = sanitize_label(display_name)
        flow_label = get_unique_label(flow_label, existing_labels)

        was_added, msg = add_single_flow(flows, env_id, flow_id, flow_label, solution_id)
        if was_added:
            added_labels.append(flow_label)
            existing_labels.add(flow_label)
            result.messages.append(f"Added flow '{flow_label}'")
        elif msg:
            result.messages.append(msg)

    result.data["added_labels"] = added_labels
    return result


def discover_solution_flows(flows: dict) -> ServiceResult:
    """Discover new flows in tracked solutions."""
    result = ServiceResult(success=True)
    solutions_registry = load_solutions()

    if not solutions_registry:
        result.data["added_labels"] = []
        return result

    # Get existing flow_ids for quick lookup
    existing_flow_ids = {info["flow_id"] for info in flows.values()}
    existing_labels = set(flows.keys())
    added_labels = []

    for sol_label, sol_info in solutions_registry.items():
        solution_id = sol_info["solution_id"]
        env_id = sol_info["environment_id"]
        ignored = set(sol_info.get("ignored", []))

        auth_url = f"https://make.powerautomate.com/environments/{env_id}"

        try:
            # Get Dataverse URL
            env_data = api_request_with_auth(get_environment, auth_url, env_id)
            dataverse_url = (
                env_data.get("properties", {})
                .get("linkedEnvironmentMetadata", {})
                .get("instanceUrl")
            )

            if not dataverse_url:
                continue

            # Get flows in solution (uses Dataverse API)
            solution_flows = api_request_with_auth(
                get_solution_flows,
                auth_url,
                dataverse_url,
                solution_id,
                use_dataverse_token=True,
            )

            for flow_info in solution_flows:
                flow_id = flow_info.get("msdyn_objectid")

                # Skip if already tracked, or if in ignored list
                if not flow_id or flow_id in existing_flow_ids or flow_id in ignored:
                    continue

                display_name = flow_info.get("msdyn_displayname", "unnamed-flow")
                label = sanitize_label(display_name)
                label = get_unique_label(label, existing_labels)

                flows[label] = {
                    "environment_id": env_id,
                    "flow_id": flow_id,
                    "solution_id": solution_id,
                }
                existing_flow_ids.add(flow_id)
                existing_labels.add(label)
                added_labels.append(label)
                result.messages.append(f"Discovered new flow: '{label}'")

        except Exception as e:
            result.messages.append(f"Warning: Could not check solution {solution_id}: {e}")

    result.data["added_labels"] = added_labels
    return result


def rename_flow_if_needed(
    flows: dict,
    old_label: str,
    new_display_name: str,
    existing_labels: set[str],
) -> tuple[str, bool, str | None]:
    """Check if flow needs renaming and perform it.

    Returns: (final_label, was_renamed, message)
    """
    new_base_label = sanitize_label(new_display_name)

    if new_base_label == old_label:
        return old_label, False, None

    # Get unique label excluding current label
    labels_for_check = existing_labels - {old_label}
    new_label = get_unique_label(new_base_label, labels_for_check)

    old_file = Path(f"{old_label}.json")
    new_file = Path(f"{new_label}.json")

    # Edge case: source file doesn't exist
    if not old_file.exists():
        return old_label, False, f"Warning: Cannot rename '{old_label}': source file not found"

    # Edge case: target file already exists
    if new_file.exists():
        return old_label, False, f"Warning: Cannot rename to '{new_label}': target file already exists"

    # Update registry
    flows[new_label] = flows.pop(old_label)

    # Git mv
    subprocess.run(["git", "mv", str(old_file), str(new_file)], check=True)

    return new_label, True, f"Renamed: '{old_label}' -> '{new_label}'"


# =============================================================================
# Service Functions
# =============================================================================


def init_repo() -> ServiceResult:
    """Initialize git repo and commit any existing flow JSON files."""
    result = ServiceResult(success=True)

    git_initialized = is_git_initialized()
    gitignore_has_pafs = (
        Path(".gitignore").exists()
        and ".pafs" in Path(".gitignore").read_text().splitlines()
    )

    # Already fully initialized
    if git_initialized and gitignore_has_pafs:
        result.messages.append("Already initialized")
        result.data["already_initialized"] = True
        return result

    result.messages.append("Initializing...")
    result.data["already_initialized"] = False

    # Initialize git if needed
    if not git_initialized:
        subprocess.run(["git", "init"], check=True)
        result.data["git_initialized"] = True

    # Ensure .pafs is in .gitignore
    gitignore_modified = ensure_gitignore_has_pafs()
    result.data["gitignore_modified"] = gitignore_modified

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
        git_result = subprocess.run(["git", "diff", "--cached", "--quiet"])
        if git_result.returncode != 0:
            subprocess.run(["git", "commit", "-m", "Initial pafs commit"], check=True)
            result.messages.append("Committed to git")
            result.data["committed"] = True
        else:
            result.messages.append("No changes to commit")
            result.data["committed"] = False
    else:
        result.messages.append("No files to commit")
        result.data["committed"] = False

    result.data["files_committed"] = files_to_commit
    return result


def clear_auth() -> ServiceResult:
    """Clear existing tokens to force re-authentication."""
    result = ServiceResult(success=True)
    clear_token()
    result.messages.append("Cleared existing tokens")
    get_tokens("https://make.powerautomate.com/", require_dataverse_token=False)
    return result


def list_flows_service() -> ServiceResult:
    """List all registered flows and solutions."""
    result = ServiceResult(success=True)
    flows = load_flows()

    flow_list = []
    for label, info in flows.items():
        flow_list.append(
            {
                "label": label,
                "environment_id": info["environment_id"],
                "flow_id": info["flow_id"],
                "solution_id": info.get("solution_id"),
                "url": build_flow_url(info["environment_id"], info["flow_id"]),
            }
        )

    solutions = load_solutions()
    solution_list = []
    for label, info in solutions.items():
        solution_list.append(
            {
                "label": label,
                "solution_id": info["solution_id"],
                "environment_id": info["environment_id"],
            }
        )

    result.data["flows"] = flow_list
    result.data["solutions"] = solution_list
    if not flows and not solutions:
        result.messages.append("No flows or solutions registered")
    return result


def delete_flow(label: str) -> ServiceResult:
    """Remove a flow from the registry and delete its JSON file."""
    result = ServiceResult(success=True)
    flows = load_flows()

    if label not in flows:
        result.success = False
        result.errors.append(f"Flow '{label}' not found")
        return result

    flow_info = flows[label]
    solution_id = flow_info.get("solution_id")

    # Add to solution's ignored list if flow is from a tracked solution
    if solution_id:
        solutions = load_solutions()
        found = find_solution_by_id(solutions, solution_id)
        if found:
            sol_label, sol_info = found
            ignored = sol_info.setdefault("ignored", [])
            if flow_info["flow_id"] not in ignored:
                ignored.append(flow_info["flow_id"])
            save_solutions(solutions)

    del flows[label]
    save_flows(flows)
    result.messages.append(f"Removed '{label}'")

    # Delete the JSON file if it exists
    flow_file = Path(f"{label}.json")
    if flow_file.exists():
        flow_file.unlink()
        result.messages.append(f"Deleted {flow_file}")
        result.data["file_deleted"] = True
    else:
        result.data["file_deleted"] = False

    result.data["label"] = label
    return result


def get_available_solutions(env_id: str) -> ServiceResult:
    """Get list of available solutions in an environment.

    Used for interactive solution selection in CLI.
    """
    result = ServiceResult(success=True)

    auth_url, dataverse_url, error = get_dataverse_url(env_id)
    if error:
        result.success = False
        result.errors.append(error)
        return result

    result.messages.append("Fetching solutions...")
    solutions = api_request_with_auth(
        get_solutions, auth_url, dataverse_url, use_dataverse_token=True
    )

    if not solutions:
        result.messages.append("No solutions found in this environment")
        result.data["solutions"] = []
        return result

    result.messages.append(f"Found {len(solutions)} solution(s)")
    result.data["solutions"] = solutions
    result.data["auth_url"] = auth_url
    result.data["dataverse_url"] = dataverse_url
    return result


def add_flow(
    url: str,
    label: str | None = None,
    solution_id: str | None = None,
    url_type: str | None = None,
) -> ServiceResult:
    """Add a flow or all flows from a solution to the registry.

    For environment URLs in non-interactive mode, solution_id must be provided.

    Args:
        url: Power Automate URL (flow, solution, or environment)
        label: Optional label for single flow adds
        solution_id: Required for environment URLs in non-interactive mode
        url_type: Pre-detected URL type (optional, will be detected if not provided)
    """
    result = ServiceResult(success=True)
    flows = load_flows()
    added_labels = []

    # Detect URL type if not provided
    if url_type is None:
        from .shared import detect_url_type

        try:
            url_type = detect_url_type(url)
        except ValueError as e:
            result.success = False
            result.errors.append(str(e))
            return result

    if url_type == "flow":
        try:
            env_id, flow_id, url_solution_id = parse_flow_url(url)
        except ValueError as e:
            result.success = False
            result.errors.append(str(e))
            return result

        # Get display name from API if no label provided
        if label is None:
            flow_url = build_flow_url(env_id, flow_id)
            result.messages.append("Fetching flow info...")
            flow_data = api_request_with_auth(get_flow, flow_url, env_id, flow_id)
            display_name = flow_data.get("properties", {}).get(
                "displayName", "unnamed-flow"
            )
            label = sanitize_label(display_name)
            label = get_unique_label(label, set(flows.keys()))

        # Don't pass solution_id for single flow adds - only track the specific flow
        was_added, msg = add_single_flow(flows, env_id, flow_id, label)
        if was_added:
            added_labels.append(label)
            result.messages.append(f"Added flow '{label}'")

            # Remove from any solution's ignored list
            solutions = load_solutions()
            modified = False
            for sol_info in solutions.values():
                if flow_id in sol_info.get("ignored", []):
                    sol_info["ignored"].remove(flow_id)
                    modified = True
            if modified:
                save_solutions(solutions)
        elif msg:
            result.messages.append(msg)

    elif url_type == "environment":
        # Environment URL - requires solution_id in non-interactive mode
        if solution_id is None:
            result.success = False
            result.errors.append(
                "Environment URL requires solution_id parameter. "
                "Use get_available_solutions() first to get the list."
            )
            return result

        try:
            env_id = parse_environment_url(url)
        except ValueError as e:
            result.success = False
            result.errors.append(str(e))
            return result

        auth_url, dataverse_url, error = get_dataverse_url(env_id)
        if error:
            result.success = False
            result.errors.append(error)
            return result

        sol_result = add_solution_flows(
            flows, env_id, solution_id, None, auth_url, dataverse_url
        )
        result.messages.extend(sol_result.messages)
        added_labels = sol_result.data.get("added_labels", [])

    elif url_type == "solution":
        try:
            env_id, solution_id = parse_solution_url(url)
        except ValueError as e:
            result.success = False
            result.errors.append(str(e))
            return result

        auth_url, dataverse_url, error = get_dataverse_url(env_id)
        if error:
            result.success = False
            result.errors.append(error)
            return result

        sol_result = add_solution_flows(
            flows, env_id, solution_id, None, auth_url, dataverse_url
        )
        result.messages.extend(sol_result.messages)
        added_labels = sol_result.data.get("added_labels", [])

    if added_labels:
        save_flows(flows)
        result.data["added_labels"] = added_labels
    else:
        result.messages.append("No flows were added")
        result.data["added_labels"] = []

    return result


def create_flow_service(
    target: str, name: str, from_label: str | None = None
) -> ServiceResult:
    """Create a new flow in Power Automate.

    Args:
        target: Either an environment URL or a solution label
        name: Display name for the new flow
        from_label: Optional label of existing flow to clone from
    """
    result = ServiceResult(success=True)
    solution_id = None

    # Auto-detect target type: URL or solution label
    if target.startswith("https://"):
        try:
            env_id = parse_environment_url(target)
        except ValueError as e:
            result.success = False
            result.errors.append(str(e))
            return result
    else:
        # Look up solution label
        solutions = load_solutions()
        if target not in solutions:
            result.success = False
            result.errors.append(
                f"Solution '{target}' not found. Run 'pafs add <solution-url>' first"
            )
            return result
        sol_info = solutions[target]
        env_id = sol_info["environment_id"]
        solution_id = sol_info["solution_id"]

    flows = load_flows()
    label = sanitize_label(name)
    label = get_unique_label(label, set(flows.keys()))

    # Get flow definition
    if from_label:
        # Clone from existing flow
        if from_label not in flows:
            result.success = False
            result.errors.append(f"Flow '{from_label}' not found")
            return result
        source_file = Path(f"{from_label}.json")
        if not source_file.exists():
            result.success = False
            result.errors.append(
                f"Source file {source_file} not found. Run 'pafs pull {from_label}' first"
            )
            return result
        flow_def = json.loads(source_file.read_text())
    else:
        # Use default template
        template_path = Path(__file__).parent / "pa_templates" / "default_flow.json"
        if not template_path.exists():
            result.success = False
            result.errors.append(f"Default template not found at {template_path}")
            return result
        flow_def = json.loads(template_path.read_text())

    # Set display name
    flow_def["properties"]["displayName"] = name

    # Create flow via API
    result.messages.append(f"Creating flow '{name}'...")
    auth_url = f"https://make.powerautomate.com/environments/{env_id}"

    try:
        api_result = api_request_with_auth(api_create_flow, auth_url, env_id, flow_def)
    except Exception as e:
        result.success = False
        result.errors.append(str(e))
        return result

    # Extract flow_id from response
    flow_id = api_result.get("name")  # API returns flow ID in "name" field
    if not flow_id:
        result.success = False
        result.errors.append("Could not get flow ID from response")
        return result

    # Add to registry
    flow_entry = {
        "environment_id": env_id,
        "flow_id": flow_id,
    }
    if solution_id:
        flow_entry["solution_id"] = solution_id
    flows[label] = flow_entry
    save_flows(flows)

    # Save flow definition locally
    file_path = Path(f"{label}.json")
    file_path.write_text(json.dumps(api_result, indent=2) + "\n")
    result.messages.append(f"Created '{label}' ({flow_id})")

    # Git commit
    changed, commit_output = git_commit_files([str(file_path)], f"Created flow: {name}")
    if commit_output:
        result.messages.append(commit_output)
    elif not changed:
        result.messages.append("No changes to commit")

    result.data["label"] = label
    result.data["flow_id"] = flow_id
    result.data["file_path"] = str(file_path)
    return result


def pull_flows_service(
    labels: list[str] | None = None, force: bool = False, auto_discover: bool = True
) -> ServiceResult:
    """Pull flows from Power Automate to local JSON files.

    Args:
        labels: Specific labels to pull, or None for all
        force: If True, rename local files to match remote display names
        auto_discover: If True (default), discover new flows in tracked solutions
    """
    result = ServiceResult(success=True)
    flows = load_flows()

    if not flows:
        result.messages.append("No flows registered")
        result.data["pulled"] = []
        return result

    # Auto-discover new flows in tracked solutions when pulling all
    discovered = []
    if labels is None and auto_discover:
        discover_result = discover_solution_flows(flows)
        result.messages.extend(discover_result.messages)
        discovered = discover_result.data.get("added_labels", [])
        if discovered:
            save_flows(flows)
            result.messages.append(f"Discovered {len(discovered)} new flow(s)")

    # Determine which flows to pull
    if labels:
        to_pull = {l: flows[l] for l in labels if l in flows}
        missing = [l for l in labels if l not in flows]
        if missing:
            result.messages.append(f"Flows not found: {', '.join(missing)}")
            result.data["missing"] = missing
    else:
        to_pull = flows
        result.data["missing"] = []

    if not to_pull:
        result.messages.append("Nothing to pull")
        result.data["pulled"] = []
        result.data["discovered"] = discovered
        return result

    pulled_files = []
    pulled_labels = []
    renamed = []
    flows_modified = False
    existing_labels = set(flows.keys())

    # Iterate over copy since we may modify flows dict
    for label, flow_info in list(to_pull.items()):
        env_id = flow_info["environment_id"]
        flow_id = flow_info["flow_id"]
        flow_url = build_flow_url(env_id, flow_id)

        flow_data = api_request_with_auth(get_flow, flow_url, env_id, flow_id)

        # Handle label rename when force flag is set
        final_label = label
        if force:
            display_name = flow_data.get("properties", {}).get("displayName", "")
            if display_name:
                final_label, was_renamed, msg = rename_flow_if_needed(
                    flows, label, display_name, existing_labels
                )
                if msg:
                    result.messages.append(f"  {msg}")
                if was_renamed:
                    flows_modified = True
                    existing_labels.discard(label)
                    existing_labels.add(final_label)
                    renamed.append((label, final_label))

        file_path = Path(f"{final_label}.json")
        file_path.write_text(json.dumps(flow_data, indent=2) + "\n")
        pulled_files.append(str(file_path))
        pulled_labels.append(final_label)

    if flows_modified:
        save_flows(flows)

    result.messages.append(f"Pulled {len(pulled_labels)} flow(s)")
    if pulled_files:
        changed, commit_output = git_commit_files(pulled_files, "Pulled from Power Automate")
        for f in changed:
            result.messages.append(f"  * {Path(f).stem} changed")
        if commit_output:
            result.messages.append("")
            result.messages.append(commit_output)
        elif not changed:
            result.messages.append("No changes to commit")

    result.data["pulled"] = pulled_labels
    result.data["discovered"] = discovered
    result.data["renamed"] = renamed
    return result


def push_flows_service(
    labels: list[str] | None = None, message: str = "Pushed to Power Automate"
) -> ServiceResult:
    """Push local JSON files to Power Automate.

    Args:
        labels: Specific labels to push, or None for all
        message: Git commit message
    """
    result = ServiceResult(success=True)
    flows = load_flows()

    if not flows:
        result.messages.append("No flows registered")
        result.data["pushed"] = []
        return result

    # Determine which flows to push
    if labels:
        to_push = {l: flows[l] for l in labels if l in flows}
        missing = [l for l in labels if l not in flows]
        if missing:
            result.messages.append(f"Flows not found: {', '.join(missing)}")
            result.data["missing"] = missing
    else:
        to_push = flows
        result.data["missing"] = []

    if not to_push:
        result.messages.append("Nothing to push")
        result.data["pushed"] = []
        return result

    pushed_files = []
    pushed_labels = []
    skipped = []
    push_errors = []

    for label, flow_info in to_push.items():
        file_path = Path(f"{label}.json")
        if not file_path.exists():
            result.messages.append(f"Skipping '{label}': {file_path} not found")
            skipped.append({"label": label, "reason": "file not found"})
            continue

        env_id = flow_info["environment_id"]
        flow_id = flow_info["flow_id"]
        flow_url = build_flow_url(env_id, flow_id)

        result.messages.append(f"Pushing '{label}'...")
        try:
            flow_data = json.loads(file_path.read_text())
        except json.JSONDecodeError as e:
            result.messages.append(f"Skipping '{label}': invalid JSON in {file_path}")
            push_errors.append({"label": label, "error": f"Invalid JSON: {e}"})
            continue

        try:
            api_request_with_auth(update_flow, flow_url, flow_data, env_id, flow_id)
            pushed_files.append(str(file_path))
            pushed_labels.append(label)
            result.messages.append(f"  Pushed {file_path}")
        except Exception as e:
            push_errors.append({"label": label, "error": str(e)})
            result.messages.append(f"  Error: {e}")

    if pushed_files:
        changed, commit_output = git_commit_files(pushed_files, message)
        if commit_output:
            result.messages.append(commit_output)
        elif not changed:
            result.messages.append("No changes to commit")

    result.data["pushed"] = pushed_labels
    result.data["skipped"] = skipped
    result.data["errors"] = push_errors
    return result
