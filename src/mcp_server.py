"""MCP server for PAFS - allows LLM clients to manage Power Automate flows."""

from fastmcp import FastMCP

from .services import (
    add_flow,
    clear_auth,
    create_flow_service,
    delete_flow,
    get_available_solutions,
    init_repo,
    list_flows_service,
    prune_flows_service,
    pull_flows_service,
    push_flows_service,
)
from .shared import detect_url_type

mcp = FastMCP(name="pafs")


def _result_to_dict(result, include_data: bool = True) -> dict:
    """Convert a ServiceResult to a dict for MCP response."""
    response = {
        "status": "success" if result.success else "error",
        "messages": result.messages,
    }
    if result.errors:
        response["errors"] = result.errors
    if include_data and result.data:
        response.update(result.data)
    return response


@mcp.tool
def init() -> dict:
    """Initialize git repo and add .pafs to .gitignore."""
    result = init_repo()
    return _result_to_dict(result)


@mcp.tool
def auth() -> dict:
    """Clear existing tokens and re-authenticate via browser."""
    result = clear_auth()
    return _result_to_dict(result)


@mcp.tool
def list_flows() -> dict:
    """List all registered flows with their metadata."""
    result = list_flows_service()
    return _result_to_dict(result)


@mcp.tool
def add_flow_tool(
    url: str, label: str | None = None, solution_id: str | None = None
) -> dict:
    """Register a new flow or add all flows from a solution.

    Args:
        url: Power Automate URL (flow, solution, or environment URL)
        label: Optional friendly name for single flow adds
        solution_id: Required for environment URLs - use list_solutions first to get IDs
    """
    # Detect URL type
    try:
        url_type = detect_url_type(url)
    except ValueError as e:
        return {"status": "error", "errors": [str(e)]}

    # For environment URLs, require solution_id
    if url_type == "environment" and not solution_id:
        return {
            "status": "error",
            "errors": [
                "Environment URL requires solution_id parameter. "
                "Use list_solutions tool first to get available solution IDs."
            ],
        }

    result = add_flow(url, label, solution_id=solution_id, url_type=url_type)

    # If flows were added, also pull them
    response = _result_to_dict(result)
    added_labels = result.data.get("added_labels", [])
    if added_labels:
        pull_result = pull_flows_service(added_labels, force=False, auto_discover=False)
        response["pull_messages"] = pull_result.messages

    return response


@mcp.tool
def list_solutions(env_id: str) -> dict:
    """List available solutions in an environment.

    Use this before add_flow_tool with an environment URL to get solution IDs.

    Args:
        env_id: The environment ID (from a Power Automate URL)
    """
    result = get_available_solutions(env_id)
    if not result.success:
        return _result_to_dict(result)

    # Format solutions for easy reading
    solutions = result.data.get("solutions", [])
    formatted = []
    for sol in solutions:
        formatted.append(
            {
                "solutionid": sol.get("solutionid"),
                "name": sol.get("friendlyname", sol.get("uniquename", "Unknown")),
                "version": sol.get("version", ""),
            }
        )

    return {
        "status": "success",
        "solutions": formatted,
        "messages": result.messages,
    }


@mcp.tool
def remove_flow(label: str) -> dict:
    """Remove a flow from the registry and delete its local JSON file.

    Args:
        label: The label of the flow to remove
    """
    result = delete_flow(label)
    return _result_to_dict(result)


@mcp.tool
def prune_flows() -> dict:
    """Remove flows that no longer exist in Power Automate.

    Checks each registered flow against the API and removes any that return 404.
    Unlike remove_flow, pruned flows are NOT added to solution ignored lists.
    """
    result = prune_flows_service()
    return _result_to_dict(result)


@mcp.tool
def create_flow(target: str, name: str, from_label: str | None = None) -> dict:
    """Create a new flow in Power Automate.

    Args:
        target: Either an environment URL or a solution label
        name: Display name for the new flow
        from_label: Optional label of existing flow to clone from
    """
    result = create_flow_service(target, name, from_label)
    return _result_to_dict(result)


@mcp.tool
def pull_flows(labels: str | None = None, force: bool = False) -> dict:
    """Download flows from Power Automate to local JSON files.

    Args:
        labels: Comma-separated list of flow labels to pull (default: all)
        force: If True, rename local files to match remote display names and remove deleted flows
    """
    # Parse labels
    label_list = None
    if labels:
        label_list = [l.strip() for l in labels.split(",") if l.strip()]

    result = pull_flows_service(label_list, force)
    return _result_to_dict(result)


@mcp.tool
def push_flows(labels: str | None = None, message: str = "Pushed to Power Automate") -> dict:
    """Upload local flow JSON files to Power Automate.

    Args:
        labels: Comma-separated list of flow labels to push (default: all)
        message: Git commit message
    """
    # Parse labels
    label_list = None
    if labels:
        label_list = [l.strip() for l in labels.split(",") if l.strip()]

    result = push_flows_service(label_list, message)
    return _result_to_dict(result)


def main():
    """Entry point for the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
