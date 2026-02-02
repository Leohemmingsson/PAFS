"""PAFS CLI entry point."""

import argparse
import importlib.metadata

from .commands import cmd_add, cmd_auth, cmd_del, cmd_init, cmd_list, cmd_pull, cmd_push


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
    add_parser = subparsers.add_parser("add", help="Add a flow or solution to the registry")
    add_parser.add_argument("url", help="Power Automate flow or solution URL")
    add_parser.add_argument(
        "-l", "--label",
        help="Custom label for the flow (auto-generated from flow name if not provided)",
    )

    # del
    del_parser = subparsers.add_parser("del", help="Remove a flow from the registry")
    del_parser.add_argument("label", help="Label of the flow to remove")

    # list
    subparsers.add_parser("list", help="List all registered flows")

    # pull
    pull_parser = subparsers.add_parser("pull", help="Pull flows from Power Automate")
    pull_parser.add_argument(
        "labels",
        nargs="?",
        help="Comma-separated labels to pull (default: all)",
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
        cmd_add(args.url, args.label)
    elif args.command == "del":
        cmd_del(args.label)
    elif args.command == "list":
        cmd_list()
    elif args.command == "pull":
        cmd_pull(parse_labels(args.labels))
    elif args.command == "push":
        cmd_push(parse_labels(args.labels), args.message)


if __name__ == "__main__":
    main()
