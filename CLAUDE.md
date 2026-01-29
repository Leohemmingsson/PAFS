# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development

- Use `uv` for all Python operations (never use `python` directly)
- Always increment the version in `pyproject.toml` before pushing to main

## Commands

```bash
uv run pafs <command>     # Run the CLI during development
uv run python -m py_compile src/flow_cli/main.py  # Syntax check
```

## Architecture

PAFS (Power Automate Flow Sync) is a CLI tool that syncs Power Automate flows to local JSON files with git versioning.

### Key Files

- `src/flow_cli/main.py` - CLI entry point and all commands (init, add, del, list, sync, push)
- `src/flow_cli/pa_api.py` - Power Automate REST API client (get_flow, update_flow)

### Authentication Flow

Token capture uses Playwright to open a browser, intercept requests to `api.flow.microsoft.com`, and extract the Bearer token from the Authorization header. Tokens are cached in `.pafs/token.json` and automatically refreshed on 401 errors.

### Local Storage (`.pafs/` directory)

- `flows.json` - Registry mapping labels to environment_id/flow_id
- `token.json` - Cached authentication token
- `browser-data/` - Playwright persistent browser context

Flow definitions are stored as `<label>.json` in the working directory (not in `.pafs/`).
