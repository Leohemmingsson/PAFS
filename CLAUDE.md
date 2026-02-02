# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development

- Use `uv` for all Python operations (never use `python` directly)
- Always increment the version in `pyproject.toml` before pushing to main, but not before getting the instruction to push the code.

## Commands

```bash
uv run pafs <command>     # Run the CLI during development
uv run pytest tests/      # Run tests
uv run python -m py_compile src/main.py  # Syntax check
```

## Testing

- Tests should only verify exception types, not exact error messages. This prevents tests from breaking when messages are reworded.

```python
# Good - only checks exception type
with pytest.raises(ValueError):
    parse_flow_url("invalid-url")

# Bad - will break if message changes
with pytest.raises(ValueError, match="Invalid Power Automate flow URL"):
    parse_flow_url("invalid-url")
```

## Architecture

PAFS (Power Automate Flow Sync) is a CLI tool that syncs Power Automate flows to local JSON files with git versioning.

### Key Files

- `src/main.py` - CLI entry point with argparse setup
- `src/commands.py` - Command implementations (init, add, del, list, pull, push)
- `src/auth.py` - Token capture and refresh via Playwright
- `src/pa_api.py` - Power Automate REST API client

### Authentication Flow

Token capture uses Playwright to open a browser, intercept requests to `api.flow.microsoft.com`, and extract the Bearer token from the Authorization header. Tokens are cached in `.pafs/token.json` and automatically refreshed on 401 errors.

### Local Storage (`.pafs/` directory)

- `flows.json` - Registry mapping labels to environment_id/flow_id
- `token.json` - Cached authentication token
- `browser-data/` - Playwright persistent browser context

Flow definitions are stored as `<label>.json` in the working directory (not in `.pafs/`).
