# PAFS - Power Automate Flow Sync

Manage Power Automate flows with automatic token handling.

## Installation

### Prerequisites

- Python 3.10 or later

### Install with pipx (recommended)

pipx installs the tool globally while keeping dependencies isolated.

1. Install pipx if you don't have it:

   **macOS:**
   ```bash
   brew install pipx
   pipx ensurepath
   ```

   **Windows:**
   ```bash
   scoop install pipx
   pipx ensurepath
   ```

   **Linux:**
   ```bash
   sudo apt install pipx
   pipx ensurepath
   ```

2. Install PAFS:

   ```bash
   pipx install git+https://github.com/Leohemmingsson/PAFS.git
   ```

3. Verify installation:

   ```bash
   pafs -h
   ```

### Updating

```bash
pipx upgrade pafs
```

### Uninstalling

```bash
pipx uninstall pafs
```

## Usage

```bash
# Initialize git repo for flow tracking
pafs init

# Add a flow to track
pafs add <label> <power-automate-url>

# List tracked flows
pafs list

# Pull flows from Power Automate to local JSON
pafs pull

# Push local changes to Power Automate
pafs push -m "Your commit message"

# Remove a flow
pafs del <label>

# Authenticate (refresh token)
pafs auth
```

## MCP Server

PAFS includes an MCP (Model Context Protocol) server that allows LLM clients like Claude to manage your Power Automate flows.

### Setup with Claude Code

1. Add the MCP server to Claude Code:

   ```bash
   claude mcp add --transport stdio pafs -- pafs-mcp
   ```

2. Verify the server is registered:

   ```bash
   claude mcp list
   ```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `init` | Initialize git repo and add .pafs to .gitignore |
| `list_flows` | List all registered flows |
| `add_flow` | Register a new flow (requires label and URL) |
| `remove_flow` | Remove a flow and delete its local file |
| `pull_flows` | Download flows from Power Automate |
| `push_flows` | Upload local flows to Power Automate |

## Troubleshooting

### MCP authentication

When the MCP server needs to authenticate, it will open a browser window. Complete the login to capture the token. If the browser doesn't appear or authentication fails:

1. Open a terminal in your flows directory
2. Run `pafs auth`
3. Complete the login in the browser
4. Try your MCP request again

Tokens are cached in `.pafs/token.json` and reused until they expire.