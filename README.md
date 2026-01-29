# PAFS - Power Automate Flow Sync

Manage Power Automate flows with automatic token handling.

## Installation

### Prerequisites

- Python 3.14 or later
- Git configured with access to this repository

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

   **Using SSH:**
   ```bash
   pipx install git+ssh://git@github.com/Leohemmingsson/PAFS.git
   ```

   **Using HTTPS:**
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
# Add a flow to track
pafs add <label> <power-automate-url>

# List tracked flows
pafs list

# Sync flows from Power Automate to local JSON
pafs sync

# Push local changes to Power Automate
pafs push -m "Your commit message"

# Remove a flow
pafs del <label>
```