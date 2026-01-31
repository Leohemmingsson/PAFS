"""Git utilities for PAFS."""

import subprocess
from pathlib import Path


def is_git_initialized() -> bool:
    """Check if git is initialized in the current directory."""
    result = subprocess.run(
        ["git", "rev-parse", "--git-dir"],
        capture_output=True,
    )
    return result.returncode == 0


def ensure_gitignore_has_pafs() -> bool:
    """Ensure .pafs is in .gitignore. Returns True if file was modified."""
    gitignore = Path(".gitignore")
    pafs_entry = ".pafs"

    if gitignore.exists():
        content = gitignore.read_text()
        # Check if .pafs is already in gitignore (as its own line)
        lines = content.splitlines()
        if pafs_entry in lines:
            return False
        # Append .pafs
        if content and not content.endswith("\n"):
            content += "\n"
        content += f"{pafs_entry}\n"
        gitignore.write_text(content)
    else:
        gitignore.write_text(f"{pafs_entry}\n")

    return True


def git_commit_files(files: list[str], message: str) -> None:
    """Add and commit files to git. Shows warning if git is not initialized."""
    if not is_git_initialized():
        print("Git not initialized. Run 'pafs init' to enable git tracking")
        return

    subprocess.run(["git", "add"] + files, check=True)
    # Only commit if there are staged changes
    result = subprocess.run(["git", "diff", "--cached", "--quiet"])
    if result.returncode != 0:
        subprocess.run(["git", "commit", "-m", message], check=True)
        print("Committed to git")
    else:
        print("No changes to commit")
