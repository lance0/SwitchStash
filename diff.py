import difflib
from pathlib import Path
from typing import Optional, List, Tuple


def compute_diff(
    old_content: str,
    new_content: str,
    fromfile: str = "previous",
    tofile: str = "current",
) -> List[str]:
    """Compute unified diff between two config files."""
    old_lines = old_content.splitlines(keepends=True)
    new_lines = new_content.splitlines(keepends=True)

    diff = difflib.unified_diff(
        old_lines, new_lines, fromfile=fromfile, tofile=tofile, lineterm=""
    )
    return list(diff)


def diff_configs(path1: Path, path2: Path) -> Tuple[bool, List[str]]:
    """Compare two config files and return diff."""
    if not path1.exists():
        return False, [f"File not found: {path1}"]
    if not path2.exists():
        return False, [f"File not found: {path2}"]

    with open(path1) as f1:
        old_content = f1.read()
    with open(path2) as f2:
        new_content = f2.read()

    if old_content == new_content:
        return True, []

    diff = compute_diff(
        old_content, new_content, fromfile=str(path1), tofile=str(path2)
    )
    return False, diff


def has_config_changed(old_path: Path, new_path: Path) -> bool:
    """Quick check if configs have changed (compares checksums)."""
    import hashlib

    if not old_path.exists() or not new_path.exists():
        return True

    def file_hash(path: Path) -> str:
        with open(path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()

    return file_hash(old_path) != file_hash(new_path)
