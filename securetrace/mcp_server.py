
from __future__ import annotations

from pathlib import Path
import os

from mcp.server.fastmcp import FastMCP

from .config import project_root
from .db import connect
from .ledger import (
    add_requirement,
    list_requirements,
    record_check,
    mark_changed_files as ledger_mark_changed_files,
)
from .reporting import render_report

mcp = FastMCP("securetrace")


def _root() -> Path:
    configured = os.environ.get("SECURETRACE_PROJECT_ROOT")
    root = Path(configured).expanduser().resolve() if configured else Path.cwd().resolve()
    with connect(root):
        pass
    return root


@mcp.tool()
def list_security_requirements() -> dict:
    """List security requirements currently tracked for the target repository."""
    root = _root()
    return {"repository": str(root), "requirements": list_requirements(root)}


@mcp.tool()
def add_security_requirement(
    title: str,
    description: str,
    category: str = "other",
    severity: str = "medium",
    file_paths: list[str] | None = None,
) -> dict:
    """Register a reviewable security requirement and optional repository-relative file links."""
    root = _root()
    item = add_requirement(root, title, description, category, severity, file_paths or [])
    return {"repository": str(root), "requirement": item}


@mcp.tool()
def record_security_check(
    requirement_id: str,
    check_name: str,
    passed: bool,
    details: str = "",
    commit_hash: str | None = None,
    verification_complete: bool = False,
) -> dict:
    """Record evidence for a security check. Only set verification_complete=true when this check fully verifies the requirement."""
    root = _root()
    return record_check(
        root,
        requirement_id,
        check_name,
        passed,
        details,
        commit_hash,
        verification_complete,
    )


@mcp.tool()
def mark_changed_files(file_paths: list[str]) -> dict:
    """Mark linked requirements as needing re-verification after relevant files change."""
    root = _root()
    affected = ledger_mark_changed_files(root, file_paths)
    return {"affected_requirements": affected, "count": len(affected)}


@mcp.tool()
def get_security_report() -> dict:
    """Return the current Markdown security report for the target repository."""
    root = _root()
    return {"repository": str(root), "report_markdown": render_report(root)}


def main() -> None:
    # Stdio transport is suitable for a local Gemini CLI MCP server.
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
