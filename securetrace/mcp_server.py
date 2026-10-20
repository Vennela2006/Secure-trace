
from __future__ import annotations

import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .db import connect
from .ledger import (
    add_requirement,
    list_requirements,
    record_check,
    record_test_check,
    get_requirement_detail,
    mark_changed_files as ledger_mark_changed_files,
)
from .reporting import render_report
from .http_probe import HttpProbeSpec, ProbeVerdict, dispatch_probe
from .monitor import start_watcher, stop_watcher


mcp = FastMCP("securetrace")


def _root() -> Path:
    """Resolve and initialize the configured target project root."""
    configured = os.environ.get("SECURETRACE_PROJECT_ROOT")

    root = (
        Path(configured).expanduser().resolve()
        if configured
        else Path.cwd().resolve()
    )

    with connect(root):
        pass

    return root


@mcp.tool()
def list_security_requirements() -> dict:
    """List security requirements tracked for the target repository."""
    root = _root()

    return {
        "repository": str(root),
        "requirements": list_requirements(root),
    }


@mcp.tool()
def add_security_requirement(
    title: str,
    description: str,
    category: str = "other",
    severity: str = "medium",
    file_paths: list[str] | None = None,
) -> dict:
    """Register a security requirement and optional repository-relative file links."""
    root = _root()

    item = add_requirement(
        root,
        title,
        description,
        category,
        severity,
        file_paths or [],
    )

    return {
        "repository": str(root),
        "requirement": item,
    }


@mcp.tool()
def record_security_check(
    requirement_id: str,
    check_name: str,
    passed: bool,
    details: str = "",
    commit_hash: str | None = None,
    verification_complete: bool = False,
) -> dict:
    """Record security-check evidence.

    Set verification_complete=True only when the check fully verifies
    the requirement.
    """
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
    """Mark linked requirements for re-verification after file changes."""
    root = _root()

    affected = ledger_mark_changed_files(root, file_paths)

    return {
        "affected_requirements": affected,
        "count": len(affected),
    }


@mcp.tool()
def get_security_report() -> dict:
    """Return the current Markdown security report."""
    root = _root()

    return {
        "repository": str(root),
        "report_markdown": render_report(root),
    }


@mcp.tool()
def probe_endpoint_security(
    requirement_id: str,
    port: int,
    path: str = "/doner",
    approved: bool = False,
) -> dict:
    """Prepare or execute an approved local unauthenticated-access probe.

    The probe is restricted to 127.0.0.1. When approved=False,
    only a plan is returned; no network request is made.
    """
    root = _root()

    detail = get_requirement_detail(root, requirement_id)

    if detail is None:
        raise ValueError(f"Unknown requirement: {requirement_id}")

    if (
        not isinstance(port, int)
        or isinstance(port, bool)
        or not 1024 <= port <= 65535
    ):
        raise ValueError(
            "port must be an unprivileged integer between 1024 and 65535"
        )

    clean_path = path.strip()

    if not clean_path.startswith("/"):
        clean_path = "/" + clean_path

    if (
        ".." in clean_path
        or "\\" in clean_path
        or "\r" in clean_path
        or "\n" in clean_path
        or "?" in clean_path
        or "#" in clean_path
    ):
        raise ValueError(
            "path must be a clean project route without traversal, "
            "backslashes, query strings, or fragments"
        )

    target_url = f"http://127.0.0.1:{port}{clean_path}"

    spec = HttpProbeSpec(
        requirement_id=requirement_id,
        target_url=target_url,
        method="GET",
        timeout_seconds=5.0,
        expected_unauthenticated_indicators=(
            "eshwar_admin",
            "Donor",
            "table",
            "doner",
        ),
    )

    if not approved:
        return {
            "status": "APPROVAL_REQUIRED",
            "message": (
                "Probe plan prepared. Explicit user approval is required "
                "before the HTTP request is dispatched."
            ),
            "plan": {
                "requirement_id": requirement_id,
                "requirement_title": detail.get("title", ""),
                "target_url": target_url,
                "method": "GET",
                "scope": "Read-only unauthenticated route check",
                "invariants": [
                    "Restricted to 127.0.0.1 loopback",
                    "External redirects must not be followed",
                    "Sensitive response content must not be persisted",
                    "A single endpoint probe cannot mark a requirement VERIFIED",
                ],
            },
        }

    eval_result = dispatch_probe(spec)
    provenance = eval_result.to_provenance(spec)
    check_name = f"http_probe:GET {clean_path}"

    record_result = record_test_check(
        root=root,
        requirement_id=requirement_id,
        test_id=check_name,
        outcome=eval_result.ledger_outcome,
        execution=provenance,
        verification_complete=False,
    )

    verdict_labels = {
        ProbeVerdict.VULNERABLE: "VULNERABLE",
        ProbeVerdict.SECURE_FOR_THIS_CHECK: "SECURE_FOR_THIS_CHECK",
        ProbeVerdict.INCONCLUSIVE: "INCONCLUSIVE",
    }

    verdict_label = verdict_labels.get(
        eval_result.verdict,
        str(eval_result.verdict),
    )

    return {
        "status": "COMPLETED",
        "verdict": eval_result.verdict.value,
        "summary": f"{verdict_label}: {eval_result.explanation}",
        "requirement_id": requirement_id,
        "requirement_status": record_result.get("status"),
        "http_status": eval_result.status_code,
        "evidence_recorded": {
            "check_name": check_name,
            "ledger_outcome": eval_result.ledger_outcome,
            "verification_complete": False,
            "body_byte_count": eval_result.body_byte_count,
            "body_sha256": eval_result.body_sha256,
        },
    }


def main() -> None:
    """Run MCP with automatic filesystem monitoring."""
    root = _root()
    observer = start_watcher(root)

    try:
        mcp.run(transport="stdio")
    finally:
        stop_watcher(observer)


if __name__ == "__main__":
    main()
