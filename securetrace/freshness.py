"""Content based source fingerprints and deterministic verification plans."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re


def fingerprint_source_state(root: Path, paths: list[str]) -> dict:
    """Hash every named working-tree file; missing or unreadable paths stay explicit.

    Files are considered regardless of version-control tracking, so an untracked
    but linked file is fingerprinted just like a tracked file.
    """
    root = root.resolve(strict=True)
    records: dict[str, dict] = {}
    for raw in sorted(set(paths)):
        normalized = str(raw).replace("\\", "/")
        pure = PurePosixPath(normalized)
        if (not normalized or pure.is_absolute() or ".." in pure.parts
                or re.match(r"^[A-Za-z]:", normalized) or "\x00" in normalized):
            records[normalized] = {"state": "INVALID_PATH"}
            continue
        lexical = root.joinpath(*pure.parts)
        try:
            resolved = lexical.resolve(strict=True)
        except FileNotFoundError:
            records[pure.as_posix()] = {"state": "MISSING"}
            continue
        except OSError as exc:
            records[pure.as_posix()] = {"state": "UNREADABLE", "error": type(exc).__name__}
            continue
        try:
            resolved.relative_to(root)
        except ValueError:
            records[pure.as_posix()] = {"state": "INVALID_PATH"}
            continue
        if not resolved.is_file():
            records[pure.as_posix()] = {"state": "UNREADABLE", "error": "NotARegularFile"}
            continue
        try:
            before = resolved.stat()
            digest = hashlib.sha256()
            with resolved.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            after = resolved.stat()
            identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            if identity_before != identity_after:
                records[pure.as_posix()] = {"state": "UNSTABLE"}
            else:
                records[pure.as_posix()] = {
                    "state": "PRESENT", "sha256": digest.hexdigest(), "size": after.st_size,
                }
        except OSError as exc:
            records[pure.as_posix()] = {"state": "UNREADABLE", "error": type(exc).__name__}

    canonical = json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    complete = all(entry["state"] == "PRESENT" for entry in records.values())
    return {
        "algorithm": "sha256",
        "digest": hashlib.sha256(canonical.encode("ascii")).hexdigest(),
        "complete": complete,
        "files": records,
    }


def _metadata(check: dict) -> dict | None:
    try:
        value = json.loads(check.get("details", ""))
    except (TypeError, json.JSONDecodeError):
        return None
    if isinstance(value, dict) and value.get("securetrace_test") == 1 and value.get("origin") == "automated":
        return value
    return None


def assess_mapping_freshness(
    root: Path,
    requirement: dict,
    mapping: dict,
    checks: list[dict],
) -> dict:
    """Assess one mapped target against its latest immutable automated run."""
    test_file = mapping["test_file"]
    test_id = mapping["test_id"]
    relevant_paths = sorted(set(requirement.get("file_paths", [])) | {test_file})
    current = fingerprint_source_state(root, relevant_paths)
    matching = []
    for check in checks:
        if check.get("check_name") == test_id:
            metadata = _metadata(check)
            if metadata and metadata.get("test_file") == test_file:
                matching.append((check, metadata))
    latest = matching[0] if matching else None
    blockers: list[str] = []
    execution_blockers: list[str] = []
    try:
        from .test_runner import validate_test_target
        validate_test_target(root, test_file, test_id)
    except (OSError, ValueError) as exc:
        blocker = f"Approved test target is invalid or unavailable: {type(exc).__name__}."
        blockers.append(blocker)
        execution_blockers.append(blocker)
    reason: str
    freshness: str
    last_outcome = latest[1].get("outcome") if latest else None
    if latest is None:
        freshness = "UNKNOWN"
        reason = "No automated execution evidence exists for this mapped test."
    else:
        saved = latest[1].get("source_fingerprint_before")
        stable = latest[1].get("source_state_stable")
        if not isinstance(saved, dict):
            freshness = "UNKNOWN"
            reason = "Historical execution has no source fingerprint."
        elif not current["complete"]:
            freshness = "UNKNOWN"
            reason = "One or more relevant files cannot be fingerprinted reliably."
        elif not saved.get("complete") or stable is not True:
            freshness = "UNKNOWN"
            reason = "The source state was incomplete or changed during the recorded execution."
        elif saved.get("digest") == current.get("digest"):
            freshness = "CURRENT"
            reason = "Current relevant file contents match the recorded execution fingerprint."
        else:
            freshness = "STALE"
            reason = "Relevant file contents differ from the recorded execution fingerprint."

    for path, item in current["files"].items():
        if item["state"] != "PRESENT":
            blocker = f"{path}: {item['state']}"
            blockers.append(blocker)
            execution_blockers.append(blocker)
    if latest and last_outcome != "PASSED":
        reason += f" Latest execution outcome was {last_outcome}."
    if not mapping.get("verification_complete"):
        blockers.append("Mapping is not designated as complete verification.")
    if last_outcome and last_outcome != "PASSED":
        blockers.append(f"Latest execution outcome is {last_outcome}.")
    return {
        "requirement_id": requirement["id"],
        "test_file": test_file,
        "test_id": test_id,
        "reason": reason,
        "evidence_freshness": freshness,
        "blockers": blockers,
        "execution_blockers": execution_blockers,
        "mapping_verification_complete": bool(mapping.get("verification_complete")),
        "has_prior_execution": latest is not None,
        "latest_outcome": last_outcome,
        "latest_ran_at": latest[0].get("ran_at") if latest else None,
        "current_fingerprint": current["digest"] if current["complete"] else None,
        "dependency_coverage": "INCOMPLETE",
        "coverage_notes": [
            "Fingerprints cover explicitly linked requirement files and the mapped test; transitive dependencies are not inferred."
        ],
        "selected": freshness != "CURRENT" or last_outcome != "PASSED" or not mapping.get("verification_complete"),
    }


def build_verification_plan(
    root: Path,
    requirements: list[dict],
    details_by_id: dict[str, dict],
    mappings_by_id: dict[str, list[dict]],
) -> list[dict]:
    """Return stable requirement/test ordering and full selection rationale."""
    plan = []
    for requirement in sorted(requirements, key=lambda item: item["id"]):
        detail = details_by_id.get(requirement["id"], {})
        for mapping in sorted(mappings_by_id.get(requirement["id"], []),
                              key=lambda item: (item["test_file"], item["test_id"])):
            plan.append(assess_mapping_freshness(root, requirement, mapping, detail.get("checks", [])))
    return plan
