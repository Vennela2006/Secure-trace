from __future__ import annotations

from pathlib import Path
import pytest

from securetrace.http_probe import HttpProbeSpec, ProbeEvaluationResult, ProbeVerdict
from securetrace.ledger import add_requirement, get_requirement_detail
import securetrace.mcp_server as mcp_server


def test_mark_changed_files_calls_ledger_function(monkeypatch, tmp_path: Path):
    expected_root = tmp_path.resolve()
    expected_paths = ["examples/example.py"]
    expected_affected = [
        {
            "requirement_id": "SEC-TEST",
            "changed_files": expected_paths,
        }
    ]

    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(expected_root))

    calls = {}

    def fake_ledger_mark_changed_files(root, changed_paths):
        calls["root"] = root
        calls["changed_paths"] = changed_paths
        return expected_affected

    monkeypatch.setattr(
        mcp_server,
        "ledger_mark_changed_files",
        fake_ledger_mark_changed_files,
    )

    result = mcp_server.mark_changed_files(expected_paths)

    assert calls["root"] == expected_root
    assert calls["changed_paths"] == expected_paths
    assert result == {
        "affected_requirements": expected_affected,
        "count": 1,
    }


def test_probe_endpoint_security_requires_explicit_approval(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))
    req = add_requirement(tmp_path, "Admin routes lack auth", "Desc", "authorization", "high")
    req_id = req["id"]

    # When approved=False (default), it must return plan without running
    result = mcp_server.probe_endpoint_security(req_id, port=8095, path="/doner", approved=False)
    assert result["status"] == "APPROVAL_REQUIRED"
    assert "Explicit user approval is required" in result["message"]
    assert result["plan"]["target_url"] == "http://127.0.0.1:8095/doner"
    assert result["plan"]["requirement_id"] == req_id

    # Ledger must have zero checks recorded
    detail = get_requirement_detail(tmp_path, req_id)
    assert len(detail["checks"]) == 0


def test_probe_endpoint_security_validates_inputs(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))
    req = add_requirement(tmp_path, "Admin routes lack auth", "Desc", "authorization", "high")
    req_id = req["id"]

    # Non-existent requirement
    with pytest.raises(ValueError, match="Unknown requirement"):
        mcp_server.probe_endpoint_security("SEC-00000000", port=8095)

    # Privileged port or out-of-range port
    with pytest.raises(ValueError, match="unprivileged integer"):
        mcp_server.probe_endpoint_security(req_id, port=80)
    with pytest.raises(ValueError, match="unprivileged integer"):
        mcp_server.probe_endpoint_security(req_id, port=70000)

    # Path traversal / invalid path
    with pytest.raises(ValueError, match="clean project route"):
        mcp_server.probe_endpoint_security(req_id, port=8095, path="/../etc/passwd")
    with pytest.raises(ValueError, match="clean project route"):
        mcp_server.probe_endpoint_security(req_id, port=8095, path="C:\\test")


def test_probe_endpoint_security_records_vulnerable_as_regression(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))
    req = add_requirement(tmp_path, "Admin routes lack auth", "Desc", "authorization", "high")
    req_id = req["id"]

    fake_eval = ProbeEvaluationResult(
        verdict=ProbeVerdict.VULNERABLE,
        status_code=200,
        explanation="HTTP 200 exposed protected donor table content.",
        safe_headers={"content-type": "text/html"},
        body_byte_count=1234,
        body_sha256="abc123hash",
        matched_indicators=("donor", "table"),
        ledger_outcome="FAILED",
        verification_complete=False,
    )
    monkeypatch.setattr(mcp_server, "dispatch_probe", lambda spec: fake_eval)

    result = mcp_server.probe_endpoint_security(req_id, port=8095, path="/doner", approved=True)
    assert result["status"] == "COMPLETED"
    assert result["verdict"] == "VULNERABLE"
    assert result["requirement_status"] == "REGRESSION"
    assert result["evidence_recorded"]["ledger_outcome"] == "FAILED"
    assert result["evidence_recorded"]["verification_complete"] is False

    detail = get_requirement_detail(tmp_path, req_id)
    assert detail["status"] == "REGRESSION"
    assert len(detail["checks"]) == 1
    assert detail["checks"][0]["result"] == "FAILED"


def test_probe_endpoint_security_secure_for_this_check_does_not_verify(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))
    req = add_requirement(tmp_path, "Admin routes lack auth", "Desc", "authorization", "high")
    req_id = req["id"]

    fake_eval = ProbeEvaluationResult(
        verdict=ProbeVerdict.SECURE_FOR_THIS_CHECK,
        status_code=302,
        explanation="Unauthenticated request was redirected to login: '/login'.",
        safe_headers={"location": "/login"},
        body_byte_count=0,
        body_sha256="emptyhash",
        matched_indicators=(),
        ledger_outcome="PASSED",
        verification_complete=False,
    )
    monkeypatch.setattr(mcp_server, "dispatch_probe", lambda spec: fake_eval)

    result = mcp_server.probe_endpoint_security(req_id, port=8095, path="/doner", approved=True)
    assert result["status"] == "COMPLETED"
    assert result["verdict"] == "SECURE_FOR_THIS_CHECK"
    assert result["evidence_recorded"]["ledger_outcome"] == "PASSED"
    assert result["evidence_recorded"]["verification_complete"] is False

    detail = get_requirement_detail(tmp_path, req_id)
    # Crucial: Must NEVER be VERIFIED from a single endpoint check!
    assert detail["status"] != "VERIFIED"
    assert len(detail["checks"]) == 1
    assert detail["checks"][0]["result"] == "PASSED"
    assert detail["checks"][0]["verification_complete"] == 0


def test_probe_endpoint_security_inconclusive_does_not_modify_status(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))
    req = add_requirement(tmp_path, "Admin routes lack auth", "Desc", "authorization", "high")
    req_id = req["id"]

    fake_eval = ProbeEvaluationResult(
        verdict=ProbeVerdict.INCONCLUSIVE,
        status_code=500,
        explanation="Server error HTTP 500.",
        safe_headers={},
        body_byte_count=0,
        body_sha256="",
        matched_indicators=(),
        ledger_outcome="ERROR",
        verification_complete=False,
    )
    monkeypatch.setattr(mcp_server, "dispatch_probe", lambda spec: fake_eval)

    result = mcp_server.probe_endpoint_security(req_id, port=8095, path="/doner", approved=True)
    assert result["status"] == "COMPLETED"
    assert result["verdict"] == "INCONCLUSIVE"

    detail = get_requirement_detail(tmp_path, req_id)
    assert detail["status"] == "IDENTIFIED"
    assert len(detail["checks"]) == 1
    assert detail["checks"][0]["result"] == "ERROR"


def test_probe_endpoint_security_never_persists_pii_or_body(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))
    req = add_requirement(tmp_path, "Admin routes lack auth", "Desc", "authorization", "high")
    req_id = req["id"]

    fake_eval = ProbeEvaluationResult(
        verdict=ProbeVerdict.VULNERABLE,
        status_code=200,
        explanation="HTTP 200 exposed donor table.",
        safe_headers={"content-type": "text/html"},
        body_byte_count=500,
        body_sha256="sensitivehash123",
        matched_indicators=("donor",),
        ledger_outcome="FAILED",
        verification_complete=False,
    )
    monkeypatch.setattr(mcp_server, "dispatch_probe", lambda spec: fake_eval)

    mcp_server.probe_endpoint_security(req_id, port=8095, path="/doner", approved=True)

    detail = get_requirement_detail(tmp_path, req_id)
    check_raw = str(detail["checks"][0])
    events_raw = str(detail["events"])

    # Ensure no PII indicators or body fragments leaked into stored database records
    assert "password" not in check_raw.lower()
    assert "cookie" not in check_raw.lower()
    assert "token" not in check_raw.lower()
    assert "password" not in events_raw.lower()
