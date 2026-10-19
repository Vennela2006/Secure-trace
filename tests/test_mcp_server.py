
from pathlib import Path

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
