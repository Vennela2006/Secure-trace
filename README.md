# SecureTrace

**Continuous Security Assurance for AI-Built Applications**

SecureTrace is a local-first prototype that maintains a persistent, feature-aware security ledger. It records security requirements, links them to relevant source files, stores verification evidence, marks evidence stale when linked files change, and generates a living Markdown report. An MCP server exposes the ledger to Gemini CLI.

> Prototype boundary: SecureTrace does not prove an entire application is secure. A `VERIFIED` status means the explicitly recorded verification completed successfully for the recorded revision. It is not a general security guarantee.

## Initial scope

- Local SQLite ledger
- Security requirements linked to files
- Verification result history
- Change-triggered stale evidence for linked files
- Markdown report
- MCP tools for Gemini CLI
- Local file watcher
- Tests for the ledger's core behavior

## Requirements

- Python 3.11+
- `uv` recommended for environment/dependency management
- Gemini CLI for agent integration (optional for standalone CLI use)

## Quick start

From this directory:

```bash
uv sync --extra dev
uv run securetrace init
uv run securetrace add-requirement \
  --title "Customers can cancel only their own appointments" \
  --description "The server must verify that the authenticated user owns the appointment." \
  --category authorization \
  --severity high \
  --file src/routes/appointments.py
uv run securetrace list
uv run securetrace report
uv run pytest
```

The database is created at `.securetrace/securetrace.db` under the project root. By default the root is the current working directory. You can override it with `SECURETRACE_PROJECT_ROOT`.

## Record a verification result

```bash
uv run securetrace record-check \
  --requirement SEC-XXXXXXXX \
  --name "appointment-owner-authorization" \
  --passed \
  --complete
```

Use `--complete` only when the check represents the full verification required for that requirement. Without it, a passing check is recorded as evidence but does not mark the requirement `VERIFIED`.

## Execute one approved local test

`run-test` executes exactly one named pytest function from `tests/` or
`examples/<sample>/tests/`. The command is fixed to the current Python
interpreter running pytest; it does not accept arbitrary shell commands, Python
snippets, or pytest arguments. The requirement ID and test function supplied on
each invocation form the explicit test-to-requirement mapping. `--complete`
must be supplied separately when that test fully verifies the requirement.

Run the included authorization demo in its own project root (PowerShell):

```powershell
Set-Location examples/authorization_demo
$env:SECURETRACE_PROJECT_ROOT = (Get-Location).Path
$env:PYTHONPATH = (Resolve-Path ../..).Path
$python = Resolve-Path ..\..\.venv\Scripts\python.exe
& $python -m securetrace.cli init
$created = & $python -m securetrace.cli add-requirement `
  --title "Only appointment owners can cancel" `
  --description "A different user must not cancel an appointment." `
  --category authorization --severity high --file app.py
$requirementId = [regex]::Match(($created -join "`n"), 'Created (SEC-[A-F0-9]+)').Groups[1].Value
& $python -m securetrace.cli run-test --approve `
  --requirement $requirementId --test-file tests/test_authorization.py `
  --test-id test_other_user_cannot_cancel_appointment --complete
& $python -m securetrace.cli run-test --approve `
  --requirement $requirementId --test-file tests/test_vulnerable_authorization.py `
  --test-id test_other_user_cannot_cancel_appointment_on_vulnerable_control
& $python -m securetrace.cli report
```

The first test executes the owner-only control and should pass. The second
executes the same denial assertion against an intentionally vulnerable legacy
implementation and should produce a real assertion failure and `REGRESSION`.
The demo database is under `examples/authorization_demo/.securetrace/`.

Test output is captured, redacted for common credential formats, limited to
16 KiB, and saved as a referenced evidence text file. The runner records the
test ID, file, timestamps, duration, exit code, outcome, and evidence path in
the existing check history. Timeouts, collection/runtime errors, and output
storage errors cannot mark a requirement verified; only an assertion failure
marks a regression. Manual `record-check` and dashboard evidence remains
available and is labeled separately from an automatically executed test.

Before launch, SecureTrace validates the requirement against the ledger and
rejects unknown IDs. The child process receives a small OS/runtime environment
allowlist; inherited `PYTEST_ADDOPTS`, `PYTEST_PLUGINS`, `PYTHONPATH`, and
other pytest/Python override variables are removed. Pytest uses a temporary
empty config and an explicit root directory. A `conftest.py` directly in the
approved test file's directory is intentionally allowed and executes as part
of that approved test scope; parent conftests and project pytest addopts are
excluded. On timeout, POSIX process groups are terminated and Windows child
processes are enumerated and terminated with bounded waits. The runner checks
the test file's identity and hash before and after execution and invalidates a
result if it changed.

If the evidence file cannot be written, SecureTrace records an `ERROR` outcome
without claiming evidence was persisted. If the ledger write fails after an
evidence file is saved, the CLI exits with an error and identifies the orphan
evidence path for manual cleanup; it does not claim the result was recorded.

These path and process checks reduce common mistakes and races, but do not
make test code safe. A same-user process can still change and restore a test
file between the runner's hash checks, and approved code runs with the current
user's full permissions. Process-tree termination also depends on OS process
controls; metadata reports when cleanup could not be verified.

This is not a security sandbox. Approved test code executes as the current
user and has that user's filesystem, network, and process permissions. Use a
controlled local test target, never production. Test execution is not exposed
through MCP or the dashboard chat interface.

For a failure:

```bash
uv run securetrace record-check \
  --requirement SEC-XXXXXXXX \
  --name "appointment-owner-authorization" \
  --details "A user could cancel an appointment owned by another user."
```

A failing check marks the requirement `REGRESSION`.

## Watch linked files

Run in a separate terminal from the target repository:

```bash
uv run securetrace watch
```

When a linked file changes, SecureTrace marks the linked requirement `STALE` and records an event. This first version watches file events; it does not yet run scanners automatically. That is a later milestone.

## Gemini CLI MCP integration

Gemini CLI supports local MCP servers configured in `settings.json`. See the official guide:
https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md

1. Install SecureTrace in its own directory:

   ```bash
   cd /absolute/path/to/securetrace
   uv sync
   ```

2. In the application repository you want Gemini to work on, create `.gemini/settings.json` (merge with any existing settings; do not overwrite existing configuration).

3. Add an MCP server entry, replacing `/ABSOLUTE/PATH/TO/SECURETRACE` with the absolute path to this SecureTrace checkout:

   ```json
   {
     "mcpServers": {
       "securetrace": {
         "command": "uv",
         "args": [
           "run",
           "--project",
           "/ABSOLUTE/PATH/TO/SECURETRACE",
           "securetrace-mcp"
         ],
         "cwd": ".",
         "trust": false
       }
     }
   }
   ```

4. Launch or restart Gemini CLI from the application repository and inspect `/mcp` to confirm the server and tools are available.

5. Try asking Gemini to use SecureTrace to list security requirements or record a requirement for a feature.

The MCP server uses the working directory as the target repository root unless `SECURETRACE_PROJECT_ROOT` is set. Keep `trust` false initially so Gemini CLI does not bypass tool confirmations.

## Current MCP tools

- `list_security_requirements`
- `add_security_requirement`
- `record_security_check`
- `mark_changed_files`
- `get_security_report`

These tools update local project metadata. The current starter does not execute arbitrary shell commands through MCP.

## Project structure

```text
securetrace/
├── pyproject.toml
├── README.md
├── GEMINI.md
├── .gitignore
├── securetrace/
│   ├── __init__.py
│   ├── config.py
│   ├── db.py
│   ├── ledger.py
│   ├── reporting.py
│   ├── monitor.py
│   ├── cli.py
│   └── mcp_server.py
└── tests/
    ├── test_ledger.py
    └── test_reporting.py
```

## Planned milestones

1. Foundation and ledger (this starter)
2. Gemini CLI MCP integration
3. Change-impact analysis and event monitoring
4. Semgrep local scanner evidence provider (first scanner integration)
5. Secret scanning and dependency scanner adapters (future work)
6. Security regression test orchestration
7. Evidence freshness and security-fix integrity
8. Evaluation against conventional scanning workflows

## Safety and correctness notes

- Run checks against a local, controlled development repository first.
- Never send secrets or full source files to a remote model unnecessarily.
- Do not mark a requirement verified just because an agent claims a fix is complete.
- A source file change only marks linked evidence stale; it does not prove a vulnerability exists.
- Human approval should be required before accepting a risk or applying automated fixes.

## Requirement-to-test mapping and change impact

Existing requirement-to-file links are the source of truth for code impact. Approved pytest targets are stored separately per requirement. To upgrade an existing ledger, run `securetrace migrate` explicitly; this additive migration creates `requirement_tests` and keeps existing requirements, checks, and events intact. No normal read or run command silently applies this migration. Until it is applied, reports explain that mapped rerun eligibility is unknown.

Map a target with `securetrace map-test --requirement SEC-XXXXXXXX --test-file tests/test_access.py --test-id test_owner_access [--complete]`. Mapping validates the path with the same allowlist as the runner. Once the mapping schema exists, `run-test --approve` accepts only a target mapped to that requirement and revalidates every mapping before launch.

Use `securetrace impact src/changed.py` to get an impact proposal without changing evidence or executing tests. `securetrace plan` shows the current deterministic verification plan. `securetrace mark-changed src/changed.py` records linked changes and marks evidence stale only when content fingerprints differ; if a source is missing or unreadable, freshness is UNKNOWN and the requirement remains scheduled conservatively. The report retains prior check history and shows each mapped check's reason, freshness, and blockers. A user must explicitly approve each `run-test`; file changes never launch tests automatically. If there is no approved mapping, rerun eligibility is reported as uncertain.

Every newly executed mapped test stores SHA-256 fingerprints for its linked requirement files and the approved test file, before and after execution. All mapped working-tree files are included whether or not Git tracks them. Identical content remains current even if timestamps change. Added or modified linked content makes the prior fingerprint STALE; deleted, unreadable, invalid, or unstable files yield UNKNOWN. Historical and manual records are not rewritten. Legacy automated evidence has no source fingerprint and is therefore UNKNOWN until a new approved run records one. This is stored in the existing checks metadata JSON; no additional database migration is required.

`securetrace orchestrate` consumes the deterministic plan. Without `--approve`, it records a plan event and does not execute tests or append check history. With `--approve`, it revalidates the requirement mapping, target path, and source fingerprint before each selected run, then uses the hardened pytest runner. A complete first run is allowed to establish a baseline when no prior automated result exists and the current source fingerprint is reliable. Legacy evidence with unknown freshness and any missing/unreadable source is blocked. Duplicate requirement/test pairs are suppressed within a run unless `--allow-duplicates` is passed. Watcher and MCP paths remain non-executing.

Dependency coverage is reported as `INCOMPLETE`: SecureTrace fingerprints only explicitly linked requirement files and the approved test file; it does not infer transitive imports or runtime dependencies. A `CURRENT` result therefore describes those recorded files, not the whole dependency graph.

## Semgrep local scanner evidence

SecureTrace supports Semgrep Community Edition through the `semgrep` CLI. Semgrep is an optional external executable and is not installed by SecureTrace. The integration uses one fixed command shape with a local YAML ruleset:

```text
semgrep scan --json --metrics=off --config <validated-project-rules.yml> --exclude .securetrace --exclude .git <validated-project-root>
```

The ruleset must be a YAML file inside the configured project root, at most 1 MiB, and cannot use Semgrep `extends` or remote/inherited rulesets. SecureTrace resolves and hashes it before execution, passes an argv list with `shell=False`, and always supplies the configured root as the only scan target. It excludes SecureTrace evidence and Git metadata. An out-of-root symlink blocks the scan. Captured output is bounded and sanitized; structured finding messages are retained without source snippets. Semgrep execution is a subprocess, not a security sandbox, and runs with the current user's permissions.

Install Semgrep separately if desired. Semgrep documents `pipx install semgrep` or `uv tool install semgrep`; on Windows its Community Edition page also documents `python3 -m pip install semgrep`. SecureTrace does not install or update it. See [Semgrep local CLI scans](https://semgrep.dev/docs/category/local-and-cli-scans) and [Semgrep Community Edition installation](https://semgrep.dev/products/community-edition/).

Run `securetrace semgrep --config rules/semgrep.yml` to inspect a plan. This does not execute Semgrep or write scanner evidence. After reviewing the local target and ruleset, run `securetrace semgrep --config rules/semgrep.yml --approve` to execute. The command records scanner version, ruleset SHA-256, start/end times, duration, exit code, status, and sanitized findings in the existing `events` table. No database migration is needed. Findings map only to requirements with an exact existing requirement-to-file link; other findings are shown as unmapped.

Semgrep outcomes (`CLEAN`, `FINDINGS`, `ERROR`, `TIMEOUT`, and `INCOMPLETE`) remain separate from manual evidence and pytest outcomes. `CLEAN` never marks a requirement `VERIFIED`. The Markdown report and dashboard report view show recent scanner records and unmapped findings. MCP tools and dashboard chat do not expose scanner execution, and file watchers do not run scans.

The Semgrep executable was unavailable in this development environment, so a real scan has not been verified here. Mocked integration tests cover structured results and failure states. To run the later local authorization-demo scan in PowerShell after installing Semgrep yourself:

```powershell
$repo = (Get-Location).Path
$env:SECURETRACE_PROJECT_ROOT = Join-Path $repo 'examples\authorization_demo'
$python = Join-Path $repo '.venv\Scripts\python.exe'
& $python -m securetrace.cli semgrep --config semgrep.yml
& $python -m securetrace.cli semgrep --config semgrep.yml --approve
& $python -m securetrace.cli report
```

This sample ruleset is deliberately narrow and only demonstrates a local custom rule; it is not a comprehensive authorization ruleset. Scanner coverage, ignored target behavior, dependencies, and transitive runtime inputs are not inferred as complete.
