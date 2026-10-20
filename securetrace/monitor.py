
from __future__ import annotations

import sys
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .ledger import mark_changed_files


IGNORED_PARTS = {
    ".git",
    ".securetrace",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
}


def is_ignored(path: Path) -> bool:
    """Return True when a path belongs to an ignored directory."""
    return any(part in IGNORED_PARTS for part in path.parts)


class SecureTraceHandler(FileSystemEventHandler):
    """Forward relevant filesystem changes to the SecureTrace ledger."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def on_any_event(self, event) -> None:
        if event.is_directory:
            return

        if event.event_type not in {
            "created",
            "modified",
            "deleted",
            "moved",
        }:
            return

        paths = [Path(event.src_path)]

        destination = getattr(event, "dest_path", None)
        if destination:
            paths.append(Path(destination))

        relative_paths: list[str] = []

        for path in paths:
            try:
                resolved = path.resolve()

                if is_ignored(resolved):
                    continue

                relative = resolved.relative_to(self.root)
                relative_paths.append(relative.as_posix())

            except (ValueError, OSError, RuntimeError):
                # Ignore paths outside the project and resolution failures.
                continue

        # A rename may provide both source and destination paths.
        relative_paths = list(dict.fromkeys(relative_paths))

        if not relative_paths:
            return

        try:
            affected = mark_changed_files(
                self.root,
                relative_paths,
            )
        except Exception as exc:
            # Never write watcher diagnostics to MCP stdout.
            print(
                f"[SecureTrace] Change processing failed: {exc}",
                file=sys.stderr,
                flush=True,
            )
            return

        for item in affected:
            print(
                "[SecureTrace] Linked requirement affected: "
                f"{item['requirement_id']} "
                f"(changed: {', '.join(item['changed_files'])})",
                file=sys.stderr,
                flush=True,
            )


def start_watcher(root: Path) -> Observer:
    """Start a non-blocking recursive filesystem observer."""
    root = root.resolve()

    if not root.is_dir():
        raise NotADirectoryError(
            f"SecureTrace project root is not a directory: {root}"
        )

    observer = Observer()
    observer.schedule(
        SecureTraceHandler(root),
        str(root),
        recursive=True,
    )

    try:
        observer.start()
    except Exception:
        observer.stop()
        observer.join()
        raise

    print(
        f"[SecureTrace] Watching project: {root}",
        file=sys.stderr,
        flush=True,
    )

    return observer


def stop_watcher(observer: Observer) -> None:
    """Stop the observer and wait for its thread to finish."""
    observer.stop()
    observer.join()


def watch(root: Path) -> None:
    """Run the standalone watcher until interrupted."""
    observer = start_watcher(root)

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print(
            "[SecureTrace] Stopping watcher.",
            file=sys.stderr,
            flush=True,
        )

    finally:
        stop_watcher(observer)
