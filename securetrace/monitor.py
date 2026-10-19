from __future__ import annotations

import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .ledger import mark_changed_files

IGNORED_PARTS = {".git", ".securetrace", ".venv", "__pycache__", ".pytest_cache", "node_modules"}


def is_ignored(path: Path) -> bool:
    return any(part in IGNORED_PARTS for part in path.parts)


class SecureTraceHandler(FileSystemEventHandler):
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def on_any_event(self, event) -> None:
        if event.is_directory or event.event_type not in {"created", "modified", "deleted", "moved"}:
            return
        paths = [Path(event.src_path)]
        if getattr(event, "dest_path", None):
            paths.append(Path(event.dest_path))

        relative_paths = []
        for path in paths:
            try:
                resolved = path.resolve()
                if is_ignored(resolved):
                    continue
                relative_paths.append(resolved.relative_to(self.root).as_posix())
            except (ValueError, OSError):
                continue

        affected = mark_changed_files(self.root, relative_paths)
        if affected:
            for item in affected:
                print(
                    f"[SecureTrace] Evidence stale candidate: {item['requirement_id']} "
                    f"(changed: {', '.join(item['changed_files'])})"
                )


def watch(root: Path) -> None:
    root = root.resolve()
    observer = Observer()
    observer.schedule(SecureTraceHandler(root), str(root), recursive=True)
    observer.start()
    print(f"[SecureTrace] Watching {root}. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[SecureTrace] Stopping watcher.")
    finally:
        observer.stop()
        observer.join()
