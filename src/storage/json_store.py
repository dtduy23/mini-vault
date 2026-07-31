"""
Thread-safe JSON file storage for Mini Vault.

Each logical record is stored as a separate .json file under base_dir.
A per-file threading.Lock ensures only one thread writes at a time.
Writes use a tmp-file + os.replace() for atomicity on POSIX.
"""
import json
import os
import threading
from pathlib import Path

# Registry of per-file locks; protected by a global meta-lock.
_file_locks: dict[str, threading.Lock] = {}
_registry_lock = threading.Lock()


def _get_lock(path: Path) -> threading.Lock:
    key = str(path.resolve())
    with _registry_lock:
        if key not in _file_locks:
            _file_locks[key] = threading.Lock()
        return _file_locks[key]


class JsonStore:
    """
    Simple flat-file store.

    Usage:
        store = JsonStore("data/users")
        store.put("alice@example.com", data={"hash": "..."})
        record = store.get("alice@example.com")   # returns dict or None
        store.delete("alice@example.com")
        names = store.list_keys()                 # ["alice@example.com", ...]

    Key parts are joined as path components, and the last part gets
    a .json suffix automatically.  Example with sub-directories:
        store.put("alice@example.com", "db", data={...})
        # → data/users/alice@example.com/db.json
    """

    def __init__(self, base_dir: str | Path) -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _resolve(self, *key_parts: str) -> Path:
        """Resolve key parts to an absolute .json file path."""
        path = self.base_dir
        for part in key_parts[:-1]:
            path = path / part
        return (path / key_parts[-1]).with_suffix(".json")

    def get(self, *key_parts: str) -> dict | None:
        p = self._resolve(*key_parts)
        with _get_lock(p):
            if not p.exists():
                return None
            return json.loads(p.read_text(encoding="utf-8"))

    def put(self, *key_parts: str, data: dict) -> None:
        p = self._resolve(*key_parts)
        with _get_lock(p):
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            os.replace(tmp, p)          # atomic on POSIX

    def delete(self, *key_parts: str) -> bool:
        p = self._resolve(*key_parts)
        with _get_lock(p):
            if not p.exists():
                return False
            p.unlink()
            return True

    def exists(self, *key_parts: str) -> bool:
        return self._resolve(*key_parts).exists()

    def list_keys(self, *dir_parts: str) -> list[str]:
        """Return stems (filenames without .json) in a sub-directory."""
        d = self.base_dir.joinpath(*dir_parts) if dir_parts else self.base_dir
        if not d.is_dir():
            return []
        return sorted(p.stem for p in d.iterdir() if p.suffix == ".json")

    def list_dirs(self, *dir_parts: str) -> list[str]:
        """Return immediate sub-directory names."""
        d = self.base_dir.joinpath(*dir_parts) if dir_parts else self.base_dir
        if not d.is_dir():
            return []
        return sorted(p.name for p in d.iterdir() if p.is_dir())
