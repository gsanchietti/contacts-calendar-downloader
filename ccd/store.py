"""Local, per-user file store for OAuth account records.

Every linked account is a single JSON file under the config directory. Files
are written atomically and are never world- or group-readable: they hold a
refresh token that is equivalent to a password for the user's contacts and
calendar data.
"""
import os
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional


def config_root() -> Path:
    """Return the directory holding all ccd state, creating it if needed."""
    override = os.environ.get("CCD_CONFIG_DIR")
    if override:
        root = Path(override)
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        if xdg:
            root = Path(xdg) / "contacts-calendar-downloader"
        elif sys.platform == "win32" and os.environ.get("APPDATA"):
            root = Path(os.environ["APPDATA"]) / "contacts-calendar-downloader"
        else:
            root = Path.home() / ".config" / "contacts-calendar-downloader"

    if not root.exists():
        root.mkdir(parents=True, mode=0o700)
    return root


def accounts_dir() -> Path:
    """Return the directory holding one JSON file per linked account."""
    path = config_root() / "accounts"
    if not path.exists():
        path.mkdir(parents=True, mode=0o700)
    return path


def account_path(provider: str, email: str) -> Path:
    """Return the path a given (provider, email) account is stored at."""
    filename = f"{provider}_{urllib.parse.quote(email, safe='')}.json"
    return accounts_dir() / filename


def save(record: Dict[str, Any]) -> Path:
    """Persist an account record atomically, with 0600 permissions.

    Writes to a temp file in the same directory (so the final ``os.replace``
    is an atomic rename on the same filesystem) using ``os.open`` with
    ``O_EXCL`` so the file is created with the right mode from the start --
    never ``open()`` followed by a separate ``chmod()``, which would leave a
    brief window where the file has default (world-readable) permissions.
    """
    import json

    provider = record["provider"]
    email = record["email"]
    target = account_path(provider, email)
    directory = target.parent

    tmp_name = f".{target.name}.{os.getpid()}.{int(time.time() * 1000)}.tmp"
    tmp_path = directory / tmp_name

    fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(record, fh, indent=2)
            fh.write("\n")
        os.replace(str(tmp_path), str(target))
    except BaseException:
        try:
            os.unlink(str(tmp_path))
        except OSError:
            pass
        raise
    return target


def load(provider: str, email: str) -> Optional[Dict[str, Any]]:
    """Load a single account record, or None if it doesn't exist / is bad."""
    import json

    path = account_path(provider, email)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        print(f"warning: could not read {path}: {exc}", file=sys.stderr)
        return None


def list_accounts() -> List[Dict[str, Any]]:
    """Return every readable account record, sorted by (provider, email)."""
    import json

    records: List[Dict[str, Any]] = []
    directory = accounts_dir()
    for path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            print(f"warning: skipping unreadable account file {path}: {exc}", file=sys.stderr)
            continue
        if not isinstance(data, dict) or "provider" not in data or "email" not in data:
            print(f"warning: skipping malformed account file {path}", file=sys.stderr)
            continue
        records.append(data)

    records.sort(key=lambda r: (r.get("provider", ""), r.get("email", "")))
    return records


def find(email: Optional[str] = None, provider: Optional[str] = None) -> List[Dict[str, Any]]:
    """Filter linked accounts by email and/or provider."""
    results = list_accounts()
    if email is not None:
        results = [r for r in results if r.get("email") == email]
    if provider is not None:
        results = [r for r in results if r.get("provider") == provider]
    return results


def delete(provider: str, email: str) -> bool:
    """Remove a stored account record. Returns True if a file was removed."""
    path = account_path(provider, email)
    if not path.exists():
        return False
    path.unlink()
    return True


def get_access_token(record: Dict[str, Any]) -> str:
    """Return a valid access token for the record, refreshing if needed.

    Refreshes proactively (2 minutes before expiry) rather than waiting for
    the provider to reject an expired token.
    """
    from .errors import AuthExpiredError

    if time.time() < record.get("expires_at", 0) - 120:
        return record["access_token"]

    provider = record["provider"]
    # Imported here, not at module scope, to avoid a circular import: the
    # auth_* modules import store.config_root() (via client_config) at
    # module load time.
    if provider == "google":
        from . import auth_google

        refreshed = auth_google.refresh(record)
    elif provider == "microsoft":
        from . import auth_microsoft

        refreshed = auth_microsoft.refresh(record)
    else:
        raise AuthExpiredError(f"Unknown provider '{provider}'; run 'ccd login' again.")

    save(refreshed)
    return refreshed["access_token"]
