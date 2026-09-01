"""Command-line client for the ccd service.

Every command except ``serve`` is a thin wrapper over the HTTP API: the CLI
holds no tokens, reads no account files and talks to no provider. That is
deliberate -- it means the commands exercise exactly the endpoints other
applications use, so anything that works here works for them.

Only ``serve`` pulls in the provider SDKs, which is why the imports for it
live inside the function: ``ccd list`` must keep working on a machine where
google-api-python-client and msal were never installed.
"""
import argparse
import json
import os
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional

from .errors import CcdError, NoAccountsError, from_wire

PROVIDERS = ("google", "microsoft")
DEFAULT_URL = "http://127.0.0.1:8080"
POLL_INTERVAL = 2.0


# --------------------------------------------------------------------------- #
# HTTP plumbing
# --------------------------------------------------------------------------- #

def _base(args: argparse.Namespace) -> str:
    return (args.url or os.environ.get("CCD_URL") or DEFAULT_URL).rstrip("/")


def _headers(args: argparse.Namespace) -> Dict[str, str]:
    key = args.api_key or os.environ.get("CCD_API_KEY", "")
    return {"Authorization": f"Bearer {key}"} if key else {}


def _api(args: argparse.Namespace, method: str, path: str, **kwargs: Any) -> Any:
    """Call the service and return the decoded body, or raise a CcdError.

    Server-side failures come back as ``{"error": ..., "code": ...}``; the
    code names the exception class the service raised, so re-raising it here
    keeps the process exit codes identical to what the pre-service CLI
    returned for the same conditions.
    """
    import requests

    url = _base(args) + path
    try:
        resp = requests.request(method, url, headers=_headers(args), timeout=60, **kwargs)
    except requests.RequestException as exc:
        raise CcdError(
            f"Could not reach the ccd service at {_base(args)}: {exc}\n"
            "Start it with 'ccd serve', or point --url / CCD_URL at it."
        ) from exc

    if resp.status_code == 401:
        raise CcdError(
            "The service rejected the API key. Set CCD_API_KEY or pass --api-key; "
            "the key is printed on first start and stored in 'api_key' in the config directory."
        )
    if resp.status_code >= 400:
        try:
            payload = resp.json()
        except ValueError:
            raise CcdError(f"{method} {path} failed with HTTP {resp.status_code}: {resp.text[:200]}")
        raise from_wire(payload.get("code", "error"), payload.get("error", "request failed"))

    if not resp.content:
        return None
    return resp.json()


# --------------------------------------------------------------------------- #
# Account selection
# --------------------------------------------------------------------------- #

def _resolve_accounts(args: argparse.Namespace, allow_all: bool) -> List[Dict[str, Any]]:
    provider = getattr(args, "provider", None)
    account_email = getattr(args, "account", None)
    want_all = allow_all and getattr(args, "all_accounts", False)

    candidates = _api(args, "GET", "/api/accounts")
    if provider:
        candidates = [a for a in candidates if a["provider"] == provider]

    if want_all:
        if not candidates:
            raise NoAccountsError(_no_accounts_message())
        return candidates

    if account_email:
        matches = [a for a in candidates if a["email"] == account_email]
        if not matches:
            raise NoAccountsError(f"No linked account for '{account_email}'." + _linked_hint(args))
        if len(matches) > 1:
            providers = ", ".join(m["provider"] for m in matches)
            raise NoAccountsError(
                f"'{account_email}' is linked on multiple providers ({providers}); "
                "pass --provider too to disambiguate."
            )
        return matches

    if len(candidates) == 1:
        return candidates
    if not candidates:
        raise NoAccountsError(_no_accounts_message())

    listing = "\n".join(f"  {a['provider']}: {a['email']}" for a in candidates)
    raise NoAccountsError(
        "Multiple accounts are linked; pass --account EMAIL"
        + (" or --all" if allow_all else "")
        + f".\nLinked accounts:\n{listing}"
    )


def _no_accounts_message() -> str:
    return "No accounts are linked. Run 'ccd login --provider google' or 'ccd login --provider microsoft' first."


def _linked_hint(args: argparse.Namespace) -> str:
    accounts = _api(args, "GET", "/api/accounts")
    if not accounts:
        return " " + _no_accounts_message()
    listing = ", ".join(f"{a['provider']}:{a['email']}" for a in accounts)
    return f" Linked accounts: {listing}"


def _account_path(account: Dict[str, Any]) -> str:
    return "/api/accounts/{0}/{1}".format(
        account["provider"], urllib.parse.quote(account["email"], safe="")
    )


# --------------------------------------------------------------------------- #
# serve
# --------------------------------------------------------------------------- #

def cmd_serve(args: argparse.Namespace) -> int:
    from . import server

    return server.serve(args.listen or "")


# --------------------------------------------------------------------------- #
# login
# --------------------------------------------------------------------------- #

def cmd_login(args: argparse.Namespace) -> int:
    started = _api(args, "POST", "/api/login", json={"provider": args.provider})

    if started["kind"] == "redirect":
        print("Open this URL in a browser and sign in / grant access:\n")
        print("  {0}\n".format(started["authorization_url"]))
        print("Waiting for you to finish...", flush=True)
    else:
        print(started.get("message") or
              "Visit {0} and enter the code {1}".format(
                  started.get("verification_uri"), started.get("user_code")), flush=True)

    deadline = time.time() + int(started.get("expires_in") or 900)
    while time.time() < deadline:
        time.sleep(POLL_INTERVAL)
        state = _api(args, "GET", "/api/login/{0}".format(started["login_id"]))
        if state["status"] == "done":
            account = state["account"]
            print("\nLinked {0} account: {1}".format(account["provider"], account["email"]))
            _print_urls(account)
            return 0
        if state["status"] == "error":
            raise CcdError(state["error"])

    raise CcdError("Timed out waiting for the login to complete.")


def _print_urls(account: Dict[str, Any]) -> None:
    print("\nDownload URLs (secret -- anyone holding one can read this account's data):")
    for label, url in account["download"].items():
        print("  {0:<14} {1}".format(label, url))


# --------------------------------------------------------------------------- #
# list / status / urls
# --------------------------------------------------------------------------- #

def cmd_list(args: argparse.Namespace) -> int:
    accounts = _api(args, "GET", "/api/accounts")

    if args.json_output:
        print(json.dumps(accounts, indent=2))
        return 0

    if not accounts:
        print(_no_accounts_message())
        return 0

    for account in accounts:
        status = "expired" if account["expired"] else f"expires in {account['expires_in']}s"
        print(f"{account['provider']:<10} {account['email']:<32} {status}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    accounts = _resolve_accounts(args, allow_all=False)

    results = [_api(args, "GET", _account_path(a) + "/status") for a in accounts]

    if args.json_output:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            expiry = "expired" if r["expired"] else f"expires in {r['expires_in']}s"
            check = "ok" if r["live_check"] == "ok" else f"FAILED ({r['error']})"
            print(f"{r['provider']:<10} {r['email']:<32} {expiry:<20} live-check: {check}")

    if all(r["live_check"] == "ok" for r in results):
        return 0
    from .errors import AuthExpiredError

    return AuthExpiredError.exit_code if any(r["auth_expired"] for r in results) else 1


def cmd_urls(args: argparse.Namespace) -> int:
    accounts = _resolve_accounts(args, allow_all=True)

    if args.json_output:
        print(json.dumps({a["email"]: a["download"] for a in accounts}, indent=2))
        return 0

    for account in accounts:
        print("{0}: {1}".format(account["provider"], account["email"]))
        for label, url in account["download"].items():
            print("  {0:<14} {1}".format(label, url))
    return 0


def cmd_rotate(args: argparse.Namespace) -> int:
    accounts = _resolve_accounts(args, allow_all=True)
    for account in accounts:
        updated = _api(args, "POST", _account_path(account) + "/rotate-token")
        print("Rotated download token for {0}: {1}".format(updated["provider"], updated["email"]))
        _print_urls(updated)
    return 0


# --------------------------------------------------------------------------- #
# download
# --------------------------------------------------------------------------- #

def _artifact_name(dl_type: str, fmt: str) -> str:
    return "calendar.ics" if dl_type == "calendar" else f"contacts.{fmt}"


def _fetch(args: argparse.Namespace, account: Dict[str, Any], artifact: str) -> str:
    """Fetch one artifact from the account's published download URL.

    The published URL is built from the service's ``CCD_BASE_URL``, which in
    production is the externally visible address -- possibly one this machine
    cannot resolve. When it is unreachable, fall back to the same path on
    ``--url``, which is where we are already talking to the service.
    """
    import requests

    key = {"contacts.csv": "contacts_csv",
           "contacts.json": "contacts_json",
           "calendar.ics": "calendar_ics"}[artifact]
    url = account["download"][key]

    for candidate in (url, _rebase(args, url)):
        if candidate is None:
            continue
        try:
            resp = requests.get(candidate, timeout=300)
        except requests.RequestException:
            continue
        if resp.status_code == 404:
            raise NoAccountsError(f"The service returned 404 for {artifact}; the download token may have been rotated.")
        if resp.status_code >= 400:
            try:
                payload = resp.json()
            except ValueError:
                raise CcdError(f"Download failed with HTTP {resp.status_code}.")
            raise from_wire(payload.get("code", "error"), payload.get("error", "download failed"))
        resp.encoding = "utf-8"
        return resp.text

    raise CcdError(f"Could not reach any download URL for {account['email']}.")


def _rebase(args: argparse.Namespace, url: str) -> Optional[str]:
    """Rewrite a published download URL onto the --url the CLI is using."""
    path = urllib.parse.urlparse(url).path
    marker = path.find("/d/")
    if marker < 0:
        return None
    candidate = _base(args) + path[marker:]
    return candidate if candidate != url else None


def cmd_download(args: argparse.Namespace) -> int:
    if args.type == "calendar":
        if args.format not in (None, "ics"):
            raise CcdError("Calendar export is always .ics; --format is not valid with --type calendar.")
        fmt = "ics"
    else:
        fmt = args.format or "csv"
        if fmt not in ("csv", "json"):
            raise CcdError(f"--format '{fmt}' is not valid with --type contacts (use csv or json).")

    accounts = _resolve_accounts(args, allow_all=True)

    output = args.output
    out_dir: Optional[Path] = None
    if output and output != "-":
        out_path = Path(output)
        if out_path.is_dir():
            out_dir = out_path
        elif len(accounts) > 1:
            raise CcdError(
                f"--output must be an existing directory when downloading multiple accounts: {output}"
            )

    if output == "-" and len(accounts) > 1:
        raise CcdError("Cannot write multiple accounts to stdout; use --output DIR or select a single --account.")

    artifact = _artifact_name(args.type, fmt)

    for account in accounts:
        email = account["email"]
        content = _fetch(args, account, artifact)

        if output == "-":
            sys.stdout.write(content)
            continue

        default_name = (
            f"calendar_{email}.ics" if args.type == "calendar" else f"contacts_{email}.{fmt}"
        )
        if out_dir is not None:
            dest = out_dir / default_name
        elif output:
            dest = Path(output)
        else:
            dest = Path.cwd() / default_name

        dest.write_text(content, encoding="utf-8")
        print(f"Wrote {dest}")

    return 0


# --------------------------------------------------------------------------- #
# logout
# --------------------------------------------------------------------------- #

def cmd_logout(args: argparse.Namespace) -> int:
    accounts = _resolve_accounts(args, allow_all=True)

    if not args.yes:
        listing = "\n".join(f"  {a['provider']}: {a['email']}" for a in accounts)
        answer = input(f"This will remove stored credentials for:\n{listing}\nContinue? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Aborted.")
            return 0

    for account in accounts:
        path = _account_path(account)
        if args.revoke:
            path += "?revoke=true"
        result = _api(args, "DELETE", path)
        print("{0}:{1} -- {2}".format(account["provider"], account["email"], result["note"]))

    return 0


# --------------------------------------------------------------------------- #
# argument parsing / entry point
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ccd",
        description="Client for the ccd service: link Google/Microsoft accounts and "
                    "download their contacts and calendar.",
    )
    parser.add_argument("--url", help=f"Base URL of the ccd service (env CCD_URL, default {DEFAULT_URL})")
    parser.add_argument("--api-key", help="API key for /api endpoints (env CCD_API_KEY)")
    sub = parser.add_subparsers(dest="command", required=True)

    serve_p = sub.add_parser("serve", help="Run the ccd HTTP service")
    serve_p.add_argument("--listen", help="HOST:PORT to bind (env CCD_LISTEN, default 127.0.0.1:8080)")
    serve_p.set_defaults(func=cmd_serve)

    login_p = sub.add_parser("login", help="Link a Google or Microsoft account")
    login_p.add_argument("--provider", required=True, choices=PROVIDERS)
    login_p.set_defaults(func=cmd_login)

    list_p = sub.add_parser("list", help="List linked accounts")
    list_p.add_argument("--json", dest="json_output", action="store_true")
    list_p.set_defaults(func=cmd_list)

    status_p = sub.add_parser("status", help="Show token expiry and do a live provider check")
    status_p.add_argument("--account", help="Email of the linked account to check")
    status_p.add_argument("--provider", choices=PROVIDERS)
    status_p.add_argument("--json", dest="json_output", action="store_true")
    status_p.set_defaults(func=cmd_status)

    urls_p = sub.add_parser("urls", help="Show an account's secret download URLs")
    urls_sel = urls_p.add_mutually_exclusive_group()
    urls_sel.add_argument("--account", help="Email of the linked account")
    urls_sel.add_argument("--all", dest="all_accounts", action="store_true")
    urls_p.add_argument("--provider", choices=PROVIDERS)
    urls_p.add_argument("--json", dest="json_output", action="store_true")
    urls_p.set_defaults(func=cmd_urls)

    rotate_p = sub.add_parser("rotate-token", help="Issue new download URLs, invalidating the old ones")
    rotate_sel = rotate_p.add_mutually_exclusive_group()
    rotate_sel.add_argument("--account", help="Email of the linked account")
    rotate_sel.add_argument("--all", dest="all_accounts", action="store_true")
    rotate_p.add_argument("--provider", choices=PROVIDERS)
    rotate_p.set_defaults(func=cmd_rotate)

    dl_p = sub.add_parser("download", help="Download contacts or calendar")
    dl_p.add_argument("--type", required=True, choices=["contacts", "calendar"])
    dl_p.add_argument("--format", choices=["csv", "json", "ics"])
    dl_sel = dl_p.add_mutually_exclusive_group()
    dl_sel.add_argument("--account", help="Email of the linked account to use")
    dl_sel.add_argument("--all", dest="all_accounts", action="store_true", help="Download for every linked account")
    dl_p.add_argument("--provider", choices=PROVIDERS)
    dl_p.add_argument("--output", help="File path, directory (with --all), or '-' for stdout")
    dl_p.set_defaults(func=cmd_download)

    logout_p = sub.add_parser("logout", help="Unlink an account")
    logout_sel = logout_p.add_mutually_exclusive_group(required=True)
    logout_sel.add_argument("--account", help="Email of the linked account to remove")
    logout_sel.add_argument("--all", dest="all_accounts", action="store_true", help="Remove every linked account")
    logout_p.add_argument("--provider", choices=PROVIDERS)
    logout_p.add_argument("--revoke", action="store_true", help="Also revoke the grant with the provider")
    logout_p.add_argument("--yes", action="store_true", help="Do not ask for confirmation")
    logout_p.set_defaults(func=cmd_logout)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return args.func(args)
    except CcdError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except EOFError:
        print(
            "error: no input available on stdin. 'ccd logout' asks for confirmation; "
            "run it on a terminal or pass --yes.",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        print()
        return 130
