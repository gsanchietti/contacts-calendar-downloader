"""Command-line interface for ccd (contacts & calendar downloader)."""
import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import serialize, store
from .errors import AuthExpiredError, CcdError, NoAccountsError, ProviderApiError

PROVIDERS = ("google", "microsoft")


# --------------------------------------------------------------------------- #
# Account resolution shared by status / download / logout
# --------------------------------------------------------------------------- #

def _resolve_accounts(args: argparse.Namespace, allow_all: bool) -> List[Dict[str, Any]]:
    provider = getattr(args, "provider", None)
    account_email = getattr(args, "account", None)
    want_all = allow_all and getattr(args, "all_accounts", False)

    candidates = store.list_accounts()
    if provider:
        candidates = [a for a in candidates if a["provider"] == provider]

    if want_all:
        if not candidates:
            raise NoAccountsError(_no_accounts_message())
        return candidates

    if account_email:
        matches = [a for a in candidates if a["email"] == account_email]
        if not matches:
            raise NoAccountsError(f"No linked account for '{account_email}'." + _linked_hint())
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


def _linked_hint() -> str:
    accounts = store.list_accounts()
    if not accounts:
        return " " + _no_accounts_message()
    listing = ", ".join(f"{a['provider']}:{a['email']}" for a in accounts)
    return f" Linked accounts: {listing}"


def _public_view(record: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of the record with token secrets stripped."""
    return {k: v for k, v in record.items() if k not in ("access_token", "refresh_token")}


# --------------------------------------------------------------------------- #
# login
# --------------------------------------------------------------------------- #

def cmd_login(args: argparse.Namespace) -> int:
    if args.provider == "google":
        from . import auth_google

        record = auth_google.login()
    elif args.provider == "microsoft":
        from . import auth_microsoft

        record = auth_microsoft.login()
    else:
        raise CcdError(f"Unknown provider: {args.provider}")

    print(f"\nLinked {record['provider']} account: {record['email']}")
    return 0


# --------------------------------------------------------------------------- #
# list
# --------------------------------------------------------------------------- #

def cmd_list(args: argparse.Namespace) -> int:
    accounts = store.list_accounts()

    if args.json_output:
        print(json.dumps([_public_view(a) for a in accounts], indent=2))
        return 0

    if not accounts:
        print(_no_accounts_message())
        return 0

    now = time.time()
    for account in accounts:
        left = account.get("expires_at", 0) - now
        status = "expired" if left <= 0 else f"expires in {int(left)}s"
        print(f"{account['provider']:<10} {account['email']:<32} {status}")
    return 0


# --------------------------------------------------------------------------- #
# status
# --------------------------------------------------------------------------- #

def _live_check(account: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Do one cheap authenticated call.

    Returns None when the token works, otherwise a dict with the error
    message and whether the cause was an unrecoverable auth failure (which
    the caller turns into exit code 3, same as everywhere else).
    """
    provider = account["provider"]
    try:
        if provider == "google":
            from googleapiclient.discovery import build

            from . import auth_google

            creds = auth_google.credentials(account)
            service = build("people", "v1", credentials=creds, cache_discovery=False)
            # people.get(people/me) reads *profile* data and would demand the
            # 'profile' scope, which ccd deliberately does not request. Listing
            # a single connection is the cheapest call covered by the scopes we
            # actually hold (contacts.readonly).
            (
                service.people()
                .connections()
                .list(resourceName="people/me", pageSize=1, personFields="names")
                .execute()
            )
        elif provider == "microsoft":
            from providers import microsoft as ms_provider

            token = store.get_access_token(account)
            ms_provider.get_profile(token)
        else:
            return {"message": f"unknown provider '{provider}'", "auth_expired": False}
    except AuthExpiredError as exc:
        return {"message": str(exc), "auth_expired": True}
    except Exception as exc:  # noqa: BLE001 - surfaced to the user, not swallowed
        return {"message": str(exc), "auth_expired": False}
    return None


def cmd_status(args: argparse.Namespace) -> int:
    accounts = _resolve_accounts(args, allow_all=False)

    results = []
    all_ok = True
    any_auth_expired = False
    for account in accounts:
        error = _live_check(account)
        if error:
            all_ok = False
            any_auth_expired = any_auth_expired or error["auth_expired"]

        # Re-read: a successful live check may have refreshed and persisted a
        # new access token, so the stored expiry is newer than what we started
        # with. Reporting the pre-check value would say "expired" right after
        # a successful refresh.
        current = store.load(account["provider"], account["email"]) or account
        seconds_left = current.get("expires_at", 0) - time.time()
        expired = seconds_left <= 0

        results.append(
            {
                "provider": account["provider"],
                "email": account["email"],
                "expires_in": None if expired else int(seconds_left),
                "expired": expired,
                "live_check": "ok" if not error else "failed",
                "error": error["message"] if error else None,
            }
        )

    if args.json_output:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            expiry = "expired" if r["expired"] else f"expires in {r['expires_in']}s"
            check = "ok" if r["live_check"] == "ok" else f"FAILED ({r['error']})"
            print(f"{r['provider']:<10} {r['email']:<32} {expiry:<20} live-check: {check}")

    if all_ok:
        return 0
    return AuthExpiredError.exit_code if any_auth_expired else 1


# --------------------------------------------------------------------------- #
# download
# --------------------------------------------------------------------------- #

def _fetch_contacts_rows(account: Dict[str, Any], page_size: int) -> List[Dict[str, str]]:
    provider = account["provider"]
    if provider == "google":
        from googleapiclient.discovery import build
        from googleapiclient.errors import HttpError

        from . import auth_google
        from providers import google as google_provider

        creds = auth_google.credentials(account)
        service = build("people", "v1", credentials=creds, cache_discovery=False)
        try:
            raw = google_provider.download_contacts(service, page_size=page_size)
        except HttpError as exc:
            raise ProviderApiError(f"Google People API error: {exc}") from exc
        return [google_provider.extract_contact_row(p) for p in raw]

    if provider == "microsoft":
        import requests

        from providers import microsoft as ms_provider

        token = store.get_access_token(account)
        try:
            raw = ms_provider.fetch_contacts({"access_token": token}, page_size=page_size)
        except requests.HTTPError as exc:
            raise ProviderApiError(f"Microsoft Graph error: {exc}") from exc
        return [ms_provider.extract_contact_row(c) for c in raw]

    raise CcdError(f"Unknown provider: {provider}")


def _fetch_calendar_ics(account: Dict[str, Any]) -> str:
    provider = account["provider"]
    if provider == "google":
        from googleapiclient.errors import HttpError

        from . import auth_google
        from providers import google as google_provider

        creds = auth_google.credentials(account)
        try:
            return google_provider.fetch_google_calendar(creds)
        except HttpError as exc:
            raise ProviderApiError(f"Google Calendar API error: {exc}") from exc

    if provider == "microsoft":
        import requests

        from providers import microsoft as ms_provider

        token = store.get_access_token(account)
        try:
            return ms_provider.fetch_microsoft_calendar({"access_token": token})
        except requests.HTTPError as exc:
            raise ProviderApiError(f"Microsoft Graph error: {exc}") from exc

    raise CcdError(f"Unknown provider: {provider}")


def _default_filename(dl_type: str, fmt: str, email: str) -> str:
    if dl_type == "calendar":
        return f"calendar_{email}.ics"
    return f"contacts_{email}.{fmt}"


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

    for account in accounts:
        email = account["email"]

        if args.type == "calendar":
            content = _fetch_calendar_ics(account)
        else:
            rows = _fetch_contacts_rows(account, args.page_size)
            content = serialize.contacts_to_csv(rows) if fmt == "csv" else serialize.contacts_to_json(rows)

        if output == "-":
            sys.stdout.write(content)
            continue

        default_name = _default_filename(args.type, fmt, email)
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
        answer = input(f"This will remove local credentials for:\n{listing}\nContinue? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Aborted.")
            return 0

    for account in accounts:
        provider = account["provider"]
        email = account["email"]
        revoked = False

        if args.revoke:
            try:
                if provider == "google":
                    from . import auth_google

                    revoked = auth_google.revoke(account)
                elif provider == "microsoft":
                    from . import auth_microsoft

                    revoked = auth_microsoft.revoke(account)
            except Exception as exc:  # noqa: BLE001 - never let a revoke failure block local cleanup
                print(f"warning: could not revoke {provider}:{email} server-side: {exc}", file=sys.stderr)

        store.delete(provider, email)

        if not args.revoke:
            print(
                f"Removed local credentials for {provider}:{email}. "
                "The grant likely still exists provider-side; pass --revoke to also revoke it."
            )
        elif revoked:
            print(f"Revoked and removed {provider}:{email}")
        elif provider == "microsoft":
            print(
                f"Removed local credentials for {provider}:{email}. Microsoft has no programmatic "
                "per-app revoke for public clients -- remove access manually at "
                "https://myaccount.microsoft.com/privacy or https://account.live.com/consent/Manage."
            )
        else:
            print(f"Removed local credentials for {provider}:{email} (server-side revoke was not confirmed).")

    return 0


# --------------------------------------------------------------------------- #
# argument parsing / entry point
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ccd",
        description="Download your own contacts and calendar from Google or Microsoft. Everything runs locally.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

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

    dl_p = sub.add_parser("download", help="Download contacts or calendar")
    dl_p.add_argument("--type", required=True, choices=["contacts", "calendar"])
    dl_p.add_argument("--format", choices=["csv", "json", "ics"])
    dl_sel = dl_p.add_mutually_exclusive_group()
    dl_sel.add_argument("--account", help="Email of the linked account to use")
    dl_sel.add_argument("--all", dest="all_accounts", action="store_true", help="Download for every linked account")
    dl_p.add_argument("--provider", choices=PROVIDERS)
    dl_p.add_argument("--output", help="File path, directory (with --all), or '-' for stdout")
    dl_p.add_argument("--page-size", type=int, default=1000)
    dl_p.set_defaults(func=cmd_download)

    logout_p = sub.add_parser("logout", help="Remove a linked account's local credentials")
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
            "error: no input available on stdin. 'ccd login' and 'ccd logout' "
            "are interactive; run them on a terminal (podman run -it ...), or "
            "pass --yes to 'ccd logout'.",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        print()
        return 130
