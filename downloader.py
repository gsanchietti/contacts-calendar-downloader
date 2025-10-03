#!/usr/bin/env python3
"""Download Google Contacts to a CSV or JSON file using the People API."""

from __future__ import annotations

import argparse
import csv
import json
import os
import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, cast

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Default OAuth scope: read-only access to contacts.
DEFAULT_SCOPES = ["https://www.googleapis.com/auth/contacts.readonly"]
# Additional per-request fields we want from the People API.
DEFAULT_PERSON_FIELDS = (
    "names,emailAddresses,phoneNumbers,addresses,organizations,birthdays,nicknames,metadata"
)


@dataclass
class Config:
    """Runtime configuration gathered from CLI arguments."""

    credentials_path: Path
    token_path: Path
    output_path: Path
    output_format: str
    person_fields: str
    page_size: int


def parse_args() -> Config:
    parser = argparse.ArgumentParser(description="Download Google contacts into CSV or JSON.")
    parser.add_argument(
        "--credentials",
        default=os.environ.get("GOOGLE_CREDENTIALS", "credentials.json"),
        type=Path,
        help="Path to the OAuth 2.0 client credentials file (credentials.json).",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("GOOGLE_TOKEN", "token.pickle"),
        type=Path,
        help="Path to store the persistent OAuth token (token.pickle).",
    )
    parser.add_argument(
        "--output",
        default=os.environ.get("GOOGLE_CONTACTS_OUTPUT", "google_contacts.csv"),
        type=Path,
        help="Destination file for exported contacts (use '-' for stdout).",
    )
    parser.add_argument(
        "--output-format",
        choices=["csv", "json"],
        default="csv",
        help="Output format: csv or json. Defaults to csv.",
    )
    parser.add_argument(
        "--person-fields",
        default=DEFAULT_PERSON_FIELDS,
        help="Comma-separated list of People API personFields to request.",
    )
    parser.add_argument(
        "--page-size",
        default=1000,
        type=int,
        help=(
            "Number of contacts to fetch per API request (max 1000 per API docs). "
            "Defaults to 1000."
        ),
    )
    args = parser.parse_args()
    
    # Adjust output path based on format
    output_path = args.output
    if str(output_path) != "-" and output_path.suffix == ".csv" and args.output_format == "json":
        output_path = output_path.with_suffix(".json")
    elif str(output_path) != "-" and output_path.suffix == ".json" and args.output_format == "csv":
        output_path = output_path.with_suffix(".csv")
    
    return Config(
        credentials_path=args.credentials,
        token_path=args.token,
        output_path=output_path,
        output_format=args.output_format,
        person_fields=args.person_fields,
        page_size=args.page_size,
    )


def _run_console_flow(flow: InstalledAppFlow) -> Credentials:
    """Perform a console-based OAuth flow using a local server."""

    print("\n" + "=" * 70)
    print("AUTHORIZATION REQUIRED")
    print("=" * 70)
    print("\nA local web server will start on http://localhost:8080")
    print("Please open the URL below in your browser to authorize access:\n")
    
    # Use run_local_server but don't auto-open browser
    # Set redirect_uri_trailing_slash=False to match the exact URI in credentials
    creds = flow.run_local_server(
        port=8080,
        open_browser=False,
        authorization_prompt_message="\n{url}\n",
        redirect_uri_trailing_slash=False,
    )
    
    print("\n✓ Authorization successful!")
    return cast(Credentials, creds)


def authenticate_google(config: Config) -> Any:
    """Authenticate the user and return an authorized People API service."""

    creds: Optional[Credentials] = None
    if config.token_path.exists():
        with config.token_path.open("rb") as token_file:
            creds = pickle.load(token_file)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                str(config.credentials_path), DEFAULT_SCOPES
            )
            creds = _run_console_flow(flow)
        with config.token_path.open("wb") as token_file:
            pickle.dump(creds, token_file)

    return build("people", "v1", credentials=creds, cache_discovery=False)


def download_contacts(service, config: Config) -> List[Dict]:
    """Fetch all contacts using the People API, handling pagination."""

    contacts: List[Dict] = []
    page_token: Optional[str] = None

    while True:
        request = (
            service.people()
            .connections()
            .list(
                resourceName="people/me",
                pageToken=page_token,
                pageSize=config.page_size,
                personFields=config.person_fields,
            )
        )
        response = request.execute()
        contacts.extend(response.get("connections", []))
        page_token = response.get("nextPageToken")
        if not page_token:
            break

    return contacts


def _choose_primary(entries: Iterable[Dict], key: str) -> str:
    primary = None
    for entry in entries:
        metadata = entry.get("metadata", {})
        if metadata.get("primary"):
            primary = entry
            break
    if primary is None:
        primary = next(iter(entries), None)
    return primary.get(key, "") if primary else ""


def _collect_all(entries: Iterable[Dict], key: str) -> str:
    values = [entry.get(key, "") for entry in entries if entry.get(key)]
    return "; ".join(values)


def _format_birthday(person: Dict) -> str:
    for birthday in person.get("birthdays", []):
        date = birthday.get("date", {})
        if date:
            parts = [
                f"{date.get('year', ''):04d}" if date.get("year") else None,
                f"{date.get('month', ''):02d}" if date.get("month") else None,
                f"{date.get('day', ''):02d}" if date.get("day") else None,
            ]
            formatted = "-".join(part for part in parts if part)
            if formatted:
                return formatted
    return ""


def _find_by_type(entries: Iterable[Dict], entry_type: str, key: str) -> str:
    for entry in entries:
        if entry.get("type", "").lower() == entry_type:
            value = entry.get(key)
            if value:
                return value
    return ""


def _extract_contact_row(person: Dict) -> Dict[str, str]:
    names = person.get("names", [])
    # Choose the primary name if marked, otherwise fall back to the first name.
    if names:
        primary_name = next((n for n in names if n.get("metadata", {}).get("primary")), names[0])
    else:
        primary_name = {}
    nicknames = person.get("nicknames", [])
    emails = person.get("emailAddresses", [])
    phones = person.get("phoneNumbers", [])
    addresses = person.get("addresses", [])
    organizations = person.get("organizations", [])

    return {
        "Full Name": primary_name.get("displayName", ""),
        "Given Name": primary_name.get("givenName", ""),
        "Family Name": primary_name.get("familyName", ""),
        "Nickname": _choose_primary(nicknames, "value"),
        "Primary Email": _choose_primary(emails, "value"),
        "Other Emails": _collect_all(emails[1:], "value") if emails else "",
        "Mobile Phone": _find_by_type(phones, "mobile", "value"),
        "Work Phone": _find_by_type(phones, "work", "value"),
        "Home Phone": _find_by_type(phones, "home", "value"),
        "Other Phones": _collect_all(phones, "value"),
        "Organization": _choose_primary(organizations, "name"),
        "Job Title": _choose_primary(organizations, "title"),
        "Birthday": _format_birthday(person),
        "Street Address": _find_by_type(addresses, "home", "streetAddress")
        or _find_by_type(addresses, "work", "streetAddress"),
        "City": _find_by_type(addresses, "home", "city")
        or _find_by_type(addresses, "work", "city"),
        "Region": _find_by_type(addresses, "home", "region")
        or _find_by_type(addresses, "work", "region"),
        "Postal Code": _find_by_type(addresses, "home", "postalCode")
        or _find_by_type(addresses, "work", "postalCode"),
        "Country": _find_by_type(addresses, "home", "country")
        or _find_by_type(addresses, "work", "country"),
        "Resource Name": person.get("resourceName", ""),
    }


def write_output(contacts: List[Dict], config: Config) -> None:
    """Write a list of contact dictionaries to a file in the specified format."""

    if not contacts:
        print("No contacts found.")
        return

    rows = [_extract_contact_row(person) for person in contacts]

    if config.output_format == "csv":
        _write_csv(rows, config.output_path)
    elif config.output_format == "json":
        _write_json(rows, config.output_path)


def _write_csv(rows: List[Dict[str, str]], filename: Path) -> None:
    """Write rows to CSV file or stdout."""

    headers = [
        "Full Name",
        "Given Name",
        "Family Name",
        "Nickname",
        "Primary Email",
        "Other Emails",
        "Mobile Phone",
        "Work Phone",
        "Home Phone",
        "Other Phones",
        "Organization",
        "Job Title",
        "Birthday",
        "Street Address",
        "City",
        "Region",
        "Postal Code",
        "Country",
        "Resource Name",
    ]

    if str(filename) == "-":
        import sys
        writer = csv.DictWriter(sys.stdout, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        print(f"Exported {len(rows)} contacts to stdout", file=sys.stderr)
    else:
        filename.parent.mkdir(parents=True, exist_ok=True)

        with filename.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)

        print(f"Exported {len(rows)} contacts to {filename}")


def _write_json(rows: List[Dict[str, str]], filename: Path) -> None:
    """Write rows to JSON file or stdout."""

    if str(filename) == "-":
        import sys
        json.dump(rows, sys.stdout, indent=2, ensure_ascii=False)
        print(f"\nExported {len(rows)} contacts to stdout", file=sys.stderr)
    else:
        filename.parent.mkdir(parents=True, exist_ok=True)

        with filename.open("w", encoding="utf-8") as jsonfile:
            json.dump(rows, jsonfile, indent=2, ensure_ascii=False)

        print(f"Exported {len(rows)} contacts to {filename}")


def main() -> None:
    config = parse_args()

    if not config.credentials_path.exists():
        raise FileNotFoundError(
            f"Credentials file not found: {config.credentials_path}. "
            "Download it from the Google Cloud Console."
        )

    service = authenticate_google(config)
    contacts = download_contacts(service, config)
    write_output(contacts, config)


if __name__ == "__main__":
    main()
