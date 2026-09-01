"""Serialization helpers for the contact rows shared across providers."""
import csv
import io
import json
from typing import Dict, List

CONTACT_HEADERS = [
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


def contacts_to_csv(rows: List[Dict[str, str]]) -> str:
    """Render contact rows as CSV text with CONTACT_HEADERS as the header."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CONTACT_HEADERS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buf.getvalue()


def contacts_to_json(rows: List[Dict[str, str]]) -> str:
    """Render contact rows as pretty-printed JSON text."""
    return json.dumps(rows, indent=2, ensure_ascii=False)
