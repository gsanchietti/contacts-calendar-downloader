"""Google provider-specific helpers for contacts and calendar.

This module contains the functions and constants that interact with Google APIs.
It was extracted from the main application to make adding new providers easier.
"""
from typing import Any, Dict, Iterable, List, Optional
from datetime import datetime, timezone
import os
import dateutil.parser

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from icalendar import Calendar, Event

# Default OAuth scopes for Google
DEFAULT_SCOPES = [
    "https://www.googleapis.com/auth/contacts.readonly",
    "https://www.googleapis.com/auth/calendar.readonly",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
]


def authenticate_google(config, user_email: str) -> Optional[Any]:
    """Authenticate a specific user and return an authorized People API service.
    
    Args:
        config: Configuration object with database connection details
        user_email: Email of the user to authenticate
        save_credentials_fn: Callback function to save refreshed credentials
            (typically save_user_credentials from main app)
    
    Returns:
        Authenticated People API service object or None if authentication fails
    """
    # This needs to import at runtime to avoid circular imports
    import database
    
    # Load credentials from database using the database's encryption methods
    db = database.get_db(config)
    creds_raw = db.load_user_credentials(user_email, provider='google')
    
    if not creds_raw:
        return None

    # creds_raw may be a google Credentials object (pickled) or a normalized dict
    creds: Optional[Credentials] = None

    # If it's already a Credentials-like object (has .valid), use it
    if hasattr(creds_raw, 'valid'):
        creds = creds_raw
    elif isinstance(creds_raw, dict):
        # Build a google.oauth2.credentials.Credentials from normalized dict
        token = creds_raw.get('access_token')
        refresh = creds_raw.get('refresh_token')
        expires_at = creds_raw.get('expires_at')
        scopes = creds_raw.get('scopes') or []

        # token_uri and client credentials may be missing; use sensible defaults
        token_uri = os.environ.get('GOOGLE_TOKEN_URI', 'https://oauth2.googleapis.com/token')
        client_id = os.environ.get('GOOGLE_CLIENT_ID')
        client_secret = os.environ.get('GOOGLE_CLIENT_SECRET')

        creds = Credentials(
            token=token,
            refresh_token=refresh,
            token_uri=token_uri,
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes,
            expiry=datetime.fromtimestamp(expires_at, tz=timezone.utc) if expires_at else None
        )

    if not creds or not getattr(creds, 'valid', False):
        if getattr(creds, 'expired', False) and getattr(creds, 'refresh_token', None):
            try:
                if not creds:
                    return None
                creds.refresh(Request())
                # Save refreshed credentials via callback
                db.save_user_credentials(user_email, creds, provider='google')
            except Exception:
                return None
        else:
            return None  # Not authenticated

    return build("people", "v1", credentials=creds, cache_discovery=False)


def download_contacts(service, page_size: int = 1000, person_fields: str = "names,emailAddresses,phoneNumbers,addresses,organizations,birthdays,nicknames,metadata") -> List[Dict]:
    """Fetch all contacts using the People API, handling pagination.
    
    Args:
        service: Authenticated People API service
        page_size: Number of contacts to fetch per page
        person_fields: Comma-separated list of person fields to request
    
    Returns:
        List of contact dicts from the People API
    """
    contacts: List[Dict] = []
    page_token: Optional[str] = None

    while True:
        request = (
            service.people()
            .connections()
            .list(
                resourceName="people/me",
                pageToken=page_token,
                pageSize=page_size,
                personFields=person_fields,
            )
        )
        response = request.execute()
        contacts.extend(response.get("connections", []))
        page_token = response.get("nextPageToken")
        if not page_token:
            break

    return contacts


def fetch_google_calendar(credentials) -> str:
    """Fetch Google Calendar events and return ICS data.

    Kept as a standalone function so provider implementations can be swapped.
    """
    service = build('calendar', 'v3', credentials=credentials)

    now = datetime.utcnow().isoformat() + 'Z'
    events_result = service.events().list(
        calendarId='primary',
        timeMin=now,
        maxResults=1000,
        singleEvents=True,
        orderBy='startTime'
    ).execute()

    events = events_result.get('items', [])

    cal = Calendar()
    cal.add('prodid', '-//Google Contacts Downloader//Calendar Export//EN')
    cal.add('version', '2.0')
    cal.add('calscale', 'GREGORIAN')
    cal.add('method', 'PUBLISH')
    cal.add('x-wr-calname', 'Google Calendar Export')
    cal.add('x-wr-timezone', 'UTC')

    for event_data in events:
        event = Event()
        event.add('uid', event_data.get('id', ''))
        event.add('summary', event_data.get('summary', 'No Title'))

        start = event_data.get('start', {})
        if 'dateTime' in start:
            start_dt = dateutil.parser.parse(start['dateTime'])
            event.add('dtstart', start_dt)
        elif 'date' in start:
            start_date = dateutil.parser.parse(start['date']).date()
            event.add('dtstart', start_date)
            event.add('x-microsoft-cdo-alldayevent', 'TRUE')

        end = event_data.get('end', {})
        if 'dateTime' in end:
            end_dt = dateutil.parser.parse(end['dateTime'])
            event.add('dtend', end_dt)
        elif 'date' in end:
            end_date = dateutil.parser.parse(end['date']).date()
            event.add('dtend', end_date)

        if 'description' in event_data:
            event.add('description', event_data['description'])

        if 'location' in event_data:
            event.add('location', event_data['location'])

        if 'created' in event_data:
            created_dt = dateutil.parser.parse(event_data['created'])
            event.add('created', created_dt)

        if 'updated' in event_data:
            updated_dt = dateutil.parser.parse(event_data['updated'])
            event.add('last-modified', updated_dt)

        status = event_data.get('status', 'confirmed').upper()
        event.add('status', status)

        transparency = event_data.get('transparency', 'opaque').upper()
        event.add('transp', transparency)

        organizer = event_data.get('organizer', {})
        if 'email' in organizer:
            event.add('organizer', f"mailto:{organizer['email']}")

        attendees = event_data.get('attendees', [])
        for attendee in attendees:
            if 'email' in attendee:
                attendee_str = f"mailto:{attendee['email']}"
                if 'displayName' in attendee:
                    attendee_str = f"{attendee['displayName']} <{attendee['email']}>"
                event.add('attendee', attendee_str)

        cal.add_component(event)

    return cal.to_ical().decode('utf-8')


def handle_oauth_callback(config, flow):
    """Complete a Google OAuth flow and return (user_email, credentials).

    This function mirrors the previous _handle_google_oauth_callback in the
    main application but returns the discovered email and credentials so the
    caller can persist them (avoids circular imports).
    """
    # Import here to avoid overhead at module import time and circular deps
    from flask import request
    from googleapiclient.discovery import build

    # Complete the OAuth flow
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)
    creds = flow.credentials

    # Identify user. Try OAuth2 userinfo first, fallback to People API.
    user_email = None
    try:
        oauth2_service = build("oauth2", "v2", credentials=creds, cache_discovery=False)
        user_info = oauth2_service.userinfo().get().execute()
        user_email = user_info.get('email')
    except Exception:
        pass

    if not user_email:
        try:
            people_service = build("people", "v1", credentials=creds, cache_discovery=False)
            profile = people_service.people().get(resourceName='people/me', personFields='emailAddresses').execute()
            emails = profile.get('emailAddresses', [])
            if emails:
                primary_email = next((e['value'] for e in emails if e.get('metadata', {}).get('primary')), None)
                user_email = primary_email or emails[0]['value']
        except Exception:
            pass

    if not user_email:
        raise ValueError("Could not identify user email from Google credentials")

    return user_email, creds


def extract_contact_row(person: Dict) -> Dict[str, str]:
    """Map People API person dict to CSV row fields.
    """
    def _choose_primary(entries: Iterable[Dict], key: str) -> str:
        primary = None
        for entry in entries:
            metadata = entry.get('metadata', {})
            if metadata.get('primary'):
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

    names = person.get("names", [])
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
        "Street Address": _find_by_type(addresses, "home", "streetAddress") or _find_by_type(addresses, "work", "streetAddress"),
        "City": _find_by_type(addresses, "home", "city") or _find_by_type(addresses, "work", "city"),
        "Region": _find_by_type(addresses, "home", "region") or _find_by_type(addresses, "work", "region"),
        "Postal Code": _find_by_type(addresses, "home", "postalCode") or _find_by_type(addresses, "work", "postalCode"),
        "Country": _find_by_type(addresses, "home", "country") or _find_by_type(addresses, "work", "country"),
        "Resource Name": person.get("resourceName", ""),
    }
