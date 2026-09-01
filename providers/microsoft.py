"""Microsoft provider helpers for Contacts and Calendar via Microsoft Graph.

This module only knows how to call Microsoft Graph given an access token; it
has no knowledge of how that token was obtained. Authentication (the device
code flow, token storage, refresh) lives in ``ccd.auth_microsoft`` and
``ccd.store``.
"""
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import requests
import dateutil.parser
from icalendar import Calendar, Event


# Default OAuth scopes for Microsoft (v2.0 / Microsoft Graph)
DEFAULT_SCOPES = [
    "offline_access",
    "openid",
    "profile",
    "User.Read",
    "Contacts.Read",
    "Calendars.Read",
]


def _graph_get(url: str, access_token: str, params: Optional[Dict] = None) -> Dict:
    headers = {"Authorization": f"Bearer {access_token}"}
    resp = requests.get(url, headers=headers, params=params, timeout=15)
    resp.raise_for_status()
    return resp.json()


def fetch_microsoft_calendar(credentials: Dict[str, Any]) -> str:
    """Fetch Microsoft calendar events and return ICS data.

    credentials is a dict that must contain at least 'access_token'.
    """
    access_token = credentials.get("access_token")
    if not access_token:
        raise RuntimeError("Missing access token for Microsoft Graph")

    # Get events from the user's default calendar (next 1000 events)
    now = datetime.now(timezone.utc).isoformat()
    url = "https://graph.microsoft.com/v1.0/me/events"
    params = {"$orderby": "start/dateTime", "$top": 1000, "$filter": f"start/dateTime ge '{now}'"}

    data = _graph_get(url, access_token, params)
    events = data.get("value", [])

    cal = Calendar()
    cal.add('prodid', '-//Contacts Calendar Downloader//Microsoft Calendar Export//EN')
    cal.add('version', '2.0')
    cal.add('calscale', 'GREGORIAN')
    cal.add('method', 'PUBLISH')
    cal.add('x-wr-calname', 'Microsoft Calendar Export')
    cal.add('x-wr-timezone', 'UTC')

    for event_data in events:
        event = Event()
        event.add('uid', event_data.get('id', ''))
        event.add('summary', event_data.get('subject', 'No Title'))

        # Start
        start = event_data.get('start', {})
        if 'dateTime' in start:
            start_dt = dateutil.parser.parse(start['dateTime'])
            event.add('dtstart', start_dt)
        elif 'date' in start:
            start_date = dateutil.parser.parse(start['date']).date()
            event.add('dtstart', start_date)
            event.add('x-microsoft-cdo-alldayevent', 'TRUE')

        # End
        end = event_data.get('end', {})
        if 'dateTime' in end:
            end_dt = dateutil.parser.parse(end['dateTime'])
            event.add('dtend', end_dt)
        elif 'date' in end:
            end_date = dateutil.parser.parse(end['date']).date()
            event.add('dtend', end_date)

        if event_data.get('body') and isinstance(event_data['body'], dict):
            event.add('description', event_data['body'].get('content', ''))

        if 'location' in event_data and event_data['location']:
            loc = event_data['location']
            event.add('location', loc.get('displayName') or loc.get('locationUri') or '')

        if 'createdDateTime' in event_data:
            created_dt = dateutil.parser.parse(event_data['createdDateTime'])
            event.add('created', created_dt)

        if 'lastModifiedDateTime' in event_data:
            updated_dt = dateutil.parser.parse(event_data['lastModifiedDateTime'])
            event.add('last-modified', updated_dt)

        status = event_data.get('showAs', 'busy').upper()
        event.add('status', status)

        attendees = event_data.get('attendees', []) or []
        for attendee in attendees:
            email = attendee.get('emailAddress', {}).get('address')
            name = attendee.get('emailAddress', {}).get('name')
            if email:
                attendee_str = f"mailto:{email}"
                if name:
                    attendee_str = f"{name} <{email}>"
                event.add('attendee', attendee_str)

        cal.add_component(event)

    return cal.to_ical().decode('utf-8')


def fetch_contacts(credentials: Dict[str, Any], page_size: int = 1000) -> List[Dict]:
    """Fetch contacts from Microsoft Graph (paginated)."""
    access_token = credentials.get('access_token')
    if not access_token:
        return []

    contacts: List[Dict] = []
    url = 'https://graph.microsoft.com/v1.0/me/contacts'
    params = {'$top': page_size}

    while url:
        data = _graph_get(url, access_token, params=params)
        contacts.extend(data.get('value', []))
        # Graph paging uses @odata.nextLink
        url = data.get('@odata.nextLink')
        params = None

    return contacts


def extract_contact_row(contact: Dict) -> Dict[str, str]:
    """Map Microsoft Graph contact to the CSV row shape used by the app.

    Microsoft Graph contact fields: givenName, surname, displayName, emailAddresses (list of {address,name}), businessPhones, homePhones, mobilePhone, companyName, jobTitle, birthday
    """
    emails = contact.get('emailAddresses', []) or []
    phones = []
    # Combine businessPhones and homePhones if present
    if contact.get('businessPhones'):
        phones.extend(contact.get('businessPhones', []))
    if contact.get('homePhones'):
        phones.extend(contact.get('homePhones', []))

    def pick_primary_email(emails_list: List[Dict]) -> str:
        if not emails_list:
            return ''
        # Prefer first entry's address
        return emails_list[0].get('address', '')

    def join_others(emails_list: List[Dict]) -> str:
        if not emails_list or len(emails_list) <= 1:
            return ''
        return '; '.join(e.get('address', '') for e in emails_list[1:])

    given = contact.get('givenName', '')
    family = contact.get('surname', '')
    display = contact.get('displayName') or f"{given} {family}".strip()

    return {
        "Full Name": display,
        "Given Name": given,
        "Family Name": family,
        "Nickname": contact.get('nickName', ''),
        "Primary Email": pick_primary_email(emails),
        "Other Emails": join_others(emails),
        "Mobile Phone": contact.get('mobilePhone', ''),
        "Work Phone": contact.get('businessPhones', [''])[0] if contact.get('businessPhones') else '',
        "Home Phone": contact.get('homePhones', [''])[0] if contact.get('homePhones') else '',
        "Other Phones": '; '.join(phones),
        "Organization": contact.get('companyName', ''),
        "Job Title": contact.get('jobTitle', ''),
        "Birthday": contact.get('birthday', ''),
        "Street Address": '',
        "City": '',
        "Region": '',
        "Postal Code": '',
        "Country": '',
        "Resource Name": contact.get('id', ''),
    }


def get_profile(access_token: str) -> Dict:
    """Return the /me profile using Graph with the given access token."""
    return _graph_get('https://graph.microsoft.com/v1.0/me', access_token)
