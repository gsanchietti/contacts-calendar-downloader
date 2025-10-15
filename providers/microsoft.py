"""Microsoft provider helpers for Contacts and Calendar via Microsoft Graph.

This module implements the minimal functions needed to exchange tokens,
fetch calendar events and map contacts to the CSV format used by the app.
It intentionally uses simple token dicts stored by the application so the
rest of the code can remain provider-agnostic.
"""
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import time
import os
import requests
import dateutil.parser
from icalendar import Calendar, Event
from flask import request
import msal
import json


# Default OAuth scopes for Microsoft (v2.0 / Microsoft Graph)
DEFAULT_SCOPES = [
    "offline_access",
    "openid",
    "profile",
    "User.Read",
    "Contacts.Read",
    "Calendars.Read",
]


def authenticate_microsoft(config, user_email: str, save_credentials_fn) -> Optional[Dict[str, Any]]:
    """Authenticate a specific user and return credentials dict for Microsoft Graph API.
    
    Args:
        config: Configuration object with database connection details
        user_email: Email of the user to authenticate
        save_credentials_fn: Callback function to save refreshed credentials
            (typically save_user_credentials from main app)
    
    Returns:
        Credentials dict with access_token or None if authentication fails
    """
    # Import database module at runtime to avoid circular imports
    import database
    import sys
    
    print(f"[DEBUG] Authenticating Microsoft user: {user_email}", file=sys.stderr, flush=True)
    
    try:
        # Load credentials from database using centralized encryption methods
        db = database.get_db(config)
        creds = db.load_user_credentials(user_email, provider='microsoft')
        
        print(f"[DEBUG] Loaded Microsoft credentials for {user_email}: {creds is not None}", file=sys.stderr, flush=True)
        
        if not creds:
            print(f"[DEBUG] No credentials found for {user_email}", file=sys.stderr, flush=True)
            return None
    except Exception as e:
        print(f"❌ Failed to load Microsoft credentials for {user_email}: {e}", file=sys.stderr, flush=True)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return None
    
    if not creds:
        return None
    
    # Check if token needs refresh
    if creds.get('expires_at') and time.time() > creds['expires_at'] and creds.get('refresh_token'):
        # Attempt token refresh
        ms_creds_path = config.microsoft_credentials_path
        if ms_creds_path.exists():
            ms_creds = json.loads(ms_creds_path.read_text())
            token_url = f"https://login.microsoftonline.com/{ms_creds.get('tenant', 'common')}/oauth2/v2.0/token"
            data = {
                'client_id': ms_creds.get('client_id'),
                'client_secret': ms_creds.get('client_secret'),
                'grant_type': 'refresh_token',
                'refresh_token': creds.get('refresh_token'),
                'scope': ' '.join(creds.get('scopes', []))
            }
            try:
                resp = requests.post(token_url, data=data, timeout=10)
                resp.raise_for_status()
                token_result = resp.json()
                creds['access_token'] = token_result.get('access_token')
                creds['refresh_token'] = token_result.get('refresh_token', creds.get('refresh_token'))
                creds['expires_at'] = int(time.time()) + int(token_result.get('expires_in', 0))
                # Save refreshed credentials
                save_credentials_fn(config, user_email, creds, provider='microsoft')
            except Exception:
                return None
    
    # Verify we have a valid access token
    if not creds.get('access_token'):
        return None
    
    return creds


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
    now = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()
    url = "https://graph.microsoft.com/v1.0/me/events"
    params = {"$orderby": "start/dateTime", "$top": 1000, "$filter": f"start/dateTime ge '{now}'"}

    data = _graph_get(url, access_token, params)
    events = data.get("value", [])

    cal = Calendar()
    cal.add('prodid', '-//Contacts Downloader//Microsoft Calendar Export//EN')
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


def handle_oauth_callback(config, flow_row):
    """Complete a Microsoft OAuth flow and return (user_email, creds_dict).

    flow_row is the DB row stored for the flow and should contain 'redirect_uri'
    and 'scopes' (JSON list). This function performs the code->token exchange
    using MSAL and returns the discovered user email and a normalized token dict
    suitable for persisting by the caller.
    """
    code = request.args.get('code')
    if not code:
        raise ValueError('Missing authorization code')

    # Read Microsoft app credentials path from config
    ms_creds_path = config.microsoft_credentials_path
    if not ms_creds_path.exists():
        raise ValueError(f"Microsoft credentials file not found: {ms_creds_path}")
    ms_creds = json.loads(ms_creds_path.read_text())

    client_id = ms_creds.get('client_id')
    client_secret = ms_creds.get('client_secret')
    tenant = ms_creds.get('tenant', 'common')
    authority = f"https://login.microsoftonline.com/{tenant}"

    app_msal = msal.ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_secret,
        authority=authority
    )

    # Ensure flow_row typing
    flow_row = flow_row
    redirect_uri = flow_row['redirect_uri']
    scopes = json.loads(flow_row['scopes'])

    # MSAL authorization URL builder filters out OIDC reserved scopes; use
    # the same filtered scopes when exchanging the code for tokens.
    msal_scopes = [s for s in scopes if s.lower() not in ('openid', 'profile', 'offline_access')]

    token_result = app_msal.acquire_token_by_authorization_code(
        code,
        scopes=msal_scopes,
        redirect_uri=redirect_uri,
    )

    if 'access_token' not in token_result:
        raise ValueError(f"Failed to acquire Microsoft token: {token_result}")

    creds = {
        'access_token': token_result.get('access_token'),
        'refresh_token': token_result.get('refresh_token'),
        'expires_at': int(time.time()) + int(token_result.get('expires_in', 0)),
        'scopes': scopes,
        'id_token': token_result.get('id_token'),
        'redirect_uri': redirect_uri,
        'tenant': tenant,
    }

    try:
        me = get_profile(creds['access_token'])
        user_email = me.get('userPrincipalName') or me.get('mail') or me.get('userPrincipalName')
    except Exception:
        user_email = None

    if not user_email:
        raise ValueError('Could not identify Microsoft user email')

    return user_email, creds
