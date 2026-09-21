import base64
import requests
import streamlit as st

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build


SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly"
]

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"


def get_oauth_config():
    config = st.secrets["gmail_oauth"]

    return {
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "redirect_uri": config["redirect_uri"],
    }


def get_authorization_url():
    config = get_oauth_config()

    state = base64.urlsafe_b64encode(
        __import__("secrets").token_bytes(32)
    ).decode()

    st.session_state["oauth_state"] = state

    params = {
        "client_id": config["client_id"],
        "redirect_uri": config["redirect_uri"],
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }

    response = requests.Request(
        "GET",
        AUTH_URL,
        params=params
    ).prepare()

    return response.url


def handle_oauth_callback():
    code = st.query_params.get("code")
    state = st.query_params.get("state")

    if not code:
        return False

    saved_state = st.session_state.get("oauth_state")

    if not saved_state or state != saved_state:
        st.error("OAuth security check failed. Please try again.")
        return False

    config = get_oauth_config()

    data = {
        "code": code,
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "redirect_uri": config["redirect_uri"],
        "grant_type": "authorization_code",
    }

    response = requests.post(
        TOKEN_URL,
        data=data,
        timeout=30
    )

    if response.status_code != 200:
        st.error("Unable to complete Google OAuth.")
        st.code(response.text)
        return False

    token_data = response.json()

    st.session_state["gmail_token"] = token_data
    st.session_state["oauth_state"] = None

    # Remove ?code=...&state=... from browser URL
    st.query_params.clear()

    return True


def get_gmail_service():
    token_data = st.session_state.get("gmail_token")

    if not token_data:
        return None

    config = get_oauth_config()

    credentials = Credentials(
        token=token_data.get("access_token"),
        refresh_token=token_data.get("refresh_token"),
        token_uri=TOKEN_URL,
        client_id=config["client_id"],
        client_secret=config["client_secret"],
        scopes=SCOPES,
    )

    if credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())

        st.session_state["gmail_token"]["access_token"] = (
            credentials.token
        )

    return build(
        "gmail",
        "v1",
        credentials=credentials
    )


def decode_message(data):
    try:
        return base64.urlsafe_b64decode(data).decode(
            "utf-8",
            errors="ignore"
        )
    except Exception:
        return ""


def extract_headers(headers):
    result = {}

    for header in headers:
        name = header.get("name", "").lower()
        value = header.get("value", "")
        result[name] = value

    return result


def get_email_body(payload):
    body = ""

    if "body" in payload:
        data = payload["body"].get("data")

        if data:
            body += decode_message(data)

    parts = payload.get("parts", [])

    for part in parts:
        mime_type = part.get("mimeType", "")

        if mime_type in ["text/plain", "text/html"]:
            data = part.get("body", {}).get("data")

            if data:
                body += "\n" + decode_message(data)

        elif "parts" in part:
            body += "\n" + get_email_body(part)

    return body


def get_recent_emails(max_results=10):
    service = get_gmail_service()

    if service is None:
        raise RuntimeError(
            "Gmail is not connected. Please sign in with Google first."
        )

    results = service.users().messages().list(
        userId="me",
        labelIds=["INBOX"],
        maxResults=max_results
    ).execute()

    messages = results.get("messages", [])

    emails = []

    for message in messages:

        message_data = service.users().messages().get(
            userId="me",
            id=message["id"],
            format="full"
        ).execute()

        payload = message_data.get("payload", {})

        headers = extract_headers(
            payload.get("headers", [])
        )

        body = get_email_body(payload)

        emails.append({
            "id": message["id"],
            "sender": headers.get("from", "Unknown"),
            "subject": headers.get(
                "subject",
                "(No Subject)"
            ),
            "date": headers.get("date", ""),
            "body": body
        })

    return emails