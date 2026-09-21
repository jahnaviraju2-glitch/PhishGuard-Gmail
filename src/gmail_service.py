import base64
import secrets
import requests
import streamlit as st

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build


# ============================================================
# GOOGLE GMAIL CONFIGURATION
# ============================================================

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly"
]

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"


# ============================================================
# GET OAUTH CONFIGURATION FROM STREAMLIT SECRETS
# ============================================================

def get_oauth_config():

    config = st.secrets["gmail_oauth"]

    return {
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "redirect_uri": config["redirect_uri"],
    }


# ============================================================
# CREATE GOOGLE AUTHORIZATION URL
# ============================================================

def get_authorization_url():

    config = get_oauth_config()

    # Generate OAuth state
    state = secrets.token_urlsafe(32)

    # Store state in session
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


# ============================================================
# HANDLE GOOGLE OAUTH CALLBACK
# ============================================================

def handle_oauth_callback():

    code = st.query_params.get("code")

    if not code:
        return False

    config = get_oauth_config()

    # Exchange authorization code for access token
    data = {
        "code": code,
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "redirect_uri": config["redirect_uri"],
        "grant_type": "authorization_code",
    }

    try:

        response = requests.post(
            TOKEN_URL,
            data=data,
            timeout=30
        )

    except Exception as e:

        st.error("Unable to connect to Google OAuth.")
        st.exception(e)

        return False

    if response.status_code != 200:

        st.error("Unable to complete Google OAuth.")

        st.code(response.text)

        return False

    token_data = response.json()

    # Store Gmail token
    st.session_state["gmail_token"] = token_data

    # Remove OAuth parameters from URL
    try:
        st.query_params.clear()
    except Exception:
        pass

    return True


# ============================================================
# CREATE GMAIL API SERVICE
# ============================================================

def get_gmail_service():

    token_data = st.session_state.get(
        "gmail_token"
    )

    if not token_data:

        return None

    config = get_oauth_config()

    credentials = Credentials(

        token=token_data.get(
            "access_token"
        ),

        refresh_token=token_data.get(
            "refresh_token"
        ),

        token_uri=TOKEN_URL,

        client_id=config["client_id"],

        client_secret=config["client_secret"],

        scopes=SCOPES,
    )

    # Refresh expired access token
    if credentials.expired and credentials.refresh_token:

        try:

            credentials.refresh(
                Request()
            )

            st.session_state[
                "gmail_token"
            ]["access_token"] = credentials.token

        except Exception as e:

            st.error(
                "Unable to refresh Gmail access token."
            )

            st.exception(e)

            return None

    return build(
        "gmail",
        "v1",
        credentials=credentials
    )


# ============================================================
# DECODE GMAIL MESSAGE
# ============================================================

def decode_message(data):

    if not data:

        return ""

    try:

        return base64.urlsafe_b64decode(
            data
        ).decode(
            "utf-8",
            errors="ignore"
        )

    except Exception:

        return ""


# ============================================================
# EXTRACT EMAIL HEADERS
# ============================================================

def extract_headers(headers):

    result = {}

    for header in headers:

        name = header.get(
            "name",
            ""
        ).lower()

        value = header.get(
            "value",
            ""
        )

        result[name] = value

    return result


# ============================================================
# EXTRACT EMAIL BODY
# ============================================================

def get_email_body(payload):

    body = ""

    # Direct body
    if "body" in payload:

        data = payload["body"].get(
            "data"
        )

        if data:

            body += decode_message(
                data
            )

    # Multipart email
    parts = payload.get(
        "parts",
        []
    )

    for part in parts:

        mime_type = part.get(
            "mimeType",
            ""
        )

        # Plain text
        if mime_type == "text/plain":

            data = part.get(
                "body",
                {}
            ).get(
                "data"
            )

            if data:

                body += "\n" + decode_message(
                    data
                )

        # HTML
        elif mime_type == "text/html":

            data = part.get(
                "body",
                {}
            ).get(
                "data"
            )

            if data:

                body += "\n" + decode_message(
                    data
                )

        # Nested multipart
        elif "parts" in part:

            body += "\n" + get_email_body(
                part
            )

    return body


# ============================================================
# GET RECENT GMAIL EMAILS
# ============================================================

def get_recent_emails(max_results=10):

    service = get_gmail_service()

    if service is None:

        raise RuntimeError(
            "Gmail is not connected. "
            "Please sign in with Google first."
        )

    # Get inbox messages
    results = service.users().messages().list(

        userId="me",

        labelIds=["INBOX"],

        maxResults=max_results

    ).execute()

    messages = results.get(
        "messages",
        []
    )

    emails = []

    # Read each email
    for message in messages:

        message_data = (
            service.users()
            .messages()
            .get(
                userId="me",
                id=message["id"],
                format="full"
            )
            .execute()
        )

        payload = message_data.get(
            "payload",
            {}
        )

        headers = extract_headers(
            payload.get(
                "headers",
                []
            )
        )

        body = get_email_body(
            payload
        )

        emails.append({

            "id": message["id"],

            "sender": headers.get(
                "from",
                "Unknown"
            ),

            "subject": headers.get(
                "subject",
                "(No Subject)"
            ),

            "date": headers.get(
                "date",
                ""
            ),

            "body": body

        })

    return emails