import base64
import hashlib
import hmac
import json
import secrets
import time
from html import unescape

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
# GET OAUTH CONFIGURATION
# ============================================================

def get_oauth_config():

    if "gmail_oauth" not in st.secrets:
        raise RuntimeError(
            "Missing [gmail_oauth] section in Streamlit Secrets."
        )

    config = st.secrets["gmail_oauth"]

    required_keys = [
        "client_id",
        "client_secret",
        "redirect_uri"
    ]

    for key in required_keys:
        if key not in config:
            raise RuntimeError(
                f"Missing '{key}' inside [gmail_oauth]."
            )

    return {
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "redirect_uri": config["redirect_uri"],
    }


# ============================================================
# CREATE SECURE OAUTH STATE
# ============================================================

def create_oauth_state():

    config = get_oauth_config()

    nonce = secrets.token_urlsafe(32)

    timestamp = str(int(time.time()))

    payload = f"{timestamp}:{nonce}"

    signature = hmac.new(
        config["client_secret"].encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    state_data = {
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": signature
    }

    encoded = json.dumps(state_data).encode("utf-8")

    state = base64.urlsafe_b64encode(
        encoded
    ).decode("utf-8")

    return state


# ============================================================
# VERIFY OAUTH STATE
# ============================================================

def verify_oauth_state(state):

    if not state:
        return False

    try:

        config = get_oauth_config()

        decoded = base64.urlsafe_b64decode(
            state.encode("utf-8")
        ).decode("utf-8")

        state_data = json.loads(decoded)

        timestamp = state_data["timestamp"]
        nonce = state_data["nonce"]
        signature = state_data["signature"]

        payload = f"{timestamp}:{nonce}"

        expected_signature = hmac.new(
            config["client_secret"].encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(
            signature,
            expected_signature
        ):
            return False

        current_time = int(time.time())

        if current_time - int(timestamp) > 600:
            return False

        return True

    except Exception:
        return False


# ============================================================
# CREATE GOOGLE AUTHORIZATION URL
# ============================================================

def get_authorization_url():

    config = get_oauth_config()

    state = create_oauth_state()

    params = {
        "client_id": config["client_id"],

        "redirect_uri": config["redirect_uri"],

        "response_type": "code",

        "scope": " ".join(SCOPES),

        "access_type": "offline",

        "prompt": "consent",

        "include_granted_scopes": "true",

        "state": state
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

    state = st.query_params.get("state")

    error = st.query_params.get("error")

    error_description = st.query_params.get(
        "error_description"
    )

    # --------------------------------------------------------
    # GOOGLE RETURNED ERROR
    # --------------------------------------------------------

    if error:

        st.error(
            f"Google OAuth error: {error}"
        )

        if error_description:

            st.warning(
                error_description
            )

        return False

    # --------------------------------------------------------
    # NO AUTHORIZATION CODE
    # --------------------------------------------------------

    if not code:
        return False

    # --------------------------------------------------------
    # VERIFY STATE
    # --------------------------------------------------------

    if not verify_oauth_state(state):

        st.error(
            "OAuth security check failed. "
            "Please start the Google sign-in again."
        )

        return False

    config = get_oauth_config()

    # --------------------------------------------------------
    # EXCHANGE CODE FOR TOKEN
    # --------------------------------------------------------

    data = {
        "code": code,

        "client_id": config["client_id"],

        "client_secret": config["client_secret"],

        "redirect_uri": config["redirect_uri"],

        "grant_type": "authorization_code"
    }

    try:

        response = requests.post(
            TOKEN_URL,
            data=data,
            timeout=30
        )

    except Exception as e:

        st.error(
            "Unable to connect to Google OAuth."
        )

        st.exception(e)

        return False

    # --------------------------------------------------------
    # TOKEN ERROR
    # --------------------------------------------------------

    if response.status_code != 200:

        st.error(
            "Unable to complete Google OAuth."
        )

        st.code(
            response.text
        )

        return False

    try:

        token_data = response.json()

    except Exception:

        st.error(
            "Google returned an invalid token response."
        )

        st.code(
            response.text
        )

        return False

    # --------------------------------------------------------
    # STORE TOKEN
    # --------------------------------------------------------

    st.session_state["gmail_token"] = token_data

    # --------------------------------------------------------
    # REMOVE QUERY PARAMETERS
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # CREATE GOOGLE CREDENTIALS
    # --------------------------------------------------------

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

        scopes=SCOPES
    )

    # --------------------------------------------------------
    # REFRESH EXPIRED TOKEN
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # BUILD GMAIL SERVICE
    # --------------------------------------------------------

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

        # Gmail uses URL-safe Base64.
        # Padding may sometimes be missing.

        missing_padding = len(data) % 4

        if missing_padding:
            data += "=" * (
                4 - missing_padding
            )

        decoded = base64.urlsafe_b64decode(
            data
        )

        return decoded.decode(
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
# REMOVE BASIC HTML TAGS
# ============================================================

def clean_html(text):

    if not text:
        return ""

    import re

    text = re.sub(
        r"<br\s*/?>",
        "\n",
        text,
        flags=re.IGNORECASE
    )

    text = re.sub(
        r"</p>",
        "\n",
        text,
        flags=re.IGNORECASE
    )

    text = re.sub(
        r"<[^>]+>",
        " ",
        text
    )

    text = unescape(text)

    return text


# ============================================================
# EXTRACT EMAIL BODY
# ============================================================

def get_email_body(payload):

    body_parts = []

    # --------------------------------------------------------
    # DIRECT BODY
    # --------------------------------------------------------

    body_data = payload.get(
        "body",
        {}
    ).get(
        "data"
    )

    if body_data:

        decoded = decode_message(
            body_data
        )

        if decoded:
            body_parts.append(decoded)

    # --------------------------------------------------------
    # MULTIPART EMAIL
    # --------------------------------------------------------

    parts = payload.get(
        "parts",
        []
    )

    for part in parts:

        mime_type = part.get(
            "mimeType",
            ""
        )

        # ----------------------------------------------------
        # PLAIN TEXT
        # ----------------------------------------------------

        if mime_type == "text/plain":

            data = part.get(
                "body",
                {}
            ).get(
                "data"
            )

            if data:

                body_parts.append(
                    decode_message(data)
                )

        # ----------------------------------------------------
        # HTML
        # ----------------------------------------------------

        elif mime_type == "text/html":

            data = part.get(
                "body",
                {}
            ).get(
                "data"
            )

            if data:

                html = decode_message(
                    data
                )

                body_parts.append(
                    clean_html(html)
                )

        # ----------------------------------------------------
        # NESTED MULTIPART
        # ----------------------------------------------------

        elif "parts" in part:

            nested_body = get_email_body(
                part
            )

            if nested_body:

                body_parts.append(
                    nested_body
                )

    return "\n".join(
        body_parts
    )


# ============================================================
# GET RECENT GMAIL EMAILS
# ============================================================

def get_recent_emails(
    max_results=10
):

    service = get_gmail_service()

    if service is None:

        raise RuntimeError(
            "Gmail is not connected. "
            "Please sign in with Google first."
        )

    # --------------------------------------------------------
    # GET INBOX MESSAGES
    # --------------------------------------------------------

    results = (
        service.users()
        .messages()
        .list(
            userId="me",
            labelIds=["INBOX"],
            maxResults=max_results
        )
        .execute()
    )

    messages = results.get(
        "messages",
        []
    )

    emails = []

    # --------------------------------------------------------
    # READ EACH EMAIL
    # --------------------------------------------------------

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
                "Unknown Sender"
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