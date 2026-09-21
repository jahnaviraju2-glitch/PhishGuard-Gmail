import os
import base64

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build


SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def get_gmail_service():
    creds = None

    # Existing login token
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file(
            "token.json",
            SCOPES
        )

    # Login / refresh
    if not creds or not creds.valid:

        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())

        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "credentials.json",
                SCOPES
            )

            creds = flow.run_local_server(port=0)

        # Save login information
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    # Connect to Gmail API
    service = build(
        "gmail",
        "v1",
        credentials=creds
    )

    return service


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

    # Simple email body
    if "body" in payload:

        data = payload["body"].get("data")

        if data:
            body += decode_message(data)

    # Multipart email
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