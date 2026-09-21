import re
from html import unescape


def remove_html(text):
    """
    Remove HTML tags from email content.
    """
    if not text:
        return ""

    text = unescape(text)

    # Remove HTML tags
    text = re.sub(r"<[^>]+>", " ", text)

    # Remove extra spaces
    text = re.sub(r"\s+", " ", text)

    return text.strip()


def extract_urls(text):
    """
    Extract URLs from email text.
    """
    if not text:
        return []

    pattern = r"https?://[^\s<>\"]+"

    urls = re.findall(pattern, text)

    # Remove duplicate URLs
    return list(dict.fromkeys(urls))


def clean_email_text(sender, subject, body):
    """
    Combine sender, subject and body into clean text
    for ML analysis.
    """

    sender = sender or ""
    subject = subject or ""
    body = body or ""

    body = remove_html(body)

    combined_text = (
        f"Sender: {sender}\n"
        f"Subject: {subject}\n"
        f"Body: {body}"
    )

    return combined_text.strip()


def parse_email(sender, subject, body):
    """
    Main email parser function.
    """

    return clean_email_text(
        sender,
        subject,
        body
    )


def get_email_urls(body):
    """
    Get URLs from email body.
    """

    clean_body = remove_html(body)

    return extract_urls(clean_body)