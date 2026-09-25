import streamlit as st

from src.gmail_service import (
    get_recent_emails,
    get_authorization_url,
    handle_oauth_callback
)

from src.risk_engine import analyze_email


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide"
)


# =========================================================
# PRIVACY POLICY PAGE
# =========================================================

if st.query_params.get("page") == "privacy":

    st.title(
        "🛡️ PhishGuard AI – Privacy Policy"
    )

    st.caption(
        "Last updated: September 25, 2026"
    )

    st.markdown(
        """
## 1. Information We Access

PhishGuard AI requests read-only access to Gmail
messages when the user chooses to connect a Google
Gmail account.

The application may access email metadata and
message content required to analyze messages for
phishing and spam indicators.

## 2. How We Use Google User Data

Gmail data is used only to provide the phishing
and spam detection functionality.

The application may analyze:

- Email text
- Sender information
- Email subject
- Suspicious keywords
- URLs
- Security-related indicators

PhishGuard AI does not use Google user data for
advertising or targeted advertising.

PhishGuard AI does not sell Google user data.

## 3. Data Storage

The application is designed to process Gmail
information only as necessary for the requested
analysis.

The application does not intentionally maintain
a separate permanent database of users' Gmail
message content.

OAuth credentials and access tokens are handled
only for authentication and Gmail API access.

## 4. Data Sharing

PhishGuard AI does not sell or rent Google user
data.

Gmail data is not shared with advertisers or
data brokers.

## 5. Google API Services

PhishGuard AI's use of information received from
Google APIs follows the Google API Services User
Data Policy and its Limited Use requirements.

## 6. Revoking Access

Users can stop using PhishGuard AI at any time.

Users can revoke Gmail access from their Google
Account security settings.

## 7. Security

Reasonable technical measures are used to protect
information handled by the application.

However, no internet-based service can guarantee
absolute security.

## 8. Children's Privacy

PhishGuard AI is not specifically directed toward
children under the age of 13.

## 9. Changes to This Policy

This Privacy Policy may be updated when the
application's functionality or data practices
change.

## 10. Contact

For questions about this Privacy Policy:

**Email:** jahnaviraju2@gmail.com
        """
    )

    st.stop()


# =========================================================
# HANDLE GOOGLE OAUTH CALLBACK
# =========================================================

if "gmail_token" not in st.session_state:

    try:

        handle_oauth_callback()

    except Exception as e:

        st.error(
            "Google authentication failed."
        )

        st.exception(e)


# =========================================================
# HEADER
# =========================================================

st.title(
    "🛡️ PhishGuard AI"
)

st.subheader(
    "Smart Gmail Phishing & Spam Detection System"
)


# =========================================================
# GMAIL CONNECTION
# =========================================================

if not st.session_state.get(
    "gmail_token"
):

    st.warning(
        "🔐 Gmail access is required to analyze your inbox."
    )

    # -----------------------------------------------------
    # GOOGLE LOGIN BUTTON
    # -----------------------------------------------------

    if st.button(
        "🔑 Generate Google Sign-In Link",
        use_container_width=True
    ):

        try:

            auth_url = get_authorization_url()

            # Store URL for debugging
            st.session_state[
                "debug_auth_url"
            ] = auth_url

            st.success(
                "Google authorization URL generated."
            )

        except Exception as e:

            st.error(
                "Unable to generate Google authorization URL."
            )

            st.exception(e)

    # -----------------------------------------------------
    # DEBUG GOOGLE URL
    # -----------------------------------------------------

    auth_url = st.session_state.get(
        "debug_auth_url"
    )

    if auth_url:

        st.divider()

        st.subheader(
            "🔧 OAuth Debug"
        )

        st.info(
            "Click the button below to open Google authorization."
        )

        st.link_button(
            "🔐 OPEN GOOGLE AUTHORIZATION",
            auth_url,
            use_container_width=True
        )

        st.write(
            "Generated OAuth URL:"
        )

        st.code(
            auth_url,
            language="text"
        )

        st.warning(
            "⚠️ Do not share screenshots containing "
            "private credentials. The URL above does "
            "not contain your client secret."
        )

    # -----------------------------------------------------
    # INFORMATION
    # -----------------------------------------------------

    st.divider()

    st.info(
        """
### What to do now

1. Click **Generate Google Sign-In Link**
2. Click **OPEN GOOGLE AUTHORIZATION**
3. Google login page will open
4. If the 403 page appears, take a screenshot
5. Send me that screenshot

Do not change your Google Cloud settings yet.
"""
    )

    st.divider()

    st.caption(
        "🛡️ PhishGuard AI | "
        "AI-powered Gmail phishing detection"
    )

    st.stop()


# =========================================================
# CONNECTED STATUS
# =========================================================

st.success(
    "🟢 Connected to Gmail"
)


# =========================================================
# REFRESH INBOX
# =========================================================

if st.button(
    "🔄 Refresh Inbox",
    use_container_width=True
):

    with st.spinner(
        "Fetching emails from Gmail..."
    ):

        try:

            emails = get_recent_emails(
                10
            )

            st.session_state[
                "emails"
            ] = emails

            st.success(
                f"Successfully fetched "
                f"{len(emails)} emails."
            )

        except Exception as e:

            st.error(
                "Unable to fetch Gmail emails."
            )

            st.exception(e)


# =========================================================
# EMAILS
# =========================================================

emails = st.session_state.get(
    "emails",
    []
)


if not emails:

    st.info(
        "📥 Click **🔄 Refresh Inbox** "
        "to fetch your Gmail emails."
    )


else:

    st.header(
        "📥 Gmail Inbox"
    )

    st.write(
        f"Showing {len(emails)} recent emails"
    )


    # =====================================================
    # ANALYZE EACH EMAIL
    # =====================================================

    for email in emails:

        sender = email.get(
            "sender",
            "Unknown Sender"
        )

        subject = email.get(
            "subject",
            "(No Subject)"
        )

        body = email.get(
            "body",
            ""
        )


        # -------------------------------------------------
        # AI ANALYSIS
        # -------------------------------------------------

        try:

            result = analyze_email(
                sender,
                subject,
                body
            )

        except Exception as e:

            st.error(
                f"Analysis failed for: {subject}"
            )

            st.exception(e)

            continue


        prediction = result.get(
            "prediction",
            "UNKNOWN"
        )

        risk_score = result.get(
            "risk_score",
            0
        )

        threat_level = result.get(
            "threat_level",
            "LOW"
        )

        confidence = result.get(
            "confidence",
            0
        )

        indicators = result.get(
            "indicators",
            []
        )

        warning = result.get(
            "warning",
            ""
        )

        urls = result.get(
            "urls",
            []
        )


        # -------------------------------------------------
        # DISPLAY STATUS
        # -------------------------------------------------

        if prediction == "PHISHING":

            icon = "🔴"

            title = "PHISHING"

            box_message = (
                "⚠️ **DON'T CLICK THIS MESSAGE**\n\n"
                "Do not enter your password or OTP."
            )


        elif threat_level in [
            "MEDIUM",
            "HIGH"
        ]:

            icon = "🟠"

            title = "SUSPICIOUS"

            box_message = (
                "⚠️ This email contains suspicious "
                "indicators. Check carefully before "
                "clicking links."
            )


        else:

            icon = "🟢"

            title = "SAFE"

            box_message = (
                "No major suspicious indicators detected."
            )


        # -------------------------------------------------
        # EMAIL CARD
        # -------------------------------------------------

        with st.container(
            border=True
        ):

            st.markdown(
                f"## {icon} {title}"
            )

            st.write(
                f"**From:** {sender}"
            )

            st.write(
                f"**Subject:** {subject}"
            )

            st.write(
                f"**Risk Score:** `{risk_score}/100`"
            )

            st.write(
                f"**Threat Level:** `{threat_level}`"
            )

            st.write(
                f"**ML Confidence:** `{confidence}%`"
            )


            # ------------------------------------------------
            # WARNING
            # ------------------------------------------------

            if prediction == "PHISHING":

                st.error(
                    box_message
                )

            elif threat_level in [
                "MEDIUM",
                "HIGH"
            ]:

                st.warning(
                    box_message
                )

            else:

                st.success(
                    box_message
                )


            # ------------------------------------------------
            # SECURITY INDICATORS
            # ------------------------------------------------

            if indicators:

                with st.expander(
                    "🔎 View Security Indicators"
                ):

                    for indicator in indicators:

                        st.write(
                            f"• {indicator}"
                        )


            # ------------------------------------------------
            # DETECTED URLS
            # ------------------------------------------------

            if urls:

                with st.expander(
                    "🔗 View Detected URLs"
                ):

                    for url in urls:

                        st.code(
                            url
                        )


            # ------------------------------------------------
            # WARNING DETAILS
            # ------------------------------------------------

            if warning:

                with st.expander(
                    "⚠️ Analysis Warning"
                ):

                    st.write(
                        warning
                    )


            # ------------------------------------------------
            # FULL EMAIL
            # ------------------------------------------------

            with st.expander(
                "📧 View Full Email"
            ):

                st.write(
                    f"**From:** {sender}"
                )

                st.write(
                    f"**Subject:** {subject}"
                )

                st.write(
                    f"**Date:** "
                    f"{email.get('date', '')}"
                )

                st.divider()

                st.text(
                    body[:5000]
                )


# =========================================================
# FOOTER
# =========================================================

st.divider()

st.caption(
    "🛡️ PhishGuard AI | "
    "AI-powered Gmail phishing detection"
)