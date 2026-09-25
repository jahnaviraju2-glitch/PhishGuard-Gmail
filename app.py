import streamlit as st

from src.gmail_service import (
    get_authorization_url,
    handle_oauth_callback,
    get_recent_emails
)

from src.risk_engine import analyze_email


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# PRIVACY POLICY PAGE
# ============================================================

if st.query_params.get("page") == "privacy":

    st.title("🛡️ PhishGuard AI – Privacy Policy")

    st.caption("Last updated: September 25, 2026")

    st.markdown("""
## 1. Information We Access

PhishGuard AI requests read-only access to Gmail
messages when the user chooses to connect a Google
Gmail account.

The application may access email metadata and
message content required to analyze messages for
phishing and spam indicators.

## 2. How We Use Google User Data

Gmail data is used only to provide phishing and
spam detection functionality.

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

The application processes Gmail information only
as necessary for the requested analysis.

The application does not intentionally maintain
a separate permanent database of users' Gmail
message content.

## 4. Data Sharing

PhishGuard AI does not sell or rent Google user data.

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
""")

    st.stop()


# ============================================================
# HANDLE GOOGLE OAUTH CALLBACK
# ============================================================

if "gmail_token" not in st.session_state:

    try:

        handle_oauth_callback()

    except Exception as e:

        st.error("Google authentication failed.")

        st.exception(e)


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ PhishGuard AI")

st.subheader(
    "Smart Gmail Phishing & Spam Detection System"
)
# =========================================================
# GOOGLE LOGIN
# =========================================================

if "gmail_token" not in st.session_state:

    st.warning(
        "🔐 Please connect your Gmail account "
        "to analyze emails."
    )

    if st.button(
        "🔐 Sign in with Google",
        use_container_width=True
    ):

        try:

            auth_url = get_authorization_url()

            st.link_button(
                "Continue with Google",
                auth_url,
                use_container_width=True
            )

        except Exception as e:

            st.error(
                "Unable to start Google authentication."
            )

            st.exception(e)

    st.divider()

    st.caption(
        "🔒 Gmail access uses read-only permission."
    )

    st.stop()


# ============================================================
# GMAIL CONNECTED
# ============================================================

st.success("🟢 Gmail Connected Successfully")


# ============================================================
# REFRESH EMAILS
# ============================================================

if st.button(
    "🔄 Fetch Recent Emails",
    use_container_width=True
):

    with st.spinner(
        "Fetching emails from Gmail..."
    ):

        try:

            emails = get_recent_emails(
                max_results=10
            )

            st.session_state["emails"] = emails

            st.success(
                f"{len(emails)} emails fetched successfully."
            )

        except Exception as e:

            st.error(
                "Unable to fetch Gmail emails."
            )

            st.exception(e)


# ============================================================
# GET EMAILS FROM SESSION
# ============================================================

emails = st.session_state.get(
    "emails",
    []
)


# ============================================================
# NO EMAILS
# ============================================================

if not emails:

    st.info(
        "📥 Click **Fetch Recent Emails** to load "
        "your Gmail messages."
    )


# ============================================================
# DISPLAY EMAILS
# ============================================================

else:

    st.header("📧 Email Security Analysis")

    st.write(
        f"Analyzing {len(emails)} recent emails"
    )

    for index, email in enumerate(emails):

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

        date = email.get(
            "date",
            ""
        )


        # ====================================================
        # ANALYZE EMAIL
        # ====================================================

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


        # ====================================================
        # GET ANALYSIS RESULT
        # ====================================================

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

        urls = result.get(
            "urls",
            []
        )

        attack_type = result.get(
            "attack_type",
            "Unknown"
        )

        warning = result.get(
            "warning",
            ""
        )


        # ====================================================
        # THREAT DISPLAY
        # ====================================================

        if prediction == "PHISHING":

            icon = "🔴"

            label = "PHISHING"

            message = (
                "⚠️ This email contains indicators "
                "associated with phishing."
            )

        elif (
            threat_level == "SUSPICIOUS"
            or threat_level == "MEDIUM"
        ):

            icon = "🟠"

            label = "SUSPICIOUS"

            message = (
                "⚠️ This email contains suspicious "
                "security indicators."
            )

        else:

            icon = "🟢"

            label = "SAFE"

            message = (
                "No major phishing indicators "
                "were detected."
            )


        # ====================================================
        # EMAIL CARD
        # ====================================================

        with st.container(border=True):

            st.markdown(
                f"## {icon} {label}"
            )

            st.write(
                f"**From:** {sender}"
            )

            st.write(
                f"**Subject:** {subject}"
            )

            if date:

                st.write(
                    f"**Date:** {date}"
                )


            # =================================================
            # SCORE COLUMNS
            # =================================================

            col1, col2, col3 = st.columns(3)

            with col1:

                st.metric(
                    "Risk Score",
                    f"{risk_score}/100"
                )

            with col2:

                st.metric(
                    "Threat Level",
                    threat_level
                )

            with col3:

                st.metric(
                    "ML Confidence",
                    f"{confidence}%"
                )


            # =================================================
            # RESULT MESSAGE
            # =================================================

            if prediction == "PHISHING":

                st.error(message)

            elif label == "SUSPICIOUS":

                st.warning(message)

            else:

                st.success(message)


            # =================================================
            # ATTACK TYPE
            # =================================================

            if attack_type and attack_type != "Unknown":

                st.write(
                    f"🎯 **Possible Attack Type:** "
                    f"{attack_type}"
                )


            # =================================================
            # SECURITY INDICATORS
            # =================================================

            if indicators:

                with st.expander(
                    "🔎 Security Indicators"
                ):

                    for indicator in indicators:

                        st.write(
                            f"• {indicator}"
                        )


            # =================================================
            # DETECTED URLS
            # =================================================

            if urls:

                with st.expander(
                    "🔗 Detected URLs"
                ):

                    for url in urls:

                        st.code(
                            url
                        )


            # =================================================
            # WARNING
            # =================================================

            if warning:

                with st.expander(
                    "⚠️ Analysis Details"
                ):

                    st.write(
                        warning
                    )


            # =================================================
            # FULL EMAIL
            # =================================================

            with st.expander(
                "📨 View Full Email"
            ):

                st.write(
                    f"**From:** {sender}"
                )

                st.write(
                    f"**Subject:** {subject}"
                )

                if date:

                    st.write(
                        f"**Date:** {date}"
                    )

                st.divider()

                if body:

                    st.text(
                        body[:10000]
                    )

                else:

                    st.info(
                        "No email body available."
                    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "🛡️ PhishGuard AI | "
    "AI-powered Gmail phishing & spam detection"
)

st.markdown(
    """
<center>
<a href="?page=privacy">
Privacy Policy
</a>
</center>
""",
    unsafe_allow_html=True
)