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

    st.title("🛡️ PhishGuard AI – Privacy Policy")

    st.caption("Last updated: September 25, 2026")

    st.write(
        """
        PhishGuard AI is a project that helps users analyze Gmail messages
        for potential phishing and spam threats. This Privacy Policy explains
        how PhishGuard AI accesses and uses information when a user chooses
        to connect a Google Gmail account.
        """
    )

    st.header("1. Information We Access")

    st.write(
        """
        When you choose to connect Gmail, PhishGuard AI requests read-only
        access to Gmail messages using the Google Gmail API. The application
        may access email metadata and message content needed to analyze
        messages for phishing and spam indicators.
        """
    )

    st.header("2. How We Use Google User Data")

    st.write(
        """
        Gmail data accessed by PhishGuard AI is used only to provide the
        application's phishing and spam analysis features. The data may be
        processed to identify suspicious links, keywords, sender information,
        message patterns, and other security indicators.

        PhishGuard AI does not use Google user data for advertising,
        targeted advertising, or selling data to third parties.
        """
    )

    st.header("3. Data Storage")

    st.write(
        """
        PhishGuard AI is designed to process Gmail information only as
        needed for the requested analysis. The application does not
        intentionally maintain a separate permanent database of users'
        Gmail message content.

        OAuth credentials or access tokens, where temporarily required,
        are handled for authentication and authorization purposes.
        """
    )

    st.header("4. Data Sharing")

    st.write(
        """
        PhishGuard AI does not sell or rent Google user data. Gmail data
        is not shared with advertisers or data brokers.

        Data may be processed by technical services used to operate the
        application only when necessary to provide the requested
        functionality.
        """
    )

    st.header("5. Google API Services User Data Policy")

    st.write(
        """
        PhishGuard AI's use and transfer of information received from
        Google APIs will comply with the Google API Services User Data
        Policy, including its Limited Use requirements.
        """
    )

    st.markdown(
        "[Google API Services User Data Policy]"
        "(https://developers.google.com/terms/api-services-user-data-policy)"
    )

    st.header("6. User Control and Revoking Access")

    st.write(
        """
        Users can stop using the application at any time. Google account
        access granted to PhishGuard AI can also be revoked through the
        user's Google Account security settings.
        """
    )

    st.header("7. Security")

    st.write(
        """
        Reasonable technical measures are used to protect information
        handled by the application. However, no internet-based service
        can guarantee absolute security.
        """
    )

    st.header("8. Children's Privacy")

    st.write(
        """
        PhishGuard AI is not specifically directed toward children under
        the age of 13 and does not knowingly collect personal information
        from children under 13.
        """
    )

    st.header("9. Changes to This Privacy Policy")

    st.write(
        """
        This Privacy Policy may be updated when the application's
        functionality or data practices change. The latest version will
        be published on this page with an updated date.
        """
    )

    st.header("10. Contact")

    st.write(
        """
        If you have questions about this Privacy Policy or PhishGuard AI's
        data practices, contact:
        """
    )

    st.markdown(
        "**Email:** [jahnaviraju2@gmail.com]"
        "(mailto:jahnaviraju2@gmail.com)"
    )

    st.divider()

    st.caption(
        "🛡️ PhishGuard AI | "
        "AI-powered Gmail phishing detection"
    )

    st.stop()


# =========================================================
# HANDLE GOOGLE OAUTH CALLBACK
# =========================================================

if "gmail_token" not in st.session_state:

    try:
        handle_oauth_callback()

    except Exception as e:

        st.error("Google authentication failed.")
        st.exception(e)


# =========================================================
# HEADER
# =========================================================

st.title("🛡️ PhishGuard AI")

st.subheader(
    "Smart Gmail Phishing & Spam Detection System"
)


# =========================================================
# GMAIL CONNECTION
# =========================================================

if not st.session_state.get("gmail_token"):

    st.warning(
        "🔐 Gmail access is required to analyze your inbox."
    )

    if st.button(
        "🔑 Sign in with Google",
        use_container_width=True
    ):

        try:

            auth_url = get_authorization_url()

            st.markdown(
                f"""
                <meta http-equiv="refresh"
                content="0; url={auth_url}">
                """,
                unsafe_allow_html=True
            )

            st.info(
                "Redirecting to Google sign-in..."
            )

        except Exception as e:

            st.error(
                "Unable to start Google authentication."
            )

            st.exception(e)

    st.divider()

    st.caption(
        "🛡️ PhishGuard AI | "
        "AI-powered Gmail phishing detection"
    )

    st.stop()


# =========================================================
# CONNECTED STATUS
# =========================================================

st.success("🟢 Connected to Gmail")


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

            emails = get_recent_emails(10)

            st.session_state["emails"] = emails

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

    st.header("📥 Gmail Inbox")

    st.write(
        f"Showing {len(emails)} recent emails"
    )


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


        # =================================================
        # AI ANALYSIS
        # =================================================

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


        prediction = result["prediction"]

        risk_score = result["risk_score"]

        threat_level = result["threat_level"]

        confidence = result["confidence"]

        indicators = result["indicators"]

        warning = result["warning"]

        urls = result["urls"]


        # =================================================
        # DISPLAY STATUS
        # =================================================

        if prediction == "PHISHING":

            icon = "🔴"

            title = "PHISHING"

            box_message = (
                "⚠️ **DON'T CLICK THIS MESSAGE**\n\n"
                "Do not enter your password or OTP."
            )


        elif threat_level == "MEDIUM":

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


        # =================================================
        # EMAIL CARD
        # =================================================

        with st.container(border=True):

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


            # =================================================
            # WARNING
            # =================================================

            if prediction == "PHISHING":

                st.error(box_message)

            elif threat_level == "MEDIUM":

                st.warning(box_message)

            else:

                st.success(box_message)


            # =================================================
            # SECURITY INDICATORS
            # =================================================

            if indicators:

                with st.expander(
                    "🔎 View Security Indicators"
                ):

                    for indicator in indicators:

                        st.write(
                            f"• {indicator}"
                        )


            # =================================================
            # URLS
            # =================================================

            if urls:

                with st.expander(
                    "🔗 View Detected URLs"
                ):

                    for url in urls:

                        st.code(url)


            # =================================================
            # FULL EMAIL
            # =================================================

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