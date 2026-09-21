import streamlit as st

from src.gmail_service import (
    get_recent_emails,
    get_authorization_url,
    handle_oauth_callback
)

from src.risk_engine import analyze_email


st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide"
)


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
            # URLs
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