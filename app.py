import streamlit as st

from src.gmail_service import get_recent_emails
from src.risk_engine import analyze_email


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide"
)


# =========================================================
# HEADER
# =========================================================

st.title("🛡️ PhishGuard AI")

st.subheader(
    "Smart Gmail Phishing & Spam Detection System"
)

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
                f"Successfully fetched {len(emails)} emails."
            )

        except Exception as e:

            st.error(
                "Unable to fetch Gmail emails."
            )

            st.exception(e)


# =========================================================
# GET EMAILS
# =========================================================

emails = st.session_state.get(
    "emails",
    []
)


if not emails:

    st.info(
        "📥 Click **🔄 Refresh Inbox** "
        "to fetch emails from Gmail."
    )

else:

    st.header(
        "📥 Gmail Inbox"
    )

    st.write(
        f"Showing {len(emails)} recent emails"
    )


    # =====================================================
    # ANALYZE EMAILS
    # =====================================================

    for index, email in enumerate(
        emails,
        start=1
    ):

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


        # -------------------------------------------------
        # ANALYSIS
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


        prediction = result[
            "prediction"
        ]

        risk_score = result[
            "risk_score"
        ]

        threat_level = result[
            "threat_level"
        ]

        confidence = result[
            "confidence"
        ]

        indicators = result[
            "indicators"
        ]

        urls = result[
            "urls"
        ]

        url_risk = result[
            "url_risk"
        ]

        attack_type = result[
            "attack_type"
        ]

        warning = result[
            "warning"
        ]


        # =================================================
        # DISPLAY STYLE
        # =================================================

        if prediction == "PHISHING":

            icon = "🔴"

            title = "PHISHING"

        elif prediction == "SUSPICIOUS":

            icon = "🟠"

            title = "SUSPICIOUS"

        else:

            icon = "🟢"

            title = "SAFE"


        # =================================================
        # EMAIL CARD
        # =================================================

        with st.container(
            border=True
        ):

            # ------------------------------------------------
            # TITLE
            # ------------------------------------------------

            st.markdown(
                f"## {icon} {title}"
            )


            # ------------------------------------------------
            # BASIC INFORMATION
            # ------------------------------------------------

            st.write(
                f"**From:** {sender}"
            )

            st.write(
                f"**Subject:** {subject}"
            )

            st.write(
                f"**Date:** {date}"
            )


            # ------------------------------------------------
            # METRICS
            # ------------------------------------------------

            col1, col2, col3, col4 = st.columns(4)


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


            with col4:

                st.metric(
                    "Prediction",
                    prediction
                )


            # ------------------------------------------------
            # ATTACK TYPE
            # ------------------------------------------------

            st.write(
                f"**Attack Type:** {attack_type}"
            )


            # =================================================
            # WARNING
            # =================================================

            if prediction == "PHISHING":

                st.error(
                    f"⚠️ **DON'T CLICK THIS MESSAGE**\n\n"
                    f"Do not enter your password, OTP "
                    f"or banking information."
                )

            elif prediction == "SUSPICIOUS":

                st.warning(
                    "⚠️ **SUSPICIOUS EMAIL**\n\n"
                    "Check the sender and links carefully "
                    "before taking action."
                )

            else:

                st.success(
                    "🟢 **SAFE EMAIL**\n\n"
                    "No major suspicious indicators detected."
                )


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

            else:

                with st.expander(
                    "🔎 View Security Indicators"
                ):

                    st.write(
                        "No suspicious indicators detected."
                    )


            # =================================================
            # DETECTED URLS
            # =================================================

            with st.expander(
                "🔗 View Detected URLs"
            ):

                if urls:

                    st.write(
                        f"URL Risk: **{url_risk}/100**"
                    )

                    for url in urls:

                        st.code(
                            url
                        )

                else:

                    st.write(
                        "No URLs detected."
                    )


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
                    f"**Date:** {date}"
                )

                st.divider()

                st.text(
                    body[:10000]
                )


# =========================================================
# FOOTER
# =========================================================

st.divider()

st.caption(
    "🛡️ PhishGuard AI | "
    "AI-powered Gmail phishing detection"
)