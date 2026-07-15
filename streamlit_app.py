"""
Job Scam Detector — Streamlit Demo
Paste a job posting or recruiter message, get a structured scam risk report.

Calls the detection pipeline (analyzer.py) directly, in-process -- this
avoids needing a separately hosted backend for the public demo. The FastAPI
service (main.py) still exists in this repo for programmatic/API access
and demonstrates the service-layer architecture.
"""

import streamlit as st
from analyzer import analyze_posting

st.set_page_config(page_title="Job Scam Detector", page_icon="🛡️", layout="centered")

st.title("🛡️ Job Scam Detector")
st.write(
    "Paste a job posting, recruiter message, or WhatsApp text below. "
    "This tool checks it for common scam patterns using rule-based detection "
    "plus AI reasoning."
)

with st.form("analyze_form"):
    text = st.text_area(
        "Job posting / message text",
        height=200,
        placeholder="Paste the full job posting or recruiter message here...",
    )

    with st.expander("Optional: check for fake-recruiter impersonation"):
        st.caption(
            "If you know the real company's website domain and the domain the "
            "recruiter actually contacted you from, enter both to check for a "
            "look-alike/typosquatted domain -- this catches scams where the job "
            "posting text itself looks completely legitimate."
        )
        col1, col2 = st.columns(2)
        with col1:
            claimed_domain = st.text_input("Real company domain", placeholder="microsoft.com")
        with col2:
            sender_domain = st.text_input("Sender's actual domain", placeholder="micros0ft-hr.com")

    submitted = st.form_submit_button("Analyze", type="primary", use_container_width=True)

if submitted:
    if len(text.strip()) < 20:
        st.error("Please paste at least 20 characters of text to analyze.")
    else:
        kwargs = {}
        if claimed_domain.strip() and sender_domain.strip():
            kwargs["claimed_company_domain"] = claimed_domain.strip()
            kwargs["sender_email_domain"] = sender_domain.strip()

        with st.spinner("Analyzing..."):
            try:
                result = analyze_posting(text, **kwargs)
                report = result.model_dump()
            except Exception as e:
                st.error(f"Analysis failed: {e}")
                report = None

        if report:
            score = report["risk_score"]
            verdict = report["verdict"]

            if verdict == "likely scam":
                st.error(f"⚠️ **{verdict.upper()}** — Risk Score: {score}/100")
            elif verdict == "uncertain":
                st.warning(f"❓ **{verdict.upper()}** — Risk Score: {score}/100")
            else:
                st.success(f"✅ **{verdict.upper()}** — Risk Score: {score}/100")

            st.progress(score / 100)

            st.subheader("Summary")
            st.write(report["summary"])

            if report["red_flags"]:
                st.subheader("🚩 Red Flags Detected")
                for flag in report["red_flags"]:
                    matched = f' — *"{flag["matched_text"]}"*' if flag.get("matched_text") else ""
                    st.markdown(f"**{flag['signal']}**{matched}")
                    st.caption(flag["explanation"])

            if report["reassuring_signals"]:
                st.subheader("✅ Reassuring Signals")
                for signal in report["reassuring_signals"]:
                    st.markdown(f"- {signal}")

            st.info(f"💡 {report['safety_reminder']}")

st.divider()
st.caption(
    "This tool provides guidance, not a guarantee. Always verify job offers "
    "independently before sharing personal or financial information."
)
