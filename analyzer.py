"""
Job Scam Detector — Step 8: Gemini Reasoning Layer
Pipeline: raw text -> rule-based detectors -> feed both to Gemini -> structured
ScamReport. Giving Gemini the rule-based flags as CONTEXT (not asking it to
detect cold) makes the reasoning more grounded and defensible.
Uses Gemini's native response_schema support for clean structured output.
"""

import os
import json
import time
from google import genai
from google.genai import types
from google.genai import errors
from dotenv import load_dotenv

from detectors import run_all_detectors, check_domain_typosquat
from schema import ScamReport

load_dotenv()

client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

SAFETY_REMINDER = (
    "Even a clean-looking posting can turn into a scam later in the process. "
    "Legitimate employers never ask for payment, banking details, or ID copies "
    "at any stage before you're formally, verifiably employed -- re-check if "
    "anything like that comes up as things progress."
)

SYSTEM_PROMPT = """You are a job-scam detection assistant. You will be given:
1. The raw text of a job posting or recruiter message
2. A list of red flags already detected by a rule-based system (may be empty)

Your job is to reason over BOTH the raw text and the pre-detected flags to
produce a final risk assessment. Do not just repeat the rule-based flags —
also read the text yourself for signals the rules might have missed
(vague duties, unrealistic pay-to-effort ratio, pressure tactics, requests
that don't match how real hiring processes work)."""


def build_user_message(text, rule_based_flags, domain_check=None):
    triggered = {
        name: matched for name, (flagged, matched) in rule_based_flags.items() if flagged
    }
    domain_note = ""
    if domain_check is not None:
        is_suspicious, similarity = domain_check
        if is_suspicious:
            domain_note = (
                f"\n\nIMPORTANT: The sender's email domain looks suspiciously similar "
                f"to the real company's domain but does NOT match it exactly "
                f"(similarity: {similarity:.0f}%). This is a strong sign of a fake "
                f"recruiter impersonating a real company -- treat this as a major red flag "
                f"even if the job posting text itself looks completely legitimate."
            )

    return f"""JOB POSTING / MESSAGE TEXT:
---
{text}
---

RULE-BASED FLAGS ALREADY DETECTED:
{json.dumps(triggered, indent=2) if triggered else "None triggered."}
{domain_note}

Analyze this and produce a risk assessment."""


def analyze_posting(
    text: str,
    max_retries: int = 3,
    claimed_company_domain: str | None = None,
    sender_email_domain: str | None = None,
) -> ScamReport:
    """
    claimed_company_domain / sender_email_domain: OPTIONAL. If you know the
    real company's domain (e.g. 'microsoft.com') and the domain the recruiter
    actually emailed/messaged you from, pass both to catch the 'real company,
    fake recruiter' scam pattern -- this is invisible from posting text alone.
    """
    rule_based_flags = run_all_detectors(text)

    domain_check = None
    if claimed_company_domain and sender_email_domain:
        domain_check = check_domain_typosquat(claimed_company_domain, sender_email_domain)

    user_message = build_user_message(text, rule_based_flags, domain_check)

    last_error = None
    for attempt in range(max_retries):
        try:
            response = client.models.generate_content(
                model="gemini-flash-latest",
                contents=user_message,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    response_mime_type="application/json",
                    response_schema=ScamReport,
                ),
            )
            if response.parsed is not None:
                report = response.parsed
            else:
                report = ScamReport(**json.loads(response.text))

            report.safety_reminder = SAFETY_REMINDER
            return report

        except errors.ServerError as e:
            last_error = e
            wait_time = 2 ** attempt  # 1s, 2s, 4s
            print(f"  [Server busy, retrying in {wait_time}s... attempt {attempt + 1}/{max_retries}]")
            time.sleep(wait_time)

    raise last_error


if __name__ == "__main__":
    test_posting = (
        "Congratulations! You have been shortlisted for a Data Entry position. "
        "Salary $35/hour, work from home, flexible hours. To proceed please "
        "message our HR manager directly on WhatsApp +1 302 555 0187 to receive "
        "your offer letter and training material."
    )

    report = analyze_posting(test_posting)
    print(report.model_dump_json(indent=2))

