"""
Job Scam Detector — Quick test batch
Runs a handful of scam + legit postings through the full pipeline
(detectors + Gemini) to sanity-check accuracy before building the API.
"""

from analyzer import analyze_posting

TEST_CASES = [
    # --- Scam-style examples (should get high risk_score / "likely scam") ---
    {
        "label": "scam",
        "text": "Hiring now! Package Handler needed, earn $900/week from home. "
                "A one-time $50 registration fee is required to activate your account "
                "and receive your starter kit. Message us on Telegram to begin.",
    },
    {
        "label": "scam",
        "text": "URGENT: We need 5 Data Entry Clerks today. No interview, no resume, "
                "guaranteed hire. Reply within 1 hour with your bank account details "
                "for direct deposit setup.",
    },
    {
        "label": "scam",
        "text": "Mystery Shopper wanted in your city. We'll send a check for $2000 - "
                "keep $200 for yourself and wire the rest to our auditor to complete "
                "the assignment.",
    },
    # --- Legit-style examples (should get low risk_score / "likely legitimate") ---
    {
        "label": "legit",
        "text": "Backend Software Engineer - Full time, hybrid. 3+ years experience "
                "with Python or Java required. Competitive salary ($90k-$120k), "
                "health benefits, 401k. Apply through our careers page; our recruiting "
                "team will follow up within one week to schedule a technical interview.",
    },
    {
        "label": "legit",
        "text": "Retail Store Associate needed at our downtown location. Part-time, "
                "$16/hour, weekend availability required. Please apply in person or "
                "through Indeed; interviews conducted on-site.",
    },
    {
        "label": "legit",
        "text": "We are hiring a Registered Nurse for our pediatric unit. Must hold "
                "an active state license and BLS certification. Full benefits package. "
                "Submit your application via our hospital's HR portal; shortlisted "
                "candidates will be contacted for an in-person interview.",
    },
]


def main():
    correct = 0
    for i, case in enumerate(TEST_CASES, 1):
        print(f"\n{'='*70}")
        print(f"Test {i} [expected: {case['label']}]")
        print(f"Text: {case['text'][:80]}...")
        print("-" * 70)

        report = analyze_posting(case["text"])

        predicted = "scam" if report.verdict == "likely scam" else (
            "legit" if report.verdict == "likely legitimate" else "uncertain"
        )
        is_correct = predicted == case["label"]
        correct += is_correct

        print(f"Risk score: {report.risk_score}  |  Verdict: {report.verdict}")
        print(f"Match expected label? {'YES' if is_correct else 'NO -- CHECK THIS'}")
        if report.red_flags:
            print("Flags:", [f.signal for f in report.red_flags])
        if report.reassuring_signals:
            print("Reassuring signals:", report.reassuring_signals)

    print(f"\n{'='*70}")
    print(f"RESULT: {correct}/{len(TEST_CASES)} matched expected label")


if __name__ == "__main__":
    main()
