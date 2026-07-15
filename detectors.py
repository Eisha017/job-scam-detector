"""
Job Scam Detector — Step 4: Rule-Based Red-Flag Detectors
Each function scans a block of text and returns (flag: bool, matched_phrase: str|None).
These run BEFORE the LLM layer and give interpretable, testable signals.
"""

import re

# ---------------------------------------------------------------------------
# Individual detectors
# ---------------------------------------------------------------------------

def detect_upfront_fee(text):
    """Registration/training/equipment fee requests — the single biggest
    scam signal. Legitimate employers never ask candidates to pay."""
    patterns = [
        r"\bregistration fee\b",
        r"\bprocessing (?:fee|payment)\b",
        r"\btraining fee\b",
        r"\bstarter (?:kit|pack)\b",
        r"\bpurchase (?:your own |a )?equipment\b",
        r"\bpay(?:ment)? (?:is |will be )?required (?:before|to start)\b",
        r"\bactivation fee\b",
        r"\b(?:refundable |insurance )?deposit (?:is |will be )?required\b",
        r"\bbackground check\b.{0,40}\brequires?\b.{0,20}\bpayment\b",
        r"\blicensing fee\b",
    ]
    return _match_any(text, patterns)


def detect_offplatform_redirect(text):
    """Requests to move communication off the platform immediately —
    common tactic to avoid moderation/scam detection systems."""
    patterns = [
        r"\bwhatsapp\b",
        r"\btelegram\b",
        r"\bcontact (?:us |me )?(?:directly )?(?:at|via) (?:this )?(?:number|phone)\b",
        r"\btext (?:us|me) (?:directly|at)\b",
        r"\breach out (?:to us )?on (?:whatsapp|telegram|signal)\b",
    ]
    return _match_any(text, patterns)


def detect_urgency_language(text):
    """Artificial urgency/pressure — designed to short-circuit due diligence."""
    patterns = [
        r"\blimited (?:slots|spots|positions)\b",
        r"\bact (?:now|fast|quickly)\b",
        r"\bimmediate(?:ly)? (?:hiring|start|joining)\b",
        r"\brespond within \d+ (?:hour|minute)s?\b",
        r"\breply (?:within|in) \d+\b",
        r"\bhurry\b",
        r"\bonly \d+ (?:positions?|spots?|openings?) left\b",
    ]
    return _match_any(text, patterns)


def detect_instant_hire(text):
    """No interview / guaranteed hire language — legitimate roles have a process."""
    patterns = [
        r"\bno experience (?:needed|required|necessary)\b",
        r"\bhired instantly\b",
        r"\binstant(?:ly)? hired?\b",
        r"\bguaranteed (?:job|position|hire|income)\b",
        r"\bno interview(?:s)? (?:needed|required)\b",
        r"\bno (?:resume|calls?)[,]? no interviews?\b",
        r"\bhired on the spot\b",
        r"\beveryone who applies (?:gets accepted|is hired)\b",
    ]
    return _match_any(text, patterns)


def detect_sensitive_info_request(text):
    """Requests for bank/ID/SSN info before any formal offer — identity theft risk."""
    patterns = [
        r"\bsocial security number\b",
        r"\bssn\b",
        r"\bbank (?:account|routing) (?:number|details)\b",
        r"\bcredit card (?:number|details)\b",
        r"\bcopy of (?:your )?(?:id|passport|driver'?s license)\b",
        r"\brouting number\b",
    ]
    return _match_any(text, patterns)


def detect_vague_high_pay(text):
    """Vague job duties paired with unusually high pay promises."""
    patterns = [
        r"\bearn (?:up to )?\$\d{2,4}(?:\s?-\s?\$?\d{2,4})?\s*(?:a|per|/)\s*(?:day|week)\b",
        r"\bwork from home.{0,30}\$\d{2,4}\b",
        r"\bno skills? (?:needed|required)\b",
        r"\beasy money\b",
    ]
    return _match_any(text, patterns)


def detect_non_corporate_email(text):
    """Free-tier email domains used for what's presented as a corporate contact."""
    patterns = [
        r"\b[\w.+-]+@(?:gmail|yahoo|hotmail|outlook|aol)\.com\b",
    ]
    return _match_any(text, patterns)


def detect_roman_urdu_scam_patterns(text):
    """
    Catches common scam phrasing in Roman Urdu (Urdu written in Latin script),
    which is how most job-scam messages actually circulate on WhatsApp/Facebook
    in Pakistan -- a gap in every English-only detector. Covers the same
    archetypes as the English detectors above: upfront fees, off-platform
    redirect, urgency, instant hire, and sensitive info requests.
    """
    patterns = [
        # Upfront fee requests
        r"\bpehle\s+fees?\b",
        r"\badvance\s+fees?\s+(?:dein|den|dein)\b",
        r"\bregistration\s+fees?\s+(?:jama|bhej|dein)\b",
        r"\bfees?\s+jama\s+karwa",
        r"\bfees?\s+bhejein\b",

        # Off-platform redirect
        r"\bwhatsapp\s+p[ea]r?\s+contact\b",
        r"\bwhatsapp\s+p[ea]\s+message\b",
        r"\bwhatsapp\s+number\s+bhejein\b",

        # Urgency
        r"\bjaldi\s+karein\b",
        r"\bsirf\s+aaj\b",
        r"\bmehdood\s+nasheeten\b",  # limited seats
        r"\bforan\s+contact\b",

        # Instant hire / no interview
        r"\bbina\s+interview\b",
        r"\bforan\s+select\b",
        r"\binterview\s+ki\s+zaroorat\s+nahi\b",

        # Sensitive info requests
        r"\bcnic\s+(?:ki\s+copy\s+)?bhejein\b",
        r"\bshanakhti\s+card\b",
        r"\bbank\s+account\s+number\s+(?:dein|den)\b",
    ]
    return _match_any(text, patterns)


def detect_check_cashing_scam(text):
    """Mystery shopper / check-cashing / wire-back scams — victim deposits a
    fake check and wires part of it back before the check bounces."""
    patterns = [
        r"\bmystery shopper\b",
        r"\bsecret shopper\b",
        r"\bwire (?:the|remaining|balance)\b",
        r"\bdeposit the (?:enclosed|attached) check\b",
        r"\bcash(?:ing)? the check\b.{0,40}\bkeep\b",
        r"\bforward the rest (?:via|using) gift cards\b",
    ]
    return _match_any(text, patterns)


def detect_reshipping_mule(text):
    """Package reshipping / forwarding roles — a common money-mule and
    stolen-goods-laundering scam pattern."""
    patterns = [
        r"\breceive packages? (?:at|to) your (?:home|address)\b",
        r"\brepackage (?:them|it|products?)\b",
        r"\bforward (?:packages?|products?) using prepaid labels?\b",
        r"\bship (?:products?|packages?) to your home\b",
        r"\breshipping\b",
    ]
    return _match_any(text, patterns)


def detect_crypto_task_scam(text):
    """Task-based 'earn crypto' schemes that require a deposit/top-up before
    withdrawal — a fast-growing scam category."""
    patterns = [
        r"\busdt\b",
        r"\bcrypto rewards?\b",
        r"\baccount top-?up\b",
        r"\bunlock (?:higher|vip|premium) (?:paying )?tasks?\b",
        r"\bcomplet(?:e|ing) (?:simple )?tasks?.{0,30}earn\b",
    ]
    return _match_any(text, patterns)


def check_domain_typosquat(claimed_company_domain, sender_email_domain):
    """
    Catches the 'real company, fake recruiter' scam pattern: the job posting
    text itself is 100% legitimate (often copy-pasted from the real listing),
    but the person contacting you is using a look-alike domain instead of the
    company's real one — e.g. 'micros0ft-hr.com' or 'google-careers-team.com'
    instead of 'microsoft.com'.

    This CANNOT be caught from posting text alone — it requires the sender's
    actual email domain as separate input. Returns (is_suspicious, similarity_score).
    """
    from rapidfuzz import fuzz

    if not claimed_company_domain or not sender_email_domain:
        return False, None

    claimed = claimed_company_domain.lower().strip()
    sender = sender_email_domain.lower().strip()

    if claimed == sender:
        return False, None  # exact match, no issue

    # partial_ratio catches "brand name embedded in a longer fake domain"
    # (e.g. 'amazon-jobs-hr.net' contains 'amazon'), which is the most common
    # real-world pattern — better than plain ratio for this specific case.
    similarity = fuzz.partial_ratio(claimed, sender)

    if 65 <= similarity < 100:
        return True, similarity
    return False, similarity


# ---------------------------------------------------------------------------
# Helper + aggregator
# ---------------------------------------------------------------------------

def _match_any(text, patterns):
    if not isinstance(text, str):
        return False, None
    lowered = text.lower()
    for pat in patterns:
        m = re.search(pat, lowered, flags=re.IGNORECASE)
        if m:
            return True, m.group(0)
    return False, None


DETECTORS = {
    "upfront_fee": detect_upfront_fee,
    "offplatform_redirect": detect_offplatform_redirect,
    "urgency_language": detect_urgency_language,
    "instant_hire": detect_instant_hire,
    "sensitive_info_request": detect_sensitive_info_request,
    "vague_high_pay": detect_vague_high_pay,
    "non_corporate_email": detect_non_corporate_email,
    "check_cashing_scam": detect_check_cashing_scam,
    "reshipping_mule": detect_reshipping_mule,
    "crypto_task_scam": detect_crypto_task_scam,
    "roman_urdu_scam_patterns": detect_roman_urdu_scam_patterns,
}


def run_all_detectors(text):
    """Run every detector on a piece of text. Returns dict of
    {flag_name: (triggered: bool, matched_phrase: str|None)}."""
    return {name: fn(text) for name, fn in DETECTORS.items()}


def red_flag_count(text):
    """Quick summary: how many distinct red flags triggered."""
    results = run_all_detectors(text)
    return sum(1 for triggered, _ in results.values() if triggered)


if __name__ == "__main__":
    import pandas as pd

    df = pd.read_csv("data/cleaned_postings.csv")

    df["red_flag_count"] = df["full_text"].apply(red_flag_count)

    print("Average red flags triggered — fraud postings:")
    print(df[df["fraudulent"] == 1]["red_flag_count"].mean())
    print("\nAverage red flags triggered — legit postings:")
    print(df[df["fraudulent"] == 0]["red_flag_count"].mean())

    print("\nDistribution of red flag counts on FRAUD postings:")
    print(df[df["fraudulent"] == 1]["red_flag_count"].value_counts().sort_index())

    print("\nDistribution of red flag counts on LEGIT postings:")
    print(df[df["fraudulent"] == 0]["red_flag_count"].value_counts().sort_index())

    # Show a couple of individual flag breakdowns per detector
    print("\nPer-detector trigger rate (fraud vs legit):")
    for name, fn in DETECTORS.items():
        fraud_rate = df[df["fraudulent"] == 1]["full_text"].apply(lambda t: fn(t)[0]).mean()
        legit_rate = df[df["fraudulent"] == 0]["full_text"].apply(lambda t: fn(t)[0]).mean()
        print(f"  {name:25s} fraud={fraud_rate:.3f}  legit={legit_rate:.3f}")
