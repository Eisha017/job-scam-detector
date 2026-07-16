"""
Job Scam Detector — URL Content Fetcher
Given a URL, fetches the page and extracts visible text so it can be fed
into the same analysis pipeline as pasted text.

Known limitation, stated honestly: LinkedIn and some other sites actively
block non-browser requests and require JavaScript rendering -- fetching
those will likely fail. This works well for company career pages, most
smaller job boards, and general web pages.
"""

import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

MAX_CONTENT_BYTES = 2_000_000  # 2MB cap, avoid downloading huge/unexpected files
REQUEST_TIMEOUT = 10  # seconds

# Basic safety: only allow http/https, and block obvious internal/private
# targets so this can't be abused to probe internal network addresses if
# deployed publicly (SSRF protection).
BLOCKED_HOST_PATTERNS = [
    r"^localhost$",
    r"^127\.",
    r"^0\.0\.0\.0$",
    r"^10\.",
    r"^192\.168\.",
    r"^172\.(1[6-9]|2\d|3[01])\.",
    r"^169\.254\.",  # link-local, catches cloud metadata endpoints
]


def _is_safe_url(url: str) -> tuple[bool, str]:
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Could not parse this as a valid URL."

    if parsed.scheme not in ("http", "https"):
        return False, "Only http:// and https:// URLs are supported."

    hostname = parsed.hostname or ""
    for pattern in BLOCKED_HOST_PATTERNS:
        if re.match(pattern, hostname):
            return False, "This URL points to a local/internal address and can't be fetched."

    return True, ""


def fetch_job_posting_text(url: str) -> tuple[bool, str]:
    """
    Returns (success, text_or_error_message).
    On success, text_or_error_message is the extracted page text.
    On failure, it's a human-readable explanation of what went wrong.
    """
    is_safe, reason = _is_safe_url(url)
    if not is_safe:
        return False, reason

    headers = {
        # A realistic browser user-agent -- many sites block requests with
        # no user-agent or an obvious bot-like one outright.
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
    }

    try:
        response = requests.get(
            url, headers=headers, timeout=REQUEST_TIMEOUT, stream=True
        )
    except requests.exceptions.Timeout:
        return False, "The site took too long to respond (timed out after 10 seconds)."
    except requests.exceptions.ConnectionError:
        return False, "Could not connect to this URL. Check that it's correct and publicly accessible."
    except requests.exceptions.RequestException as e:
        return False, f"Could not fetch this URL: {e}"

    if response.status_code == 403:
        return False, (
            "This site blocked the request (403 Forbidden). Sites like LinkedIn "
            "actively block automated fetching -- please copy and paste the "
            "posting text directly instead."
        )
    if response.status_code == 999:
        # LinkedIn's specific anti-scraping status code
        return False, (
            "LinkedIn blocks automated access to its pages. Please copy and "
            "paste the posting text directly instead."
        )
    if response.status_code != 200:
        return False, f"The site returned an error (HTTP {response.status_code})."

    content_length = int(response.headers.get("content-length", 0))
    if content_length > MAX_CONTENT_BYTES:
        return False, "This page is too large to analyze."

    content_type = response.headers.get("content-type", "")
    if "text/html" not in content_type:
        return False, "This URL doesn't point to a normal web page (not HTML content)."

    try:
        soup = BeautifulSoup(response.text, "html.parser")
    except Exception as e:
        return False, f"Could not parse this page's content: {e}"

    # Strip script/style tags -- their text isn't real page content
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    text = soup.get_text(separator=" ")
    text = " ".join(text.split())  # normalize whitespace

    if len(text.strip()) < 50:
        return False, (
            "Very little text was found on this page. It may require "
            "JavaScript to load its content (common on LinkedIn and some "
            "modern job boards) -- please copy and paste the posting text "
            "directly instead."
        )

    # Detect login/auth walls -- sites like LinkedIn often return a 200 OK
    # with a "sign in to view this" page instead of an error, which would
    # otherwise get fed to the LLM as if it were real job content.
    login_wall_indicators = [
        "sign in to linkedin", "join now to view", "welcome back",
        "email or phone", "forgot password", "new to linkedin",
        "sign in or join now", "please log in to continue",
        "create your account to continue",
    ]
    lowered_check = text.lower()
    matches = sum(1 for phrase in login_wall_indicators if phrase in lowered_check)
    if matches >= 2:
        return False, (
            "This page returned a login/sign-in wall instead of the actual "
            "posting content (common on LinkedIn for non-logged-in visitors). "
            "Please copy and paste the posting text directly instead."
        )

    return True, text
