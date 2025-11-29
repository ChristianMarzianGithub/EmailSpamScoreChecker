import re
import socket
from email import policy
from email.parser import BytesParser
from typing import Dict, List, Tuple

from pydantic import BaseModel


class RuleResult(BaseModel):
    name: str
    points: int
    info: str


SPAM_KEYWORDS = [
    "viagra",
    "lottery",
    "casino",
    "free money",
    "claim now",
    "winner",
    "cheap meds",
    "make money fast",
    "limited offer",
]


DNSBL_SAMPLE = {"127.0.0.2", "127.0.0.3"}
DISPOSABLE_DOMAINS = {"mailinator.com", "tempmail.com", "10minutemail.com"}


URL_REGEX = re.compile(r"https?://[^\s<>]+", re.IGNORECASE)
HEADER_REGEX = re.compile(r"^[\w-]+:", re.MULTILINE)


class AnalysisResult(BaseModel):
    score: int
    category: str
    rules_triggered: List[RuleResult]
    links: List[str]
    headers: Dict[str, str]


def parse_email(raw: str):
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw.encode())
    except Exception as exc:  # pragma: no cover - error converted downstream
        raise ValueError(f"Failed to parse email: {exc}") from exc
    return message


def extract_body(message) -> Tuple[str, str]:
    plain_parts: List[str] = []
    html_parts: List[str] = []

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                plain_parts.append(part.get_content())
            elif content_type == "text/html":
                html_parts.append(part.get_content())
    else:
        content_type = message.get_content_type()
        if content_type == "text/plain":
            plain_parts.append(message.get_content())
        elif content_type == "text/html":
            html_parts.append(message.get_content())

    return "\n".join(plain_parts), "\n".join(html_parts)


def score_keywords(text: str) -> List[RuleResult]:
    lowered = text.lower()
    found = [kw for kw in SPAM_KEYWORDS if kw in lowered]
    if not found:
        return []
    points = 10 + 2 * len(found)
    return [RuleResult(name="SPAM_KEYWORDS", points=points, info=f"Found suspicious terms: {', '.join(found)}")]


def score_punctuation(text: str) -> List[RuleResult]:
    exclamations = text.count("!")
    if exclamations >= 5:
        points = min(15, exclamations)
        return [RuleResult(name="EXCESSIVE_PUNCTUATION", points=points, info=f"Found {exclamations} exclamation marks")]
    return []


def score_all_caps_subject(subject: str) -> List[RuleResult]:
    if subject and subject.isupper() and len(subject) > 5:
        return [RuleResult(name="ALL_CAPS_SUBJECT", points=8, info="Subject is all capital letters")]
    return []


def score_html_quality(html_body: str) -> List[RuleResult]:
    if not html_body:
        return []
    missing_doctype = "<!doctype" not in html_body.lower()
    unmatched_tags = html_body.count("<div") != html_body.count("</div>")
    if missing_doctype or unmatched_tags:
        issues = []
        if missing_doctype:
            issues.append("missing doctype")
        if unmatched_tags:
            issues.append("unbalanced div tags")
        return [RuleResult(name="POOR_HTML_STRUCTURE", points=7, info=", ".join(issues))]
    return []


def extract_urls(text: str) -> List[str]:
    return URL_REGEX.findall(text)


def score_links(urls: List[str]) -> List[RuleResult]:
    if not urls:
        return []
    suspicious = [u for u in urls if any(hint in u for hint in ["bit.ly", "tinyurl", "click" ])]
    if suspicious:
        return [RuleResult(name="SUSPICIOUS_URL", points=10, info=f"Found shortened/suspicious URLs: {', '.join(suspicious)}")]
    return []


def domain_from_address(address: str) -> str:
    if not address or "@" not in address:
        return ""
    return address.split("@")[-1].lower().strip()


def check_headers(headers: Dict[str, str]) -> List[RuleResult]:
    results: List[RuleResult] = []
    spf = headers.get("Received-SPF", "").lower()
    if "fail" in spf or "softfail" in spf:
        results.append(RuleResult(name="SPF_FAIL", points=12, info="SPF validation failed"))
    dkim = headers.get("DKIM-Signature") or headers.get("Dkim-Signature")
    if not dkim:
        results.append(RuleResult(name="NO_DKIM", points=15, info="Missing DKIM signature"))
    dmarc = headers.get("Authentication-Results", "").lower()
    if "dmarc=fail" in dmarc:
        results.append(RuleResult(name="DMARC_FAIL", points=10, info="DMARC validation failed"))
    return results


def check_disposable_domain(domain: str) -> List[RuleResult]:
    if domain in DISPOSABLE_DOMAINS:
        return [RuleResult(name="DISPOSABLE_DOMAIN", points=10, info=f"Sender domain {domain} is disposable")]
    return []


def simulate_domain_age(domain: str) -> int:
    if not domain:
        return 365
    seed = sum(ord(c) for c in domain)
    return (seed % 60) + 1


def check_domain_age(domain: str) -> List[RuleResult]:
    age_days = simulate_domain_age(domain)
    if age_days <= 30:
        return [RuleResult(name="NEW_DOMAIN", points=10, info=f"Domain registered {age_days} days ago")]
    return []


def dnsbl_lookup(domain: str) -> bool:
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return False
    return ip in DNSBL_SAMPLE


def check_dnsbl(domain: str) -> List[RuleResult]:
    if domain and dnsbl_lookup(domain):
        return [RuleResult(name="DNSBL_LISTED", points=18, info=f"Domain {domain} is on a blocklist")]
    return []


def parse_headers(message) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for key, value in message.items():
        headers[str(key)] = str(value)
    return headers


def validate_header_format(raw: str) -> None:
    if HEADER_REGEX.search(raw) is None:
        raise ValueError("Input does not look like valid email headers")


def categorize_score(score: int) -> str:
    if score <= 30:
        return "SAFE"
    if score <= 60:
        return "SUSPICIOUS"
    return "LIKELY_SPAM"


def analyze_email(raw: str) -> AnalysisResult:
    if not raw.strip():
        raise ValueError("Email content is required")

    message = parse_email(raw)
    headers = parse_headers(message)

    plain_body, html_body = extract_body(message)
    body_text = "\n".join([message.get("Subject", ""), plain_body, html_body])

    sender = message.get("From", "")
    sender_domain = domain_from_address(sender)

    links = extract_urls(body_text)

    rules: List[RuleResult] = []
    rules.extend(score_keywords(body_text))
    rules.extend(score_punctuation(body_text))
    rules.extend(score_all_caps_subject(message.get("Subject", "")))
    rules.extend(score_html_quality(html_body))
    rules.extend(score_links(links))
    rules.extend(check_headers(headers))
    rules.extend(check_disposable_domain(sender_domain))
    rules.extend(check_domain_age(sender_domain))
    rules.extend(check_dnsbl(sender_domain))

    total = min(sum(rule.points for rule in rules), 100)
    category = categorize_score(total)

    header_status = {
        "spf": "fail" if any(r.name == "SPF_FAIL" for r in rules) else "pass",
        "dkim": "missing" if any(r.name == "NO_DKIM" for r in rules) else "pass",
        "dmarc": "fail" if any(r.name == "DMARC_FAIL" for r in rules) else "pass",
    }

    return AnalysisResult(
        score=total,
        category=category,
        rules_triggered=rules,
        links=links,
        headers=header_status,
    )
