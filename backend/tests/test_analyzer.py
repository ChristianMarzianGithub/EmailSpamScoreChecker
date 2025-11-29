import pytest

from app import analyzer


SAMPLE_EMAIL = """From: spammer@mailinator.com\nSubject: WINNER WINNER\n\nClaim now for free money!!! Visit http://bit.ly/spammy\n"""


def test_analyze_email_returns_score_and_category():
    result = analyzer.analyze_email(SAMPLE_EMAIL)
    assert result.score > 0
    assert result.category in {"SAFE", "SUSPICIOUS", "LIKELY_SPAM"}
    assert any(rule.name == "SPAM_KEYWORDS" for rule in result.rules_triggered)


def test_empty_email_raises_value_error():
    with pytest.raises(ValueError):
        analyzer.analyze_email("")


def test_header_validation_rejects_invalid_headers():
    with pytest.raises(ValueError):
        analyzer.validate_header_format("No headers here")


def test_domain_age_and_disposable_detection():
    domain = "mailinator.com"
    results = analyzer.check_disposable_domain(domain)
    assert results
    age_result = analyzer.check_domain_age(domain)
    assert age_result[0].points == 10


def test_suspicious_links_detected():
    urls = analyzer.extract_urls(SAMPLE_EMAIL)
    link_rules = analyzer.score_links(urls)
    assert link_rules
