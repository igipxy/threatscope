import pytest
from fastapi import HTTPException

from app.url_analysis import analyze_url_structure, normalize_url


def test_normalization_removes_fragment_and_credentials():
    normalized = normalize_url("https://user:secret@example.com/path#section")

    assert normalized == "https://example.com/path"


def test_malformed_port_is_rejected():
    with pytest.raises(HTTPException) as error:
        normalize_url("https://example.com:not-a-port/path")

    assert error.value.status_code == 422
    assert error.value.detail == "The URL must include a valid port."


def test_embedded_credentials_raise_url_risk():
    normalized = normalize_url("https://user@example.com/login")
    score, findings = analyze_url_structure("https://user@example.com/login", normalized)

    assert score >= 30
    assert any(finding.label == "Embedded credentials" for finding in findings)


def test_private_ip_url_is_blocked():
    normalized = normalize_url("http://127.0.0.1/admin")

    with pytest.raises(HTTPException) as error:
        analyze_url_structure("http://127.0.0.1/admin", normalized)

    assert error.value.status_code == 422


def test_phishing_style_url_gets_explainable_signals():
    target = "http://secure-login.verify.example.com/account/update"
    normalized = normalize_url(target)
    score, findings = analyze_url_structure(target, normalized)

    assert score >= 30
    labels = {finding.label for finding in findings}
    assert "Unencrypted connection" in labels
    assert "Sensitive-action wording" in labels
