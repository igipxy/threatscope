from datetime import datetime, timezone

from app.domain_intelligence import interpret_rdap, registrable_domain, validate_rdap_base_url


def test_recent_domain_is_a_high_risk_signal():
    payload = {
        "events": [{"eventAction": "registration", "eventDate": "2026-08-10T00:00:00Z"}],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}],
        "nameservers": [{"ldhName": "ns1.example.test"}],
    }

    score, findings = interpret_rdap(payload, now=datetime(2026, 8, 20, tzinfo=timezone.utc))

    assert score == 25
    assert any(item.label == "Domain registration age" and item.severity == "high" for item in findings)
    assert any(item.label == "Registrar" for item in findings)


def test_established_domain_does_not_add_risk():
    payload = {
        "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
    }

    score, findings = interpret_rdap(payload, now=datetime(2026, 8, 20, tzinfo=timezone.utc))

    assert score == 0
    assert any(item.label == "Domain registration age" and item.severity == "info" for item in findings)


def test_registrable_domain_uses_public_suffix_list():
    assert registrable_domain("login.accounts.example.co.uk") == "example.co.uk"


def test_rdap_base_rejects_non_https_and_private_addresses():
    for value in ("http://rdap.example", "https://127.0.0.1", "https://user@rdap.example"):
        try:
            validate_rdap_base_url(value)
        except ValueError:
            pass
        else:
            raise AssertionError(f"Unsafe RDAP URL was accepted: {value}")
