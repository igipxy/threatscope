import json
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.url_analysis import analyze_url_structure, normalize_url


FIXTURES = json.loads(
    (Path(__file__).parent / "fixtures" / "scoring_v1.json").read_text(encoding="utf-8-sig")
)


@pytest.mark.parametrize("case", FIXTURES["cases"], ids=lambda case: case["name"])
def test_versioned_scoring_fixture(case):
    normalized = normalize_url(case["target"])

    if case.get("blocked"):
        with pytest.raises(HTTPException) as error:
            analyze_url_structure(case["target"], normalized)
        assert error.value.status_code == 422
        return

    score, findings = analyze_url_structure(case["target"], normalized)
    labels = {finding.label for finding in findings}

    assert score >= case["minimum_score"]
    assert set(case["expected_labels"]).issubset(labels)
