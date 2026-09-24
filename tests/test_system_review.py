import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from secman_web_check.models import TargetResult, TargetStatus
from secman_web_check.system_review import ReviewOptions, _evidence, _parse, load_prompt
from secman_web_check.targets import normalize_target


def target_result():
    now = datetime.now(UTC)
    return TargetResult(
        normalize_target("https://example.com"),
        TargetStatus.SUCCESS,
        started_at=now,
        completed_at=now,
    )


def test_user_prompt_is_loaded_from_file(tmp_path):
    path = tmp_path / "prompt.txt"
    path.write_text("  custom system instructions\n", encoding="utf-8")
    assert load_prompt(path) == "custom system instructions"


def test_empty_prompt_is_rejected(tmp_path):
    path = tmp_path / "prompt.txt"
    path.write_text(" \n", encoding="utf-8")
    with pytest.raises(ValueError, match="must not be empty"):
        load_prompt(path)


def test_openrouter_json_becomes_attributed_finding():
    content = json.dumps(
        {
            "findings": [
                {
                    "category": "architecture gap",
                    "severity": "medium",
                    "title": "Review title",
                    "description": "Supported by evidence",
                    "evidence": "Observed metadata",
                    "recommendation": "Review configuration",
                    "confidence": 0.7,
                }
            ]
        }
    )
    findings = _parse(
        {"choices": [{"message": {"content": content}}]}, target_result(), "test/model"
    )
    assert findings[0].rule_id == "LLM-architecture-gap"
    assert findings[0].model == "test/model"
    assert findings[0].engine == "secman-web-check-openrouter"


def test_review_options_require_secret_and_https(tmp_path):
    with pytest.raises(ValueError, match="OPENROUTER_API_KEY"):
        ReviewOptions(tmp_path / "prompt", "")
    with pytest.raises(ValueError, match="HTTPS"):
        ReviewOptions(tmp_path / "prompt", "secret", base_url="http://example.com")


def test_packaged_prompts_cover_aws_and_secret_reviews():
    prompts = Path(__file__).parents[1] / "src" / "prompts"
    aws = load_prompt(prompts / "aws-security-review.txt")
    secrets = load_prompt(prompts / "secrets-security-review.txt")
    default = load_prompt(prompts / "system-review.txt")

    assert "awsAccountNumber" in aws
    assert "IAM" in aws
    assert "Never reconstruct" in secrets
    assert "JavaScript SHA-256" in secrets
    assert "AWS exposure" in default
    assert "secret-exposure" in default


def test_review_evidence_includes_aws_asset_binding():
    result = target_result()
    bound = replace(result.target, aws_account_number="111122223333")
    evidence = _evidence(replace(result, target=bound))

    assert evidence["awsAccountNumber"] == "111122223333"
