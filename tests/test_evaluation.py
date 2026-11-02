import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secman_web_check.cli import app
from secman_web_check.evaluation import evaluate

CORPUS = Path(__file__).parent / "fixtures/detection.json"


def test_labeled_corpus_measures_supported_classes_and_no_false_results():
    result = evaluate(CORPUS)
    assert result["passed"]
    assert len(result["cases"]) == 20
    assert set(result["perClass"]) == {
        "hsts",
        "csp",
        "cookies",
        "cors",
        "mixed-content",
        "components",
        "directory-listing",
        "debug-disclosure",
        "insecure-forms",
        "secret-signatures",
    }
    assert all(item["precision"] == item["recall"] == 1.0 for item in result["perClass"].values())


def test_measurements_expose_missed_detection_and_safe_fixture_false_positive(tmp_path):
    document = json.loads(CORPUS.read_text())
    document["cases"][0]["headers"] = [["strict-transport-security", "max-age=31536000"]]
    document["cases"][1]["headers"] = []
    path = tmp_path / "regression.json"
    path.write_text(json.dumps(document))
    result = evaluate(path)
    assert not result["passed"]
    assert result["perClass"]["hsts"]["fp"] == result["perClass"]["hsts"]["fn"] == 1
    output = tmp_path / "measurements.json"
    command = CliRunner().invoke(app, ["evaluate", str(path), "--output", str(output)])
    assert command.exit_code == 1
    assert json.loads(output.read_text())["passed"] is False


def test_corpus_cannot_omit_negative_fixtures(tmp_path):
    document = json.loads(CORPUS.read_text())
    document["cases"] = [item for item in document["cases"] if item["label"] == "vulnerable"]
    path = tmp_path / "positive-only.json"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="both vulnerable and safe"):
        evaluate(path)
