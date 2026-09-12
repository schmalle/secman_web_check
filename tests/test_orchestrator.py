from datetime import UTC, datetime

from secman_web_check.config import ScannerConfig
from secman_web_check.models import TargetResult, TargetStatus
from secman_web_check.orchestrator import scan_all
from secman_web_check.targets import normalize_target


def test_batch_preserves_input_order_and_isolates_failure(monkeypatch):
    targets = (normalize_target("https://bad.example"), normalize_target("https://good.example"))

    def fake_scan(target, _config):
        if target.host == "bad.example":
            raise RuntimeError("secret upstream detail")
        now = datetime.now(UTC)
        return TargetResult(target, TargetStatus.SUCCESS, started_at=now, completed_at=now)

    monkeypatch.setattr("secman_web_check.orchestrator.scan_target", fake_scan)
    run = scan_all(targets, ScannerConfig(concurrency=2))
    assert [result.target.host for result in run.targets] == ["bad.example", "good.example"]
    assert [result.status for result in run.targets] == [TargetStatus.FAILED, TargetStatus.SUCCESS]
    assert "secret" not in repr(run)
