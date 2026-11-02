import pytest

from secman_web_check.integration_outbox import DeliveryError, Outbox


def test_timeout_after_acceptance_replays_exact_body_after_restart(tmp_path):
    path = tmp_path / "queue"
    queue = Outbox(path)
    key = queue.enqueue("https://secman.example.test", {"scannerId": 1, "report": "original"})
    sent = []

    def send(body):
        sent.append(body)
        raise DeliveryError("timeout", True)

    original = {"scannerId": 1, "subjectId": 2, "runKey": "immutable", "findings": []}
    queue.retry("https://secman.example.test", lambda item: original, send)
    queue.close()
    queue = Outbox(path)

    def no_remapping(item):
        raise AssertionError("An already prepared request must never be remapped")

    def accepted(body):
        sent.append(body)
        return {"id": 3, "scannerId": 1, "subjectId": 2, "replayed": True}

    rows = queue.retry("https://secman.example.test", no_remapping, accepted, resume=True)
    assert sent == [original, original]
    assert rows[0]["id"] == key and rows[0]["state"] == "delivered"
    queue.close()


def test_queue_destination_isolation_and_blocked_order(tmp_path):
    queue = Outbox(tmp_path / "queue")
    for scanner in (1, 1, 2):
        queue.enqueue(
            "https://one.example.test", {"scannerId": scanner, "value": len(queue.status())}
        )
    queue.enqueue("https://two.example.test", {"scannerId": 3})
    calls = []

    def send(body):
        calls.append(body["scannerId"])
        if body["scannerId"] == 1:
            raise DeliveryError("http_403")
        return {"id": 1, "scannerId": body["scannerId"], "subjectId": 2}

    queue.retry("https://one.example.test", lambda item: dict(item, subjectId=2), send)
    assert calls == [1, 2]
    rows = queue.status()
    assert [r["state"] for r in rows] == ["blocked", "pending", "delivered", "pending"]
    assert all("template" not in row and "payload" not in row for row in rows)
    queue.close()


def test_queue_rejects_symlink_and_oversize(tmp_path):
    (tmp_path / "link").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError):
        Outbox(tmp_path / "link")
    queue = Outbox(tmp_path / "queue")
    with pytest.raises(ValueError):
        queue.enqueue(
            "https://secman.example.test", {"scannerId": 1, "data": "x" * (8 * 1024 * 1024)}
        )
    assert not queue.status()
    queue.close()


def test_quarantine_retains_failed_record_and_unblocks_queue(tmp_path):
    queue = Outbox(tmp_path / "queue")
    first = queue.enqueue("https://example.com", {"scannerId": 1, "value": 1})
    second = queue.enqueue("https://example.com", {"scannerId": 1, "value": 2})

    def fail(body):
        raise DeliveryError("http_409")

    queue.retry("https://example.com", lambda item: dict(item, subjectId=2), fail)
    queue.quarantine(first)
    rows = queue.retry(
        "https://example.com",
        lambda item: dict(item, subjectId=2),
        lambda body: {"id": 1, "scannerId": 1, "subjectId": 2},
    )
    assert [(r["id"], r["state"]) for r in rows] == [(first, "quarantined"), (second, "delivered")]
    assert queue.db.execute("SELECT template FROM delivery WHERE id=?", (first,)).fetchone()
    with pytest.raises(ValueError):
        queue.quarantine(second)
    queue.close()
