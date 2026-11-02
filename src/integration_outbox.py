"""Durable, credential-free delivery queue for optional SecMan synchronization."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import random
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any


class DeliveryError(RuntimeError):
    def __init__(self, code: str, retryable: bool = False, retry_after: float = 0):
        super().__init__(code)
        self.retryable = retryable
        self.retry_after = min(max(retry_after, 0), 86400)


def canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


class Outbox:
    """One sender per queue; immutable requests survive ambiguous HTTP acknowledgements."""

    def __init__(self, directory: Path):
        directory = directory.expanduser()
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.is_symlink() or directory.stat().st_uid != os.getuid():
            raise ValueError("Queue must be a private directory owned by this user")
        directory.chmod(0o700)
        self.directory = directory
        path = directory / "delivery.sqlite"
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        path.chmod(0o600)
        self.db = sqlite3.connect(path, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute("""CREATE TABLE IF NOT EXISTS delivery (
            id TEXT PRIMARY KEY, destination TEXT NOT NULL, template TEXT NOT NULL,
            payload TEXT, state TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt REAL NOT NULL DEFAULT 0, error TEXT, acknowledgement TEXT,
            created REAL NOT NULL)""")
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def enqueue(self, destination: str, template: dict[str, Any]) -> str:
        encoded = canonical(template)
        if len(encoded.encode()) > 8 * 1024 * 1024:
            raise ValueError("Delivery exceeds 8 MiB; retain the local report")
        identity = hashlib.sha256((destination + "\0" + encoded).encode()).hexdigest()
        with self.db:
            if not self.db.execute("SELECT 1 FROM delivery WHERE id=?", (identity,)).fetchone():
                count, size = self.db.execute(
                    "SELECT count(*), coalesce(sum(length(template)),0) FROM delivery"
                ).fetchone()
                if count >= 1000 or size + len(encoded) > 256 * 1024 * 1024:
                    raise ValueError(
                        "Delivery queue capacity reached; archive acknowledged records first"
                    )
                self.db.execute(
                    "INSERT INTO delivery(id,destination,template,created) VALUES(?,?,?,?)",
                    (identity, destination, encoded, time.time()),
                )
        return identity

    def status(self) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.db.execute(
                "SELECT id,state,attempts,next_attempt,error,created FROM delivery ORDER BY created LIMIT 1000"
            )
        ]

    def quarantine(self, identity: str) -> None:
        """Retain a permanently failed request while explicitly unblocking later deliveries."""
        with self.db:
            changed = self.db.execute(
                "UPDATE delivery SET state='quarantined' WHERE id=? AND state='blocked'",
                (identity,),
            ).rowcount
            if changed != 1:
                raise ValueError("Only a blocked delivery can be quarantined")

    def retry(
        self,
        destination: str,
        prepare: Callable[[dict[str, Any]], dict[str, Any]],
        send: Callable[[dict[str, Any]], dict[str, Any]],
        *,
        resume: bool = False,
    ) -> list[dict[str, Any]]:
        fd = os.open(self.directory / "sender.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError("Another sender is processing this queue") from exc
            rows = self.db.execute(
                "SELECT * FROM delivery WHERE destination=? AND state NOT IN ('delivered','quarantined') ORDER BY created LIMIT 1000",
                (destination,),
            ).fetchall()
            blocked_scanners: set[int] = set()
            for row in rows:
                template = json.loads(row["template"])
                scanner = int(template["scannerId"])
                if scanner in blocked_scanners:
                    continue
                if not resume and (row["state"] == "blocked" or row["next_attempt"] > time.time()):
                    blocked_scanners.add(scanner)
                    continue
                try:
                    payload = json.loads(row["payload"]) if row["payload"] else prepare(template)
                    # Commit before HTTP: a crash must replay the identical body, even after rebinding.
                    if not row["payload"]:
                        with self.db:
                            self.db.execute(
                                "UPDATE delivery SET payload=? WHERE id=?",
                                (canonical(payload), row["id"]),
                            )
                    acknowledgement = send(payload)
                    if (
                        not isinstance(acknowledgement, dict)
                        or not isinstance(acknowledgement.get("id"), int)
                        or acknowledgement.get("scannerId") != payload.get("scannerId")
                        or acknowledgement.get("subjectId") != payload.get("subjectId")
                    ):
                        raise DeliveryError("invalid_acknowledgement", True)
                    with self.db:
                        self.db.execute(
                            "UPDATE delivery SET state='delivered',error=NULL,acknowledgement=?,attempts=attempts+1 WHERE id=?",
                            (canonical(acknowledgement), row["id"]),
                        )
                except DeliveryError as exc:
                    delay = max(
                        exc.retry_after,
                        min(3600, 2 ** min(row["attempts"] + 1, 11)) + random.uniform(0, 1),
                    )
                    with self.db:
                        self.db.execute(
                            "UPDATE delivery SET state=?,error=?,attempts=attempts+1,next_attempt=? WHERE id=?",
                            (
                                "pending" if exc.retryable else "blocked",
                                str(exc),
                                time.time() + delay,
                                row["id"],
                            ),
                        )
                    blocked_scanners.add(scanner)
            return self.status()
