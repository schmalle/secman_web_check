"""Shared report serialization and atomic file output."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from ..models import BrowserHttpObservation, BrowserNavigationDiagnostic, ExposureObservation

_FLAG_LABELS = {True: "Yes", False: "No", None: "Unknown"}


def flag_label(value: bool | None) -> str:
    return _FLAG_LABELS[value]


def redirect_label(exposure: ExposureObservation | None) -> str:
    return flag_label(exposure.redirect_followed if exposure is not None else None)


def browser_navigation_label(
    observed: bool | None, diagnostic: BrowserNavigationDiagnostic | None
) -> str:
    if diagnostic is None:
        return "Not checked" if observed is None else flag_label(observed)
    if diagnostic.reason == "blocked-origin":
        return f"Attempted → {diagnostic.hostname} · blocked by scanner policy"
    if diagnostic.reason == "blocked-http-redirect":
        return f"HTTP redirect → {diagnostic.hostname} · blocked by scanner policy"
    if diagnostic.reason == "script-failure":
        return f"{flag_label(observed)} · page scripts failed to load or run"
    if diagnostic.reason == "browser-limit":
        return "Inconclusive · browser redirect limit or deadline reached"
    return "Inconclusive · browser navigation could not be verified"


def browser_http_label(observation: BrowserHttpObservation | None) -> str:
    if observation is None:
        return "Not checked"
    if observation.status_code is None:
        return "Inconclusive"
    if observation.redirect_hostname is not None:
        return f"HTTP {observation.status_code} → {observation.redirect_hostname}"
    return f"HTTP {observation.status_code} · no redirect"


def atomic_write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return path
