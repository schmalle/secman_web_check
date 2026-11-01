"""Shared provider privacy policy and bounded, pinned JSON requests."""

from __future__ import annotations

import json
from contextlib import nullcontext
from time import monotonic
from typing import Any

import httpx

from .http import pinned_transport, target_origin
from .provider_dns import resolve_allowed
from .targets import AddressPolicy, normalize_target
from .traffic import TrafficController

POLICY_VERSION = "sanitized-evidence-v1"
PROVIDER_POLICY = {"zdr": True, "data_collection": "deny", "require_parameters": True}


def post_json(
    base_url: str,
    api_key: str,
    body: dict[str, Any],
    timeout: float,
    traffic: TrafficController | None = None,
) -> dict[str, Any]:
    if len(json.dumps(body).encode()) > 3_000_000:
        raise ValueError("provider request exceeds size limit")
    provider = normalize_target(base_url)
    if provider.scheme != "https" or "?" in base_url:
        raise ValueError("provider must use HTTPS without a query")
    deadline = monotonic() + timeout
    with traffic.admit(target_origin(provider), "provider", deadline) if traffic else nullcontext():
        addresses = resolve_allowed(provider, AddressPolicy(), deadline)
        if monotonic() >= deadline:
            raise ValueError("provider deadline exceeded")
        with (
            httpx.Client(
                headers={"Authorization": f"Bearer {api_key}"},
                transport=pinned_transport(provider, addresses, deadline=deadline),
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client,
            client.stream(
                "POST",
                base_url.rstrip("/") + "/chat/completions",
                json={**body, "provider": PROVIDER_POLICY},
            ) as response,
        ):
            response.raise_for_status()
            raw = bytearray()
            for chunk in response.iter_bytes(chunk_size=16384):
                raw.extend(chunk)
                if len(raw) > 65536 or monotonic() >= deadline:
                    raise ValueError("provider response budget exceeded")
            result = json.loads(raw)
    if not isinstance(result, dict):
        raise TypeError("invalid provider response")
    return result
