"""Interruptible provider DNS resolution, including calls outside target workers."""

from __future__ import annotations

import multiprocessing
from time import monotonic
from typing import Any

from .targets import AddressPolicy, NormalizedTarget
from .targets import resolve_allowed as _resolve


def _worker(connection: Any, target: NormalizedTarget, policy: AddressPolicy) -> None:
    try:
        connection.send(_resolve(target, policy))
    except Exception:  # noqa: BLE001 - never return resolver-controlled exception details
        connection.send(None)
    finally:
        connection.close()


def resolve_allowed(
    target: NormalizedTarget, policy: AddressPolicy, deadline: float
) -> tuple[str, ...]:
    context = multiprocessing.get_context("spawn")
    reader, writer = context.Pipe(duplex=False)
    process = context.Process(target=_worker, args=(writer, target, policy))
    try:
        process.start()
        writer.close()
        if reader.poll(max(0.0, deadline - monotonic())):
            try:
                value = reader.recv()
            except EOFError:
                raise ValueError("provider DNS worker failed") from None
            if isinstance(value, tuple) and value and all(isinstance(item, str) for item in value):
                return value
        raise ValueError("provider DNS failed or timed out")
    finally:
        reader.close()
        writer.close()
        if process.pid is not None:
            if process.is_alive():
                process.kill()
            process.join(timeout=2)
            process.close()
