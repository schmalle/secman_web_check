"""Bounded OpenAPI metadata inventory; operations are never synthesized or executed."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .models import ApiOperation, public_url

_METHODS = {"get", "head", "post", "put", "patch", "delete", "options", "trace"}
_NAME = re.compile(r"^[A-Za-z0-9_.\[\]-]{1,100}$")


def _resolve(document: dict[str, Any], value: Any) -> dict[str, Any]:
    seen: set[str] = set()
    while isinstance(value, dict) and "$ref" in value:
        ref = value["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/") or ref in seen or len(seen) >= 10:
            raise ValueError("API references must be bounded local references")
        seen.add(ref)
        value = document
        for part in ref[2:].split("/"):
            value = (
                value.get(part.replace("~1", "/").replace("~0", "~"))
                if isinstance(value, dict)
                else None
            )
    if not isinstance(value, dict):
        raise TypeError("invalid API schema object")
    return value


def openapi_inventory(path: Path) -> tuple[ApiOperation, ...]:
    if path.stat().st_size > 1_000_000:
        raise ValueError("OpenAPI document exceeds the 1 MB limit")
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        raise TypeError("OpenAPI document must contain paths")
    operations = []
    for route, raw in document["paths"].items():
        if (
            not isinstance(route, str)
            or not route.startswith("/")
            or route.startswith("//")
            or any(c in route for c in "?#\\")
            or ".." in route.split("/")
            or len(route) > 2048
        ):
            raise ValueError("invalid API operation path")
        item = _resolve(document, raw)
        for method, raw_operation in item.items():
            if method not in _METHODS:
                continue
            op = _resolve(document, raw_operation)
            params = []
            for raw_param in [*item.get("parameters", []), *op.get("parameters", [])][:100]:
                param = _resolve(document, raw_param)
                name, location = param.get("name"), param.get("in")
                if (
                    isinstance(name, str)
                    and _NAME.fullmatch(name)
                    and location in {"query", "path", "header", "cookie"}
                ):
                    schema = _resolve(document, param.get("schema", {}))
                    kind = schema.get("type", "unknown")
                    if kind not in {"string", "number", "integer", "boolean", "array", "object"}:
                        kind = "unknown"
                    params.append(f"{location}:{name}:{kind}")
            request = _resolve(document, op.get("requestBody", {}))
            request_types = request.get("content", {})
            response_types = set()
            for response in list(op.get("responses", {}).values())[:100]:
                response_types.update(_resolve(document, response).get("content", {}))
            safe_type = re.compile(r"^[a-zA-Z0-9.+-]+/[a-zA-Z0-9.+-]+$")
            operations.append(
                ApiOperation(
                    route,
                    method.upper(),
                    "openapi",
                    tuple(sorted(set(params))),
                    tuple(sorted(t for t in request_types if safe_type.fullmatch(t))),
                    tuple(sorted(t for t in response_types if safe_type.fullmatch(t))),
                    bool(op.get("security", document.get("security", []))),
                    False,
                )
            )
            if len(operations) > 1000:
                raise ValueError("API inventory exceeds 1000 operations")
    return tuple(operations)


def observed_operation(url: str, method: str, content_type: str = "") -> ApiOperation:
    """Only parameter names survive: values are transient request inputs."""
    params = tuple(
        sorted(
            {
                f"query:{name}:unknown"
                for name, _ in parse_qsl(urlsplit(url).query)
                if _NAME.fullmatch(name)
            }
        )
    )
    mime = content_type.split(";", 1)[0].strip().lower()
    return ApiOperation(
        public_url(url),
        method,
        "browser",
        params,
        response_content_types=(mime,) if re.fullmatch(r"[a-z0-9.+-]+/[a-z0-9.+-]+", mime) else (),
        executed=method in {"GET", "HEAD"},
    )
