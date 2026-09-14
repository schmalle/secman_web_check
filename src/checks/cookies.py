"""Inspect Set-Cookie attributes without ever persisting names or values."""

from urllib.parse import urlsplit

from ..models import Finding
from .registry import RULES, CheckContext


def check_cookies(context: CheckContext) -> tuple[Finding, ...]:
    affected: dict[str, list[int]] = {}
    target = urlsplit(context.response.url)
    for index, header in enumerate(context.header_values("set-cookie"), 1):
        first, *attributes = header.split(";")
        name, equals, _ = first.partition("=")
        if not equals or not name.strip():
            continue
        name = name.strip()
        attrs = {}
        for attribute in attributes:
            key, _, value = attribute.strip().partition("=")
            attrs[key.lower()] = value.strip()

        def flag(suffix: str, cookie_index: int = index) -> None:
            affected.setdefault(suffix, []).append(cookie_index)

        if "secure" not in attrs:
            flag("SECURE-MISSING")
        if "httponly" not in attrs:
            flag("HTTPONLY-MISSING")
        same_site = attrs.get("samesite", "").lower()
        if same_site not in {"strict", "lax", "none"}:
            flag("SAMESITE-MISSING")
        if same_site == "none" and "secure" not in attrs:
            flag("SAMESITE-NONE-INSECURE")
        invalid_secure = "secure" not in attrs or target.scheme != "https"
        if (name.startswith("__Secure-") and invalid_secure) or (
            name.startswith("__Host-")
            and (invalid_secure or "domain" in attrs or attrs.get("path") != "/")
        ):
            flag("PREFIX-INVALID")
        domain = attrs.get("domain", "").lower().lstrip(".")
        host = target.hostname or ""
        if domain and domain != host and host.endswith("." + domain):
            flag("DOMAIN-BROAD")
    return tuple(
        RULES[f"WEB-COOKIE-{suffix}"].finding(
            context,
            "Set-Cookie "
            + ", ".join(f"#{index}" for index in indices)
            + ": "
            + suffix.lower().replace("-", " "),
        )
        for suffix, indices in affected.items()
    )
