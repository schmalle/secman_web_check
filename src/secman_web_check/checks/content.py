"""Bounded, non-executing content heuristics. Evidence contains signatures only."""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from ..models import Finding
from .registry import RULES, CheckContext


def _scheme(base: str, reference: str) -> str:
    try:
        return urlsplit(urljoin(base, reference.strip())).scheme.lower()
    except ValueError:
        return ""


class _Document(HTMLParser):
    def __init__(self, url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.url = url
        self.base = url
        self.base_seen = False
        self.form_action: str | None = None
        self.insecure_form = False
        self.mixed_active = False
        self.index_heading = False
        self.parent_link = False
        self._heading = False
        self._heading_text = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # HTML duplicate attributes use their first value.
        attributes: dict[str, str] = {}
        for key, value in attrs:
            attributes.setdefault(key, value or "")
        if tag == "base" and "href" in attributes and not self.base_seen:
            self.base_seen = True
            try:
                self.base = urljoin(self.url, attributes["href"])
            except ValueError:
                pass  # Invalid HTML URL is ignored; no resource is ever fetched.
        if tag in {"h1", "title"}:
            self._heading = True
            self._heading_text = ""
        if tag == "a" and attributes.get("href") in {"../", ".."}:
            self.parent_link = True
        if tag == "form":
            self.form_action = attributes.get("action") or self.url
            if (
                _scheme(self.url, self.url) == "https"
                and _scheme(self.base, self.form_action) == "http"
            ):
                self.insecure_form = True
        if (
            tag in {"button", "input"}
            and "formaction" in attributes
            and (
                _scheme(self.url, self.url) == "https"
                and _scheme(self.base, attributes["formaction"]) == "http"
            )
        ):
            self.insecure_form = True
        if (
            tag == "input"
            and attributes.get("type", "").lower() == "password"
            and (
                _scheme(self.url, self.url) == "http"
                or (self.form_action is not None and _scheme(self.base, self.form_action) == "http")
            )
        ):
            self.insecure_form = True
        resource = None
        if tag in {"script", "iframe", "embed"}:
            resource = attributes.get("src")
        elif tag == "object":
            resource = attributes.get("data")
        elif tag == "link" and "stylesheet" in attributes.get("rel", "").lower().split():
            resource = attributes.get("href")
        if (
            resource
            and _scheme(self.url, self.url) == "https"
            and _scheme(self.base, resource) == "http"
        ):
            self.mixed_active = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self.form_action = None
        if tag in {"h1", "title"}:
            if self._heading_text.strip().lower().startswith("index of /"):
                self.index_heading = True
            self._heading = False

    def handle_data(self, data: str) -> None:
        if self._heading:
            self._heading_text = (self._heading_text + data)[:256]


def _has_internal_address(text: str) -> bool:
    candidates = re.findall(
        r"(?:https?://|\b(?:server|upstream|address|ip)\s*[:=]\s*)"
        r"(\[[0-9a-fA-F:]+\]|\d{1,3}(?:\.\d{1,3}){3})(?![\d.])",
        text,
        re.IGNORECASE,
    )
    for value in candidates:
        try:
            address = ipaddress.ip_address(value.strip("[]"))
        except ValueError:
            continue
        if address.is_private or address.is_loopback or address.is_link_local:
            return True
    return False


def _security_txt(context: CheckContext) -> tuple[Finding, ...]:
    response = context.security_txt
    if response is None:
        return ()
    suffix = None
    if response.status_code in {404, 410}:
        suffix = "MISSING"
    elif response.status_code == 200 and not response.truncated:
        fields: dict[str, list[str]] = {}
        for line in response.body.decode("utf-8", errors="replace").splitlines():
            name, colon, value = line.partition(":")
            if colon:
                fields.setdefault(name.strip().lower(), []).append(value.strip())
        contact_valid = any(
            re.match(r"(?:mailto:[^\s@]+@[^\s@]+|https://[^\s/]+(?:/\S*)?)$", v)
            for v in fields.get("contact", [])
        )
        expires = fields.get("expires", [])
        expiry = None
        if len(expires) == 1 and re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})",
            expires[0],
            re.IGNORECASE,
        ):
            try:
                expiry = datetime.fromisoformat(expires[0])
            except ValueError:
                pass  # Report invalid metadata without copying field values into evidence.
        content_types = [v for k, v in response.headers if k.lower() == "content-type"]
        if (
            not contact_valid
            or expiry is None
            or expiry.tzinfo is None
            or not content_types
            or content_types[0].split(";", 1)[0].strip().lower() != "text/plain"
        ):
            suffix = "INVALID"
        elif expiry <= (
            context.now.replace(tzinfo=UTC) if context.now.tzinfo is None else context.now
        ):
            suffix = "EXPIRED"
    if suffix is None:
        return ()
    return (
        RULES[f"WEB-CONTENT-SECURITY-TXT-{suffix}"].finding(
            context, f"Collected security.txt: {suffix.lower()}"
        ),
    )


def check_content(context: CheckContext) -> tuple[Finding, ...]:
    findings = []

    def add(suffix: str, evidence: str) -> None:
        findings.append(RULES[f"WEB-CONTENT-{suffix}"].finding(context, evidence))

    response = context.response
    if (
        300 <= response.status_code < 400
        and response.redirect_url
        and _scheme(response.url, response.url) == "https"
        and _scheme(response.url, response.redirect_url) == "http"
    ):
        findings.append(
            RULES["WEB-TRANSPORT-HTTPS-DOWNGRADE"].finding(
                context, "HTTPS response redirects to HTTP"
            )
        )

    text = response.body.decode("utf-8", errors="replace")
    if context.is_html:
        document = _Document(response.url)
        document.feed(text)
        document.close()
        if document.index_heading and document.parent_link:
            add("DIRECTORY-LISTING", "HTML index heading and parent-directory link")
        if document.insecure_form:
            add("INSECURE-FORM", "HTML form or password input uses HTTP transport")
        if document.mixed_active:
            add("MIXED-ACTIVE", "HTTPS HTML contains an HTTP active resource reference")

    if (
        (
            "Traceback (most recent call last):" in text
            and re.search(r'File "[^"\n]+", line \d+', text)
        )
        or (
            re.search(r"\b(?:java|javax)\.[\w.]+(?:Exception|Error)\b", text)
            and re.search(r"\bat [\w.$]+\([^\n)]+\.java:\d+\)", text)
        )
        or ("SQLSTATE[" in text and re.search(r"(?:PDOException|SQL syntax|Stack trace)", text))
        or ("Werkzeug Debugger" in text and "Traceback" in text)
    ):
        add("DEBUG-ERROR", "Paired runtime error and stack trace signatures")
    if _has_internal_address(text) or any(
        _has_internal_address(value) for value in context.header_values("location")
    ):
        add("INTERNAL-ADDRESS", "Private/local IP literal in URL or explicit address field")
    if re.search(
        r"-----BEGIN ((?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----"
        r"\s+\S[\s\S]+?-----END \1-----",
        text,
    ):
        add("SECRET", "Matching PEM private key delimiters enclosing material; value redacted")
    findings.extend(_security_txt(context))
    return tuple(findings)
