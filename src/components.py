"""Passive, bounded technology detection from already-collected evidence."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

from .http import HttpResponseEvidence
from .models import ComponentCategory, DetectedComponent, Finding, Severity

_VERSION = r"(?P<version>[0-9]+(?:\.[0-9]+){0,3})"
_JS_SIGNATURES = (
    (
        "jQuery",
        re.compile(
            r"(?:^|[/@._-])jquery(?:[-@./]" + _VERSION + r")?(?:\.min)?\.js(?:$|/)", re.IGNORECASE
        ),
    ),
    (
        "React",
        re.compile(
            r"(?:^|[/@._-])react(?:[-@./]" + _VERSION + r")?(?:\.production)?(?:\.min)?\.js(?:$|/)",
            re.IGNORECASE,
        ),
    ),
    (
        "Vue.js",
        re.compile(
            r"(?:^|[/@._-])vue(?:[-@./]"
            + _VERSION
            + r")?(?:\.global|\.runtime)?(?:\.prod)?(?:\.min)?\.js(?:$|/)",
            re.IGNORECASE,
        ),
    ),
    (
        "AngularJS",
        re.compile(
            r"(?:^|[/@._-])angular(?:[-@./]" + _VERSION + r")?(?:\.min)?\.js(?:$|/)", re.IGNORECASE
        ),
    ),
    (
        "Lodash",
        re.compile(
            r"(?:^|[/@._-])lodash(?:[-@./]" + _VERSION + r")?(?:\.min)?\.js(?:$|/)", re.IGNORECASE
        ),
    ),
    (
        "Moment.js",
        re.compile(
            r"(?:^|[/@._-])moment(?:[-@./]" + _VERSION + r")?(?:\.min)?\.js(?:$|/)", re.IGNORECASE
        ),
    ),
    (
        "D3.js",
        re.compile(
            r"(?:^|[/@._-])d3(?:[-@.v/]" + _VERSION + r")?(?:\.min)?\.js(?:$|/)", re.IGNORECASE
        ),
    ),
)
_CSS_SIGNATURES = (
    (
        "Bootstrap",
        re.compile(
            r"(?:^|[/@._-])bootstrap(?:[-@./]" + _VERSION + r")?(?:\.min)?\.css(?:$|/)",
            re.IGNORECASE,
        ),
    ),
    (
        "Tailwind CSS",
        re.compile(
            r"(?:^|[/@._-])tailwind(?:[-@./]" + _VERSION + r")?(?:\.min)?\.css(?:$|/)",
            re.IGNORECASE,
        ),
    ),
    (
        "Bulma",
        re.compile(
            r"(?:^|[/@._-])bulma(?:[-@./]" + _VERSION + r")?(?:\.min)?\.css(?:$|/)", re.IGNORECASE
        ),
    ),
    (
        "Foundation",
        re.compile(
            r"(?:^|[/@._-])foundation(?:[-@./]" + _VERSION + r")?(?:\.min)?\.css(?:$|/)",
            re.IGNORECASE,
        ),
    ),
    (
        "Materialize CSS",
        re.compile(
            r"(?:^|[/@._-])materialize(?:[-@./]" + _VERSION + r")?(?:\.min)?\.css(?:$|/)",
            re.IGNORECASE,
        ),
    ),
)
_SERVER_SIGNATURES = (
    ("nginx", re.compile(r"(?:^|[\s,(])nginx(?:/" + _VERSION + r")?", re.IGNORECASE)),
    ("Apache HTTP Server", re.compile(r"(?:^|[\s,(])apache(?:/" + _VERSION + r")?", re.IGNORECASE)),
    (
        "Microsoft IIS",
        re.compile(r"(?:^|[\s,(])microsoft-iis(?:/" + _VERSION + r")?", re.IGNORECASE),
    ),
    ("Caddy", re.compile(r"(?:^|[\s,(])caddy(?:/" + _VERSION + r")?", re.IGNORECASE)),
    ("Envoy", re.compile(r"(?:^|[\s,(])envoy(?:/" + _VERSION + r")?", re.IGNORECASE)),
    ("Cloudflare", re.compile(r"(?:^|[\s,(])cloudflare(?:/" + _VERSION + r")?", re.IGNORECASE)),
)

# Deliberately small, reviewed local catalogue.  It provides useful offline results without
# sending an inventory to a third party.  Bounds are exclusive and entries must identify a
# publicly documented vulnerability rather than merely an end-of-life release.
_VULNERABILITIES = (
    ("jQuery", (1, 0, 0), (3, 5, 0), "CVE-2020-11022", Severity.MEDIUM),
    ("jQuery", (1, 0, 0), (3, 5, 0), "CVE-2020-11023", Severity.MEDIUM),
    ("AngularJS", (1, 0, 0), (1, 7, 9), "CVE-2019-10768", Severity.HIGH),
    ("Lodash", (0, 0, 0), (4, 17, 21), "CVE-2021-23337", Severity.HIGH),
    ("Bootstrap", (3, 0, 0), (3, 4, 1), "CVE-2019-8331", Severity.MEDIUM),
    ("Bootstrap", (4, 0, 0), (4, 3, 1), "CVE-2019-8331", Severity.MEDIUM),
)


def _version_tuple(value: str) -> tuple[int, int, int, int] | None:
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,3}", value):
        return None
    parts = [int(part) for part in value.split(".")]
    parts.extend([0] * (4 - len(parts)))
    return parts[0], parts[1], parts[2], parts[3]


def find_component_vulnerabilities(
    components: tuple[DetectedComponent, ...], target_url: str
) -> tuple[Finding, ...]:
    """Match exact detected versions against the bundled conservative advisory catalogue."""
    findings: list[Finding] = []
    for component in components:
        if component.version is None or (version := _version_tuple(component.version)) is None:
            continue
        for name, minimum, fixed, advisory, severity in _VULNERABILITIES:
            if component.name != name or not ((*minimum, 0) <= version < (*fixed, 0)):
                continue
            findings.append(
                Finding.create(
                    f"WEB-COMPONENT-{advisory}",
                    target_url,
                    severity,
                    f"Potentially vulnerable {name} {component.version}",
                    confidence=component.confidence,
                    description=f"The detected version is in the affected range for {advisory}.",
                    recommendation=f"Upgrade {name} to {'.'.join(map(str, fixed))} or newer.",
                    evidence=(
                        f"{component.evidence}; version {component.version}; advisory {advisory}"
                    ),
                    engine="secman-web-check-components",
                )
            )
    return tuple({finding.external_id: finding for finding in findings}.values())


def sanitize_inventory_url(value: str) -> str | None:
    """Keep only a credential-free HTTP(S) URL without query or fragment."""
    try:
        parts = urlsplit(value)
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
        ):
            return None
        return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", "", ""))
    except ValueError:
        return None


def inventory_response_is_complete(response: HttpResponseEvidence) -> bool:
    """Return whether absence of HTML resource signatures is meaningful."""
    if response.truncated or response.status_code not in range(200, 400):
        return False
    content_types = [value for key, value in response.headers if key.lower() == "content-type"]
    return bool(
        content_types
        and content_types[0].split(";", 1)[0].strip().lower()
        in {"text/html", "application/xhtml+xml"}
    )


class _Resources(HTMLParser):
    def __init__(self, url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.url = url
        self.base = url
        self.scripts: list[str] = []
        self.stylesheets: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes: dict[str, str] = {}
        for key, value in attrs:
            attributes.setdefault(key.lower(), value or "")
        if tag.lower() == "base" and attributes.get("href"):
            try:
                self.base = urljoin(self.url, attributes["href"])
            except ValueError:
                pass
        if tag.lower() == "script" and attributes.get("src"):
            self.scripts.append(attributes["src"])
        if (
            tag.lower() == "link"
            and "stylesheet" in attributes.get("rel", "").lower().split()
            and attributes.get("href")
        ):
            self.stylesheets.append(attributes["href"])

    def absolute(self, reference: str) -> str | None:
        try:
            return sanitize_inventory_url(urljoin(self.base, reference.strip()))
        except ValueError:
            return None


def _resource_components(
    document: _Resources,
    references: list[str],
    signatures: tuple[tuple[str, re.Pattern[str]], ...],
    category: ComponentCategory,
) -> list[DetectedComponent]:
    components = []
    for reference in references:
        source_url = document.absolute(reference)
        if source_url is None:
            continue
        candidate = urlsplit(source_url).netloc + urlsplit(source_url).path
        for name, signature in signatures:
            match = signature.search(candidate)
            if match is None:
                continue
            components.append(
                DetectedComponent.create(
                    category,
                    name,
                    version=match.groupdict().get("version"),
                    confidence=0.95,
                    evidence_type="RESOURCE_URL",
                    evidence=f"Matched {name} resource URL",
                    source_url=source_url,
                )
            )
            break
    return components


def detect_components(response: HttpResponseEvidence) -> tuple[DetectedComponent, ...]:
    """Identify conservative signatures without issuing additional requests."""
    components: list[DetectedComponent] = []
    for key, value in response.headers:
        if key.lower() != "server":
            continue
        for name, signature in _SERVER_SIGNATURES:
            match = signature.search(value)
            if match is not None:
                components.append(
                    DetectedComponent.create(
                        ComponentCategory.WEB_SERVER,
                        name,
                        version=match.groupdict().get("version"),
                        confidence=0.9,
                        evidence_type="HTTP_HEADER",
                        evidence=f"Server header matched {name}",
                    )
                )

    content_types = [value for key, value in response.headers if key.lower() == "content-type"]
    is_html = bool(
        content_types
        and content_types[0].split(";", 1)[0].strip().lower()
        in {"text/html", "application/xhtml+xml"}
    )
    if is_html:
        document = _Resources(response.url)
        document.feed(response.body.decode("utf-8", errors="replace"))
        document.close()
        components.extend(
            _resource_components(
                document,
                document.scripts,
                _JS_SIGNATURES,
                ComponentCategory.JAVASCRIPT_LIBRARY,
            )
        )
        components.extend(
            _resource_components(
                document,
                document.stylesheets,
                _CSS_SIGNATURES,
                ComponentCategory.CSS_LIBRARY,
            )
        )

    unique = {component.component_key: component for component in components}
    return tuple(
        sorted(
            unique.values(),
            key=lambda component: (
                component.category.value,
                component.name.casefold(),
                component.version or "",
                component.source_url or "",
            ),
        )
    )


__all__ = [
    "detect_components",
    "find_component_vulnerabilities",
    "inventory_response_is_complete",
    "sanitize_inventory_url",
]
