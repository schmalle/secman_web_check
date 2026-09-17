from __future__ import annotations

import asyncio
import ipaddress

from secman_web_check.models import Severity
from secman_web_check.targets import AddressPolicy, normalize_target
from secman_web_check.visual import _parse_analysis, _route_handler


class FakeRequest:
    resource_type = "document"

    def __init__(self, url: str) -> None:
        self.url = url


class FakeRoute:
    def __init__(self, url: str) -> None:
        self.request = FakeRequest(url)
        self.outcome = ""

    async def abort(self) -> None:
        self.outcome = "aborted"

    async def continue_(self) -> None:
        self.outcome = "continued"


def test_browser_route_blocks_denied_network_destination(monkeypatch) -> None:
    monkeypatch.setattr(
        "secman_web_check.visual.resolve_allowed",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("denied")),
    )
    route = FakeRoute("http://169.254.169.254/latest/meta-data")

    asyncio.run(_route_handler(AddressPolicy())(route))

    assert route.outcome == "aborted"


def test_visual_analysis_maps_to_normalized_finding() -> None:
    payload = {
        "choices": [
            {
                "message": {
                    "content": '{"findings":[{"category":"directory_listing",'
                    '"severity":"high","title":"Directory listing exposed",'
                    '"evidence":"Index of /backup","recommendation":"Disable listing",'
                    '"confidence":0.95}]}'
                }
            }
        ]
    }

    findings = _parse_analysis(payload, normalize_target("https://example.com"), "vision-test")

    assert len(findings) == 1
    assert findings[0].rule_id == "VISUAL-directory_listing"
    assert findings[0].severity is Severity.HIGH
    assert findings[0].engine == "secman-web-check-visual"
    assert findings[0].model == "vision-test"


def test_playwright_bracketed_ipv6_address_uses_normal_address_policy() -> None:
    address = ipaddress.ip_address("[2606:4700:10::ac42:93f3]".strip("[]"))

    assert AddressPolicy().allows(address)
