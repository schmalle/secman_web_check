from secman_web_check.checks.redirects import check_redirects
from secman_web_check.http import HttpRequest, HttpResponseEvidence


def redirect(source, destination, *, blocked=None):
    return HttpResponseEvidence(
        HttpRequest("GET", source),
        302,
        (),
        b"",
        False,
        0.01,
        redirect_url=destination,
        blocked_redirect_reason=blocked,
    )


def test_redirect_chain_identifies_each_hop_and_cross_host_boundary():
    findings = check_redirects(
        (
            redirect("http://example.com/", "https://example.com/login"),
            redirect("https://example.com/login", "https://identity.example/sso"),
        )
    )
    rules = [finding.rule_id for finding in findings]
    assert rules.count("WEB-TRANSPORT-REDIRECT") == 2
    assert rules.count("WEB-TRANSPORT-CROSS-HOST-REDIRECT") == 1
    assert "https://identity.example/sso" in findings[-1].evidence


def test_blocked_downgrade_is_identified_without_following_it():
    findings = check_redirects(
        (
            redirect(
                "https://example.com/",
                "http://other.example/path?token=<redacted>",
                blocked="HTTPS downgrade",
            ),
        )
    )
    assert {finding.rule_id for finding in findings} >= {
        "WEB-TRANSPORT-REDIRECT",
        "WEB-TRANSPORT-CROSS-HOST-REDIRECT",
        "WEB-TRANSPORT-HTTPS-DOWNGRADE",
        "WEB-TRANSPORT-REDIRECT-BLOCKED",
    }
    assert "token=<redacted>" in findings[0].evidence
