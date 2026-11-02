# Detection evaluation

The owned synthetic corpus at `tests/fixtures/detection.json` contains 20 fixtures:
one vulnerable-signature and one safe/negative response for each of ten classes.
It performs no requests and contains no real credentials or private keys.

```bash
uv run --locked secman-web-check evaluate tests/fixtures/detection.json \
  --output docs/evaluation/detection-results.json
```

The committed [measurement artifact](evaluation/detection-results.json) records corpus
SHA-256 and evaluator/source revision, each case's expected and actual eligible rules,
TP/FP/FN/TN, and per-class precision/recall. The command fails on any false positive or
missed fixture. Tests also intentionally invert vulnerable/safe HSTS responses to prove
that a detection regression produces both an FP and FN and a nonzero CLI exit.

| Class | Positive fixture | Negative fixture |
| --- | --- | --- |
| HSTS | No HSTS on HTTPS | Long-lived HSTS |
| CSP | Unsafe script sources | Narrow nonce policy |
| Cookies | Missing Secure | Secure/HttpOnly/SameSite |
| CORS | Wildcard with credentials | Explicit trusted origin |
| Mixed content | HTTP script on HTTPS | HTTPS script |
| Components | Affected jQuery version | Fixed version |
| Directory listing | Index heading plus parent link | Index-like documentation without parent link |
| Debug disclosure | Paired runtime/stack signatures | Tutorial text without a stack trace |
| Insecure forms | Password form submits over HTTP | HTTPS submission |
| Secret signatures | PEM delimiters enclosing synthetic material | Empty delimiters |

Current corpus measurements are 1.0 precision and recall for each class. These are
measurements of the listed signature contracts, not estimates of real-world detection
quality or exploitability. In particular, synthetic PEM material is not a functioning
private key, banner/file-name versions can be spoofed, and CORS observations alone do
not prove browser-readable credential exposure. Eligible-rule lists make the measured
scope explicit; unrelated hardening findings are not treated as corpus false positives.

Transport, scope and operational behavior have separate tests: a real Chromium fixture
builds links dynamically and attempts blocked writes/cross-origin requests; spawned
workers exercise shared pacing/concurrency; OSV fixtures exercise fixed/prerelease/
withdrawn/disjoint ranges and tampering; archive tests verify the complete JSON round
trip and rollback; a local self-signed TLS fixture exercises the real SSLyze/Nassl
socket hook and lease release; provider fixtures reject invented references and preserve earlier
results when a later request fails.

Native macOS external containment can be tested separately where nesting sandboxes is
permitted:

```bash
SECMAN_TEST_SANDBOX=1 uv run --locked pytest -q \
  tests/test_external_containment.py::test_native_sandbox_denies_direct_egress_and_allows_only_scope_proxy
```

It uses local fixture servers and curl, and proves denied direct egress plus successful
proxy-only access. It does not certify a Nuclei/Nikto installation: their version labels,
asset hashes, template/plugin review and real-tool compatibility remain operator-specific.
Other platforms reject external execution until an enforced containment implementation
exists. The ordinary suite skips only this separately enabled native test.

Future corpus additions should pair a positive and safe fixture, identify eligible rules,
and include realistic negative context. Broader recall claims require independent,
application-level datasets and a denominator of known vulnerability instances. TLS,
authenticated workflows, arbitrary injection and business logic are not measured by this
response-signature corpus.
