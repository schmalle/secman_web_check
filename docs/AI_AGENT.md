# AI agent and image privacy

`--ai-agent` requires `--active` and a security scan. It uses OpenRouter to choose the
next check from the reviewed `ACTIVE_PROBES` catalogue. A decision contains one check ID
or `stop`. The model cannot create a target URL, request method, header, or payload. The
scanner executes the selected probe through the pinned HTTP collector and accepts a
finding only when the deterministic matcher recognizes its response. The agent gets at
most 10 model calls and 20 actions per target; an early stop, invalid decision, provider
failure, or exhausted budget leaves agent coverage incomplete.
SecMan uploads use a separate extended `WEB_SECURITY` scanner registration and do not
auto-resolve findings from variable AI check selection.

The model receives the target origin, observed rule IDs and severities, and completed
and available check IDs. It does not receive HTTP bodies, full URLs, query values,
credentials, cookies, screenshots, or page text. OpenRouter requests use strict JSON
Schema output, Zero Data Retention provider routing, and `data_collection: deny`.
Configure a spend-limited OpenRouter key separately; the scanner enforces call and
output-token limits but cannot guarantee a currency ceiling across model prices.

Visual analysis is a separate explicit mode. First run `--scan-mode visual
--visual-no-ai` to capture a local PNG. Review it, create a redacted PNG crop in a
different directory, and rerun the same target with `--scan-mode visual
--visual-redacted-crops DIR` and `SECMAN_VISION_API_KEY`. The file must have the same
name as the local screenshot, be smaller than 2 MB, and differ from it. The scanner
sends only that crop, target origin, and HTTP status to OpenRouter. It cannot prove that
an operator supplied image is fully redacted; missing or invalid crops fail closed and
mark visual analysis partial.

Page content and model output are untrusted. A model finding is a review signal, not
proof of a vulnerability. The agent's active findings come from deterministic checks;
visual findings still require a human to validate their context. No authenticated
testing, role comparison, arbitrary payload generation, or autonomous scope expansion
is available.
