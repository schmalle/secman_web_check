# Agent guardrails

`secman_web_check` is an authorized, non-invasive web-security scanner. Preserve passive defaults; active checks and private-target access must remain explicit opt-ins.

## Branches

- `dev` is the default and only branch for agent-authored commits unless the user explicitly names another branch.
- Verify `git branch --show-current` is `dev` before editing and before committing. Never commit directly to `main` or `master` by inference.

## Skills

- Any contributor or automation skill must be available to both harnesses: `.claude/skills/<name>/` for Claude Code and `.agents/skills/<name>/` for Codex.
- Create, update, or delete both renderings in the same commit. Translate harness-specific mechanics and paths; do not leave one tree stale.

## Security boundaries

- Keep scanner runtime, tests, scripts, SQL, examples, and scanner documentation in this extension repository.
- Revalidate every DNS answer and redirect. Approved connections pin the resolved IP while retaining the hostname for HTTP Host and TLS SNI.
- Never persist raw response bodies. Keep MariaDB and SecMan REST/MCP integration optional and explicit.
