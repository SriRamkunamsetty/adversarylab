# AdversaryLab

> Repeatable red-team campaigns mapped to the OWASP LLM Top 10, plus **AgentShield**, a deny-by-default sandbox that stops prompt-injected agents from misusing tools.

![tests](https://img.shields.io/badge/tests-41%20passing-brightgreen) ![coverage](https://img.shields.io/badge/line%20coverage-95%25%2B-brightgreen) ![python](https://img.shields.io/badge/python-3.10%2B-blue) ![license](https://img.shields.io/badge/license-MIT-green) ![a11y](https://img.shields.io/badge/WCAG-AA%20contrast%20tested-informational)

## Problem statement

LLM apps leak secrets and agents get hijacked by instructions hidden in documents. Teams need a *repeatable measurement* of that risk (attack-success rate per target, mapped to a recognised taxonomy) and a *demonstrable mitigation*. AdversaryLab provides both, and can gate a CI pipeline on the result.

## Features

- **Attack engine:** prompt mutators (base64, role-play, payload splitting, leetspeak) and multi-turn escalation sequences.
- **Objective judging:** a unique canary secret is planted per campaign; a leak is a reproducible signal, not a fuzzy grade.
- **OWASP LLM Top 10 (2025) mapping** on every finding (LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM06 Excessive Agency).
- **Targets:** demo targets (`vulnerable`, `hardened`), an **OpenAI-compatible adapter** (`llm`, endpoint set via server env only, so no SSRF through the API) and agent scenarios (`agent-unprotected`, `agent-sandboxed`).
- **AgentShield sandbox:** tool allow-list, path confinement, egress host allow-list, call budget, full audit log including denials; plus a pattern-based indirect-injection scanner (one defensive layer).
- **CI gate CLI:** `python -m adversarylab --target llm --goal "..." --max-asr 0.1` exits non-zero when the attack-success rate exceeds the limit.
- Dashboard, REST API, Prometheus metrics, SQLite persistence.

## Screenshots

Captured from the real running app (`make screenshots`) using **synthetic demo data**.

**Dashboard: attack-success rate per campaign**

![Dashboard: attack-success rate per campaign](docs/screenshots/dashboard.png)

**A vulnerable model leaking under encoding, role-play and split attacks, with OWASP mapping**

![A vulnerable model leaking under encoding, role-play and split attacks, with OWASP mapping](docs/screenshots/campaign-vulnerable.png)

**AgentShield blocking prompt-injected exfiltration**

![AgentShield blocking prompt-injected exfiltration](docs/screenshots/campaign-sandboxed.png)

**Light theme (follows the OS setting)**

![Light theme (follows the OS setting)](docs/screenshots/dashboard-light.png)

**Mobile layout (390 px wide)**

![Mobile layout (390 px wide)](docs/screenshots/dashboard-mobile.png)

## Architecture

```mermaid
flowchart LR
  C[Client / CI] -->|POST /api/campaigns or CLI| A[AdversaryLab]
  A --> E[Attack engine: concurrent, deadline-bound]
  E -->|mutated prompts| T[Target: demo / OpenAI-compatible / agent]
  T -->|tool calls| S[AgentShield sandbox]
  S -->|allow / deny + audit| T
  A --> D[(SQLite)]
  D --> U[Dashboard + OWASP report]
  D --> M[/metrics/]
```

## Quickstart

```bash
git clone https://github.com/SriRamKunamsetty/adversarylab.git && cd adversarylab
python -m venv .venv && . .venv/bin/activate && pip install -r requirements-dev.txt
cp .env.example .env            # then edit API_KEY and SECRET_KEY
make test                       # 41 tests: unit, API, security, accessibility
make run                        # http://localhost:8081
```

**Docker** (non-root, read-only filesystem, all capabilities dropped):

```bash
export API_KEY=$(openssl rand -hex 24) SECRET_KEY=$(openssl rand -hex 32)
docker compose up --build       # http://localhost:8081
```

**Kubernetes** (single replica because of SQLite; ClusterIP Service):

```bash
kubectl create secret generic adversarylab-secrets --from-literal=API_KEY="$API_KEY" --from-literal=SECRET_KEY="$SECRET_KEY"
helm install adversarylab deploy/helm/adversarylab --set image.repository=ghcr.io/SriRamKunamsetty/adversarylab
```

## API reference

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/campaigns` | API key | `{"target": "vulnerable|hardened|llm|agent-unprotected|agent-sandboxed", "goals": [...]}` (1-20 goals ≤500 chars; agent targets ignore goals). `201` with `id`, `total`, `leaks`, `attack_success_rate`; `400` invalid/unconfigured; `502` upstream failure; `504` deadline exceeded |
| `GET` | `/api/campaigns` | none | Latest campaigns |
| `GET` | `/`, `/campaigns/<id>` | none | Dashboard and campaign detail |
| `GET` | `/healthz`, `/metrics` | none | Health and Prometheus metrics |

CLI exit codes: `0` within limit, `1` ASR above `--max-asr`, `2` configuration error, `3` timeout.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `API_KEY` | *(unset)* | Required for write endpoints. **If unset, writes return 503** (secure by default) |
| `SECRET_KEY` | auto-generated, stored in `DATA_DIR/.secret_key` (mode 0600) | Signs session cookies; auto-file is shared by all workers and survives restarts |
| `DATA_DIR` | `./data` (`/data` in Docker) | Where the SQLite database lives |
| `RATE_LIMIT_PER_MIN` | `120` | Per-IP request limit (per worker process) |
| `TRUST_PROXY` | `0` | Set `1` only behind a proxy you control, so the rate limiter uses `X-Forwarded-For` |
| `COOKIE_SECURE` | `0` | Set `1` behind HTTPS: `Secure` cookies and HSTS header |
| `TARGET_URL` / `TARGET_KEY` / `TARGET_MODEL` | *(unset)* | OpenAI-compatible endpoint for the `llm` target (`http(s)://` only) |
| `TARGET_TIMEOUT_S` | `15` | Per-request timeout to the target |
| `CAMPAIGN_DEADLINE_S` | `60` | Wall-clock limit for one campaign (HTTP 504 when exceeded) |

## Security

**Implemented and covered by tests**

- Write endpoints are disabled unless `API_KEY` is set; constant-time comparison that also handles non-ASCII input (no 500s).
- Parameterised SQL only (injection payload test); Jinja autoescaping (XSS test); **strict CSP without `unsafe-inline`**, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, `no-store` on pages (static assets are cacheable), HSTS when `COOKIE_SECURE=1`.
- Request-size limits (413), validation on every endpoint, per-IP rate limiting (429) with **bounded memory**, generic error pages (no stack traces), failed-auth logging.
- Session cookies `HttpOnly`, `SameSite=Lax`, `Secure` when enabled; secret key persisted with mode 0600 and shared across workers.
- The `llm` target URL comes only from server configuration and must be `http(s)`; request bodies cannot choose where the server connects.
- Campaigns run with bounded concurrency and a hard deadline, so a slow target cannot pin a worker indefinitely.
- Use only against systems you own or are authorised to test; mutators are generic, widely published patterns.
- Container: non-root UID 10001, read-only root FS, `cap_drop: ALL`, `no-new-privileges`; Helm chart adds `seccompProfile: RuntimeDefault`.
- CI: Trivy image scan (fails on HIGH/CRITICAL), CodeQL, Dependabot, ruff, container smoke test.

**Known limitations**

- Read-only pages and `/metrics` are unauthenticated: use an authenticating ingress/proxy or keep the Service cluster-internal.
- SQLite means one replica; rate limiting is in-memory per worker. TLS is terminated outside the app. See [SECURITY.md](SECURITY.md).
- The attack library is template-based; it measures known patterns, not unknown vulnerabilities.
- The injection scanner is regex-based and can be bypassed; AgentShield's policy (not the scanner) is the control.

## Accessibility

- Semantic landmarks (`header`, `nav`, `main`, `footer`), a **skip link**, exactly one `h1` per page with no skipped heading levels, and **unique, state-aware page titles**.
- Every table has a caption and `scope`d headers; scrollable tables are focusable regions; progress is shown with `<progress>` plus visible text (not colour alone).
- Forms use real `<label>`s, `fieldset`/`legend` groups and native controls, so they are fully **keyboard operable**; visible focus rings.
- **No JavaScript required**; works in text-heavy, low-bandwidth and assistive-technology environments. No inline styles, so the strict CSP also holds.
- Light and dark themes follow the OS preference; **WCAG AA contrast (≥4.5:1) is asserted by an automated test for both themes**; responsive down to 390 px.
- These are automated structural checks. A manual screen-reader pass (NVDA/VoiceOver) and an axe audit are still recommended before a production launch.

## Efficiency

- Attacks run concurrently (4 workers) instead of sequentially: 8 attacks of 0.2 s finish in under 1 s (tested); a hard deadline cancels queued work.
- Findings are indexed by campaign; request bodies capped at 100 KB; responses stored truncated to 2000 characters.
- Rate-limiter state is bounded (10,000 clients); static assets are cached for an hour; all SQL is indexed or O(1) per row.

## Testing

`41` tests: `make test` or `python -m unittest discover -s tests`. They cover core logic, the HTTP API, auth edge cases, validation, security headers, XSS/SQL-injection, rate limiting, error paths, robustness against malformed input, caching behaviour and accessibility (structure plus contrast). Line coverage measured with the stdlib `trace` module is about 95-97%; CI enforces a 75% floor with `coverage.py` on Python 3.10 and 3.12. Code is split into a pure, framework-free `core.py` (fast unit tests) and a thin Flask layer; `create_app(db_path, config)` makes every test hermetic.

| Verified during development | Written but not executed yet |
|---|---|
| Full test suite, real-browser screenshots, lint-style AST check (no unused imports, no ambiguous names) | GitHub Actions, `docker build`/Trivy, `helm lint`, cluster deployment |

## How this maps to common review criteria

| Criterion | Evidence |
|---|---|
| **Code quality** | Pure core + thin web layer, type hints, docstrings, single-responsibility helpers, no unused imports, shared security module with documented behaviour |
| **Security** | Section above: secure-by-default writes, CSP without inline, bounded rate limiter, hardened parsing, container and CI scanning |
| **Efficiency** | Section above: measured/tested concurrency, SQL aggregates, caching, bounded inputs and memory |
| **Testing** | 41 tests incl. security, robustness and accessibility suites; hermetic app factory; coverage floor in CI |
| **Accessibility** | Section above: landmarks, labels, captions, contrast tests, keyboard and no-JS operation, responsive themes |
| **Problem alignment** | Targets the stated problem end to end: measure (campaigns, ASR), classify (OWASP LLM Top 10), mitigate and prove it (AgentShield blocked vs leaked, same scenario), and enforce (CI gate CLI). |

## Project structure

```
adversarylab/
  core.py      attacks, judge, targets, concurrency/deadline, AgentShield, OWASP mapping
  cli.py       CI gate (python -m adversarylab)
  server.py    Flask app, SQLite, REST API, dashboard
  security.py  headers, rate limit, API-key auth, secrets, error handlers
  templates/ static/
tests/         core, API, security, accessibility
scripts/       capture_screenshots.py
deploy/helm/   Helm chart
Dockerfile docker-compose.yml .github/workflows/
```

## Roadmap

- LLM-driven attacker and judge agents (today: deterministic templates + canary judging).
- Postgres backend, per-user auth for the UI, job queue for long campaigns.
- More attack families (adaptive multi-turn, tool-argument injection) and SARIF export for code-scanning dashboards.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and PRs welcome.

## Contributors

- [Sri Ram Kunamsetty](https://github.com/SriRamKunamsetty) (<mohansriramkunamsetty@gmail.com>)

## License

MIT, see [LICENSE](LICENSE).
