# AdversaryLab System Architecture & Threat Model

> Technical architecture, threat model, and defense-in-depth specification for AdversaryLab and AgentShield.

---

## 1. System Architecture Overview

AdversaryLab is structured into five decoupled, domain-driven layers:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Clients & Consumers                             │
│   Web Dashboard (Zero-JS)   │   CI Gate CLI   │   REST API / Webhooks       │
└───────────────────────┬─────────────────┬──────────────────────┬────────────┘
                        │                 │                      │
┌───────────────────────▼─────────────────▼──────────────────────▼────────────┐
│                         Security & Ingress Gateway                          │
│   - Strict CSP (no 'unsafe-inline')      - Bounded-Memory Rate Limiting     │
│   - Constant-time API Key Auth           - Request Size Limit (100KB)       │
│   - HSTS & Security Headers              - Contextual Error Handling        │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────┐
│                            Core Execution Engine                             │
│                                                                             │
│   ┌─────────────────────┐   ┌────────────────────┐   ┌──────────────────┐   │
│   │   Attack Suite      │   │   Target Adapter   │   │  Judging Engine  │   │
│   │ - Base64, ROT13     │   │ - Vulnerable Demo  │   │ - Canary Matcher │   │
│   │ - Homoglyphs, Leet  │──>│ - Hardened Baseline│──>│ - Fuzzy Semantic │   │
│   │ - Crescendo Multi   │   │ - OpenAI-compatible│   │ - Refusal Class. │   │
│   │ - PAIR Refinement   │   │ - Autonomous Agent │   │ - PII/Entropy    │   │
│   │ - DoS Probes (LLM10)│   │                    │   │ - SARIF Exporter │   │
│   └─────────────────────┘   └─────────┬──────────┘   └──────────────────┘   │
│                                       │                                     │
│   ┌───────────────────────────────────▼─────────────────────────────────┐   │
│   │                 AgentShield Dual-Engine Guardrails                  │   │
│   │   - Ingress Heuristic & Entropy Prompt Inspection                   │   │
│   │   - Deny-by-Default Tool Use Policy & Strict Allowlist              │   │
│   │   - POSIX Canonical Path Confinement (Traversal Defense)            │   │
│   │   - Egress Firewall (Host Allowlist + Cloud Metadata Blocking)      │   │
│   │   - Invocation Budgeting & Tamper-Evident Audit Logging             │   │
│   │   - Egress Canary & Secret Redaction                                │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────┐
│                    Persistence & Operational Observability                  │
│   - SQLite (WAL Mode) / PostgreSQL       - Prometheus Metrics (/metrics)    │
│   - Kubernetes Probes (/healthz, /readyz)- Grafana Monitoring Dashboard    │
│   - SARIF v2.1.0 Security Reports        - OpenAPI 3.0 Specification        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Threat Model & Attack Surface

| Threat Vector | Mechanism | Target Vulnerability | AdversaryLab Mitigation / Detection |
|---|---|---|---|
| **Direct Prompt Injection** | Roleplay, virtualization, base64 encoding, Caesar ciphers, homoglyphs | OWASP LLM01:2025 | Mutator test suite evaluates model resilience; AgentShield flags adversarial syntax. |
| **System Prompt Leakage** | Crescendo multi-turn escalation, PAIR iterative refinement | OWASP LLM07:2025 | Canary secret planted dynamically per campaign; leaks detected with zero false positives. |
| **Sensitive Info Disclosure** | PII, credentials, database connection strings | OWASP LLM02:2025 | Dual detection: deterministic canary search + entropy/regex scanning for AWS, OpenAI, JWT, and private keys. |
| **Indirect Prompt Injection** | Malicious text in untrusted RAG documents | OWASP LLM01:2025 | `scan_untrusted()` detects embedded injection signatures before tool execution. |
| **Excessive Agency & SSRF** | Hijacked agent calling `fetch()` with internal URLs | OWASP LLM06:2025 | AgentShield Egress Firewall strictly enforces allowed hostnames and drops metadata IP requests (`169.254.169.254`). |
| **Filesystem Traversal** | Agent writing or reading `../../etc/passwd` | OWASP LLM06:2025 | AgentShield `_safe_path()` normalizes paths and blocks any reference escaping `/sandbox`. |
| **Unbounded Consumption** | Infinite token loops, recursive expansions | OWASP LLM10:2025 | Request size limits (100KB), rate limiting (120 req/min), call budget caps, and thread pool deadlines. |

---

## 3. OWASP Top 10 for LLM Applications (2025 Edition) Mapping

AdversaryLab maps every evaluated finding directly to the 2025 OWASP taxonomy:

- **LLM01: Prompt Injection** — Evaluated across all obfuscation mutators, crescendo sequences, and PAIR loops.
- **LLM02: Sensitive Information Disclosure** — Triggered whenever canary tokens or high-entropy credential patterns are leaked.
- **LLM03: Supply Chain Vulnerabilities** — Mitigated via Docker multi-stage non-root containers, Trivy scans, and dependency pin audits.
- **LLM04: Data and Model Poisoning** — Tested via synthetic poisoned RAG corpus injection scenarios.
- **LLM05: Improper Output Handling** — Mitigated via Jinja HTML auto-escaping, strict CSP without `'unsafe-inline'`, and parameterized SQL queries.
- **LLM06: Excessive Agency** — Evaluated via agent tool-misuse scenarios; blocked via AgentShield's deny-by-default execution sandbox.
- **LLM07: System Prompt Leakage** — Specifically evaluated via extraction goals against system prompts containing isolated canaries.
- **LLM08: Vector and Embedding Weaknesses** — Addressed by isolating document ingestion vectors.
- **LLM09: Misinformation** — Measured via refusal vs. ungrounded compliance scoring.
- **LLM10: Unbounded Consumption** — Tested via automated DoS and recursive expansion probe sets.

---

## 4. AgentShield Execution Guardrails

AgentShield implements the **Principle of Least Privilege**:

1. **Deny-by-Default Policy:** Tools cannot be executed unless explicitly enumerated in `allowed`.
2. **Path Confinement:** Every file operation undergoes canonical resolution with `posixpath.normpath` against the designated jail root (`/sandbox`). Any path escaping the boundary raises a `PolicyError`.
3. **Egress Firewall & SSRF Defense:** Outbound network requests undergo hostname verification against `allowed_hosts`. In addition, internal cloud metadata IP addresses (`169.254.169.254`, `metadata.google.internal`) are blocked.
4. **Call Budget:** Execution halts with a `PolicyError` if total tool invocations exceed `max_calls`.
5. **Tamper-Evident Audit Logging:** Every allowed and denied invocation is logged with tool name, arguments, status, and policy denial reason.

---

## 5. Production DevOps & Kubernetes Architecture

### 5.1. Container Hardening
- Unprivileged execution under user `app` (UID `10001`).
- Read-only root filesystem (`readOnlyRootFilesystem: true`).
- Linux capabilities completely dropped (`capabilities: drop: ["ALL"]`).
- No privilege escalation permitted (`allowPrivilegeEscalation: false`).
- Dedicated `emptyDir` memory tmpfs mounted for `/dev/shm` and `/tmp`.

### 5.2. Kubernetes Zero-Trust Network Policy
- Ingress: Restricted to port 8081 from trusted cluster ingresses.
- Egress: Restricted to UDP/TCP port 53 (DNS) and TCP port 443 (HTTPS for designated external LLMs).

### 5.3. High-Availability & Scalability
- Health Probes: `/healthz` (liveness) and `/readyz` (readiness).
- Horizontal Pod Autoscaling (HPA) targeting CPU and memory utilization thresholds.
- Pod Disruption Budget (PDB) guaranteeing high availability during cluster drains.
- Native Prometheus Operator integration via `ServiceMonitor`.
