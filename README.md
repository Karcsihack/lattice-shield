# Lattice-Shield — The AI-Code Sentinel

> **"Lattice-Shield is the firewall between your proprietary algorithms and the public cloud AI."**

[![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8?logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)
[![Security](https://img.shields.io/badge/security-DevSecOps-red)](docs/security.md)
[![Part of](https://img.shields.io/badge/part%20of-Lattice%20Suite-blueviolet)](https://github.com/lattice-suite)

---

## The Problem

Google, Apple, and Samsung have **banned** their engineers from pasting internal code into ChatGPT,
GitHub Copilot, and other public LLMs — not out of technophobia, but because **every snippet you
share with a public AI may be ingested into its training data**, permanently exposing:

- Proprietary algorithms worth years of R&D
- API keys, database credentials, and infrastructure secrets
- Internal business logic and competitive moats
- Customer PII your organization is legally obligated to protect

**Lattice-Shield solves this.** It intercepts code before it leaves the developer's machine,
scans it for 43+ categories of sensitive data, anonymizes proprietary identifiers, and routes
everything through the local **Lattice-Proxy** for a final PII-scrubbing pass.

---

## What Lattice-Shield Does

| Step | Action             | How                                                               |
| ---- | ------------------ | ----------------------------------------------------------------- |
| 1    | **Detect secrets** | 43-rule regex engine (AWS, Stripe, Slack, keys, DB strings…)      |
| 2    | **Anonymize IP**   | AST-based renaming (Go) or regex heuristics (all other languages) |
| 3    | **Scrub PII**      | Routes through `Lattice-Proxy` on `localhost:8080`                |
| 4    | **Block commits**  | Git pre-commit hook — zero config after `install-hook`            |

---

## Architecture: The 5-Layer Lattice Suite

```
┌─────────────────────────────────────────────────────────────────────┐
│                        LATTICE SUITE                                │
├─────────────┬─────────────┬─────────────┬──────────┬───────────────┤
│  Lattice    │  Lattice    │  Lattice    │ Lattice  │ Lattice       │
│  Proxy      │  Automate   │  Dashboard  │ SDK      │ Shield ◄ HERE │
│  (Data)     │  (Rules)    │  (Visibility│ (Access) │ (Code)        │
│  :8080      │  Webhooks   │  Web UI)    │ Unified  │ CLI / Hook    │
└─────────────┴─────────────┴─────────────┴──────────┴───────────────┘
```

Lattice-Shield is the **Shield** layer — the last line of defence at the developer's workstation.

---

## Detection Coverage (43 Rules)

| Category                                                      | Rules | Severity                 |
| ------------------------------------------------------------- | ----- | ------------------------ |
| AWS Credentials (Key ID, Secret, Session)                     | 3     | CRITICAL / HIGH          |
| Stripe Keys (Live, Test, Publishable, Restricted)             | 4     | CRITICAL / HIGH / MEDIUM |
| Slack Tokens (Webhook, Bot, User, App)                        | 4     | CRITICAL / HIGH          |
| Private Keys (RSA, EC, OpenSSH, PGP, DSA, PKCS#8)             | 6     | CRITICAL                 |
| GitHub Tokens (Classic PAT, Fine-Grained, OAuth, App)         | 4     | CRITICAL                 |
| Google / GCP (API Key, OAuth Secret, Service Account)         | 3     | CRITICAL / HIGH          |
| Azure (Storage Connection String, SAS Token)                  | 2     | CRITICAL / HIGH          |
| Database Strings (Postgres, MySQL, MongoDB, Redis)            | 4     | CRITICAL / HIGH          |
| JWT Tokens                                                    | 1     | MEDIUM                   |
| Hardcoded Credentials (Password, API Key, Secret, Basic Auth) | 4     | CRITICAL / HIGH          |
| Communication APIs (Twilio, SendGrid, Mailgun)                | 3     | HIGH                     |
| DevOps Tokens (NPM, PyPI, Heroku)                             | 3     | HIGH                     |
| Internal Network (Private IPs, .corp/.internal domains)       | 2     | MEDIUM / LOW             |

---

## Installation

**Prerequisites:** Go 1.22+

```bash
# Option A — build from source
git clone https://github.com/lattice-suite/lattice-shield.git
cd lattice-shield
go mod tidy
go build -o lattice-shield .

# Option B — install globally via go install
go install github.com/lattice-suite/lattice-shield@latest
```

---

## Usage

### Scan a file

```bash
lattice-shield scan main.go

# Filter by severity
lattice-shield scan --severity CRITICAL config.py

# JSON output for SIEM / CI pipeline integration
lattice-shield scan --json --exit-on-detect src/auth.go

# Show masked matching values (verbose)
lattice-shield scan --verbose secrets.env
```

### Scan from stdin (pipe-friendly)

```bash
cat internal/risk_engine.go | lattice-shield scan
git show HEAD:src/payment.go | lattice-shield scan
```

### Anonymize proprietary code

```bash
# Preview — nothing is modified
lattice-shield anonymize --dry-run internal/algorithm.go

# Anonymize and write to a new file
lattice-shield anonymize internal/algorithm.go --output safe_algorithm.go

# Pipe directly into your LLM prompt
lattice-shield anonymize main.go | pbcopy
```

### Install the Git pre-commit hook

```bash
# One command — protects the entire repository from this moment forward
lattice-shield install-hook
```

After installation, every `git commit` automatically triggers a scan:

```
  Running Lattice-Shield security check...

  ✗ src/config.go — 2 finding(s)
    [CRITICAL] Line 14: AWS Access Key ID
    [HIGH]     Line 22: Hardcoded Password

  BLOCKED — 2 secret(s) detected.
  Run 'lattice-shield anonymize <file>' to sanitize before committing.

  ╔══════════════════════════════════════════════════════════╗
  ║  COMMIT BLOCKED by Lattice-Shield                        ║
  ╚══════════════════════════════════════════════════════════╝
```

---

## Example: Protecting Proprietary Algorithms

**Before — dangerous to paste into any LLM:**

```go
func calculateInternalRisk(portfolio Portfolio) float64 {
    baseScore := computeProprietaryScore(portfolio.Assets)
    return applyInternalMultiplier(baseScore, 0.847)
}
```

**After `lattice-shield anonymize` — safe to share:**

```go
func process_data_v1_3a4f(portfolio Portfolio) float64 {
    baseScore := process_data_v2_1b2c(portfolio.Assets)
    return process_data_v3_9d8e(baseScore, 0.847)
}
```

Your algorithm remains functionally identical; its identity is gone.

---

## Data Flow Through the Lattice Suite

```
Developer's IDE / Terminal
         │
         ▼
┌─────────────────────┐
│   lattice-shield    │  ←  Secret Detection + Code Anonymization
│   (this tool)       │
└──────────┬──────────┘
           │  sanitized code
           ▼
┌─────────────────────┐
│   Lattice-Proxy     │  ←  PII Scrubbing + Audit Logging (port 8080)
│   localhost:8080    │
└──────────┬──────────┘
           │  clean payload
           ▼
┌─────────────────────┐
│   LLM API           │  ←  Only sanitized code arrives here
│   (Copilot / GPT)   │
└─────────────────────┘
```

---

## CI/CD Integration

Add to your GitHub Actions workflow:

```yaml
- name: Lattice-Shield secret scan
  run: |
    go install github.com/lattice-suite/lattice-shield@latest
    lattice-shield scan --json --exit-on-detect --severity HIGH ./...
```

---

## Why Lattice-Shield vs. Alternatives

| Feature                       | Lattice-Shield | detect-secrets | gitleaks |
| ----------------------------- | -------------- | -------------- | -------- |
| 43-rule secret scanner        | ✅             | Partial        | ✅       |
| AST-based Go anonymization    | ✅             | ❌             | ❌       |
| AI-specific IP protection     | ✅             | ❌             | ❌       |
| Lattice-Proxy PII integration | ✅             | ❌             | ❌       |
| Auto pre-commit install       | ✅             | Manual         | Manual   |
| JSON output for SIEM          | ✅             | ✅             | ✅       |
| 5-layer enterprise governance | ✅             | ❌             | ❌       |

---

## Roadmap

- [ ] Language-specific AST anonymizers (Python, TypeScript, Java)
- [ ] VS Code & JetBrains plugins
- [ ] Lattice Dashboard integration
- [ ] Real-time Copilot interceptor mode (`lattice-shield intercept`)
- [ ] Rule customization via `lattice-shield.yaml`
- [ ] SARIF output for GitHub Advanced Security

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributors must sign the CLA.

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

_Part of the [Lattice Suite](https://github.com/lattice-suite) — Enterprise AI Governance Platform._
