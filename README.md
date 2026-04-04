# Malicious PoC Hunter

A security platform that automatically hunts malicious fake CVE exploitation PoCs on GitHub, disguised as legitimate vulnerability research but actually targeting security researchers.

The tool runs YARA static analysis on GitHub repositories matching CVE naming patterns, presents results in a polished web dashboard, and supports community voting and commenting on findings.

## Real-World Findings

Despite its small size, the tool has successfully identified active campaigns distributing malware disguised as exploits.

During routine scanning, the analyzer flagged two distinct Python droppers masquerading as legitimate vulnerability research. Instead of exploiting target systems, these scripts executed obfuscated payloads on the researcher's local machine. The intercepted repositories were titled:

- **CVE-2025-4606**

<img width="735" height="448" alt="image" src="https://github.com/user-attachments/assets/6a1748fa-da8a-401f-a0bd-311246b448b6" />

- **CVE-2026-0770**

<img width="734" height="485" alt="image" src="https://github.com/user-attachments/assets/0740bafa-30ad-46e6-a901-0bced693022e" />

---

## Features

- **Automated scanning** every 30 minutes with a visible "last updated" timestamp
- **Web dashboard** with code snippets and visual highlighting of YARA match locations
- **Archive** of all historical scan results
- **Search and filters** by rule name, status, date range, repository name, and sort order
- **Upvote / downvote / comment** system (GitHub OAuth login required)
- **11 YARA rules** across 6 categories: Obfuscation, Ransomware, Reverse Shell, RAT/Dropper, Exfiltration, Persistence
- **Concurrent downloads** via asyncio + httpx (5 repos in parallel)
- **Rate-limit aware** with exponential backoff and GitHub header parsing
- **Security hardened**: CSP headers, parameterised queries, HTML sanitisation, per-IP rate limiting

---

## YARA Rules

| Rule | File | Category | Severity |
|------|------|----------|----------|
| `Obfuscation_Encoded_Execution` | `obfuscation.yar` | Obfuscation | Critical |
| `Ransomware` | `ransomware.yar` | Ransomware | Critical |
| `PowerShell_Reverse_Shell` | `reverse_shell.yar` | Reverse Shell | Critical |
| `Python_Reverse_Shell` | `reverse_shell.yar` | Reverse Shell | Critical |
| `Bash_Reverse_Shell` | `reverse_shell.yar` | Reverse Shell | Critical |
| `Python_RAT_Indicators` | `rat.yar` | RAT | Critical |
| `Python_Dropper` | `rat.yar` | Dropper | Critical |
| `Data_Exfiltration_Python` | `exfiltration.yar` | Exfiltration | High |
| `Credential_Harvesting` | `exfiltration.yar` | Exfiltration | High |
| `Windows_Persistence` | `persistence.yar` | Persistence | High |
| `Linux_Persistence` | `persistence.yar` | Persistence | High |

---

## Project Structure

```
Malicious-Poc-Hunter/
├── backend/
│   ├── api/           FastAPI app, routes, auth, middleware, schemas
│   ├── db/            SQLite schema + async database layer
│   └── scanner/       GitHub client, YARA engine, analyzer, scheduler
├── frontend/
│   ├── index.html     SPA shell (Preact + HTM, no build step)
│   └── static/        CSS, JS app, API client, Preact components
├── Rules/             YARA rule files (6 files, 11 rules)
├── tests/             pytest suite + malicious/benign fixture files
├── Dockerfile         Python 3.12 image
├── fly.toml           Fly.io deployment config
├── poc-scanner.py     Original CLI scanner (still functional)
└── .env.example       Environment variable template
```
