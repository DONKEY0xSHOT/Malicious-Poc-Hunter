# Malicious PoC Hunter

A security platform that automatically hunts malicious fake CVE exploitation PoCs on GitHub — those disguised as legitimate vulnerability research but actually targeting security researchers.

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

## Architecture

```
Browser (Preact SPA)
      │  HTTP
      ▼
Fly.io VM
  ├── FastAPI (uvicorn, port 8000)
  │     ├── /api/v1/*  — REST API (findings, votes, comments, auth, stats)
  │     └── /*         — Static frontend (Preact, no build step)
  ├── APScheduler — runs scan every 30 minutes in-process
  ├── SQLite — persistent volume at /data/poc-hunter.db
  └── YARA engine — compiles rules from ./Rules/ at startup
```

**No build pipeline.** The frontend uses Preact + HTM loaded from `esm.sh` CDN as ES modules.

---

## Quick Start (Local Development)

### Prerequisites

- Python 3.12+
- System YARA library:
  - Ubuntu/Debian: `sudo apt-get install yara`
  - macOS: `brew install yara`

### Setup

```bash
# Clone the repo
git clone https://github.com/DONKEY0xSHOT/Malicious-Poc-Hunter.git
cd Malicious-Poc-Hunter

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r backend/requirements.txt

# Copy environment template and fill in values
cp .env.example .env
# Edit .env with your SESSION_SECRET and GitHub OAuth credentials
```

### GitHub OAuth App (Required for votes/comments)

1. Go to [GitHub Developer Settings → OAuth Apps](https://github.com/settings/developers)
2. Click **New OAuth App** and set:
   - **Homepage URL**: `http://localhost:8000`
   - **Callback URL**: `http://localhost:8000/api/v1/auth/github/callback`
3. Copy **Client ID** and generate **Client Secret** into `.env`

### Run

```bash
uvicorn backend.api.main:app --reload --port 8000
```

Open [http://localhost:8000](http://localhost:8000).

The first automated scan runs after `SCAN_INTERVAL_MINUTES` (default: 30 min).

**CLI mode** (original tool, still works):

```bash
python poc-scanner.py --dir Rules --number 50
```

---

## Running Tests

```bash
pip install pytest pytest-asyncio
pytest
```

Tests cover YARA rules (true positives + false positive prevention), database CRUD, scanner unit tests, and API endpoint integration tests.

---

## Deployment to Fly.io (Free Tier)

### One-Time Setup

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh
fly auth login

# Create the app
fly launch --name poc-hunter --region iad --vm-size shared-cpu-1x --vm-memory 256 --no-deploy

# Create a 1GB persistent volume for SQLite
fly volumes create poc_hunter_data --size 1 --region iad

# Set secrets
fly secrets set \
  GITHUB_TOKEN="ghp_your_token_here" \
  GITHUB_OAUTH_CLIENT_ID="your_client_id" \
  GITHUB_OAUTH_CLIENT_SECRET="your_client_secret" \
  SESSION_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

**Update `fly.toml`:** Change `FRONTEND_URL` to `https://poc-hunter.fly.dev`.

**Update GitHub OAuth callback URL** to `https://poc-hunter.fly.dev/api/v1/auth/github/callback`.

### Deploy

```bash
fly deploy
```

The app is live at `https://poc-hunter.fly.dev`.

### Automatic Deployments (GitHub Actions)

1. Get your Fly.io deploy token: `fly tokens create deploy`
2. Add it as a GitHub secret named `FLY_API_TOKEN`
3. Every push to `main` runs tests, then deploys automatically

---

## Maintenance

### Logs

```bash
fly logs
```

### Database Backup

```bash
fly sftp get /data/poc-hunter.db ./backup-$(date +%Y%m%d).db
```

### Adding a New YARA Rule

1. Create `Rules/my_rule.yar`:
   ```yara
   rule My_Rule {
       meta:
           description = "What it detects"
           category    = "Category"
           severity    = "Critical"
       strings:
           $s1 = "suspicious_pattern" ascii
       condition:
           $s1
   }
   ```
2. Add a test fixture to `tests/fixtures/` and a test case to `tests/test_yara_rules.py`
3. Run `pytest tests/test_yara_rules.py -v` to verify
4. `fly deploy`

### Tuning False Positives

Add exclusion strings to the relevant `.yar` file (e.g. `$doc_readme = "README" nocase ascii`), use them in the condition with `not (2 of ($doc_*))`, and add the false-positive file as a benign fixture in `tests/fixtures/` with a corresponding test assertion.

### Updating Scan Interval

Edit `fly.toml` → `SCAN_INTERVAL_MINUTES`, then `fly deploy`.

---

## API Reference

Base URL: `/api/v1` · Interactive docs: `/api/docs`

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/findings` | — | List findings (filters: status, rule_name, repo_name, date_from, date_to, sort, page, per_page) |
| GET | `/findings/{id}` | — | Full detail with matches, votes, comments |
| POST | `/findings/{id}/vote` | ✓ | `{"vote": 1}` or `{"vote": -1}`; same vote toggles off |
| POST | `/findings/{id}/comments` | ✓ | `{"body": "..."}` (max 2000 chars) |
| DELETE | `/findings/{id}/comments/{cid}` | ✓ | Delete your own comment |
| GET | `/scan-runs` | — | Paginated scan run history |
| GET | `/scan-runs/latest` | — | Most recent scan run |
| GET | `/stats` | — | Aggregate statistics |
| GET | `/rules` | — | All loaded YARA rules with metadata |
| GET | `/auth/github` | — | Start GitHub OAuth |
| GET | `/auth/me` | — | Current user (null if not logged in) |
| POST | `/auth/logout` | — | Clear session |

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

## Security

- HTML tags stripped from all user input before storage
- All SQL queries use parameterised statements
- Frontend renders user content via `textContent` (no `innerHTML`)
- Session cookies: `HttpOnly`, `Secure` (production), `SameSite=Lax`
- Per-IP rate limiting: 60 req/min (read), 20 req/min (write)
- Content-Security-Policy header on every response
- ZIP extraction validates paths against zip-slip attacks
- Non-root Docker user

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
