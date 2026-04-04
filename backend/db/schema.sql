PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scan_runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    repos_scanned INTEGER NOT NULL DEFAULT 0,
    repos_flagged INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'running'
        CHECK (status IN ('running', 'completed', 'failed'))
);

CREATE TABLE IF NOT EXISTS findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id      INTEGER NOT NULL REFERENCES scan_runs(id),
    repo_full_name   TEXT NOT NULL,
    repo_url         TEXT NOT NULL,
    repo_size_kb     INTEGER NOT NULL DEFAULT 0,
    default_branch   TEXT NOT NULL DEFAULT 'main',
    repo_description TEXT,
    repo_stars       INTEGER NOT NULL DEFAULT 0,
    repo_created_at  TEXT,
    repo_updated_at  TEXT,
    scan_status      TEXT NOT NULL
        CHECK (scan_status IN ('clean', 'suspicious', 'error', 'rate_limited')),
    scanned_at       TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS matches (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id          INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    rule_name           TEXT NOT NULL,
    rule_category       TEXT,
    rule_severity       TEXT,
    file_path           TEXT NOT NULL,
    file_size           INTEGER,
    matched_strings     TEXT,
    code_snippet        TEXT,
    snippet_start_line  INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS votes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    github_user TEXT NOT NULL,
    vote        INTEGER NOT NULL CHECK (vote IN (-1, 1)),
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (finding_id, github_user)
);

CREATE TABLE IF NOT EXISTS comments (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id       INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    github_user      TEXT NOT NULL,
    github_avatar_url TEXT,
    body             TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_run   ON findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_findings_status     ON findings(scan_status);
CREATE INDEX IF NOT EXISTS idx_findings_repo       ON findings(repo_full_name);
CREATE INDEX IF NOT EXISTS idx_findings_scanned_at ON findings(scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_matches_finding     ON matches(finding_id);
CREATE INDEX IF NOT EXISTS idx_matches_rule        ON matches(rule_name);
CREATE INDEX IF NOT EXISTS idx_votes_finding       ON votes(finding_id);
CREATE INDEX IF NOT EXISTS idx_comments_finding    ON comments(finding_id);
