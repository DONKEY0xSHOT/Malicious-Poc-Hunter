from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Database
    database_path: str = "/data/poc-hunter.db"

    # GitHub scanner
    github_token: str = ""
    max_repos_per_scan: int = 100
    max_concurrent_downloads: int = 5
    max_repo_size_kb: int = 100
    rules_dir: str = "./Rules"

    # Scheduler
    scan_interval_minutes: int = 30

    # GitHub OAuth
    github_oauth_client_id: str = ""
    github_oauth_client_secret: str = ""
    frontend_url: str = "http://localhost:8000"

    # Session
    session_secret: str = "change-me-in-production"

    # Rate limiting
    public_rate_limit: str = "60/minute"
    write_rate_limit: str = "20/minute"


settings = Settings()
