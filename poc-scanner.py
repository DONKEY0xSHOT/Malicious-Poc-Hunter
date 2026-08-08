# Imports
import argparse
import io
import os
import time
import zipfile
import requests
import yara
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

console = Console()

# Constants
SEARCH_URL = "https://api.github.com/search/repositories"
HEADERS = {"Accept": "application/vnd.github.v3+json"}
MAX_REPO_SIZE_KB = 100
MAX_RETRIES = 5
MAX_SLEEP = 60
DEFAULT_THREADS = 8
ERRORS = ("Network Error", "Fetch/Extraction Error")
RETRYABLE = ("RATE_LIMIT", "Network Error")

# Exclude media files
SKIP_EXTENSIONS = frozenset({
    ".md", ".markdown", ".rst", ".txt", ".adoc", ".pdf",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".webm", ".ttf", ".woff", ".woff2",
})


def search_github_pocs(session):
    """Generator that dynamically fetches PoC repositories, handling pagination automatically"""
    page = 1
    cursor = ""
    last_pushed = None
    seen = set()

    while True:

        # Look for CVE in the repo's name
        params = {"q": f"/CVE-20 in:name{cursor}", "sort": "updated", "order": "desc",
                  "per_page": 100, "page": page}
        try:
            response = session.get(SEARCH_URL, params=params, headers=HEADERS, timeout=(10, 30))

            if response.status_code in [403, 429]:

                # The Search API has a different rate limit than the download API
                console.print("\n[yellow][!] GitHub Search API Rate Limit Hit. Waiting 30s...[/yellow]")
                time.sleep(30)
                continue

            items = response.json().get("items", []) if response.ok else []

        # A dropped search connection must not discard a run
        except (requests.RequestException, ValueError):
            time.sleep(5)
            continue

        # A query exposes only 1000 results, so resume from the oldest push date
        if not items:
            if last_pushed is None or cursor.endswith(last_pushed):
                break

            cursor, page = f" pushed:<={last_pushed}", 1
            continue

        for item in items:
            last_pushed = item["pushed_at"]

            if item["full_name"] not in seen:
                seen.add(item["full_name"])
                yield item

        page += 1
        time.sleep(2)


def analyze_repo(session, repo_url, default_branch, rules):
    """Downloads a repo as a zip & scans it with YARA straight from memory"""
    zip_url = f"{repo_url}/archive/refs/heads/{default_branch}.zip"

    try:
        response = session.get(zip_url, timeout=(10, 30))

        if response.status_code in [403, 429]:
            return ["RATE_LIMIT"]

        response.raise_for_status()

        # A missing archive returns HTML under a 200, so confirm the PK magic number of a zip
        if not response.content.startswith(b"PK"):
            return ["Fetch/Extraction Error"]

        matches_found = set()

        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            for entry in archive.infolist():

                # No file should significantly outgrow its own repo, so anything larger is probably a decompression bomb
                if entry.is_dir() or entry.file_size > MAX_REPO_SIZE_KB * 1024:
                    continue

                if os.path.splitext(entry.filename)[1].lower() in SKIP_EXTENSIONS:
                    continue

                matches_found.update(m.rule for m in rules.match(data=archive.read(entry)))

        return sorted(matches_found)

    except (requests.Timeout, requests.ConnectionError):
        return ["Network Error"]

    # A corrupt entry must not escape, or one bad repo discards the whole run's results
    except (requests.RequestException, zipfile.BadZipFile, yara.Error, OSError, RuntimeError, EOFError):
        return ["Fetch/Extraction Error"]


def scan_repo(session, repo, rules, base_sleep):
    """Scans one repository, backing off on its own while the API is rate limiting it"""
    sleep = base_sleep

    for _ in range(MAX_RETRIES):
        triggers = analyze_repo(session, repo["html_url"], repo["default_branch"], rules)

        if not triggers or triggers[0] not in RETRYABLE:
            break

        sleep = min(sleep * 2, MAX_SLEEP)
        time.sleep(sleep)

    # Paces every worker, so the request rate stays proportional to the thread count
    time.sleep(base_sleep)
    return triggers


def main():
    parser = argparse.ArgumentParser(description="Naive GitHub PoC Analyzer")
    parser.add_argument("-n", "--number", type=int, default=10, help="Number of valid repos to analyze")
    parser.add_argument("-d", "--dir", type=str, required=True, dest="yara_dir", help="Directory containing YARA rules")
    parser.add_argument("-s", "--sleep", type=int, default=1, help="Initial sleep between downloads in seconds (default: 1)")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help=f"Concurrent downloads (default: {DEFAULT_THREADS})")
    args = parser.parse_args()

    yara_filepaths = {}
    if not os.path.isdir(args.yara_dir):
        console.print(f"[bold red]Error:[/bold red] The directory '{args.yara_dir}' does not exist.")
        return

    for root, _, files in os.walk(args.yara_dir):
        for file in files:
            if file.endswith(('.yar', '.yara')):
                yara_filepaths[file] = os.path.join(root, file)

    if not yara_filepaths:
        console.print(f"[bold red]Error:[/bold red] No .yar or .yara files found in '{args.yara_dir}'.")
        return

    try:
        rules = yara.compile(filepaths=yara_filepaths)
        console.print(f"[*] Successfully compiled {len(yara_filepaths)} YARA rule files.", style="green")
    except yara.SyntaxError as e:
        console.print(f"[bold red]YARA Syntax Error:[/bold red] {e}")
        return

    table = Table(title="PoC Repository Analysis Results")
    table.add_column("Repository", justify="left", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center", style="bold")
    table.add_column("YARA Triggers", justify="left", style="magenta")

    session = requests.Session()

    # Every worker needs its own connection
    session.mount("https://", requests.adapters.HTTPAdapter(pool_maxsize=args.threads))

    console.print(f"[*] Searching for {args.number} valid PoC repositories (<{MAX_REPO_SIZE_KB}KB)...", style="bold blue")

    # Using Progress() to manually control the bar
    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning valid repositories...", total=args.number)

        # Submitting
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            pending = []

            for repo in search_github_pocs(session):

                # Silently skip large repos without printing or adding to table
                if repo["size"] > MAX_REPO_SIZE_KB:
                    continue

                future = pool.submit(scan_repo, session, repo, rules, args.sleep)
                future.add_done_callback(lambda _: progress.update(task, advance=1))
                pending.append((repo["full_name"], future))

                # Break the loop if we've reached the target number
                if len(pending) >= args.number:
                    break

        # Read back in search order, so concurrency does not shuffle the report
        for repo_name, future in pending:
            triggers = future.result()

            if triggers and "RATE_LIMIT" in triggers:
                table.add_row(repo_name, "[bold red]SKIPPED[/bold red]", "Persistent Rate Limit")
            elif not triggers:
                table.add_row(repo_name, "[green]Clean[/green]", "None")
            elif triggers[0] in ERRORS:
                table.add_row(repo_name, "[yellow]Error[/yellow]", triggers[0])
            else:
                trigger_str = ", ".join(triggers)
                table.add_row(repo_name, "[red]Suspicious[/red]", trigger_str)

    console.print("\n")
    console.print(table)


if __name__ == "__main__":
    main()
