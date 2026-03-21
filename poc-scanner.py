import argparse
import requests
import yara
import tempfile
import zipfile
import io
import os
import time
from rich.console import Console
from rich.table import Table
from rich.progress import Progress # Changed from track to Progress

console = Console()

def search_github_pocs():
    """Generator that dynamically fetches PoC repositories, handling pagination automatically."""
    page = 1
    while True:
        url = "https://api.github.com/search/repositories"
        
        # Look for CVE in the repo's name
        params = {"q": "/CVE-20 in:name", "sort": "updated", "order": "desc", "per_page": 100, "page": page}
        headers = {"Accept": "application/vnd.github.v3+json"}
        
        response = requests.get(url, params=params, headers=headers)
        
        if response.status_code in [403, 429]:
        
            # The Search API has a different rate limit than the download API
            console.print("\n[yellow][!] GitHub Search API Rate Limit Hit. Waiting 30s...[/yellow]")
            time.sleep(30)
            continue
            
        response.raise_for_status()
        items = response.json().get("items", [])
        
        # We've exhausted all GitHub search results
        if not items:
            break
            
        for item in items:
            yield item
            
        page += 1
        time.sleep(2)

def analyze_repo(repo_url, default_branch, rules):
    """Downloads a repo as a zip, extracts it, and scans with YARA."""
    zip_url = f"{repo_url}/archive/refs/heads/{default_branch}.zip"
    
    try:
        response = requests.get(zip_url, timeout=(10, 15))
        
        if response.status_code in [403, 429]:
            return ["RATE_LIMIT"]
            
        response.raise_for_status()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                z.extractall(temp_dir)
            
            matches_found = []
            for root, _, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    if os.path.getsize(file_path) > 10 * 1024 * 1024:
                        continue
                        
                    matches = rules.match(file_path)
                    if matches:
                        matches_found.extend([m.rule for m in matches])
                        
            return list(set(matches_found)) 
            
    except Exception as e:
        return ["Fetch/Extraction Error"]

def main():
    parser = argparse.ArgumentParser(description="Naive GitHub PoC Analyzer")
    parser.add_argument("-n", "--number", type=int, default=10, help="Number of valid repos to analyze")
    parser.add_argument("-d", "--dir", type=str, required=True, dest="yara_dir", help="Directory containing YARA rules")
    parser.add_argument("-s", "--sleep", type=int, default=1, help="Initial sleep between downloads in seconds (default: 1)")
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

    current_sleep = args.sleep
    valid_scanned_count = 0

    console.print(f"[*] Searching for {args.number} valid PoC repositories (<100KB)...", style="bold blue")

    # Using Progress() instead of track() to manually control the bar
    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning valid repositories...", total=args.number)
        
        for repo in search_github_pocs():
        
            # Break the loop if we've reached the target number
            if valid_scanned_count >= args.number:
                break
                
            repo_name = repo["full_name"]
            repo_url = repo["html_url"]
            default_branch = repo["default_branch"]
            repo_size_kb = repo["size"]
            
            # Silently skip large repos without printing or adding to table
            if repo_size_kb > 100:
                continue
                
            max_retries = 5
            retries = 0
            triggers = []
            
            while retries < max_retries:
                triggers = analyze_repo(repo_url, default_branch, rules)
                
                if triggers and "RATE_LIMIT" in triggers:
                    retries += 1
                    current_sleep *= 2
                    progress.console.print(f"[yellow][!] Rate limit hit on {repo_name}. Sleeping for {current_sleep}s...[/yellow]")
                    time.sleep(current_sleep)
                else:
                    break 
            
            if triggers and "RATE_LIMIT" in triggers:
                table.add_row(repo_name, "[bold red]SKIPPED[/bold red]", "Persistent Rate Limit")
            elif not triggers:
                table.add_row(repo_name, "[green]Clean[/green]", "None")
            elif "Fetch/Extraction Error" in triggers:
                table.add_row(repo_name, "[yellow]Error[/yellow]", "Could not scan")
            else:
                trigger_str = ", ".join(triggers)
                table.add_row(repo_name, "[red]Suspicious[/red]", trigger_str)

            # We successfully processed a valid repository : )
            valid_scanned_count += 1
            progress.update(task, advance=1)
            time.sleep(current_sleep)

    console.print("\n")
    console.print(table)

if __name__ == "__main__":
    main()