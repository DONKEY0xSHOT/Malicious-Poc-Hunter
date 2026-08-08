# Malicious-Poc-Hunter

Malicious-Poc-Hunter is a lightweight utility designed to detect malicious code hidden within fake Proof of Concept (PoC) repositories on GitHub. It operates on a simple premise - Find fake CVE exploits that are designed to attack the security community.

It does one job and does it well : )

## Features

* **Discovery:** Queries the GitHub API for repositories matching standard CVE naming conventions.
* **Downloading:** Downloads repository archives and analyzes them entirely in memory. Nothing is written to disk.
* **Static Analysis:** Compiles and executes YARA rules against the repository's code, skipping documentation and media.
* **Concurrency:** Downloads and scans repositories in parallel, backing off automatically when the API pushes back.

## Usage

```bash
python poc-scanner.py --dir <path_to_rules> [options]
```

### Arguments

* `-d`, `--dir`: (Required) Path to the directory containing YARA rules.
* `-n`, `--number`: The maximum number of valid repositories to process. (Default: 10)
* `-s`, `--sleep`: Initial sleep duration between requests in seconds to mitigate rate limiting. (Default: 1)
* `-t`, `--threads`: Number of repositories downloaded and scanned concurrently. (Default: 8)

## Included YARA Signatures

The repository includes three YARA rules targeting common techniques found in deceptive PoCs:

* **Obfuscation Detection:** Identifies an encoded payload that the repository itself decodes and runs, such as a Base64 blob larger than 200 characters paired with a decoder and an interpreter call.
* **Exfiltration Detection:** Identifies data sent to a hardcoded chat webhook or bot API, matching only well formed Discord and Telegram credentials rather than the placeholders a genuine PoC documents.
* **Supply Chain Detection:** Identifies code that runs while a dependency is installed, such as a `setuptools` install hook or an npm lifecycle script that fetches and executes a payload.


## Real World Findings

Despite its small size, the tool has successfully identified active campaigns distributing malware disguised as exploits!

* **Yetazyyy/CVE-2025-4606** - A `scanner.py` marked "Obfuscated by Ohang", carrying an AES-GCM blob that is decrypted behind a password prompt and then executed. ([`48e96cd`](https://github.com/Yetazyyy/CVE-2025-4606/blob/48e96cdfe5aab7a01ac69ca0c05d73b72bf68720/scanner.py))
* **Yetazyyy/CVE-2026-0770** - The same dropper, republished under a second CVE. ([`3540636`](https://github.com/Yetazyyy/CVE-2026-0770/blob/3540636de6b2b94b7f1343f0fd1bbba7b583600d/scanner.py))
* **Yetazyyy/CVE-2025-25347** - A third repository by the same author, built from the same template. ([`533b9aa`](https://github.com/Yetazyyy/CVE-2025-25347/blob/533b9aa46a105d8dc6da7cfce3cb838b56234380/scanner.py))
* **maybe-O/CVE-2025-67303** - An `__init__.py` that opens a PowerShell reverse shell the moment the package is imported, with a `setuptools` hook opening another on `pip install`. ([`a5b0d90`](https://github.com/maybe-O/CVE-2025-67303/blob/a5b0d90646c157adb9cd973e167656742f26ee81/__init__.py))

Every finding links to the exact file at the commit it was observed at, so the code can still be read even if the repository is edited : )

## TODO

* Support an optional GitHub token to raise the search API rate limit.
