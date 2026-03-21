# Malicious-Poc-Hunter

Malicious-Poc-Hunter is a lightweight utility designed to detect malicious code hidden within fake Proof of Concept (PoC) repositories on GitHub. It operates on a simple premise - Find fake CVE exploits that are designed to attack the security community. 

It does one job and does it well : )

## Features

* **Discovery:** Queries the GitHub API for repositories matching standard CVE naming conventions.
* **Downloading:** Downloads and extracts repository archives directly into temporary directories. The files are analyzed and discarded.
* **Static Analysis:** Compiles and executes YARA rules against the extracted files.

## Usage

```bash
python poc-scanner.py --dir <path_to_rules> [options]
```

### Arguments

* `-d`, `--dir`: (Required) Path to the directory containing YARA rules.
* `-n`, `--number`: The maximum number of valid repositories to process. (Default: 10)
* `-s`, `--sleep`: Initial sleep duration between requests in seconds to mitigate rate limiting. (Default: 1)

## Included YARA Signatures

The repository includes two YARA rules targeting common techniques found in deceptive PoCs:

**Obfuscation Detection:** Identifies encoded command execution attempts, specifically targeting Base64 payloads larger than 200 characters combined with PowerShell execution flags or Python base64 decoding routines.
**Ransomware Indicators:** Detects basic ransomware behaviors, such as attempts to delete Volume Shadow Copies via `vssadmin`and the presence of extortion terminology.

## In the Wild: Real World Findings

Despite its small size, the tool has successfully identified active campaigns distributing malware disguised as exploits. 

During routine scanning, the analyzer flagged two distinct Python droppers masquerading as legitimate vulnerability research. Instead of exploiting target systems, these scripts executed obfuscated payloads on the researcher's local machine. The intercepted repositories were titled:
* **CVE-2025-4606**
<img width="735" height="448" alt="image" src="https://github.com/user-attachments/assets/6a1748fa-da8a-401f-a0bd-311246b448b6" />


* **CVE-2026-0770**
<img width="734" height="485" alt="image" src="https://github.com/user-attachments/assets/0740bafa-30ad-46e6-a901-0bced693022e" />


## TODO

* Add new YARA rules to expand detection capabilities.
* Refine existing YARA rules to reduce FPs and improve precision..
* Implement multi-threading to improve performance.
