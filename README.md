<p align="center">
<pre style="color:#00BFFF; font-weight:bold;">

██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝
██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝

        VulnScope Vulnerability Scanner

</pre>
</p>

## VulnScope

VulnScope is a fast, modular vulnerability assessment CLI tool inspired by RustScan, Gobuster, and Nmap.

It focuses on:

- **Ultra-fast port scanning** (asyncio-based, 1–65535)
- **Directory brute-force** (Gobuster-like)
- **Subdomain enumeration**
- **Banner grabbing & basic vuln detection**
- **Basic SQL injection detection**
- **JSON, HTML, and Nmap-style XML reporting**
- **Plugin-based architecture** for future extensions

### Features

- **Port scanner**
  - Async TCP connect using `asyncio`
  - Scans arbitrary port ranges (1–65535)
  - Basic service detection (port + banner heuristics)
  - Banner grabbing and example CVE matching

- **Directory brute-force**
  - HTTP(S) requests with `requests`
  - Multithreaded
  - Shows HTTP status (200, 301, 302, 403 by default)
  - Progress bar via `tqdm`

- **Subdomain enumeration**
  - Wordlist-based
  - DNS resolution using `socket.gethostbyname`
  - Displays found subdomains and IPs

- **SQLi detection**
  - Common SQL payload set
  - Detects anomalies via HTTP 5xx and large response length changes

- **Reports**
  - JSON and HTML reports in `reports/`
  - Nmap-style XML reports for port and full scans
  - Simple, dark-themed HTML containing structured JSON

- **Plugins**
  - Drop modules under `vulnscope/plugins/` to extend functionality

---

### Installation on Kali Linux

1. **Clone the repository**

   ```bash
   git clone https://github.com/yourusername/vulnscope.git
   cd vulnscope
   ```

2. **Create a virtual environment (recommended)**

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies**

   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Install VulnScope as a CLI**

   ```bash
   pip install -e .
   ```

   This will install the `vulnscope` command into your environment.

---

### Usage

All commands:

```bash
vulnscope -h
```

#### 1. Port scanning

```bash
vulnscope scan 192.168.1.10 -p 1-65535 --json --html --nmap-xml
```

- **`-p` / `--ports`**: port range spec (e.g. `1-1024`, `80,443,8000-8100`)
- **`--json` / `--html` / `--nmap-xml`**: enable report formats
- Reports are stored in `reports/scan_<target>_<timestamp>.*`

#### 2. Directory brute-force

```bash
vulnscope dir https://example.com/ wordlists/directories.txt --json
```

- **`url`**: base URL
- **`wordlist`**: path to directory wordlist
- **`-t` / `--threads`**: worker threads (default 30)
- Only responses with `200`, `301`, `302`, `403` are printed by default.

#### 3. Subdomain enumeration

```bash
vulnscope sub example.com wordlists/subdomains.txt --html
```

- **`domain`**: base domain (e.g. `example.com`)
- **`wordlist`**: subdomain wordlist

#### 4. SQLi detection

```bash
vulnscope sqli "https://example.com/item.php?id=1" --json
```

- URL should have at least one query parameter.
- VulnScope mutates the first parameter’s value with common SQL payloads.
- Detection is heuristic and **not** a definitive vulnerability confirmation.

#### 5. Full assessment

```bash
vulnscope full 192.168.1.10 \
  --ports 1-65535 \
  --url https://example.com/ \
  --wordlist wordlists/directories.txt \
  --domain example.com \
  --sub-wordlist wordlists/subdomains.txt \
  --json --html --nmap-xml
```

- Runs:
  - Port scan
  - Directory brute-force (if `--url` + valid wordlist)
  - Subdomain enumeration (if `--domain` + valid wordlist)

---

### Plugin architecture

- Plugins live under `vulnscope/plugins/`.
- Any `.py` module placed there is auto-imported at startup.
- Plugins implement the `VulnScopePlugin` protocol and register via `register_plugin()`.
- Hooks:
  - `on_start(argv)`
  - `on_args_parsed(args)`
  - `on_before_command(args)`
  - `on_after_command(args, result)`

Example: `vulnscope/plugins/example_plugin.py`.

---

### CVE database

- Built-in static mappings live in `vulnscope/utils/helpers.py`.
- You can overlay additional data by providing a JSON file:
  - Set env `VULNSCOPE_CVE_DB=/path/to/cves.json`, or
  - Place `data/cves.json` at project root.

`cves.json` format:

```json
{
  "Apache": [
    {
      "version_regex": "^2\\.4\\.50",
      "cve": "CVE-2021-42013",
      "description": "Path traversal and RCE in Apache HTTP Server 2.4.50"
    }
  ]
}
```

---

### Legal

Use VulnScope **only** on systems you own or have explicit permission to test. Unauthorized scanning may be illegal.

