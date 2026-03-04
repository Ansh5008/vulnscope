import json
import os
import re
from typing import Iterable, List, Dict, Any, Optional

from colorama import Fore, Style

from vulnscope import __version__


PORT_SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
}


SERVICE_CVE_DB: Dict[str, List[Dict[str, str]]] = {
    "OpenSSH": [
        {
            "version_regex": r"^7\.2",
            "cve": "CVE-2016-0777",
            "description": "OpenSSH roaming vulnerability (information leak)",
        },
        {
            "version_regex": r"^6\.",
            "cve": "CVE-2015-5600",
            "description": "OpenSSH keyboard-interactive bruteforce issue",
        },
    ],
    "Apache": [
        {
            "version_regex": r"^2\.2",
            "cve": "CVE-2011-3192",
            "description": "Apache HTTPD Range header DoS",
        },
        {
            "version_regex": r"^2\.4\.49",
            "cve": "CVE-2021-41773",
            "description": "Path traversal and RCE in Apache HTTP Server 2.4.49",
        },
    ],
    "nginx": [
        {
            "version_regex": r"^1\.4",
            "cve": "CVE-2013-4547",
            "description": "nginx SPDY heap buffer overflow",
        },
        {
            "version_regex": r"^1\.18",
            "cve": "CVE-2021-23017",
            "description": "1-byte memory overwrite in resolver (DoS / RCE)",
        },
    ],
    "MySQL": [
        {
            "version_regex": r"^5\.5",
            "cve": "CVE-2012-2122",
            "description": "Authentication bypass in MySQL",
        }
    ],
    "PostgreSQL": [
        {
            "version_regex": r"^9\.3",
            "cve": "CVE-2014-0063",
            "description": "DoS via crafted input to array functions",
        }
    ],
}


def _overlay_external_cve_db() -> None:
    global SERVICE_CVE_DB
    path = os.getenv("VULNSCOPE_CVE_DB")

    if not path:
        here = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        candidate = os.path.join(here, "data", "cves.json")
        path = candidate if os.path.isfile(candidate) else None

    if not path or not os.path.isfile(path):
        return

    try:
        with open(path, "r", encoding="utf-8") as f:
            external = json.load(f)
        if isinstance(external, dict):
            for svc, rules in external.items():
                if isinstance(rules, list):
                    SERVICE_CVE_DB.setdefault(svc, []).extend(rules)
    except Exception as exc:
        print(
            Fore.RED
            + f"[!] Failed to load external CVE DB from {path}: {exc}"
            + Style.RESET_ALL
        )


_overlay_external_cve_db()


def parse_port_range(spec: str) -> Iterable[int]:
    ports: List[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    seen = set()
    out = []
    for p in ports:
        if 1 <= p <= 65535 and p not in seen:
            out.append(p)
            seen.add(p)
    return out


def detect_service_from_port(port: int, banner: Optional[str] = None) -> str:
    if banner:
        banner_lower = banner.lower()
        if "vmware authentication daemon" in banner_lower:
            return "vmware-auth"
        if "ssh" in banner_lower:
            return "ssh"
        if "http" in banner_lower or "apache" in banner_lower or "nginx" in banner_lower:
            return "http"
        if "mysql" in banner_lower:
            return "mysql"
        if "postgres" in banner_lower:
            return "postgresql"
        if "ftp" in banner_lower:
            return "ftp"
    return PORT_SERVICE_MAP.get(port, "unknown")


def detect_vulns_from_banner(banner: str) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    if not banner:
        return found

    for service_name, rules in SERVICE_CVE_DB.items():
        if service_name.lower() in banner.lower():
            m = re.search(r"(\d+\.\d+(?:\.\d+)?)", banner)
            if not m:
                continue
            version = m.group(1)
            for rule in rules:
                if re.match(rule.get("version_regex", ""), version):
                    found.append(
                        {
                            "service": service_name,
                            "version": version,
                            "cve": rule.get("cve"),
                            "description": rule.get("description"),
                        }
                    )
    return found


def generate_reports(
    base_name: str,
    data: Dict[str, Any],
    output_dir: str = "reports",
    write_json: bool = True,
    write_html: bool = True,
    write_nmap_xml: bool = False,
) -> None:
    os.makedirs(output_dir, exist_ok=True)

    if write_json:
        json_path = os.path.join(output_dir, f"{base_name}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(Fore.GREEN + f"[+] JSON report written to {json_path}" + Style.RESET_ALL)

    if write_html:
        html_path = os.path.join(output_dir, f"{base_name}.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(_render_html_report(base_name, data))
        print(Fore.GREEN + f"[+] HTML report written to {html_path}" + Style.RESET_ALL)

    if write_nmap_xml:
        xml_path = os.path.join(output_dir, f"{base_name}.xml")
        with open(xml_path, "w", encoding="utf-8") as f:
            f.write(_render_nmap_xml_report(data))
        print(
            Fore.GREEN
            + f"[+] Nmap-style XML report written to {xml_path}"
            + Style.RESET_ALL
        )


def _render_html_report(title: str, data: Dict[str, Any]) -> str:
    escaped_title = title.replace("<", "&lt;").replace(">", "&gt;")
    body = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VulnScope Report - {escaped_title}</title>
<style>
body {{ font-family: Arial, sans-serif; background: #111; color: #eee; }}
h1 {{ color: #4dd0e1; }}
pre {{ background: #222; padding: 1rem; border-radius: 4px; overflow-x: auto; }}
code {{ color: #a5d6a7; }}
.footer {{ font-size: 0.8rem; color: #777; margin-top: 2rem; }}
</style>
</head>
<body>
<h1>VulnScope Report</h1>
<h2>{escaped_title}</h2>
<pre><code>{json.dumps(data, indent=2)}</code></pre>
<div class="footer">
Generated by VulnScope v{__version__}
</div>
</body>
</html>
"""
    return body


def _render_nmap_xml_report(data: Dict[str, Any]) -> str:
    from datetime import datetime

    scan_type = data.get("type", "scan")
    now = int(datetime.utcnow().timestamp())
    target = data.get("target") or data.get("host") or "unknown"

    if scan_type == "full_scan":
        port_component = data.get("components", {}).get("port_scan", {})
        open_ports = port_component.get("open_ports", [])
    else:
        open_ports = data.get("open_ports", [])

    host_xml_parts = []
    host_xml_parts.append(f'  <host starttime="{now}" endtime="{now}">')
    host_xml_parts.append(f'    <address addr="{target}" addrtype="ipv4"/>')
    host_xml_parts.append("    <ports>")

    for entry in open_ports:
        port_id = entry.get("port")
        service = entry.get("service") or "unknown"
        state = entry.get("state", "open")
        banner = (entry.get("banner") or "").replace('"', "&quot;")
        host_xml_parts.append(
            f'      <port protocol="tcp" portid="{port_id}">'
            f'<state state="{state}"/>'
            f'<service name="{service}" product="{banner}"/></port>'
        )

    host_xml_parts.append("    </ports>")
    host_xml_parts.append("  </host>")

    host_block = "\n".join(host_xml_parts)

    xml = f"""<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="vulnscope" args="vulnscope" start="{now}" version="{__version__}">
{host_block}
</nmaprun>
"""
    return xml


def load_default_wordlist_path(filename: str) -> Optional[str]:
    here = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    candidate = os.path.join(here, "wordlists", filename)
    if os.path.isfile(candidate):
        return candidate
    return None


def load_plugins() -> None:
    import pkgutil
    import importlib

    package = "vulnscope.plugins"
    try:
        pkg = importlib.import_module(package)
    except ImportError:
        return

    for _finder, name, _ispkg in pkgutil.iter_modules(pkg.__path__, package + "."):
        try:
            importlib.import_module(name)
        except Exception as exc:
            print(
                Fore.RED
                + f"[!] Failed to load plugin {name}: {exc}"
                + Style.RESET_ALL
            )

