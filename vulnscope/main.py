import argparse
import os
import sys
from datetime import datetime

from colorama import init as colorama_init, Fore, Style

from vulnscope.utils.banner import print_banner
from vulnscope.utils.logger import get_logger
from vulnscope.utils.helpers import (
    parse_port_range,
    generate_reports,
    load_default_wordlist_path,
    load_plugins,
)
from vulnscope.scanner.port_scan import run_port_scan
from vulnscope.web.dir_bruteforce import run_dir_bruteforce
from vulnscope.recon.subdomain_enum import enumerate_subdomains
from vulnscope.web.sqli_detector import detect_sqli
from vulnscope.plugins.base import get_plugins


colorama_init(autoreset=True)
logger = get_logger(__name__)


def cmd_scan(args):
    ports = parse_port_range(args.ports)
    logger.info(f"Starting port scan on {args.target} for ports {args.ports}")
    scan_result = run_port_scan(
        target=args.target,
        ports=ports,
        concurrency=args.concurrency,
        timeout=args.timeout,
        show_progress=not args.no_progress,
    )

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base_name = f"scan_{args.target.replace('.', '_')}_{timestamp}"
    report_payload = {
        "type": "port_scan",
        "target": args.target,
        "ports": args.ports,
        "result": scan_result,
        "open_ports": scan_result.get("open_ports", []),
    }

    if args.json or args.html or args.nmap_xml:
        generate_reports(
            base_name=base_name,
            data=report_payload,
            output_dir=args.output_dir,
            write_json=args.json,
            write_html=args.html,
            write_nmap_xml=args.nmap_xml,
        )

    if not scan_result["open_ports"]:
        print(Fore.YELLOW + "[!] No open ports found.")
    else:
        print(Fore.GREEN + "[+] Open ports:")
        for entry in sorted(scan_result["open_ports"], key=lambda e: e["port"]):
            port = entry["port"]
            service = entry.get("service") or "unknown"
            banner = entry.get("banner") or ""
            print(
                f"  {Fore.CYAN}{port:>5}/tcp{Style.RESET_ALL}  "
                f"{service:<15} {Fore.MAGENTA}{banner}{Style.RESET_ALL}"
            )

    return scan_result


def cmd_dir(args):
    if not os.path.isfile(args.wordlist):
        logger.error(f"Wordlist not found: {args.wordlist}")
        sys.exit(1)

    logger.info(f"Starting directory brute-force on {args.url}")
    results = run_dir_bruteforce(
        base_url=args.url,
        wordlist_path=args.wordlist,
        threads=args.threads,
        timeout=args.timeout,
        status_filter=[200, 301, 302, 403],
        show_progress=not args.no_progress,
    )

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base_name = f"dir_{args.url.replace('://', '_').replace('/', '_')}_{timestamp}"
    report_payload = {
        "type": "dir_bruteforce",
        "target": args.url,
        "wordlist": args.wordlist,
        "result": results,
    }

    if args.json or args.html:
        generate_reports(
            base_name=base_name,
            data=report_payload,
            output_dir=args.output_dir,
            write_json=args.json,
            write_html=args.html,
        )

    return results


def cmd_sub(args):
    if not os.path.isfile(args.wordlist):
        logger.error(f"Wordlist not found: {args.wordlist}")
        sys.exit(1)

    logger.info(f"Starting subdomain enumeration on {args.domain}")
    results = enumerate_subdomains(
        domain=args.domain,
        wordlist_path=args.wordlist,
        threads=args.threads,
        timeout=args.timeout,
        show_progress=not args.no_progress,
    )

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base_name = f"sub_{args.domain.replace('.', '_')}_{timestamp}"
    report_payload = {
        "type": "subdomain_enum",
        "target": args.domain,
        "wordlist": args.wordlist,
        "result": results,
    }

    if args.json or args.html:
        generate_reports(
            base_name=base_name,
            data=report_payload,
            output_dir=args.output_dir,
            write_json=args.json,
            write_html=args.html,
        )

    return results


def cmd_sqli(args):
    logger.info(f"Starting basic SQLi detection on {args.url}")
    result = detect_sqli(
        url=args.url,
        method=args.method,
        timeout=args.timeout,
        show_progress=not args.no_progress,
    )

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base_name = f"sqli_{result['target_id']}_{timestamp}"
    report_payload = {
        "type": "sqli_detection",
        "target": args.url,
        "result": result,
    }

    if args.json or args.html:
        generate_reports(
            base_name=base_name,
            data=report_payload,
            output_dir=args.output_dir,
            write_json=args.json,
            write_html=args.html,
        )

    return result


def cmd_full(args):
    logger.info(f"Starting full scan on {args.target}")
    full_output = {
        "type": "full_scan",
        "target": args.target,
        "components": {},
    }

    ports = parse_port_range(args.ports)
    full_output["components"]["port_scan"] = run_port_scan(
        target=args.target,
        ports=ports,
        concurrency=args.concurrency,
        timeout=args.timeout,
        show_progress=not args.no_progress,
    )

    if args.url:
        wordlist = args.wordlist or load_default_wordlist_path("directories.txt")
        if wordlist and os.path.isfile(wordlist):
            full_output["components"]["dir_bruteforce"] = run_dir_bruteforce(
                base_url=args.url,
                wordlist_path=wordlist,
                threads=args.threads,
                timeout=args.timeout,
                status_filter=[200, 301, 302, 403],
                show_progress=not args.no_progress,
            )

    if args.domain:
        sub_wordlist = args.sub_wordlist or load_default_wordlist_path("subdomains.txt")
        if sub_wordlist and os.path.isfile(sub_wordlist):
            full_output["components"]["subdomain_enum"] = enumerate_subdomains(
                domain=args.domain,
                wordlist_path=sub_wordlist,
                threads=args.sub_threads,
                timeout=args.timeout,
                show_progress=not args.no_progress,
            )

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base_name = f"full_{args.target.replace('.', '_')}_{timestamp}"

    if args.json or args.html or args.nmap_xml:
        generate_reports(
            base_name=base_name,
            data=full_output,
            output_dir=args.output_dir,
            write_json=args.json,
            write_html=args.html,
            write_nmap_xml=args.nmap_xml,
        )

    return full_output


def build_parser():
    parser = argparse.ArgumentParser(
        prog="vulnscope",
        description="VulnScope – Fast, modular vulnerability assessment CLI tool",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default="reports",
        help="Directory to store generated reports (default: reports)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Ultra-fast port scan")
    scan.add_argument("target", help="Target IP or hostname")
    scan.add_argument(
        "-p",
        "--ports",
        default="1-1024",
        help="Port range, e.g. 1-65535 (default: 1-1024)",
    )
    scan.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=500,
        help="Number of concurrent connections (default: 500)",
    )
    scan.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)",
    )
    scan.add_argument(
        "--json",
        action="store_true",
        help="Write JSON report",
    )
    scan.add_argument(
        "--html",
        action="store_true",
        help="Write HTML report",
    )
    scan.add_argument(
        "--nmap-xml",
        action="store_true",
        help="Write Nmap-style XML report",
    )
    scan.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress bar",
    )
    scan.set_defaults(func=cmd_scan)

    dscan = subparsers.add_parser("dir", help="Directory brute-force (Gobuster-like)")
    dscan.add_argument("url", help="Base URL (e.g. https://example.com/)")
    dscan.add_argument("wordlist", help="Path to wordlist file")
    dscan.add_argument(
        "-t",
        "--threads",
        type=int,
        default=30,
        help="Number of concurrent threads (default: 30)",
    )
    dscan.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Request timeout in seconds (default: 5.0)",
    )
    dscan.add_argument(
        "--json",
        action="store_true",
        help="Write JSON report",
    )
    dscan.add_argument(
        "--html",
        action="store_true",
        help="Write HTML report",
    )
    dscan.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress bar",
    )
    dscan.set_defaults(func=cmd_dir)

    ssub = subparsers.add_parser("sub", help="Subdomain enumeration")
    ssub.add_argument("domain", help="Target domain (e.g. example.com)")
    ssub.add_argument("wordlist", help="Path to subdomain wordlist")
    ssub.add_argument(
        "-t",
        "--threads",
        type=int,
        default=50,
        help="Number of concurrent threads (default: 50)",
    )
    ssub.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="DNS resolution timeout in seconds (default: 3.0)",
    )
    ssub.add_argument(
        "--json",
        action="store_true",
        help="Write JSON report",
    )
    ssub.add_argument(
        "--html",
        action="store_true",
        help="Write HTML report",
    )
    ssub.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress bar",
    )
    ssub.set_defaults(func=cmd_sub)

    sqli = subparsers.add_parser("sqli", help="Basic SQL injection detection")
    sqli.add_argument(
        "url",
        help=(
            "URL with at least one query parameter, e.g. "
            "https://example.com/item.php?id=1"
        ),
    )
    sqli.add_argument(
        "-X",
        "--method",
        default="GET",
        choices=["GET", "POST"],
        help="HTTP method to use (default: GET)",
    )
    sqli.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Request timeout in seconds (default: 5.0)",
    )
    sqli.add_argument(
        "--json",
        action="store_true",
        help="Write JSON report",
    )
    sqli.add_argument(
        "--html",
        action="store_true",
        help="Write HTML report",
    )
    sqli.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress bar",
    )
    sqli.set_defaults(func=cmd_sqli)

    full = subparsers.add_parser("full", help="Run full assessment workflow")
    full.add_argument("target", help="Target IP or hostname")
    full.add_argument(
        "-p",
        "--ports",
        default="1-1024",
        help="Port range for port scan (default: 1-1024)",
    )
    full.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=500,
        help="Port scan concurrency (default: 500)",
    )
    full.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.0,
        help="Network timeout in seconds (default: 1.0)",
    )
    full.add_argument(
        "--url",
        help="Optional HTTP base URL for directory brute-force",
    )
    full.add_argument(
        "--wordlist",
        help="Optional directory wordlist path; default: wordlists/directories.txt",
    )
    full.add_argument(
        "--threads",
        type=int,
        default=30,
        help="Directory brute-force threads (default: 30)",
    )
    full.add_argument(
        "--domain",
        help="Optional domain for subdomain enumeration",
    )
    full.add_argument(
        "--sub-wordlist",
        help="Optional subdomain wordlist; default: wordlists/subdomains.txt",
    )
    full.add_argument(
        "--sub-threads",
        type=int,
        default=50,
        help="Subdomain enumeration threads (default: 50)",
    )
    full.add_argument(
        "--json",
        action="store_true",
        help="Write JSON report",
    )
    full.add_argument(
        "--html",
        action="store_true",
        help="Write HTML report",
    )
    full.add_argument(
        "--nmap-xml",
        action="store_true",
        help="Write Nmap-style XML report (includes port scan results)",
    )
    full.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress bar",
    )
    full.set_defaults(func=cmd_full)

    return parser


def main(argv=None):
    print_banner()

    if argv is None:
        argv = sys.argv[1:]

    load_plugins()
    for plugin in get_plugins():
        try:
            plugin.on_start(list(argv))
        except Exception:
            pass

    parser = build_parser()
    args = parser.parse_args(argv)

    for plugin in get_plugins():
        try:
            plugin.on_args_parsed(args)
        except Exception:
            pass

    try:
        for plugin in get_plugins():
            try:
                plugin.on_before_command(args)
            except Exception:
                pass

        result = args.func(args)

        for plugin in get_plugins():
            try:
                plugin.on_after_command(args, result)
            except Exception:
                pass
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan aborted by user.")
        sys.exit(1)


if __name__ == "__main__":
    main()

