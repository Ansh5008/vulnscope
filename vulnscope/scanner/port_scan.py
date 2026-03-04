import asyncio
from typing import Iterable, Dict, Any, List

from colorama import Fore, Style
from tqdm import tqdm

from vulnscope.scanner.banner_grab import grab_banner
from vulnscope.utils.helpers import detect_service_from_port, detect_vulns_from_banner


async def _scan_single_port(
    semaphore: asyncio.Semaphore,
    target: str,
    port: int,
    timeout: float,
) -> Dict[str, Any]:
    async with semaphore:
        try:
            conn = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            if hasattr(writer, "wait_closed"):
                await writer.wait_closed()
            banner = grab_banner(target, port, timeout=timeout)
            service = detect_service_from_port(port, banner)
            vulns = detect_vulns_from_banner(banner) if banner else []
            return {
                "port": port,
                "state": "open",
                "service": service,
                "banner": banner,
                "vulnerabilities": vulns,
            }
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return {
                "port": port,
                "state": "closed",
            }


async def _scan_all_ports(
    target: str,
    ports: Iterable[int],
    concurrency: int,
    timeout: float,
    show_progress: bool = True,
) -> List[Dict[str, Any]]:
    semaphore = asyncio.Semaphore(concurrency)
    ports_list = list(ports)
    tasks = [
        _scan_single_port(semaphore, target, port, timeout) for port in ports_list
    ]

    results: List[Dict[str, Any]] = []
    if show_progress:
        for coro_result in tqdm(
            asyncio.as_completed(tasks),
            total=len(tasks),
            desc="Port scan",
            unit="port",
        ):
            res = await coro_result
            if res["state"] == "open":
                print(
                    f"{Fore.GREEN}[OPEN]{Style.RESET_ALL} "
                    f"Port {Fore.CYAN}{res['port']}{Style.RESET_ALL} "
                    f"Service: {res.get('service') or 'unknown'}"
                )
            results.append(res)
    else:
        for coro_result in asyncio.as_completed(tasks):
            res = await coro_result
            results.append(res)

    return results


def run_port_scan(
    target: str,
    ports: Iterable[int],
    concurrency: int = 500,
    timeout: float = 1.0,
    show_progress: bool = True,
) -> Dict[str, Any]:
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        all_results = loop.run_until_complete(
            _scan_all_ports(
                target=target,
                ports=ports,
                concurrency=concurrency,
                timeout=timeout,
                show_progress=show_progress,
            )
        )
    finally:
        loop.close()

    open_ports = [r for r in all_results if r["state"] == "open"]
    closed_count = len(all_results) - len(open_ports)

    vulnerabilities = []
    for r in open_ports:
        for v in r.get("vulnerabilities", []):
            vulnerabilities.append(
                {
                    "port": r["port"],
                    "service": r.get("service"),
                    **v,
                }
            )

    return {
        "target": target,
        "open_ports": open_ports,
        "closed_count": closed_count,
        "total_ports": len(all_results),
        "vulnerabilities": vulnerabilities,
    }

