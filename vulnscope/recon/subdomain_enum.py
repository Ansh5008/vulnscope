import concurrent.futures
import socket
from typing import List, Dict, Any

from colorama import Fore, Style
from tqdm import tqdm


def _resolve_subdomain(subdomain: str, timeout: float) -> Dict[str, Any]:
    try:
        ip = socket.gethostbyname(subdomain)
        return {"subdomain": subdomain, "ip": ip, "resolved": True}
    except socket.gaierror:
        return {"subdomain": subdomain, "ip": None, "resolved": False}


def enumerate_subdomains(
    domain: str,
    wordlist_path: str,
    threads: int = 50,
    timeout: float = 3.0,
    show_progress: bool = True,
) -> List[Dict[str, Any]]:
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        words = [line.strip() for line in f if line.strip()]

    candidates = [f"{w}.{domain.strip()}" for w in words]
    results: List[Dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(_resolve_subdomain, c, timeout) for c in candidates]
        iterator = (
            tqdm(
                concurrent.futures.as_completed(futures),
                total=len(futures),
                desc="Subdomain enum",
                unit="host",
            )
            if show_progress
            else concurrent.futures.as_completed(futures)
        )

        for future in iterator:
            res = future.result()
            results.append(res)
            if res["resolved"]:
                print(
                    f"{Fore.GREEN}[FOUND]{Style.RESET_ALL} "
                    f"{res['subdomain']} -> {res['ip']}"
                )

    return results

