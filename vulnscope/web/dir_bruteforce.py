import concurrent.futures
from typing import List, Dict, Any

import requests
from colorama import Fore, Style
from tqdm import tqdm


def _make_url(base_url: str, path: str) -> str:
    base = base_url.rstrip("/")
    path = path.lstrip("/")
    return f"{base}/{path}"


def _check_path(url: str, timeout: float) -> Dict[str, Any]:
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=False)
        return {"url": url, "status": resp.status_code, "length": len(resp.content)}
    except requests.RequestException:
        return {"url": url, "status": None, "length": 0}


def run_dir_bruteforce(
    base_url: str,
    wordlist_path: str,
    threads: int = 30,
    timeout: float = 5.0,
    status_filter=None,
    show_progress: bool = True,
) -> List[Dict[str, Any]]:
    if status_filter is None:
        status_filter = [200, 301, 302, 403]

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        words = [line.strip() for line in f if line.strip()]

    urls = [_make_url(base_url, w) for w in words]
    results: List[Dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(_check_path, u, timeout) for u in urls]
        iterator = (
            tqdm(
                concurrent.futures.as_completed(futures),
                total=len(futures),
                desc="Dir brute-force",
                unit="req",
            )
            if show_progress
            else concurrent.futures.as_completed(futures)
        )

        for future in iterator:
            res = future.result()
            results.append(res)
            status = res["status"]
            if status in status_filter:
                color = Fore.GREEN if status == 200 else Fore.YELLOW
                print(
                    f"{color}[{status}]{Style.RESET_ALL} "
                    f"{res['url']} (len={res['length']})"
                )

    return results

