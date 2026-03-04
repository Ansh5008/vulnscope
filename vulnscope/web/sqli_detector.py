from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests
from colorama import Fore, Style
from tqdm import tqdm


SQLI_PAYLOADS = [
    "' OR '1'='1'--",
    "\" OR \"1\"=\"1\"--",
    "1 OR 1=1",
    "1' UNION SELECT NULL--",
    "1' AND SLEEP(5)--",
]


def _modify_url_query(url: str, payload: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    if not query:
        query = {"id": [payload]}
    else:
        first_key = next(iter(query.keys()))
        query[first_key] = [payload]

    new_query = urlencode(query, doseq=True)
    new_parsed = parsed._replace(query=new_query)
    return urlunparse(new_parsed)


def _send_request(
    url: str,
    method: str,
    timeout: float,
) -> Dict[str, Any]:
    try:
        if method.upper() == "GET":
            resp = requests.get(url, timeout=timeout)
        else:
            parsed = urlparse(url)
            data = parse_qs(parsed.query, keep_blank_values=True)
            base_url = urlunparse(parsed._replace(query=""))
            resp = requests.post(base_url, data=data, timeout=timeout)
        return {
            "status": resp.status_code,
            "length": len(resp.content),
            "text_snippet": resp.text[:200],
        }
    except requests.RequestException as e:
        return {
            "status": None,
            "length": 0,
            "text_snippet": str(e),
        }


def detect_sqli(
    url: str,
    method: str = "GET",
    timeout: float = 5.0,
    show_progress: bool = True,
) -> Dict[str, Any]:
    method = method.upper()
    baseline_res = _send_request(url, method, timeout)

    attempts: List[Dict[str, Any]] = []
    suspicious = []

    iterator = (
        tqdm(SQLI_PAYLOADS, desc="SQLi payloads", unit="payload")
        if show_progress
        else SQLI_PAYLOADS
    )

    for payload in iterator:
        mutated_url = _modify_url_query(url, payload)
        res = _send_request(mutated_url, method, timeout)
        attempt = {
            "payload": payload,
            "mutated_url": mutated_url,
            "response": res,
        }
        attempts.append(attempt)

        if res["status"] and baseline_res["status"]:
            if res["status"] >= 500 and baseline_res["status"] < 500:
                suspicious.append(
                    {
                        "reason": "Server error after SQL-like payload",
                        "payload": payload,
                        "status": res["status"],
                    }
                )
                print(
                    Fore.RED
                    + f"[!] Possible SQLi (server error) with payload: {payload}"
                    + Style.RESET_ALL
                )

        if baseline_res["length"] and abs(res["length"] - baseline_res["length"]) > (
            0.3 * baseline_res["length"]
        ):
            suspicious.append(
                {
                    "reason": "Significant response length change",
                    "payload": payload,
                    "length_diff": res["length"] - baseline_res["length"],
                }
            )
            print(
                Fore.YELLOW
                + f"[!] Anomalous length change with payload: {payload}"
                + Style.RESET_ALL
            )

    return {
        "target": url,
        "target_id": url.replace("://", "_").replace("/", "_"),
        "baseline": baseline_res,
        "attempts": attempts,
        "suspicious": suspicious,
    }

