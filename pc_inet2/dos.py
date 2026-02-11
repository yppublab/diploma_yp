#!/usr/bin/env python3
import argparse
import time
import requests
from urllib.parse import urlencode

def send_req(domain: str):
    url = f"http://{domain}"
    session = requests.Session()

    while True:
        try:
            resp = session.get(url, timeout=10)
            status = resp.status_code
            full_url = f"{url}"
            print(f"[{time.strftime('%H:%M:%S')}] {status} -> {full_url}")
        except requests.RequestException as e:
            print(f"[!] Request error: {e}")
            status = None

        # обработка 429 Too Many Requests
        if status == 429:
            print("[!] Got 429 Too Many Requests, sleeping 60 seconds...")
            time.sleep(60)
        else:
            time.sleep(1)  # 1 запрос в секунду



def main():
    parser = argparse.ArgumentParser(
        description="Simple SQLi payload sender with rate limit handling (429)."
    )
    parser.add_argument(
        "-d",
        "--domain",
        default="layer8.ag",
        help="Домен или хост без схемы (например, example.com/path/to/app)"
    )

    args = parser.parse_args()
    send_req(args.domain)


if __name__ == "__main__":
    main()