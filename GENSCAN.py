import requests
import argparse
import socket
from threading import Thread, Lock
from queue import Queue
import time
import sys
from urllib.parse import urljoin, urlparse
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # disabled ssl because scanning unsecure website


request_times = []
rate_lock = Lock()
MIN_DELAY = 0.1
TIMEOUT = 5  # it means 5 seconds


def scan_post(data_str):
    if not data_str:
        return None
    post_data = {}
    for pair in data_str.split("&"):
        if "=" in pair:
            key, value = pair.split("=", 1)
            post_data[key] = value
    return post_data


def scan_ratelimit(max_rate):
    global request_times
    with rate_lock:
        now = time.time()
        request_times = [t for t in request_times if now - t < 1]
        if len(request_times) >= max_rate:
            oldest = request_times[0]
            wait_time = max(1 - (now - oldest), MIN_DELAY)
            time.sleep(wait_time)
        request_times.append(now)


def scan_keyword(response, keyword):
    if not keyword:
        return False, ""
    try:
        content = response.text.lower()
        if keyword.lower() in content:
            pos = content.find(keyword.lower())
            start = max(0, pos - 30)
            end = min(len(content), pos + len(keyword) + 30)
            context = content[start:end].replace('\n', ' ').strip()
            return True, context
        return False, ""
    except:
        return False, ""


def scan_subdomain(url):
    parsed = urlparse(url)
    if "SCAN" in parsed.netloc and parsed.netloc.startswith("SCAN."):
        return True
    return False


def scan_target(target, word, user_agent, mode, post_data=None, keyword=None, desired_status_codes=None):
    try:
        headers = {"User-Agent": user_agent}
        target_url = target.replace("SCAN", word.strip())

        if mode == "subdomain":
            domain = target_url.split("//")[-1].split("/")[0]
            try:
                socket.gethostbyname(domain)
            except socket.gaierror:
                return False

            try:
                response = requests.get(
                    target_url,
                    headers=headers,
                    timeout=TIMEOUT,
                    allow_redirects=True,
                    verify=False  # SSL verification disabled
                )

                if (desired_status_codes and response.status_code in desired_status_codes) or (not desired_status_codes and response.status_code == 200):
                    print(f"[+] Found: {target_url} ({response.status_code})")
                    return True
            except requests.RequestException:

                return False

        elif mode == "directory":
            base_url = target.replace("SCAN", "")
            if not base_url.endswith('/'):
                base_url += '/'
            test_url = urljoin(base_url, word.strip())

            try:
                response = requests.get(
                    test_url,
                    headers=headers,
                    timeout=TIMEOUT,
                    allow_redirects=True,
                    verify=False  # SSL verification disabled
                )

                if (desired_status_codes and response.status_code in desired_status_codes) or (not desired_status_codes and response.status_code == 200):
                    print(f"  {test_url} ({response.status_code})")
                    return True
            except requests.RequestException as e:
                return False

        elif mode == "param":
            try:
                if post_data:
                    processed_data = {k: v.replace("SCAN", word.strip()) for k, v in post_data.items()}
                    response = requests.post(
                        target_url,
                        headers=headers,
                        data=processed_data,
                        timeout=TIMEOUT,
                        verify=False
                    )
                else:
                    response = requests.get(
                        target_url,
                        headers=headers,
                        timeout=TIMEOUT,
                        verify=False  # SSL verification disabled
                    )


                if (desired_status_codes and response.status_code in desired_status_codes) or (not desired_status_codes and response.status_code == 200):
                    found, context = scan_keyword(response, keyword)
                    if found or not keyword:  # Show if keyword found or no keyword specified
                        print("\n" + "*-*-" * 60)
                        print(f": {target_url} ({response.status_code})")
                        if post_data:
                            print(f" Data: {processed_data}")
                        if found:
                            print("\nKeyword :")
                            print(f"...{context}...")
                        print("*-*-" * 60)
                        return True
            except requests.RequestException as e:
                return False

    except Exception as e:
        print(f"Error *-*  {target_url}: {str(e)}", file=sys.stderr)
    return False


def scan_worker(target, queue, user_agent, mode, post_data, keyword, delay, max_rate, desired_status_codes):
    while not queue.empty():
        word = queue.get()
        scan_ratelimit(max_rate)
        scan_target(target, word, user_agent, mode, post_data, keyword, desired_status_codes)
        if delay > 0:
            time.sleep(delay)
        queue.task_done()


def main_scan():
    parser = argparse.ArgumentParser(description="Multi-Purpose Web Scanner (please use magical word 'SCAN' in it")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
    parser.add_argument("-u", "--url", required=True, help="Target URL with SCAN placeholder")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Thread count")
    parser.add_argument("--user-agent", default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36", help="Custom User-Agent")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests")
    parser.add_argument("-p", "--post", action="store_true", help="Use POST method")
    parser.add_argument("-d", "--data", help="POST data with SCAN placeholder")
    parser.add_argument("-k","--keyword", help="Keyword to search for in responses")
    parser.add_argument("-r","--max-rate", type=int, default=10, help="Max requests per second")
    parser.add_argument("--verify-ssl", action="store_true", help="Enable SSL certificate verification")
    parser.add_argument("-sc","--status-codes", type=str, help="Comma-separated list of specific status codes to show (e.g., '200,404,500')")

    args = parser.parse_args()

    if "SCAN" not in args.url and not args.post:
        print("please enter the magical word 'SCAN' according to your search", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.wordlist, "r") as f:
            words = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"enter valid wordlist *-* ", file=sys.stderr)
        sys.exit(1)

    # Parse desired status codes
    desired_status_codes = None
    if args.status_codes:
        try:
            desired_status_codes = [int(code.strip()) for code in args.status_codes.split(',')]
            print(f"\n specified status codes: {', '.join(map(str, desired_status_codes))}")
        except ValueError:
            print("please enter ',' in status code eg .. '200,400,300'.",
                  file=sys.stderr)
            sys.exit(1)
    else:
        print("\n default status code: 200")

    # Determine scan mode
    if scan_subdomain(args.url):
        mode = "subdomain"
        print(f" subdomain enumeration begins *-* {args.url.replace('SCAN.', '')}")
    elif args.url.endswith("/SCAN") or args.url.endswith("/SCAN/"):
        mode = "directory"
        print(f"  directory brute-force begins *-* {args.url.replace('SCAN', '')}")
    else:
        mode = "param"
        print(f"  parameter fuzzing begins *-* {args.url}")
        if args.keyword:
            print(f" Keyword: '{args.keyword}'")

    post_data = scan_post(args.data) if args.data else None
    queue = Queue()
    for word in words:
        queue.put(word)

    print(f"[•] Threads: {args.threads} | Rate: {args.max_rate}/sec | Delay: {args.delay}s")
    print("=" * 50)

    threads = []
    for _ in range(args.threads):
        t = Thread(
            target=scan_worker,
            args=(args.url, queue, args.user_agent, mode, post_data, args.keyword, args.delay, args.max_rate,
                  desired_status_codes),
            daemon=True
        )
        t.start()
        threads.append(t)

    queue.join()
    print("\n*-*-*-*-* Scan completed *-*-*-*-*")


if __name__ == "__main__":
    main_scan()