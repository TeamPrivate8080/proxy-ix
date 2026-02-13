import socket
import queue
import threading
import time
import struct
import os
import random
import re
import concurrent.futures
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

SOURCES_FILE     = "urls.txt"
OUTPUT_FILE      = "working_socks5.txt"
TIMEOUT          = 10        
CHECKER_THREADS  = 10000
FETCHER_THREADS  = 100
MAX_QUEUE_SIZE   = 800000

IP_PORT_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b')

check_queue      = queue.Queue(maxsize=MAX_QUEUE_SIZE)
known_ips        = set()
write_lock       = threading.Lock()

if os.path.exists(OUTPUT_FILE):
    try:
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or ":" not in line:
                    continue
                cleaned = line.replace("socks5://", "").replace("socks4://", "").replace("http://", "").replace("https://", "")
                ip = cleaned.split(":", 1)[0].strip()
                if ip:
                    known_ips.add(ip)
        print(f"[INIT] Loaded {len(known_ips)} unique known IPs (cleaned)")
    except Exception as e:
        print(f"[WARN] Load error: {e}")

def is_real_socks5(sock):
    try:
        sock.sendall(b"\x05\x01\x00")
        data = sock.recv(2)
        return len(data) >= 2 and data[0] == 0x05 and data[1] == 0x00
    except:
        return False

def check_proxy(proxy_line):
    proxy = proxy_line.strip()
    if not proxy or ":" not in proxy:
        return None

    proxy = proxy.replace("socks5://", "").replace("socks4://", "").replace("http://", "").replace("https://", "")
    if proxy.count(":") != 1:
        return None

    host, port_str = proxy.rsplit(":", 1)
    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            return None
    except:
        return None

    ip = host.strip()

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((host, port))

        if is_real_socks5(s):
            s.close()
            return f"socks5://{proxy}", ip

        s.close()
        return None
    except:
        return None

def checker_worker():
    while True:
        try:
            proxy = check_queue.get(timeout=2.0)
        except queue.Empty:
            break

        result_tuple = check_proxy(proxy)
        if not result_tuple:
            check_queue.task_done()
            continue

        result, ip = result_tuple

        with write_lock:
            if ip not in known_ips:
                known_ips.add(ip)
                print(f"[OK] {result}")
                try:
                    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                        f.write(result + "\n")
                except Exception as e:
                    print(f"[WRITE ERROR] {e}")

        check_queue.task_done()

def fetch_and_extract(url):
    try:
        req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urlopen(req, timeout=8) as resp:
            if resp.code != 200:
                return []
            content = resp.read().decode("utf-8", errors="ignore")
            found = IP_PORT_REGEX.findall(content)
            return [p for p in found if ":" in p and p.count(":") == 1]
    except Exception as e:
        print(f"[FETCH FAIL] {url} → {e}")
        return []

def main():
    if not os.path.exists(SOURCES_FILE):
        print(f"Error: {SOURCES_FILE} not found")
        return

    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        sources = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    print(f"Found {len(sources)} sources. Fetching parallel...")

    all_proxies = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=FETCHER_THREADS) as executor:
        futures = [executor.submit(fetch_and_extract, url) for url in sources]
        for future in concurrent.futures.as_completed(futures):
            all_proxies.extend(future.result())

    unique_proxies = list(set(all_proxies))
    random.shuffle(unique_proxies)

    print(f"Collected {len(unique_proxies)} unique IP:PORT")

    for p in unique_proxies:
        check_queue.put(p)

    for _ in range(CHECKER_THREADS):
        t = threading.Thread(target=checker_worker, daemon=True)
        t.start()

    print(f"Started {CHECKER_THREADS} checkers. Waiting...")

    check_queue.join()
    time.sleep(5)

    print(f"\nDone! Unique SOCKS5 IPs saved: {len(known_ips)}")
    print(f"Output: {OUTPUT_FILE}")

if __name__ == "__main__":
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_NOFILE, (65535, 1048576))
    except:
        print("Run with: ulimit -n 1048576")

    main()
