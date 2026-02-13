import socket
import queue
import threading
import time
import os
import random
import re
import concurrent.futures
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import requests
from bs4 import BeautifulSoup

SOURCES_FILE     = "urls.txt"
OUTPUT_FILE      = "working_socks5.txt"
TIMEOUT          = 12  
CHECKER_THREADS  = 800 
FETCHER_THREADS  = 120
MAX_QUEUE_SIZE   = 600000

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
        print(f"[INIT] Loaded {len(known_ips)} unique known SOCKS5 IPs")
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

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((host, port))

        if is_real_socks5(s):
            s.close()
            return f"socks5://{proxy}", host

        s.close()
        return None
    except:
        return None

def checker_worker():
    while True:
        try:
            proxy = check_queue.get(timeout=3.0)
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

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
]

def fetch_and_extract(url, retries=2):
    for attempt in range(retries + 1):
        try:
            ua = random.choice(USER_AGENTS)
            if "proxyscrape.com" in url or "github" in url:
                r = requests.get(url, timeout=10, headers={"User-Agent": ua})
            else:
                req = Request(url, headers={'User-Agent': ua})
                with urlopen(req, timeout=10) as resp:
                    if resp.code != 200:
                        return []
                    content = resp.read().decode("utf-8", errors="ignore")
                    found = IP_PORT_REGEX.findall(content)
                    return [p for p in found if ":" in p and p.count(":") == 1]

            if r.status_code != 200:
                return []
            content = r.text
            found = IP_PORT_REGEX.findall(content)
            return [p for p in found if ":" in p and p.count(":") == 1]

        except Exception as e:
            if attempt == retries:
                print(f"[FETCH FAIL] {url} → {e}")
            time.sleep(1.5)
    return []

def search_duckduckgo(query="socks5 proxy list txt raw -inurl:(login signup forum)"):
    urls = []
    try:
        params = {"q": query, "kl": "wt-wt"}
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        r = requests.get("https://duckduckgo.com/html/", params=params, headers=headers, timeout=10)
        if r.status_code != 200:
            return []

        soup = BeautifulSoup(r.text, "html.parser")
        for result in soup.select(".result__url"):
            href = result.get("href", "")
            if not href or not href.startswith("http"):
                continue
            if "uddg=" in href:
                href = href.split("uddg=")[1].split("&")[0]
                href = requests.utils.unquote(href)
            if any(x in href.lower() for x in [".txt", "raw", "githubusercontent", "socks5", "proxy-list"]):
                urls.append(href)
    except Exception as e:
        print(f"[DDG search error] {e}")
    return urls[:12]

def search_bing(query="socks5 proxy list txt raw github"):
    urls = []
    try:
        params = {"q": query, "count": 20}
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        r = requests.get("https://www.bing.com/search", params=params, headers=headers, timeout=10)
        if r.status_code != 200:
            return []

        soup = BeautifulSoup(r.text, "html.parser")
        for link in soup.select("li.b_algo h2 a"):
            href = link.get("href", "")
            if href and any(x in href.lower() for x in [".txt", "/raw/", "github", "socks5"]):
                urls.append(href)
    except Exception as e:
        print(f"[Bing search error] {e}")
    return urls[:10]

def discover_sources():
    print("[DISCOVER] Searching DuckDuckGo + Bing for fresh proxy lists...")
    queries = [
        "socks5 proxy list txt raw github",
        "free socks5 proxies txt updated 2026",
        "socks5.txt site:raw.githubusercontent.com"
    ]

    found = []
    for q in queries:
        found.extend(search_duckduckgo(q))
        found.extend(search_bing(q))
        time.sleep(random.uniform(1.2, 2.8))

    good_patterns = [".txt", "raw.githubusercontent.com", "cdn.jsdelivr.net", "socks5", "proxy-list"]
    filtered = [u for u in set(found) if any(p in u.lower() for p in good_patterns) and len(u) < 180]

    print(f"[DISCOVER] Found {len(filtered)} potential new sources")
    return filtered

def main():
    static_sources = []
    if os.path.exists(SOURCES_FILE):
        try:
            with open(SOURCES_FILE, "r", encoding="utf-8") as f:
                static_sources = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
        except:
            pass

    dynamic_sources = discover_sources()

    all_sources = list(set(static_sources + dynamic_sources))
    random.shuffle(all_sources)

    print(f"Total sources to fetch: {len(all_sources)} (static + discovered)")

    all_proxies = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=FETCHER_THREADS) as executor:
        futures = [executor.submit(fetch_and_extract, url) for url in all_sources]
        for future in concurrent.futures.as_completed(futures):
            all_proxies.extend(future.result())

    unique_proxies = list(set(all_proxies))
    random.shuffle(unique_proxies)

    print(f"Collected {len(unique_proxies)} unique IP:PORT combinations")

    for p in unique_proxies:
        try:
            check_queue.put(p, block=False)
        except queue.Full:
            print("[QUEUE FULL] Stopping early...")
            break

    threads = []
    for _ in range(CHECKER_THREADS):
        t = threading.Thread(target=checker_worker, daemon=True)
        t.start()
        threads.append(t)

    print(f"Started {CHECKER_THREADS} checker threads. Waiting for completion...")

    check_queue.join()
    time.sleep(4)

    print(f"\nFinished! Unique working SOCKS5 proxies saved: {len(known_ips)}")
    print(f"Output file: {OUTPUT_FILE}")

if __name__ == "__main__":
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(65535, hard), hard))
    except:
        print("Consider running with:  ulimit -n 65535  or higher")

    main()
