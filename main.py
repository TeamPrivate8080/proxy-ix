import socket
import queue
import threading
import time
import os
import random
import re
import sys
import concurrent.futures
import requests
from bs4 import BeautifulSoup
from urllib.parse import unquote

SOURCES_FILE     = "urls.txt"
TIMEOUT          = 20         
FETCH_TIMEOUT    = 2        
CHECKER_THREADS  = 7500     
FETCHER_THREADS  = 50
MAX_QUEUE_SIZE   = 300000

IP_PORT_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b')

check_queue      = queue.Queue(maxsize=MAX_QUEUE_SIZE)
known_ips        = set()
write_lock       = threading.Lock()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0",
]

OUTPUT_FILES = {
    "socks5": "working_socks5.txt",
    "socks4": "working_socks4.txt",
    "http":   "working_http.txt",
}

def parse_args():
    mode = "socks5"
    if len(sys.argv) >= 2:
        arg = sys.argv[1].lower()
        if arg in ["-socks5", "--socks5"]:
            mode = "socks5"
        elif arg in ["-socks4", "--socks4"]:
            mode = "socks4"
        elif arg in ["-http", "--http", "-https", "--https"]:
            mode = "http"
        else:
            print("Usage: python start.py [-socks5 | -socks4 | -http]")
            sys.exit(1)
    return mode

MODE = parse_args()
OUTPUT_FILE = OUTPUT_FILES[MODE]
print(f"[MODE] {MODE.upper()} → saving to {OUTPUT_FILE}")

if os.path.exists(OUTPUT_FILE):
    try:
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or ":" not in line:
                    continue
                cleaned = re.sub(r'^(socks[45]|https?)://', '', line)
                ip = cleaned.split(":", 1)[0].strip()
                if ip:
                    known_ips.add(ip)
        print(f"[CACHE] Loaded {len(known_ips)} known {MODE.upper()} IPs")
    except Exception as e:
        print(f"[CACHE ERROR] {e}")

def is_socks5(sock):
    try:
        sock.sendall(b"\x05\x01\x00")
        data = sock.recv(2)
        return len(data) == 2 and data == b"\x05\x00"
    except:
        return False

def is_socks4(sock):
    try:
        req = b"\x04\x01\x00\x00\x00\x00\x00\x00\x00root\0"
        sock.sendall(req)
        data = sock.recv(8)
        if len(data) < 8:
            return False
        return data[0] == 0 and data[1] in (90, 92, 93)
    except:
        return False

def is_http_proxy(sock):
    try:
        req = b"CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n\r\n"
        sock.sendall(req)
        data = sock.recv(512)
        return b"200" in data
    except:
        return False

CHECK_FNS = {"socks5": is_socks5, "socks4": is_socks4, "http": is_http_proxy}
PREFIX = {"socks5": "socks5://", "socks4": "socks4://", "http": "http://"}

def check_proxy(line):
    line = line.strip()
    if not line or ":" not in line:
        return None
    cleaned = re.sub(r'^(socks[45]|https?)://', '', line)
    if cleaned.count(":") != 1:
        return None
    host, port_str = cleaned.rsplit(":", 1)
    try:
        port = int(port_str)
        if not 1 <= port <= 65535:
            return None
    except:
        return None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((host, port))
        if CHECK_FNS[MODE](s):
            s.close()
            return PREFIX[MODE] + cleaned, host
        s.close()
    except:
        pass
    return None

def checker_worker():
    while True:
        try:
            proxy = check_queue.get(timeout=6)
        except queue.Empty:
            break
        res = check_proxy(proxy)
        if res:
            result, ip = res
            with write_lock:
                if ip not in known_ips:
                    known_ips.add(ip)
                    print(f"[OK {MODE.upper()}] {result}")
                    try:
                        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                            f.write(result + "\n")
                    except:
                        pass
        check_queue.task_done()

def fetch_and_extract(url, retries=4):
    for _ in range(retries):
        try:
            ua = random.choice(USER_AGENTS)
            r = requests.get(url, headers={"User-Agent": ua}, timeout=FETCH_TIMEOUT, allow_redirects=True)
            if r.status_code != 200:
                return []
            found = IP_PORT_REGEX.findall(r.text)
            return [p for p in found if p.count(":") == 1]
        except:
            time.sleep(random.uniform(1.5, 5.5))
    return []

def extract_clean_url(href):
    if not href:
        return None
    if "uddg=" in href:
        href = unquote(href.split("uddg=")[1].split("&")[0])
    elif "/url?q=" in href:
        href = unquote(href.split("/url?q=")[1].split("&")[0])
    if not href.startswith("http"):
        return None
    return href

def search_duckduckgo(query):
    urls = []
    try:
        r = requests.get("https://duckduckgo.com/html/", params={"q": query},
                         headers={"User-Agent": random.choice(USER_AGENTS)}, timeout=2)
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.select(".result__url"):
            href = extract_clean_url(a.get("href", ""))
            if href and any(k in href.lower() for k in [".txt", "/raw/", "githubusercontent"]):
                urls.append(href)
    except:
        pass
    return list(set(urls))[:10]

def search_bing(query):
    urls = []
    try:
        r = requests.get("https://www.bing.com/search", params={"q": query},
                         headers={"User-Agent": random.choice(USER_AGENTS)}, timeout=2)
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.select("li.b_algo h2 a"):
            href = a.get("href", "")
            if href and any(k in href.lower() for k in [".txt", "/raw/", "github"]):
                urls.append(href)
    except:
        pass
    return list(set(urls))[:8]

def search_mojeek(query):
    urls = []
    try:
        r = requests.get("https://www.mojeek.com/search", params={"q": query},
                         headers={"User-Agent": random.choice(USER_AGENTS)}, timeout=2)
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.select("a.ob"):
            href = a.get("href", "")
            if href and ".txt" in href.lower():
                urls.append(href)
    except:
        pass
    return list(set(urls))[:6]

def discover_sources():
    print("[DISCOVER] Querying search engines")
    queries = [
        "socks5 proxy list txt raw github 2026",
        "free socks5 socks4 http proxies txt site:raw.githubusercontent.com",
        "proxy list txt raw github -forum -signup -login",
        "socks5.txt filetype:txt site:github.com",
    ]

    engines = [search_duckduckgo, search_bing, search_mojeek]

    found = []
    for q in queries:
        for engine in engines:
            try:
                found.extend(engine(q))
                time.sleep(random.uniform(1, 4))
            except:
                time.sleep(1)

    good_keywords = [
        ".txt", "/raw/", "raw.githubusercontent.com", "cdn.jsdelivr.net",
        "socks5", "socks4", "http", "proxies", "proxy-list"
    ]

    filtered = []
    seen = set()
    for u in found:
        lu = u.lower()
        if any(kw in lu for kw in good_keywords) and len(u) < 220 and u not in seen:
            seen.add(u)
            filtered.append(u)

    count = len(filtered)
    print(f"[DISCOVER] Found {count} promising proxy list URLs")

    if count == 0:
        print("[DISCOVER] No sources found from search engines → will only use urls.txt (if exists)")

    return filtered

def main():
    static_sources = []
    if os.path.exists(SOURCES_FILE):
        try:
            with open(SOURCES_FILE, "r", encoding="utf-8") as f:
                static_sources = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
            print(f"[STATIC] Loaded {len(static_sources)} sources from {SOURCES_FILE}")
        except Exception as e:
            print(f"[STATIC ERROR] {e}")

    dynamic_sources = discover_sources()

    all_sources = list(set(static_sources + dynamic_sources))
    random.shuffle(all_sources)

    if not all_sources:
        print("\n[WARNING] No proxy list sources at all (search failed + urls.txt empty/missing)")
        print("          Nothing to check. Exiting early.\n")
        return

    print(f"[SOURCES] Fetching from {len(all_sources)} URLs total")

    all_proxies = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=FETCHER_THREADS) as executor:
        futures = [executor.submit(fetch_and_extract, url) for url in all_sources]
        for future in concurrent.futures.as_completed(futures):
            all_proxies.extend(future.result())

    unique_proxies = list(set(p for p in all_proxies if ":" in p and p.count(":") == 1))
    random.shuffle(unique_proxies)

    print(f"[PROXIES] Collected {len(unique_proxies):,} unique IP:PORT")

    enqueued = 0
    for p in unique_proxies:
        try:
            check_queue.put_nowait(p)
            enqueued += 1
        except queue.Full:
            print("[QUEUE] Full → stopping enqueue")
            break

    print(f"[QUEUE] Enqueued {enqueued:,} proxies")

    threads = []
    for _ in range(CHECKER_THREADS):
        t = threading.Thread(target=checker_worker, daemon=True)
        t.start()
        threads.append(t)

    check_queue.join()
    time.sleep(3)

    print(f"\n[FINISHED] Working {MODE.upper()} proxies found: {len(known_ips)}")
    print(f"           Saved to → {OUTPUT_FILE}\n")

if __name__ == "__main__":
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(65536, hard), hard))
    except:
        print("[INFO] Consider: ulimit -n 65536  (or higher)")

    main()
