import socket
import queue
import threading
import time
import os
import random
import re
import sys
import concurrent.futures
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, unquote

SOURCES_FILE     = "urls.txt"
TIMEOUT          = 22
CHECKER_THREADS  = 1800
FETCHER_THREADS  = 220
MAX_QUEUE_SIZE   = 450000

IP_PORT_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b')

check_queue      = queue.Queue(maxsize=MAX_QUEUE_SIZE)
known_ips        = set()
write_lock       = threading.Lock()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
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
print(f"[MODE] Running as {MODE.upper()} → output: {OUTPUT_FILE}")

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
        req = (
            b"CONNECT www.google.com:443 HTTP/1.1\r\n"
            b"Host: www.google.com:443\r\n"
            b"User-Agent: curl/7.68.0\r\n"
            b"Proxy-Connection: Keep-Alive\r\n\r\n"
        )
        sock.sendall(req)
        data = sock.recv(512)
        return b"200" in data[:128]
    except:
        return False

CHECK_FNS = {
    "socks5": is_socks5,
    "socks4": is_socks4,
    "http":   is_http_proxy,
}

PREFIX = {
    "socks5": "socks5://",
    "socks4": "socks4://",
    "http":   "http://",
}

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
            full = PREFIX[MODE] + cleaned
            return full, host
        s.close()
        return None
    except:
        return None

def checker_worker():
    while True:
        try:
            proxy = check_queue.get(timeout=5)
        except queue.Empty:
            break

        res = check_proxy(proxy)
        if not res:
            check_queue.task_done()
            continue

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

def fetch_and_extract(url, retries=3):
    for attempt in range(retries):
        try:
            ua = random.choice(USER_AGENTS)
            headers = {"User-Agent": ua}
            r = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            if r.status_code != 200:
                return []
            found = IP_PORT_REGEX.findall(r.text)
            return [p for p in found if ":" in p and p.count(":") == 1]
        except Exception as e:
            if attempt == retries - 1:
                print(f"[FETCH FAIL] {url}")
            time.sleep(random.uniform(1, 4))
    return []

def extract_clean_url(href):
    if not href:
        return None
    if "uddg=" in href:
        href = unquote(href.split("uddg=")[1].split("&")[0])
    elif "/url?q=" in href:
        href = unquote(href.split("/url?q=")[1].split("&")[0])
    elif "ruclick" in href or "yabs" in href:
        return None
    if not href.startswith("http"):
        return None
    return href

def search_duckduckgo(query):
    urls = []
    try:
        params = {"q": query, "kl": "wt-wt"}
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        r = requests.get("https://duckduckgo.com/html/", params=params, headers=headers, timeout=8)
        soup = BeautifulSoup(r.text, "html.parser")
        for result in soup.select(".result__url"):
            href = extract_clean_url(result.get("href", ""))
            if href and any(x in href.lower() for x in [".txt", "/raw/", "githubusercontent", "socks5", "proxy", "list", "proxies"]):
                urls.append(href)
    except Exception as e:
        print(f"[DDG error] {e}")
    return list(set(urls))[:20]

def search_bing(query):
    urls = []
    try:
        params = {"q": query, "count": 30}
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        r = requests.get("https://www.bing.com/search", params=params, headers=headers, timeout=8)
        soup = BeautifulSoup(r.text, "html.parser")
        for link in soup.select("li.b_algo h2 a, .b_title a"):
            href = link.get("href", "")
            if href and any(x in href.lower() for x in [".txt", "/raw/", "github", "socks5", "proxy"]):
                urls.append(href)
    except Exception as e:
        print(f"[Bing error] {e}")
    return list(set(urls))[:18]

def search_yahoo(query):
    urls = []
    try:
        params = {"p": query, "n": 30}
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        r = requests.get("https://search.yahoo.com/search", params=params, headers=headers, timeout=8)
        soup = BeautifulSoup(r.text, "html.parser")
        for link in soup.select("a.ac-algo, .compTitle a"):
            href = extract_clean_url(link.get("href", ""))
            if href and any(x in href.lower() for x in [".txt", "raw.githubusercontent", "socks5", "proxy-list"]):
                urls.append(href)
    except Exception as e:
        print(f"[Yahoo error] {e}")
    return list(set(urls))[:15]

def search_startpage(query):
    urls = []
    try:
        params = {"q": query, "page": "1"}
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        r = requests.get("https://www.startpage.com/sp/search", params=params, headers=headers, timeout=8)
        soup = BeautifulSoup(r.text, "html.parser")
        for result in soup.select(".w-gl__result__url"):
            href = result.get("href", "")
            if href and any(x in href.lower() for x in [".txt", "/raw/", "socks5", "proxy"]):
                urls.append(href)
    except Exception as e:
        print(f"[Startpage error] {e}")
    return list(set(urls))[:12]

def search_mojeek(query):
    urls = []
    try:
        params = {"q": query}
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        r = requests.get("https://www.mojeek.com/search", params=params, headers=headers, timeout=8)
        soup = BeautifulSoup(r.text, "html.parser")
        for result in soup.select("a.ob"):
            href = result.get("href", "")
            if href and any(x in href.lower() for x in [".txt", "githubusercontent", "socks5"]):
                urls.append(href)
    except Exception as e:
        print(f"[Mojeek error] {e}")
    return list(set(urls))[:10]

def search_yandex(query):
    urls = []
    try:
        params = {"text": query, "lr": "213"}
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        r = requests.get("https://yandex.com/search/", params=params, headers=headers, timeout=12)
        soup = BeautifulSoup(r.text, "html.parser")
        for link in soup.select("a.link"):
            href = link.get("href", "")
            if href and any(x in href.lower() for x in [".txt", "/raw/", "socks5", "proxy"]):
                urls.append(href)
    except Exception as e:
        print(f"[Yandex error] {e}")
    return list(set(urls))[:12]

def discover_sources():
    print("[DISCOVER] Querying search engines for fresh proxy lists...")
    base_queries = [
        "socks5 proxy list txt raw github",
        "free socks5 proxies txt updated 2026",
        "socks5.txt site:raw.githubusercontent.com",
        "socks5 proxy list txt -inurl:(login signup forum)",
        "free socks5 list txt github raw",
        "free proxies list",
        "free proxies download txt",
        "http socks4 socks5 free proxy list txt",
        "socks4 proxy list txt 2026",
        "http proxy list txt raw github",
    ]

    engines = [
        search_duckduckgo,
        search_bing,
        search_yahoo,
        search_startpage,
        search_mojeek,
        search_yandex,
    ]

    found = []
    for q in base_queries:
        for engine_func in engines:
            try:
                found.extend(engine_func(q))
                time.sleep(random.uniform(1.8, 4.2))
            except:
                pass

    good_keywords = [
        ".txt", "/raw/", "raw.githubusercontent.com", "cdn.jsdelivr.net",
        "socks5", "socks4", "http", "proxy-list", "proxies", "socks5.txt", "data.txt"
    ]

    filtered = []
    seen = set()
    for u in found:
        lu = u.lower()
        if any(kw in lu for kw in good_keywords) and len(u) < 240 and u not in seen:
            seen.add(u)
            filtered.append(u)

    print(f"[DISCOVER] Found {len(filtered)} promising proxy list URLs")
    return filtered

def main():
    static_sources = []
    if os.path.exists(SOURCES_FILE):
        try:
            with open(SOURCES_FILE, "r", encoding="utf-8") as f:
                static_sources = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except:
            pass

    dynamic_sources = discover_sources()
    all_sources = list(set(static_sources + dynamic_sources))
    random.shuffle(all_sources)

    print(f"[SOURCES] Fetching from {len(all_sources)} URLs")

    all_proxies = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=FETCHER_THREADS) as executor:
        futures = [executor.submit(fetch_and_extract, url) for url in all_sources]
        for future in concurrent.futures.as_completed(futures):
            all_proxies.extend(future.result())

    unique_proxies = list(set(all_proxies))
    random.shuffle(unique_proxies)

    print(f"[PROXIES] Collected {len(unique_proxies):,} unique IP:PORT entries")

    enqueued = 0
    for p in unique_proxies:
        try:
            check_queue.put_nowait(p)
            enqueued += 1
        except queue.Full:
            print("[QUEUE FULL] Stopping feed")
            break

    print(f"[QUEUE] Enqueued {enqueued:,} proxies for checking")

    threads = []
    for _ in range(CHECKER_THREADS):
        t = threading.Thread(target=checker_worker, daemon=True)
        t.start()
        threads.append(t)

    check_queue.join()
    time.sleep(5)

    print(f"\n[FINISHED] Working {MODE.upper()} proxies: {len(known_ips)}")
    print(f"           Saved → {OUTPUT_FILE}\n")

if __name__ == "__main__":
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(65536, hard), hard))
    except:
        print("[INFO] run: ulimit -n 65536  (recommended)")

    main()
