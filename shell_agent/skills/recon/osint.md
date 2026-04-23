# OSINT 技术手册

## 域名与 IP 情报

### WHOIS 信息

```bash
whois example.com
whois 1.2.3.4

# 批量查询
for domain in $(cat domains.txt); do
    echo "=== $domain ==="
    whois "$domain" | grep -iE "registrant|admin|tech|name server|creation|expir"
done
```

关注字段：注册人/组织、注册邮箱、名称服务器、创建/过期日期。

### DNS 全面枚举

```bash
# 所有记录类型
for type in A AAAA CNAME MX NS TXT SOA SRV; do
    echo "=== $type ==="
    dig example.com $type +short
done

# 反向 DNS
dig -x 1.2.3.4 +short

# DNS 区域传送（配置不当时可获取全部记录）
dig axfr example.com @ns1.example.com

# dnsx 批量解析
echo "example.com" | dnsx -resp -a -aaaa -cname -mx -ns -txt
```

### 子域名枚举

```bash
# 被动枚举（推荐组合使用）
subfinder -d example.com -all -silent -o subs-subfinder.txt
amass enum -passive -d example.com -o subs-amass.txt

# 合并去重
cat subs-*.txt | sort -u > all-subdomains.txt

# 验证存活
httpx -l all-subdomains.txt -status-code -title -tech-detect -o alive-subs.txt

# 暴力枚举（主动，慎用）
gobuster dns -d example.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50
```

### 证书透明度日志

```bash
# crt.sh（最常用）
curl -s "https://crt.sh/?q=%.example.com&output=json" | \
    jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

# 提取 SAN 中的域名
echo | openssl s_client -connect example.com:443 2>/dev/null | \
    openssl x509 -noout -text | grep -oP '(?<=DNS:)[^,]+'
```

---

## 真实 IP 发现（绕过 CDN）

### 常见方法

```bash
# 1. 历史 DNS 记录（SecurityTrails / ViewDNS / completedns）
# 查看域名上 CDN 之前的 A 记录

# 2. 子域名可能未接 CDN
# 枚举子域名后检查哪些直接解析到源站

# 3. 邮件头中的真实 IP
# 让目标发送邮件（注册/找回密码），查看 Received 头

# 4. 全网扫描匹配
# 在 Shodan/Censys 中搜索目标的特征（SSL 证书、页面标题、favicon hash）
shodan search ssl.cert.subject.cn:example.com
shodan search http.favicon.hash:HASH_VALUE

# 5. favicon hash 计算
python3 -c "
import mmh3, requests, codecs
resp = requests.get('https://example.com/favicon.ico')
fhash = mmh3.hash(codecs.lookup('base64').encode(resp.content)[0])
print(f'Favicon hash: {fhash}')
print(f'Shodan: http.favicon.hash:{fhash}')
"
```

---

## 人员与组织情报

### 邮箱收集

```bash
# theHarvester
theHarvester -d example.com -b google,bing,linkedin -l 200

# hunter.io（需 API）
curl -s "https://api.hunter.io/v2/domain-search?domain=example.com&api_key=KEY" | jq '.data.emails[].value'

# 手动 Google Dorks
# "@example.com" site:linkedin.com
# "@example.com" site:github.com
```

### 凭证泄露检查

```bash
# 检查邮箱是否在已知泄露库中（合法使用）
# haveibeenpwned API
curl -s -H "hibp-api-key: KEY" "https://haveibeenpwned.com/api/v3/breachedaccount/user@example.com"

# dehashed / intelx / snusbase（需订阅）
```

### 社交媒体侦察

```
# LinkedIn：员工列表、技术职位描述 → 推断技术栈
# GitHub/GitLab：
  - 组织账号下的公开仓库
  - 员工个人仓库中的项目代码
  - commit 历史中泄露的密钥/配置
  - .git/config 中的内部 URL

# Twitter/微博：员工发布的技术内容、内部截图
```

---

## GitHub 情报收集

```bash
# 搜索敏感信息
# 在 github.com/search 中搜索：
"example.com" password
"example.com" secret_key
"example.com" api_key
"example.com" jdbc:
"example.com" BEGIN RSA PRIVATE KEY
org:target-org filename:.env
org:target-org filename:config

# 使用 trufflehog 扫描
trufflehog github --org=target-org

# 使用 gitleaks
gitleaks detect --source=./repo --report-path=gitleaks-report.json
```

---

## 网络空间搜索引擎

### Shodan 语法

```
# 基础查询
hostname:example.com
ip:1.2.3.4
net:192.168.1.0/24
port:22
org:"Target Corp"

# 组合查询
hostname:example.com port:80,443,8080 country:CN

# 漏洞搜索
vuln:CVE-2021-44228 country:CN

# 特定服务
product:nginx
product:Apache http.title:"Dashboard"
ssl.cert.issuer.cn:"example.com"
```

### Fofa 语法

```
domain="example.com"
host="example.com"
ip="1.2.3.4"
ip="1.2.3.0/24"
port="8080"
cert="example.com"
title="管理后台"
body="powered by"
header="X-Powered-By: PHP"
banner="SSH-2.0"
protocol="https"

# 组合
domain="example.com" && port="8080"
domain="example.com" && status_code="200"
```

### Censys 语法

```
services.http.response.headers.server: nginx
services.tls.certificates.leaf.subject.common_name: example.com
ip: 1.2.3.0/24
services.port: 22
autonomous_system.name: "Target ISP"
```

---

## 基础设施情报

### ASN 与 IP 段

```bash
# 查询目标 ASN
whois -h whois.radb.net -- "-i origin AS12345"

# 通过组织名查 ASN
curl -s "https://api.bgpview.io/search?query_term=Target+Corp" | jq '.data.asns'

# 获取 ASN 下所有 IP 段
curl -s "https://api.bgpview.io/asn/12345/prefixes" | jq '.data.ipv4_prefixes[].prefix'

# amass 查找关联基础设施
amass intel -org "Target Corp"
amass intel -asn 12345
```

### 历史数据

```bash
# Wayback Machine 历史快照
curl -s "http://web.archive.org/cdx/search/cdx?url=example.com/*&output=json&fl=original,timestamp&collapse=urlkey&limit=1000" | \
    jq -r '.[][] ' | sort -u

# 可能发现已删除的敏感页面、旧版应用、测试环境
```

---

## OSINT 工具汇总

| 工具 | 用途 | 安装 |
|---|---|---|
| subfinder | 被动子域名枚举 | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| amass | 全面资产发现 | `go install -v github.com/owasp-amass/amass/v4/...@master` |
| httpx | HTTP 探测 | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| dnsx | DNS 查询 | `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| theHarvester | 邮箱/子域名收集 | `pip install theHarvester` |
| trufflehog | Git 仓库密钥扫描 | `brew install trufflehog` |
| gitleaks | Git 泄露检测 | `brew install gitleaks` |
| katana | Web 爬虫 | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| wafw00f | WAF 识别 | `pip install wafw00f` |
