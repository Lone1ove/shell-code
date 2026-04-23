# 网络扫描与服务枚举

## 主机发现

### 内网环境

```bash
# ARP 扫描（最可靠，仅限同网段）
arp-scan -l
nmap -sn -PR 192.168.1.0/24

# ICMP + TCP + ARP 组合
nmap -sn 192.168.1.0/24

# 禁 ICMP 时用 TCP
nmap -sn -PS22,80,443,3389 -PA80,443 192.168.1.0/24
```

### 外网环境

```bash
# masscan 大规模快速扫描
masscan -p80,443,22,8080,8443,3306,6379,27017 TARGET_RANGE --rate=10000 -oG evidence/masscan.txt

# 按需分级
# 先扫常见端口定位存活主机 → 再对存活主机做全端口
```

---

## 端口扫描策略

### 分级扫描流程

**第一级：快速发现**（2-5 分钟）

```bash
nmap -sS -T4 --top-ports 1000 --open -oN evidence/nmap-quick.txt TARGET
```

**第二级：全端口**（10-30 分钟）

```bash
nmap -sS -p- -T4 --min-rate 5000 --open -oN evidence/nmap-allports.txt TARGET
```

**第三级：服务识别**（对发现的端口）

```bash
nmap -sV -sC -p PORT_LIST -oN evidence/nmap-services.txt TARGET
```

**第四级：深度脚本**（针对特定服务）

```bash
nmap --script=vuln,exploit -p PORT_LIST -oN evidence/nmap-scripts.txt TARGET
```

### 扫描性能调优

| 场景 | 推荐参数 |
|---|---|
| 稳定内网 | `-T4 --min-rate 5000` |
| 不稳定网络 | `-T3 --max-retries 3 --host-timeout 30m` |
| 绕过 IDS | `-T2 -f --data-length 24 --randomize-hosts` |
| 大规模外网 | masscan 先筛 → nmap 精扫 |

### UDP 扫描

```bash
# UDP 扫描很慢，只扫常见端口
nmap -sU --top-ports 50 -T4 TARGET

# 常见 UDP 服务
# 53 DNS / 67-68 DHCP / 69 TFTP / 123 NTP / 161 SNMP / 500 IKE / 514 Syslog
```

---

## 服务专项枚举

### SSH (22)

```bash
# 版本信息
nmap -sV -p22 TARGET

# 支持的认证方式
nmap --script=ssh-auth-methods -p22 TARGET

# 弱口令检测
hydra -L users.txt -P passwords.txt ssh://TARGET -t 4 -f
medusa -h TARGET -U users.txt -P passwords.txt -M ssh

# SSH 密钥审计
nmap --script=ssh-hostkey -p22 TARGET
```

### FTP (21)

```bash
# 匿名登录检测
nmap --script=ftp-anon -p21 TARGET

# FTP Bounce 攻击
nmap --script=ftp-bounce -p21 TARGET

# 版本漏洞
nmap --script=ftp-vsftpd-backdoor,ftp-proftpd-backdoor -p21 TARGET

# 弱口令
hydra -L users.txt -P passwords.txt ftp://TARGET -t 10
```

### SMB/NetBIOS (139/445)

```bash
# 综合枚举
enum4linux -a TARGET

# 共享列表
smbclient -L //TARGET -N
smbmap -H TARGET

# 用户枚举
rpcclient -U "" -N TARGET -c "enumdomusers"
crackmapexec smb TARGET -u '' -p '' --users

# 漏洞检测
nmap --script=smb-vuln* -p445 TARGET
# MS17-010 (EternalBlue)
nmap --script=smb-vuln-ms17-010 -p445 TARGET

# 密码喷洒
crackmapexec smb TARGET -u users.txt -p 'Password123' --continue-on-success
```

### SMTP (25/587)

```bash
# 用户枚举
smtp-user-enum -M VRFY -U users.txt -t TARGET
nmap --script=smtp-enum-users -p25 TARGET

# 开放中继检测
nmap --script=smtp-open-relay -p25 TARGET
```

### DNS (53)

```bash
# 区域传送
dig axfr example.com @TARGET
dnsrecon -d example.com -t axfr

# DNS 枚举
dnsrecon -d example.com -t std
dnsenum example.com
```

### SNMP (161/UDP)

```bash
# Community String 爆破
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt TARGET

# 信息提取
snmpwalk -v2c -c public TARGET
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.25.4.2.1.2  # 进程列表
snmpwalk -v2c -c public TARGET 1.3.6.1.4.1.77.1.2.25    # 用户列表
```

### LDAP (389/636)

```bash
# 匿名绑定
ldapsearch -x -H ldap://TARGET -b "dc=example,dc=com"

# 枚举域信息
ldapsearch -x -H ldap://TARGET -b "dc=example,dc=com" "(objectclass=user)" sAMAccountName

# 使用 windapsearch
python3 windapsearch.py -d example.com --dc-ip TARGET -U
```

### MySQL (3306)

```bash
# 信息收集
nmap --script=mysql-info,mysql-enum -p3306 TARGET

# 弱口令
hydra -L users.txt -P passwords.txt mysql://TARGET

# 直接连接（已有凭证）
mysql -h TARGET -u root -p
```

### Redis (6379)

```bash
# 未授权访问检测
redis-cli -h TARGET INFO
redis-cli -h TARGET CONFIG GET dir
redis-cli -h TARGET CONFIG GET dbfilename

# 常见利用路径
# 1. 写 SSH 公钥
# 2. 写 WebShell
# 3. 写 Crontab
# 4. 主从复制 RCE
```

### MongoDB (27017)

```bash
# 未授权访问
mongosh --host TARGET --eval "db.adminCommand('listDatabases')"

# nmap 脚本
nmap --script=mongodb-info,mongodb-databases -p27017 TARGET
```

### RDP (3389)

```bash
# 加密检测
nmap --script=rdp-enum-encryption -p3389 TARGET

# BlueKeep (CVE-2019-0708)
nmap --script=rdp-vuln-ms12-020 -p3389 TARGET

# NLA 检测
nmap --script=rdp-ntlm-info -p3389 TARGET

# 弱口令
hydra -L users.txt -P passwords.txt rdp://TARGET -t 4
```

---

## 网络拓扑探测

```bash
# 路由追踪
traceroute TARGET
traceroute -T -p 80 TARGET  # TCP traceroute

# 网关发现
route -n
ip route show

# ARP 表
arp -a

# 内网网段发现（已获取内网访问后）
for net in $(seq 1 254); do
    ping -c 1 -W 1 192.168.$net.1 &>/dev/null && echo "192.168.$net.0/24 alive"
done
```

---

## 输出格式化

### Nmap 输出解析

```bash
# 提取开放端口
grep "open" evidence/nmap-services.txt | awk '{print $1,$3,$4}'

# XML 输出用于后续工具
nmap -sV -oX evidence/nmap.xml TARGET

# 转换为 HTML 报告
xsltproc evidence/nmap.xml -o evidence/nmap-report.html
```

### 结果汇总脚本

```python
import xml.etree.ElementTree as ET

def parse_nmap_xml(xml_file):
    """解析 nmap XML 输出，返回结构化数据"""
    tree = ET.parse(xml_file)
    results = []
    for host in tree.findall('.//host'):
        ip = host.find('.//address[@addrtype="ipv4"]').get('addr')
        for port in host.findall('.//port'):
            port_id = port.get('portid')
            protocol = port.get('protocol')
            state = port.find('state').get('state')
            service = port.find('service')
            svc_name = service.get('name', '') if service is not None else ''
            svc_product = service.get('product', '') if service is not None else ''
            svc_version = service.get('version', '') if service is not None else ''
            if state == 'open':
                results.append({
                    'ip': ip,
                    'port': port_id,
                    'protocol': protocol,
                    'service': svc_name,
                    'product': svc_product,
                    'version': svc_version,
                })
    return results
```
