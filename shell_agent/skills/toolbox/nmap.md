# Nmap 速查手册

## 基础语法

```
nmap [扫描类型] [选项] [目标]
```

## 目标指定

```bash
nmap 192.168.1.1              # 单个 IP
nmap 192.168.1.0/24           # CIDR 网段
nmap 192.168.1.1-100          # IP 范围
nmap 192.168.1.1,2,3          # 多个 IP
nmap -iL targets.txt          # 从文件读取
nmap --exclude 192.168.1.1    # 排除目标
```

## 扫描类型

| 参数 | 类型 | 说明 |
|---|---|---|
| `-sS` | TCP SYN | 半开扫描，默认，需 root |
| `-sT` | TCP Connect | 全连接扫描，无需 root |
| `-sU` | UDP | UDP 端口扫描（慢） |
| `-sN` | TCP Null | 无标志位，绕过简单防火墙 |
| `-sF` | TCP FIN | FIN 标志，类似 Null |
| `-sX` | TCP Xmas | FIN+PSH+URG 标志 |
| `-sA` | TCP ACK | 检测防火墙规则 |
| `-sn` | Ping Scan | 仅主机发现，不扫端口 |

## 端口指定

```bash
-p 22                   # 单个端口
-p 22,80,443            # 多个端口
-p 1-1000               # 端口范围
-p-                     # 全部 65535 端口
--top-ports 1000        # TOP N 常见端口
-p U:53,T:80            # 指定协议
```

## 服务与版本检测

```bash
-sV                     # 服务版本探测
-sV --version-intensity 5  # 探测强度 (0-9)
-sC                     # 默认脚本扫描（等同 --script=default）
-sV -sC                 # 常用组合：版本 + 默认脚本
-O                      # 操作系统检测
-A                      # 激进模式：-sV -sC -O --traceroute
```

## 时序与性能

| 参数 | 说明 |
|---|---|
| `-T0` | 偏执（5 分钟/探针），IDS 规避 |
| `-T1` | 鬼祟（15 秒/探针） |
| `-T2` | 礼貌（0.4 秒/探针） |
| `-T3` | 正常（默认） |
| `-T4` | 激进（推荐日常使用） |
| `-T5` | 疯狂（可能丢包） |

```bash
--min-rate 5000         # 最小发包速率
--max-rate 10000        # 最大发包速率
--max-retries 2         # 最大重试次数
--host-timeout 30m      # 主机超时
--scan-delay 1s         # 探针间隔
```

## 输出格式

```bash
-oN output.txt          # 正常文本
-oX output.xml          # XML（方便程序解析）
-oG output.gnmap        # Grepable 格式
-oA output              # 同时输出三种格式
-v                      # 详细输出
-vv                     # 更详细
```

## NSE 脚本

```bash
# 脚本分类
--script=default        # 默认脚本
--script=vuln           # 漏洞检测脚本
--script=exploit        # 漏洞利用脚本
--script=auth           # 认证相关
--script=brute          # 暴力破解
--script=discovery      # 信息发现

# 指定脚本
--script=http-title
--script=smb-vuln-ms17-010
--script=ssl-heartbleed

# 通配符
--script="http-*"
--script="smb-vuln*"

# 脚本参数
--script-args 'user=admin,pass=admin'
```

## 常用组合

```bash
# 快速内网扫描
nmap -sS -T4 --top-ports 1000 --open -oN quick.txt 192.168.1.0/24

# 全端口扫描
nmap -sS -p- -T4 --min-rate 5000 --open -oN allports.txt TARGET

# 详细服务识别
nmap -sV -sC -p 22,80,443,8080 -oN detail.txt TARGET

# 漏洞扫描
nmap --script=vuln -p 80,443,445 -oN vuln.txt TARGET

# 绕过防火墙
nmap -sS -T2 -f --data-length 24 --randomize-hosts -D RND:5 TARGET

# UDP 常见端口
nmap -sU --top-ports 50 -T4 TARGET

# Web 应用侦察
nmap -sV --script=http-title,http-headers,http-methods,http-robots.txt -p 80,443,8080,8443 TARGET

# SMB 漏洞全检
nmap --script="smb-vuln*" -p 445 TARGET
```

## 防火墙/IDS 规避

```bash
-f                      # IP 分片
--mtu 24                # 指定 MTU
-D RND:5               # 使用 5 个随机诱饵
-D decoy1,decoy2,ME    # 指定诱饵 IP
--source-port 53        # 指定源端口
--data-length 24        # 附加随机数据
-sS -T2                 # 慢速 SYN 扫描
--randomize-hosts       # 随机化扫描顺序
--spoof-mac 0           # 随机 MAC（仅限同网段）
```
