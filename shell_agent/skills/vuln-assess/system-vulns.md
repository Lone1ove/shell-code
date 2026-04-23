# 操作系统漏洞手册

## Linux 系统漏洞

### 内核漏洞

| CVE | 名称 | 影响版本 | 检测方式 |
|---|---|---|---|
| CVE-2021-4034 | PwnKit (pkexec) | 几乎所有 Linux | `ls -la /usr/bin/pkexec` |
| CVE-2022-0847 | DirtyPipe | 5.8 ≤ kernel < 5.16.11 | `uname -r` |
| CVE-2021-3156 | Baron Samedit (sudo) | sudo < 1.9.5p2 | `sudoedit -s /` |
| CVE-2022-2588 | 内核 cls_route | 多个版本 | `uname -r` |
| CVE-2016-5195 | DirtyCow | kernel < 4.8.3 | `uname -r` |
| CVE-2019-14287 | sudo bypass | sudo < 1.8.28 | `sudo -V` |
| CVE-2021-22555 | Netfilter | 2.6.19 ≤ kernel ≤ 5.12 | `uname -r` |

### 检测命令

```bash
# 内核版本
uname -r
cat /proc/version

# 发行版信息
cat /etc/os-release
cat /etc/issue

# 已安装安全补丁
# Debian/Ubuntu
apt list --installed 2>/dev/null | grep -i security
# RHEL/CentOS
rpm -qa --last | head -20

# 使用 linux-exploit-suggester
./linux-exploit-suggester.sh

# 使用 linpeas
curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

### 常见配置缺陷

```bash
# SUID 文件
find / -perm -4000 -type f 2>/dev/null
# 参考 GTFOBins: https://gtfobins.github.io/

# 可写的敏感文件
find /etc -writable -type f 2>/dev/null
ls -la /etc/passwd /etc/shadow /etc/sudoers

# sudo 配置
sudo -l
# 关注：NOPASSWD 条目、通配符、env_keep

# Crontab
cat /etc/crontab
ls -la /etc/cron.*
crontab -l
# 关注：以 root 运行的可写脚本、通配符注入

# 可写的 PATH 目录
echo $PATH | tr ':' '\n' | xargs ls -ld 2>/dev/null

# 敏感文件搜索
find / -name "*.conf" -o -name "*.config" -o -name "*.cfg" -o -name "*.ini" -o -name ".env" 2>/dev/null | head -30
find / -name "id_rsa" -o -name "id_dsa" -o -name "*.pem" 2>/dev/null
grep -rl "password" /etc/ 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null
# 危险 capability: cap_setuid / cap_dac_override / cap_sys_admin

# NFS 导出
showmount -e TARGET
cat /etc/exports
# 关注 no_root_squash → 可挂载写入 SUID 文件

# Docker 组成员
id
groups
# docker 组成员可以提权到 root

# 进程信息
ps aux
# 关注以 root 运行的服务、可能的凭证泄露

# 网络连接
ss -tlnp
netstat -tlnp
# 发现仅监听本地的服务（需要端口转发访问）

# 历史命令
cat ~/.bash_history
cat ~/.zsh_history
# 可能包含密码、密钥
```

---

## Windows 系统漏洞

### 关键漏洞

| CVE | 名称 | 影响 | 检测 |
|---|---|---|---|
| MS17-010 | EternalBlue | Win7/2008/2012 | nmap smb-vuln-ms17-010 |
| CVE-2020-1472 | Zerologon | DC 全版本 | mimikatz |
| CVE-2021-34527 | PrintNightmare | 全版本 | `Get-Service Spooler` |
| CVE-2021-1675 | PrintNightmare (LPE) | 全版本 | 同上 |
| CVE-2021-36934 | HiveNightmare | Win10/11 | `icacls C:\Windows\System32\config\SAM` |
| MS16-032 | 辅助登录提权 | Win7-10/2008-2012 | `systeminfo` |
| CVE-2019-1388 | UAC 绕过 | Win7-10 | 需 GUI |

### 信息收集

```powershell
# 系统信息
systeminfo
hostname
whoami /all

# 补丁信息
wmic qfe list
systeminfo | findstr /i "kb"

# 已安装软件
wmic product get name,version
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s

# 网络信息
ipconfig /all
route print
arp -a
netstat -ano

# 用户和组
net user
net localgroup administrators
net group "domain admins" /domain

# 服务
wmic service list brief
sc query state=all

# 计划任务
schtasks /query /fo TABLE /nh

# 注册表敏感信息
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"

# AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# 如果都为 1 → 可通过 msi 提权

# 自动登录凭证
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
```

### 自动化枚举

```powershell
# WinPEAS
.\winpeas.exe

# Seatbelt
.\Seatbelt.exe -group=all

# PowerUp
. .\PowerUp.ps1
Invoke-AllChecks

# Sherlock（旧版 Windows 提权检查）
. .\Sherlock.ps1
Find-AllVulns
```

### 常见配置缺陷

```powershell
# 不安全的服务权限
# 查找当前用户可修改的服务
accesschk.exe /accepteula -uwcqv "Everyone" *
accesschk.exe /accepteula -uwcqv "Users" *
# 可修改服务 → 替换二进制路径为反弹 Shell

# 未引用的服务路径
wmic service get name,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """
# C:\Program Files\Some App\service.exe → 可在 C:\Program.exe 放恶意文件

# 可写的 PATH 目录
# DLL 劫持：在可写目录放置恶意 DLL

# 敏感文件搜索
dir /s /b C:\Users\*.txt C:\Users\*.ini C:\Users\*.cfg C:\Users\*.xml 2>nul
findstr /si "password" *.txt *.xml *.ini *.cfg *.config 2>nul
type C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Login Data

# 令牌特权
whoami /priv
# SeImpersonatePrivilege → 土豆家族提权
# SeDebugPrivilege → 可访问任何进程内存
# SeBackupPrivilege → 可读取任何文件
# SeRestorePrivilege → 可写入任何文件
# SeAssignPrimaryTokenPrivilege → 可创建进程令牌
```

---

## 域环境漏洞

### AD 枚举

```powershell
# 域信息
nltest /dclist:DOMAIN
net group "Domain Controllers" /domain

# BloodHound 收集
.\SharpHound.exe -c All
# 或 Python 版
bloodhound-python -c All -d domain.local -u user -p pass -ns DC_IP

# PowerView
. .\PowerView.ps1
Get-Domain
Get-DomainController
Get-DomainUser
Get-DomainGroup -AdminCount
Get-DomainComputer
Find-LocalAdminAccess
```

### AD 攻击面

```
# Kerberoasting（获取服务票据离线破解）
# AS-REP Roasting（预认证禁用的用户）
# DCSync（域管理员权限获取所有哈希）
# Golden/Silver Ticket（伪造票据）
# Pass-the-Hash / Pass-the-Ticket
# 约束委派/非约束委派利用
# NTLM 中继
# GPP 密码（组策略首选项）
```
