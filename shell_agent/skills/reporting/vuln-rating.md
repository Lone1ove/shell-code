# CVSS v3.1 评分指南

## 评分向量

CVSS v3.1 评分由 8 个指标组成：

```
CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X
```

---

## 攻击向量 (AV - Attack Vector)

| 值 | 说明 | 场景 |
|---|---|---|
| N (Network) | 通过网络远程利用 | Web 漏洞、远程服务漏洞 |
| A (Adjacent) | 需要在同一网段 | ARP 欺骗、蓝牙漏洞 |
| L (Local) | 需要本地访问 | 本地提权、DLL 劫持 |
| P (Physical) | 需要物理接触 | USB 攻击、冷启动攻击 |

---

## 攻击复杂度 (AC - Attack Complexity)

| 值 | 说明 | 场景 |
|---|---|---|
| L (Low) | 无需特殊条件 | 直接利用的注入、RCE |
| H (High) | 需要特定条件配合 | 竞争条件、需要中间人 |

---

## 权限要求 (PR - Privileges Required)

| 值 | 说明 | 场景 |
|---|---|---|
| N (None) | 无需认证 | 未授权 RCE、登录页注入 |
| L (Low) | 普通用户权限 | 认证后越权、存储型 XSS |
| H (High) | 管理员权限 | 后台功能漏洞 |

---

## 用户交互 (UI - User Interaction)

| 值 | 说明 | 场景 |
|---|---|---|
| N (None) | 无需用户交互 | 服务端漏洞 |
| R (Required) | 需要用户操作 | XSS（需点击链接）、CSRF |

---

## 影响范围 (S - Scope)

| 值 | 说明 | 场景 |
|---|---|---|
| U (Unchanged) | 影响仅限于漏洞组件 | 普通 SQL 注入 |
| C (Changed) | 影响超出漏洞组件 | 虚拟机逃逸、SSRF 访问内网 |

---

## 机密性影响 (C - Confidentiality)

| 值 | 说明 | 场景 |
|---|---|---|
| N (None) | 无影响 | DoS |
| L (Low) | 部分数据泄露 | 信息泄露、路径泄露 |
| H (High) | 全部数据可被读取 | SQL 注入读取全库、RCE |

---

## 完整性影响 (I - Integrity)

| 值 | 说明 | 场景 |
|---|---|---|
| N (None) | 无影响 | 仅读取的 SQL 注入 |
| L (Low) | 有限修改 | 存储型 XSS |
| H (High) | 完全修改 | RCE、SQL 注入写入 |

---

## 可用性影响 (A - Availability)

| 值 | 说明 | 场景 |
|---|---|---|
| N (None) | 无影响 | 信息泄露 |
| L (Low) | 性能下降 | 资源消耗 |
| H (High) | 服务中断 | DoS、删库 |

---

## 常见漏洞 CVSS 速查

| 漏洞 | 向量 | 评分 |
|---|---|---|
| 未授权 RCE | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 |
| 认证 RCE | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 8.8 |
| SQL 注入（读+写） | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 |
| SQL 注入（仅读） | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 |
| SSRF（内网访问） | AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N | 7.2 |
| 任意文件读取 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 |
| 存储型 XSS | AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N | 5.4 |
| 反射型 XSS | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 |
| CSRF | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N | 6.5 |
| IDOR | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 |
| 信息泄露 | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 |
| 弱口令 | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N | 6.5 |
| 缺少安全头 | AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N | 3.1 |
| 本地提权（内核） | AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 7.8 |
| 本地提权（SUID） | AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 7.8 |

---

## 评分工具

```
# 在线计算器
https://www.first.org/cvss/calculator/3.1

# NVD 搜索已知 CVE 评分
https://nvd.nist.gov/vuln/search
```

---

## 环境评分调整

根据客户环境调整最终风险等级：

| 因素 | 上调 | 下调 |
|---|---|---|
| 资产重要性 | 核心业务系统、域控 | 测试/开发环境 |
| 暴露程度 | 面向公网 | 仅内网、有防火墙 |
| 数据敏感度 | 个人信息、金融数据 | 公开信息 |
| 可补偿控制 | 无 WAF/IDS | 有多层防御 |
| 利用难度 | 有公开 PoC | 需要特殊条件 |
