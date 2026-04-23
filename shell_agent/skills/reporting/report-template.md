# 渗透测试报告模板

生成报告时，将以下模板中的占位符替换为实际内容。

---

```markdown
# 渗透测试报告

## 项目信息

| 项目 | 内容 |
|---|---|
| 项目名称 | {project_name} |
| 客户名称 | {client_name} |
| 测试人员 | {tester_name} |
| 测试日期 | {start_date} ~ {end_date} |
| 报告日期 | {report_date} |
| 报告版本 | v1.0 |
| 密级 | 机密 |

---

## 免责声明

本报告仅供 {client_name} 内部安全改进使用。本次渗透测试在 {client_name} 书面授权下进行，测试范围和方法已事先约定。报告中的漏洞详情和利用方法仅用于安全评估目的，不得用于非法活动。

本报告中的发现反映测试时间窗口内的系统安全状态，不代表系统在其他时间的安全水平。

---

## 1. 执行摘要

### 测试概述

{executive_summary}

受 {client_name} 委托，对其 {scope_description} 进行了渗透测试。测试时间为 {start_date} 至 {end_date}，采用 {methodology}（黑盒/灰盒/白盒）测试方法。

### 关键发现

本次测试共发现 **{total_vulns}** 个安全漏洞：

| 等级 | 数量 | 占比 |
|---|---|---|
| 严重 (Critical) | {critical_count} | {critical_pct}% |
| 高危 (High) | {high_count} | {high_pct}% |
| 中危 (Medium) | {medium_count} | {medium_pct}% |
| 低危 (Low) | {low_count} | {low_pct}% |

### 整体风险评估

{overall_risk_assessment}

### 关键建议

1. {recommendation_1}
2. {recommendation_2}
3. {recommendation_3}

---

## 2. 测试范围与方法

### 测试范围

| 类型 | 目标 |
|---|---|
| IP 范围 | {ip_ranges} |
| 域名 | {domains} |
| URL | {urls} |

### 排除范围

| 目标 | 原因 |
|---|---|
| {exclusion_1} | {reason_1} |

### 测试方法

本次测试遵循 PTES（渗透测试执行标准）方法论，包含以下阶段：

1. **信息收集**：被动和主动信息收集，包括子域名枚举、端口扫描、服务识别
2. **漏洞评估**：基于收集到的信息进行系统化的漏洞识别和验证
3. **漏洞利用**：对已确认的漏洞进行利用，验证其影响
4. **后渗透**：评估成功利用后可造成的进一步影响
5. **报告**：汇总发现，提供修复建议

### 测试限制

{test_limitations}

---

## 3. 漏洞详情

### 3.1 严重漏洞

#### VULN-{id}: {vuln_title}

| 属性 | 值 |
|---|---|
| 等级 | 严重 |
| CVSS 评分 | {cvss_score} |
| CVSS 向量 | {cvss_vector} |
| 影响目标 | {affected_target} |
| 漏洞类型 | {vuln_type} |

**描述**

{vuln_description}

**复现步骤**

1. {step_1}
2. {step_2}
3. {step_3}

**证据**

{evidence_description}

![证据截图](../evidence/{evidence_file})

**影响**

{impact_description}

**修复建议**

- **短期缓解**: {short_term_fix}
- **长期修复**: {long_term_fix}
- **验证方法**: {verification_method}

**参考资料**

- {reference_1}
- {reference_2}

---

（对每个漏洞重复上述格式）

---

### 3.2 高危漏洞

（同上格式）

### 3.3 中危漏洞

（同上格式）

### 3.4 低危漏洞

（同上格式）

---

## 4. 攻击路径

### 攻击链描述

{attack_chain_description}

```
外部侦察 → {step_1} → {step_2} → {step_3} → 目标达成
```

### 攻击路径图

（如有多条攻击路径，用列表或图示描述）

---

## 5. 修复建议优先级

按修复优先级排序：

| 优先级 | 漏洞 | 修复建议 | 预计工作量 |
|---|---|---|---|
| P0 | {vuln_name} | {fix_summary} | {effort} |
| P1 | {vuln_name} | {fix_summary} | {effort} |
| P2 | {vuln_name} | {fix_summary} | {effort} |

### 安全加固建议

除漏洞修复外，建议实施以下安全加固措施：

1. **网络层**: {network_recommendations}
2. **应用层**: {application_recommendations}
3. **系统层**: {system_recommendations}
4. **管理层**: {management_recommendations}

---

## 附录 A: 使用的工具

| 工具 | 版本 | 用途 |
|---|---|---|
| Nmap | {version} | 端口扫描、服务识别 |
| Nuclei | {version} | 漏洞扫描 |
| sqlmap | {version} | SQL 注入检测 |
| Metasploit | {version} | 漏洞利用 |
| {tool} | {version} | {purpose} |

## 附录 B: 测试时间线

| 时间 | 操作 | 结果 |
|---|---|---|
| {timestamp} | {action} | {result} |

## 附录 C: 详细证据

（附加截图和命令输出）
```

---

## 报告生成指南

### 语言风格

- 执行摘要面向管理层，避免过多技术术语
- 漏洞详情面向技术人员，需要足够的复现细节
- 修复建议需要具体可操作，不能只说"加强安全"
- 使用客观中性的语言，避免批判性措辞

### 敏感信息处理

- 密码/凭证：显示前 2 位 + 星号，如 `ad***`
- IP 地址：可完整显示（在授权范围内）
- 个人数据：脱敏处理
- 截图中的敏感信息：打码

### 漏洞编号规则

```
VULN-{序号}-{类型缩写}
示例：VULN-001-SQLI、VULN-002-RCE、VULN-003-XSS
```

### 证据要求

每个漏洞至少包含：
1. 请求/响应截图或关键输出
2. payload 或利用步骤
3. 成功利用的证据（如 whoami 输出、数据样本）
