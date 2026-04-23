---
name: struts2-ognl
description: Struts2 OGNL 漏洞族（含 S2-045/S2-057 等）通用识别、验证与归因规则。面向任意环境，不绑定单一靶场。
allowed-tools: Bash, Read, Write
---

# Struts2 OGNL 通用技能

适用于 Struts2 相关目标的 OGNL 注入场景。该技能用于“漏洞族级别”的判断，不针对单一靶场。

## 触发条件

- 目标存在 Struts2 / xwork / Action 路由特征。
- 响应或页面中出现 OGNL、ActionChain、namespace 等线索。
- 检测阶段出现与 Struts2 相关的可疑回显、路径异常或请求头异常。

## 验证流程（必须按顺序）

1. 建立基线响应：记录无 payload 的正常请求响应。
2. 低风险探测：先验证可控表达式或可控头/路径行为。
   常见向量分两类：
   - 请求头/上传链路：`Content-Type`、`multipart/form-data`、`doUpload.action`
   - 路径/路由链路：`namespace`、`ActionChain`、路径级 OGNL
3. 运行时证据：必须拿到可重复的命令执行证据（如 `whoami`、`id`、稳定计算回显）。
4. 负样本复检：更换无害 payload 验证是否存在“伪阳性回显”。
5. 交叉确认：至少两次独立请求确认结果一致，再进入“已验证”。

## 关键细节

- 如果是上传/请求头链路，`Content-Type` 类 payload 是否保持 `.multipart/form-data` 结尾会直接影响结果，缺失时常见“看似命中、实际未执行”。
- 如果是路径/namespace 链路，必须把基线 URL 与注入后 URL 一起记录，防止把普通 `showcase` 页面或路由跳转误报成漏洞成功。
- 只有页面标题、状态码变化、单次异常页或普通报错，不能作为 OGNL 已验证证据。

## 类型与 CVE 归因分离

- 第一步只确认“是否为 OGNL/RCE 类型问题”。
- 第二步再归因具体 CVE。

常见归因线索：

- 更偏 `CVE-2017-5638 (S2-045)`：注入点主要在 `Content-Type`（multipart 上传链路）。
- 更偏 `CVE-2018-11776 (S2-057)`：注入点主要在 URL 路径/namespace/ActionChain 路由处理。

若证据不足以区分具体 CVE：

- 报告为“已确认漏洞类型 + 候选 CVE 概率排序”。
- 不要把低证据候选 CVE 写成已验证。

## 误报防护

- 仅有状态码变化、页面模板回显、单次偶然返回，不视为漏洞已验证。
- 仅凭“目标是 Struts2”不能直接判定任意 CVE。
- 与 SSTI、命令注入等其他类型要做差异化验证，避免混淆。

## 报告要求

- 记录请求 URL、方法、关键 payload（可脱敏）。
- 记录响应中的关键证据片段与重复验证结果。
- 结论分层输出：漏洞类型结论、CVE 归因结论、置信度与未确认原因。
