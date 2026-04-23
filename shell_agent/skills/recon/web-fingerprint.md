# Web 应用指纹识别

## 技术栈识别

### 响应头分析

```bash
# 完整响应头
curl -sI https://target.com

# 关注字段
# Server: Apache/2.4.41 / nginx/1.18.0 / Microsoft-IIS/10.0
# X-Powered-By: PHP/7.4.3 / Express / ASP.NET
# X-AspNet-Version: 4.0.30319
# Set-Cookie: JSESSIONID=xxx (Java) / PHPSESSID=xxx (PHP) / ASP.NET_SessionId=xxx (.NET)
# X-Generator: Drupal / WordPress
# X-Drupal-Cache: HIT
```

### 常见框架指纹

| 特征 | 框架/CMS |
|---|---|
| `/wp-login.php`、`/wp-admin/`、`/wp-content/` | WordPress |
| `/administrator/`、`/components/` | Joomla |
| `/user/login`、`/node/`、`/sites/default/` | Drupal |
| `/admin/login.html`、`thinkphp` | ThinkPHP |
| `__VIEWSTATE`、`.aspx` | ASP.NET WebForms |
| `csrftoken`、`/admin/`、Django 错误页 | Django |
| `_csrf_token`、Rack Session | Ruby on Rails |
| `XDEBUG_SESSION`、`Laravel` Cookie | Laravel |
| `connect.sid`、Express 错误页 | Node.js/Express |
| `/actuator/`、`/swagger-ui.html` | Spring Boot |
| Shiro `rememberMe` Cookie | Apache Shiro |

### 自动化指纹识别

```bash
# httpx 综合探测
httpx -u https://target.com -tech-detect -status-code -title -content-length -web-server -cdn

# whatweb
whatweb https://target.com -v

# wappalyzer CLI
wappalyzer https://target.com
```

---

## 源码泄露探测

### 版本控制泄露

```bash
# Git 泄露
curl -s https://target.com/.git/HEAD
# 返回 ref: refs/heads/main → 存在 Git 泄露
# 工具恢复：GitHack / git-dumper
git-dumper https://target.com/.git/ output-dir

# SVN 泄露
curl -s https://target.com/.svn/entries
curl -s https://target.com/.svn/wc.db
# 工具：svn-extractor

# DS_Store 泄露（macOS）
curl -s https://target.com/.DS_Store | strings
# 工具：ds_store_exp
```

### 备份文件探测

```bash
# 常见备份文件名
paths=(
    "www.zip" "www.tar.gz" "www.rar" "web.zip" "backup.zip"
    "site.zip" "htdocs.zip" "html.zip" "data.zip"
    "db.sql" "database.sql" "dump.sql" "backup.sql"
    ".env" "config.php.bak" "config.php~" "config.php.swp"
    "web.config" "web.config.bak" "web.xml"
    ".idea/workspace.xml" ".vscode/settings.json"
)

for path in "${paths[@]}"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path")
    if [ "$code" != "404" ] && [ "$code" != "403" ]; then
        echo "[+] Found: $path (HTTP $code)"
    fi
done
```

---

## API 发现

### Swagger/OpenAPI

```bash
# 常见路径
paths=(
    "/swagger-ui.html" "/swagger-ui/" "/swagger/index.html"
    "/api-docs" "/v2/api-docs" "/v3/api-docs"
    "/openapi.json" "/openapi.yaml"
    "/swagger.json" "/swagger.yaml"
    "/api/swagger.json"
    "/docs" "/redoc"
)

for path in "${paths[@]}"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path")
    if [ "$code" = "200" ]; then
        echo "[+] API Docs: $path"
    fi
done
```

### GraphQL 端点

```bash
# 常见路径
for path in /graphql /graphiql /api/graphql /graphql/console /v1/graphql; do
    # Introspection 查询
    resp=$(curl -s "https://target.com$path" -X POST \
        -H "Content-Type: application/json" \
        -d '{"query":"{__typename}"}')
    if echo "$resp" | grep -q "__typename"; then
        echo "[+] GraphQL endpoint: $path"
    fi
done

# 完整 Introspection
curl -s "https://target.com/graphql" -X POST \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}' | jq .
```

---

## Web 服务器默认页面与管理面板

### 管理后台路径探测

```bash
admin_paths=(
    "/admin" "/admin/" "/admin/login" "/admin/login.php"
    "/administrator" "/manager" "/manage"
    "/backend" "/console" "/dashboard"
    "/wp-admin" "/phpmyadmin" "/adminer.php"
    "/webmail" "/cpanel" "/plesk"
    "/jenkins" "/gitlab" "/grafana"
    "/kibana" "/nacos" "/xxl-job-admin"
    "/actuator" "/actuator/env" "/actuator/health"
    "/druid" "/druid/login.html"
    "/solr" "/solr/admin"
)

for path in "${admin_paths[@]}"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path")
    if [ "$code" = "200" ] || [ "$code" = "302" ] || [ "$code" = "401" ]; then
        echo "[!] $path → HTTP $code"
    fi
done
```

### Spring Boot Actuator（Java 应用特有）

```bash
actuator_paths=(
    "/actuator" "/actuator/env" "/actuator/health"
    "/actuator/info" "/actuator/beans" "/actuator/configprops"
    "/actuator/mappings" "/actuator/metrics" "/actuator/threaddump"
    "/actuator/heapdump" "/actuator/loggers" "/actuator/jolokia"
    "/env" "/health" "/info" "/mappings" "/trace"
)

for path in "${actuator_paths[@]}"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path")
    if [ "$code" = "200" ]; then
        echo "[!] Actuator exposed: $path"
    fi
done
# heapdump 可能包含敏感信息（密码、密钥）
```

---

## JavaScript 分析

### JS 文件收集与分析

```bash
# 收集 JS 文件 URL
katana -u https://target.com -jc -d 3 | grep -iE "\.js$" | sort -u > js-files.txt

# 从 HTML 中提取
curl -s https://target.com | grep -oP 'src="[^"]*\.js"' | sed 's/src="//;s/"//'

# 从 JS 中提取 API 路径
for js_url in $(cat js-files.txt); do
    curl -s "$js_url" | grep -oP '["'"'"'](/api/[a-zA-Z0-9_/.-]+)["'"'"']' | sort -u
done

# 提取硬编码密钥/Token
for js_url in $(cat js-files.txt); do
    curl -s "$js_url" | grep -iE "(api[_-]?key|secret|token|password|auth)\s*[:=]\s*['\"]" | head -20
done
```

### Source Map 泄露

```bash
# 检查 JS 文件末尾的 sourceMappingURL
curl -s https://target.com/static/js/main.js | tail -5
# //# sourceMappingURL=main.js.map

# 下载 source map 可还原前端源码
curl -s https://target.com/static/js/main.js.map -o main.js.map
# 使用 shuji 或 sourcemapper 还原
```

---

## HTTPS/TLS 分析

```bash
# SSL/TLS 配置检查
nmap --script=ssl-enum-ciphers -p443 TARGET
sslyze TARGET

# 证书信息
echo | openssl s_client -connect TARGET:443 2>/dev/null | openssl x509 -noout -text

# 关注信息：
# - 证书中的域名和 SAN（可能暴露内网域名）
# - 证书颁发者（内部 CA → 内网系统）
# - 弱加密套件
# - 过期证书

# testssl.sh 全面测试
testssl.sh https://target.com
```
