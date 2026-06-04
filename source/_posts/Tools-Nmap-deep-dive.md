---
title: Nmap深度使用指南
date: 2026-05-20 08:00:00
tags:
  - 工具
  - 渗透测试
description: Nmap 深度使用指南——扫描类型、NSE 脚本引擎与防火墙/IDS 规避技巧。
categories: 渗透测试
---

## 前言

Nmap（Network Mapper）是信息安全领域最负盛名的开源网络扫描工具，自1997年由Gordon Lyon（Fyodor）发布以来，已成为渗透测试、网络审计和资产管理中不可或缺的瑞士军刀。本文从扫描技术原理、NSE脚本引擎、时序策略、OS指纹识别、输出管理到防火墙规避，系统性拆解Nmap深度用法。

> **免责声明：** 本文所述技术仅供安全研究、授权渗透测试及网络管理学习使用。未经授权对他人系统进行扫描可能违反法律法规，使用者须自行承担全部法律责任。

---

## 一、安装与主机发现

```bash
# Debian/Ubuntu
sudo apt update && sudo apt install nmap -y
# CentOS/RHEL
sudo yum install nmap -y
# 源码编译（最新版本）
git clone https://github.com/nmap/nmap.git
cd nmap && ./configure && make && sudo make install
nmap --version
```

主机发现是扫描的第一步——确认目标是否存活，避免在不存在的IP上浪费时间：

```bash
# ICMP Echo（-PE）：经典但常被防火墙拦截
nmap -sn -PE 192.168.1.0/24
# ICMP Timestamp（-PP）与Netmask（-PM）：穿透部分防火墙
nmap -sn -PP 192.168.1.0/24
nmap -sn -PM 192.168.1.0/24
# TCP SYN Ping（-PS）：向指定端口发SYN包，RST/ACK即存活
nmap -sn -PS80,443,22,3389 192.168.1.0/24
# TCP ACK Ping（-PA）：发ACK包探测
nmap -sn -PA80,443 192.168.1.0/24
# UDP Ping（-PU）：UDP包探测
nmap -sn -PU53,161 192.168.1.0/24
# ARP Ping（-PR）：局域网最可靠，防火墙无法阻止
nmap -sn -PR 192.168.1.0/24
# 禁用主机发现（-Pn）：将所有目标视为存活
nmap -Pn 10.0.0.0/24
```

**建议：** 内网使用`-PR`（ARP），外网使用`-PS`组合`-PA`，不确定时用`-Pn`强制扫描。

---

## 二、端口扫描技术详解

端口扫描是Nmap核心能力，不同类型在速度、隐蔽性和精确度间存在权衡。以下逐一剖析六种关键扫描方式。

### 2.1 TCP SYN 半开扫描（-sS）——默认首选

发送SYN包后，若收到SYN-ACK则端口开放，RST则关闭，无响应则被过滤。未完成三次握手，目标应用层通常不记录，隐蔽性较好。**需要root/Administrator权限。**

```
发送方--SYN(x)-->目标
开放端口: <--SYN-ACK(y,x+1)-- 发送方--RST--> (终止，不建立连接)
关闭端口: <--RST(0,x+1)----- (直接拒绝)
```

```bash
sudo nmap -sS 192.168.1.1
sudo nmap -sS -p 1-1000 192.168.1.1
sudo nmap -sS -F 192.168.1.1          # 快速扫描Top100端口
```

### 2.2 TCP Connect 全连接扫描（-sT）——无需特权

通过系统`connect()`系统调用完成三次握手，**无需root权限**，但速度较慢且会在目标日志留下记录。

```bash
nmap -sT 192.168.1.1
nmap -sT -sV 192.168.1.1             # 结合版本探测
```

### 2.3 UDP 扫描（-sU）——盲区覆盖

UDP无连接，开放端口通常沉默，关闭端口回复ICMP Port Unreachable（但受ICMP速率限制）。UDP扫描天生缓慢，但DNS(53)、SNMP(161)、NTP(123)等关键服务均走UDP。

```bash
sudo nmap -sU 192.168.1.1
# TCP+UDP组合——同时覆盖两协议
sudo nmap -sS -sU -p T:22,80,443,U:53,161,500 192.168.1.1
# UDP常见端口精扫
sudo nmap -sU -p 53,67-69,123,135,137-139,161-162,445,500,514,1900,5353 192.168.1.1
```

### 2.4 TCP ACK 扫描（-sA）——绘制防火墙规则

发送仅带ACK标志的包。**无法区分"开放"和"关闭"**，但可以判断端口是否被防火墙过滤：收到RST表示unfiltered（未被过滤），无响应或ICMP不可达表示filtered（被过滤）。常用于绘制防火墙ACL。

```bash
sudo nmap -sA 192.168.1.1
# ACK+SYN组合：SYN看开放，ACK看过滤
sudo nmap -sS -sA -p 1-1024 192.168.1.1
```

### 2.5 TCP Window 窗口扫描（-sW）

与ACK扫描类似，但通过检查RST包中的TCP窗口字段区分开放和关闭。部分系统实现中开放端口返回非零窗口值，关闭端口窗口值为零。**依赖特定OS实现，非通用。**

```bash
sudo nmap -sW 192.168.1.1
sudo nmap -sS -sW -p 80,443 192.168.1.1  # 与SYN对照验证
```

### 2.6 TCP Maimon 扫描（-sM）

发送FIN+ACK包。多数BSD衍生系统对开放端口丢弃该包（无响应），对关闭端口回复RST。能绕过部分仅过滤SYN包的防火墙。

```bash
sudo nmap -sM 192.168.1.1
# 综合多类型扫描比对防火墙行为
sudo nmap -sS -sA -sM -sW -p 22,80,443,3389 192.168.1.1
```

### 扫描类型速查

| 参数 | 扫描类型 | 权限 | 速度 | 隐蔽性 | 区分open/close |
|------|---------|------|------|--------|:---:|
| `-sS` | TCP SYN半开 | root | 快 | 高 | 是 |
| `-sT` | TCP Connect | 普通 | 中 | 低 | 是 |
| `-sU` | UDP | root | 慢 | 中 | 是 |
| `-sA` | TCP ACK | root | 快 | 中 | 否(filtered/unfiltered) |
| `-sW` | TCP Window | root | 中 | 中 | 部分系统 |
| `-sM` | TCP Maimon | root | 中 | 较高 | 部分BSD |
| `-sN` | TCP NULL | root | 中 | 高 | 对Windows/Linux无效 |
| `-sF` | TCP FIN | root | 中 | 高 | 同上 |
| `-sX` | Xmas Tree | root | 中 | 高 | 同上 |

---

## 三、服务版本与OS指纹识别

### 3.1 服务版本探测（-sV）

端口开放只是第一步，确定运行的服务及版本才是关键情报。

```bash
sudo nmap -sV 192.168.1.1
sudo nmap -sV --version-intensity 9 192.168.1.1   # 激进(0-9，默认7)
sudo nmap -sV --version-all 192.168.1.1           # 全探针，最慢最准
sudo nmap -sV --version-light 192.168.1.1         # 轻量，仅匹配常见指纹
```

### 3.2 OS指纹识别（-O）

发送16个精心构造的TCP/UDP/ICMP探针，与`nmap-os-db`数据库比对，推测目标操作系统及版本。

```bash
sudo nmap -O 192.168.1.1
sudo nmap -O --osscan-guess 192.168.1.1           # 更激进猜测
sudo nmap -O --osscan-limit 192.168.1.1           # 仅对已知目标检测
# 聚合参数 -A = -sV + -O + -sC + --traceroute
sudo nmap -A 192.168.1.1
```

---

## 四、时序与性能调优（T0-T5）

Nmap提供六种时序模板，在速度与隐蔽性之间取舍：

| 模板 | 参数 | 特点 | 适用场景 |
|------|------|------|----------|
| T0 | `-T0` | 偏执模式：串行，包间隔5分钟 | IDS/IPS规避 |
| T1 | `-T1` | 潜行模式：包间隔15秒 | 隐蔽渗透 |
| T2 | `-T2` | 礼貌模式：包间隔0.4秒 | 生产环境谨慎扫描 |
| T3 | `-T3` | 正常模式（默认），动态并行 | 大多数场景 |
| T4 | `-T4` | 侵略模式：快速并行 | 内网/高速网络 |
| T5 | `-T5` | 疯狂模式：最大并行，仅等300ms | 低延迟局域网 |

模板只是预设，底层每个参数均可独立控制：

```bash
sudo nmap \
  --min-rtt-timeout 100ms --max-rtt-timeout 1500ms \
  --max-retries 2 \
  --min-hostgroup 32 --max-hostgroup 256 \
  --min-parallelism 32 --max-parallelism 128 \
  --scan-delay 5ms --host-timeout 30m \
  192.168.1.0/24
```

**发包速率直接控制（包/秒）：**

```bash
sudo nmap -sS --min-rate 500 --max-rate 2000 192.168.1.0/24
```

**经验法则：** 内网`-T4`大胆扫，外网`-T3`保准确，IDS规避`-T2`甚至`-T1`并加大`--scan-delay`。

---

## 五、输出管理（-oA）

Nmap提供四种输出格式，合理组合提升效率：

```bash
# -oN：人类可读文本
sudo nmap -sS 192.168.1.1 -oN scan.txt
# -oX：XML（程序解析、导入Metasploit）
sudo nmap -sS 192.168.1.1 -oX scan.xml
# -oG：Grepable（grep/awk/sed处理）
sudo nmap -sS 192.168.1.0/24 -oG scan.gnmap
# -oA：一次性生成所有格式（.nmap .xml .gnmap）
sudo nmap -sS -sV -O -A 192.168.1.1 -oA full_scan
```

**-oG 实战数据提取：**

```bash
grep "22/open" scan.gnmap | cut -d " " -f 2          # 提取开放22端口的IP
grep "Status: Up" scan.gnmap | cut -d " " -f 2       # 提取所有存活主机
```

**XML转HTML报告：** `xsltproc /usr/share/nmap/nmap.xsl scan.xml > report.html`

---

## 六、NSE脚本引擎

NSE是Nmap的终极武器——以Lua编写脚本实现自动化探测、漏洞检测、暴力破解和高级信息收集。脚本分类存储在`/usr/share/nmap/scripts/`。

### 6.1 脚本分类速查

| 分类 | 说明 | 示例 |
|------|------|------|
| `safe` | 安全无损探测，不触发告警 | `http-title`, `dns-brute` |
| `default` | `-sC`执行的默认脚本 | 随Nmap版本变化 |
| `auth` | 认证绕过、弱口令检测 | `http-brute`, `ftp-anon` |
| `discovery` | 深度信息收集 | `dns-zone-transfer`, `smb-enum-shares` |
| `vuln` | 漏洞检测（可能危险） | `ssl-heartbleed`, `smb-vuln-ms17-010` |
| `exploit` | 主动利用漏洞（高风险） | `http-shellshock`, `smb-vuln-ms17-010` |
| `brute` | 暴力破解 | `ssh-brute`, `mysql-brute` |
| `malware` | 恶意软件检测 | `http-google-malware` |
| `broadcast` | 广播发现 | `broadcast-dns-service-discovery` |
| `dos` | 拒绝服务测试 | `http-slowloris` |
| `external` | 依赖外部资源 | `shodan-api` |
| `intrusive` | 入侵式扫描 | 大部分brute/exploit脚本 |

### 6.2 脚本选择器语法

```bash
# 按类别
nmap --script safe 192.168.1.1
nmap --script "safe or discovery" 192.168.1.1
# 按通配符
nmap --script http-* 192.168.1.1
nmap --script "smb-vuln-*" 192.168.1.1
# 排除特定脚本
nmap --script "default and not http-slowloris" 192.168.1.1
# 多脚本
nmap --script http-enum,smb-enum-shares,dns-brute 192.168.1.1
```

### 6.3 典型实战用例

**信息收集（discovery）：**

```bash
nmap --script smb-enum-shares -p 445 192.168.1.1
nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain=example.com -p 53 192.168.1.1
nmap --script http-enum -p 80,443 192.168.1.1
```

**认证检测（auth）：**

```bash
nmap --script ftp-anon -p 21 192.168.1.0/24
nmap --script mysql-empty-password -p 3306 192.168.1.1
nmap --script http-default-accounts -p 80,443,8080 192.168.1.1
```

**漏洞检测（vuln）：**

```bash
nmap --script ssl-heartbleed -p 443 192.168.1.1
nmap --script smb-vuln-ms17-010 -p 445 192.168.1.0/24
nmap --script http-shellshock --script-args uri=/cgi-bin/test.cgi -p 80 192.168.1.1
nmap --script vuln -sV 192.168.1.1
```

**漏洞利用（exploit）：**

```bash
nmap --script smb-vuln-ms08-067 -p 445 192.168.1.1
nmap --script http-vuln-cve2015-1427 -p 9200 192.168.1.1
```

**暴力破解（brute）：**

```bash
nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=rockyou.txt 192.168.1.1
```

**常用--script-args：**

```bash
--script-args unsafe=1              # 允许危险操作
--script-args timeout=30s           # 脚本超时
--script-args userdb=<file>         # 用户名字典
--script-args passdb=<file>         # 密码字典
--script-args http.useragent="Mozilla/5.0 (CustomBot/1.0)"
--script-trace                      # 打印脚本详细执行日志
```

---

## 七、防火墙/IDS规避技术

### 7.1 分片（-f / --mtu）

将TCP头拆分到多个小包中，降低IDS签名匹配概率。

```bash
sudo nmap -f 192.168.1.1             # IP包分片为8字节
sudo nmap -f --mtu 16 192.168.1.1    # --mtu必须为8的倍数
```

### 7.2 诱饵扫描（-D）

混入虚假IP地址，使目标难以确认真实扫描源。

```bash
sudo nmap -D 192.168.1.100,ME,192.168.1.200 192.168.1.1
sudo nmap -D RND:5 192.168.1.1       # 随机5个诱饵IP
```

**注意：** 诱饵IP必须是真实存活主机，否则反而暴露身份。

### 7.3 源端口伪装与数据伪造

```bash
sudo nmap --source-port 53 192.168.1.1      # 伪装DNS流量绕过ACL
sudo nmap -g 80 -sS 192.168.1.1             # -g简写
sudo nmap --spoof-mac 00:11:22:33:44:55 192.168.1.1  # 伪造MAC
sudo nmap --spoof-mac 0 192.168.1.1         # 随机MAC
sudo nmap --ttl 128 192.168.1.1             # 伪造TTL
sudo nmap --data-length 128 192.168.1.1     # 填充额外数据改变包特征
sudo nmap --randomize-hosts 192.168.1.0/24  # 随机化扫描顺序
```

### 7.4 代理与跳板

```bash
nmap --proxies socks4://127.0.0.1:1080 192.168.1.1
nmap --proxies http://127.0.0.1:8080 192.168.1.1
nmap --proxies socks4://p1:1080,socks4://p2:1080 192.168.1.1  # 链式
```

### 7.5 隐蔽扫描组合范例

单技术效果有限，多层组合才是规避之道：

```bash
sudo nmap -sS -Pn -n \
  -f --mtu 24 \
  -D RND:5 \
  --source-port 53 \
  --randomize-hosts \
  --data-length 32 \
  -T1 --max-retries 1 \
  -p 22,80,443,3389 \
  -oA stealth_scan 192.168.1.1
```

参数要点：`-Pn`跳过主机发现、`-n`禁用DNS解析、`-f`分片、`-D RND:5`诱饵、`--source-port 53`伪装DNS、`--data-length`随机填充、`-T1`极慢速率。

---

## 八、进阶组合实战

### 场景一：快速内网资产探测

```bash
sudo nmap -sn 192.168.1.0/24 -oA ping_sweep
grep "Up" ping_sweep.gnmap | cut -d " " -f 2 > alive_hosts.txt
sudo nmap -iL alive_hosts.txt -sS -sV -p 1-1000 -T4 -oA intel
```

### 场景二：外网Web目标全面评估

```bash
sudo nmap -sS -sV -sC -O -p 80,443,8080,8443,9090 \
  --script "http-*,ssl-*" -T3 -oA web_scan 203.0.113.10
```

### 场景三：漏洞导向针对性扫描

```bash
sudo nmap -sS -sV -p- -T4 -oA full_scan 192.168.1.1
sudo nmap -sV --script "vuln and safe" -p 22,25,80,443,445,3306,8080 -oA vuln_scan 192.168.1.1
```

---

## 九、NSE脚本开发入门

当内置脚本无法满足需求时，可编写自定义NSE脚本。NSE使用嵌入式Lua 5.4，提供丰富的API库。

```lua
-- custom-version-check.nse
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[自定义HTTP Server头检测]]
author = "Researcher"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service({80, 443}, {"http", "https"})

action = function(host, port)
    local resp = http.get(host, port, "/")
    if not resp then return nil end
    local server = resp.header["server"]
    if server then
        return string.format("Server: %s", server)
    else
        return "No Server header"
    end
end
```

```bash
# 放置脚本并刷新数据库
sudo cp custom-version-check.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb
# 执行
nmap --script custom-version-check -p 80,443 192.168.1.1
```

**关键API模块：** `nmap`（核心上下文）、`shortport`（端口规则）、`http`（HTTP库）、`stdnse`（工具函数）、`brute`（暴力破解框架）、`comm`（原始socket）、`smb`、`sslcert`、`vulns`、`json`。

---

## 十、常见问题排错

| 问题 | 原因 | 解决 |
|------|------|------|
| `-sS requires root` | 需构造原始套接字 | `sudo`，或改用`-sT` |
| UDP扫描无结果 | ICMP速率限制 | `sudo sysctl -w net.ipv4.icmp_ratelimit=0` |
| 扫描极慢 | 误用`-T0`/`-T1`或`-sU` | 内网`-T4`，缩减端口范围 |
| NSE脚本报错 | 脚本依赖或参数问题 | 加`--script-trace`查看详情 |
| 目标封锁IP | IDS检测到扫描 | 用`-T2`、`--scan-delay`、`-D`诱饵组合 |

---

## 十一、总结

Nmap的威力在于组合。核心心法：

1. **先发现后扫描：** `-sn`收缩目标面，避免无谓的全端口扫描
2. **按需选择扫描类型：** 内网`-sS`首选，特权不足用`-sT`，覆盖盲区加`-sU`
3. **NSE先safe后vuln：** 侦查阶段用`safe`和`discovery`，确认后才跑`vuln`和`exploit`
4. **速度与隐蔽平衡：** 内网`-T4`，外网/红队`-T2`谨慎推进
5. **输出即资产：** 养成`-oA`保存记录的习惯，XML可喂入Metasploit等下游工具
6. **遵守法律边界：** 仅授权测试，善用`-sn`、`--exclude`精确控制范围

掌握以上内容，你已经能应对绝大多数网络侦察场景。在合法合规的前提下，持续动手实践。

---

*参考：[Nmap官方手册](https://nmap.org/book/man.html) | [NSE脚本文档](https://nmap.org/nsedoc/) | [Nmap网络扫描指南](https://nmap.org/book/toc.html)*
