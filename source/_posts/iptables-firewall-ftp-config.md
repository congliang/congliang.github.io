---
title: Linux 防火墙管理：iptables 基础与 vsftpd 配置
date: 2024-08-14 15:14:16
tags:
  - 安全运维
  - 渗透测试
description: 实训笔记：iptables 防火墙规则管理（链、表、规则增删改），multiport 模块实战，vsftpd FTP 服务配置（主动/被动模式），以及 iptables 规则持久化。
categories: 安全运维
---


> 本文为个人实训笔记，记录了 iptables 高频操作与 vsftpd 服务部署要点。

***

## 一、iptables 防火墙基础

### 1.1 概述

iptables 类似于网络 ACL（访问控制列表），**按顺序匹配并执行规则**，一旦命中即停止后续匹配。

### 1.2 五条链（Chains）

| 链 | 方向 | 说明 |
|----|------|------|
| **INPUT** | 入站 | 外部发送到本机的数据包是否接收 |
| **OUTPUT** | 出站 | 本机发出的数据包（一般无限制） |
| **FORWARD** | 转发 | 本机作为路由器时是否转发 |
| **PREROUTING** | 路由前 | 数据包进入路由决策前修改 |
| **POSTROUTING** | 路由后 | 数据包离开路由决策后修改 |

```bash
# 查看当前规则（含编号）
iptables -L -n --line-number
```

<img src="/imgs/B-image1.png" alt="iptables 链结构" />

### 1.3 四张表（Tables）

| 表 | 用途 | 说明 |
|----|------|------|
| **filter** | 数据过滤 | 默认表，用于允许/拒绝流量 |
| **nat** | 地址转换 | SNAT / DNAT / MASQUERADE |
| **mangle** | 数据包修改 | TTL、TOS 修改 |
| **raw** | 连接跟踪豁免 | 跳过状态跟踪 |

```bash
# 不指定表则默认 filter
iptables -t nat -L
iptables -t mangle -L
```

### 1.4 常用操作参数

```bash
iptables -t [table] [command] [chain] [match] -j [target]
```

| 参数 | 说明 | 示例 |
|------|------|------|
| `-I` | 插入规则（默认首行） | `iptables -I INPUT 2 ...` |
| `-A` | 末行追加 | `iptables -A INPUT -p tcp --dport 80 -j ACCEPT` |
| `-D` | 删除规则 | `iptables -D INPUT 3` |
| `-F` | 清空链 | `iptables -F INPUT` |
| `-P` | 修改默认策略 | `iptables -P INPUT DROP` |
| `-p` | 指定协议 | tcp / udp / icmp |
| `--dport` | 目标端口 | 80、443 等 |
| `-j` | 动作 | ACCEPT / DROP / REJECT / LOG |

```bash
# 允许外部访问 80 端口
iptables -I INPUT -p tcp --dport 80 -j ACCEPT

# 删除第三条 INPUT 规则
iptables -D INPUT 3

# 修改默认策略为拒绝
iptables -P INPUT DROP
```

<img src="/imgs/B-image2.png" alt="防火墙规则配置" />
<img src="/imgs/B-image3.png" alt="删除规则操作" />

### 1.5 multiport 模块

当多个端口需要相同策略时，用 `multiport` 合并为一条规则：

```bash
# 将 20、21、80 端口合并为一条 ACCEPT 规则
iptables -I INPUT 2 -p tcp -m multiport --dport 20,21,80 -j ACCEPT
```

<img src="/imgs/B-image4.png" alt="multiport 配置" />

> 减少规则数量 = 提升匹配效率，也更便于维护。

***

## 二、vsftpd FTP 服务配置

### 2.1 修改配置文件

```bash
vim /etc/vsftpd/vsftpd.conf
```

关键配置：

```ini
pasv_enable=YES
pasv_min_port=30000
pasv_max_port=31000
```

<img src="/imgs/B-image5.png" alt="vsftpd 配置" />

### 2.2 主动模式 vs 被动模式

| 模式 | 数据连接发起方 | 防火墙注意 |
|------|---------------|-----------|
| **主动 (PORT)** | 服务器 → 客户端:20 | 客户端防火墙可能阻止 |
| **被动 (PASV)** | 客户端 → 服务器随机端口 | 服务器需开放指定端口范围 |

### 2.3 FTP 连接跟踪

使用 `ip_conntrack_ftp` 模块让 iptables 自动追踪 FTP 数据连接：

```bash
vim /etc/sysconfig/iptables-config

# 添加模块
IPTABLES_MODULES="ip_conntrack_ftp"
```

<img src="/imgs/B-image7.png" alt="ip_conntrack_ftp 配置" />

配置后主动/被动模式均可正常连接。

<img src="/imgs/B-image8.png" alt="连接测试 1" />
<img src="/imgs/B-image9.png" alt="连接测试 2" />
<img src="/imgs/B-image10.png" alt="连接测试 3" />
<img src="/imgs/B-image11.png" alt="连接成功" />

***

## 三、规则持久化

iptables 规则重启即失，需持久化写入配置文件：

```bash
# 方法一：手动编辑规则文件
vim /etc/sysconfig/iptables

# 方法二：导出当前规则
iptables-save > /etc/sysconfig/iptables
```

<img src="/imgs/B-image6.png" alt="iptables 规则持久化" />

---

> 本文为个人实训笔记，记录 iptables 日常高频操作与 vsftpd 部署要点。
