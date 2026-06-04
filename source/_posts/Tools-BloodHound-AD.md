---
title: BloodHound AD攻击路径分析
date: 2026-04-20 08:00:00
tags:
  - 内网渗透
  - 工具
  - 渗透测试
categories: 渗透测试
description: 深入解析 BloodHound 在 Active Directory 环境中的攻击路径分析技术，涵盖 SharpHound 数据采集、Cypher 查询、域提权路径、Kerberoasting/AS-REP Roasting、ACL 滥用及自定义查询。
---

## 引言

Active Directory 作为企业身份认证与访问控制的核心，其攻击面庞大且复杂。传统工具（PowerView、ADFind）缺乏对攻击路径的可视化分析能力。**BloodHound** 利用 Neo4j 图数据库将 AD 中的用户、计算机、组、ACL 等实体映射为节点与边，通过图论算法自动发现从普通账户到高价值目标的攻击路径，是渗透测试与蓝队防御的必备利器。

---

## 1. 架构与数据采集

### 1.1 核心组件

| 组件 | 功能 |
|------|------|
| **SharpHound** | 低权限 AD 数据采集器 |
| **Neo4j** | 图数据库后端 |
| **BloodHound GUI** | 前端图形化查询界面 |

```
[SharpHound] --收集--> [Neo4j] <--Cypher查询-- [BloodHound GUI]
```

### 1.2 SharpHound 收集方法

| 方法 | 说明 | 完整度 |
|------|------|--------|
| `Default` | 常用对象与关系 | 中 |
| `Stealth` | 隐匿模式，降低检测风险 | 低 |
| `DCOnly` | 仅从域控收集 | 基础 |
| `All` | 完整采集 | 最高 |
| `Session` / `ACL` / `Trusts` | 按需单项采集 | 按需 |

```powershell
# 完整收集
SharpHound.exe -c All --zipfilename result.zip

# 隐匿模式（降低检测风险）
SharpHound.exe -c Stealth --throttle 1000 --jitter 250

# 指定域和域控
SharpHound.exe -c All -d corp.local --domaincontroller dc01.corp.local

# 循环采集（持续监控）
SharpHound.exe -c All --loop --loopduration 04:00:00 --loopinterval 00:30:00
```

SharpHound 收集用户（SPN、组成员、管理员权限）、计算机（OS、会话、本地管理员）、组（成员与嵌套）、域（信任、GPO）、ACL（DACL、所有权）以及会话关系（HasSession）。

---

## 2. 核心 Edge 类型

BloodHound 用 "Edge"（边）表示 AD 对象间的关系。理解每种边是分析攻击路径的关键：

| Edge | 含义 | 利用方式 |
|------|------|----------|
| `MemberOf` | 组成员关系 | 继承组权限 |
| `AdminTo` | 本地管理员 | 横向移动 |
| `HasSession` | 活动会话 | 凭证窃取（Mimikatz） |
| `GenericAll` | 完全控制 | 重置密码/添加成员 |
| `GenericWrite` | 写入权限 | SPN 劫持 |
| `WriteOwner` | 可修改所有者 | 更改所有权 |
| `WriteDacl` | 可修改 DACL | 授予 DCSync 权限 |
| `ForceChangePassword` | 强制改密 | 重置目标密码 |
| `AddMember` | 可添加组成员 | 加入高权限组 |
| `Owns` | 对象所有者 | 修改 DACL |
| `GPLink` | GPO 链接 | GPO 滥用 |
| `AllowedToDelegate` | 允许委派 | Kerberos 委派攻击 |
| `TrustedBy` | 域信任 | 跨域攻击 |
| `CanRDP` / `CanPSRemote` | 远程访问 | RDP/WinRM 横向移动 |
| `ExecuteDCOM` | DCOM 执行 | 远程代码执行 |
| `SQLAdmin` | SQL Server 管理 | SQL 服务器接管 |

**高价值目标标记**：`Domain Admins` 成员、`Enterprise Admins` 成员、域控计算机、`krbtgt` 账户、具有 DCSync 权限的对象。

---

## 3. 预置分析查询

### 3.1 域提权路径

- `Find Shortest Paths to Domain Admins` — 到达域管的最短路径
- `Find Principals with DCSync Rights` — 具有 DCSync 权限的主体
- `Shortest Paths to High Value Targets` — 到达高价值目标的最短路径
- `Shortest Paths from Owned Principals` — 从已控主体出发的攻击路径

### 3.2 Kerberoasting

- `List all Kerberoastable Accounts` — 列出所有可 Kerberoasting 的账户
- `Find Kerberoastable Members of High Value Groups` — 高价值组中可 Kerberoasting 成员
- `Shortest Path to Domain Admins from Kerberoastable Users` — Kerberoastable 用户到域管的路径

### 3.3 AS-REP Roasting 与 ACL 滥用

- `List all AS-REP Roastable Users` — 关闭 Kerberos 预认证的用户
- `Find ACL Abuse Paths` — ACL 滥用路径
- `Find Shortest Paths to Domain Admins via ACL Abuse` — ACL 滥用到达域管

---

## 4. 典型攻击路径分析

### 4.1 完整多跳攻击链

```
john.smith --(Kerberoastable)--> svc_sql --(AdminTo)--> SQL-SERVER --(HasSession)--> DOMAIN\administrator
```

① 通过钓鱼获得域用户 `john.smith` 凭证；② 运行 SharpHound 导入 BloodHound；③ 识别可 Kerberoasting 的服务账户 `svc_sql`；④ 获取 TGS 票据离线破解获得明文密码；⑤ `svc_sql` 对 `SQL-SERVER` 具有 `AdminTo` 权限，横向移动登录；⑥ `SQL-SERVER` 上存在域管的 `HasSession` 会话；⑦ 从 lsass 导出域管凭证，提权完成。

### 4.2 Kerberoasting 原理

```
攻击者（普通域用户）→ 查询所有 SPN 账户 → 申请 TGS → 离线破解 → 获得服务账户密码
```

恶意利用要点：普通域用户即可申请任意 TGS 票据（无需提权）；服务账户密码常为弱密码；TGS 请求是正常 Kerberos 流量，检测困难。**最高优先级目标**：属于 `Domain Admins` 的服务账户。

### 4.3 AS-REP Roasting 原理

```
攻击者 → 向 KDC 发送 AS-REQ（伪装为目标）→ KDC 返回 AS-REP → 离线破解目标用户密码
```

与 Kerberoasting 不同，AS-REP Roasting 针对**关闭 Kerberos 预认证**的用户。危险之处：无需域用户身份（仅需目标用户名），无需任何特殊权限。BloodHound 通过 `dontreqpreauth: true` 属性快速定位所有脆弱账户。

### 4.4 DCSync 攻击路径

DCSync 是 AD 中最危险的攻击之一。BloodHound 可发现持有以下权限的非特权主体：

| 权限 | 滥用方式 |
|------|----------|
| `DS-Replication-Get-Changes-All` | 完整 DCSync（复制所有分区） |
| `GenericAll` / `GenericWrite` | 重置 DC 计算机账户 |
| `WriteDacl` | 给自己添加 DCSync 权限 |
| `Owns` | 修改 DACL 获得所需权限 |

---

## 5. Cypher 自定义查询

### 5.1 可 Kerberoasting 的用户

```cypher
MATCH (u:User {hasspn: true})
WHERE NOT u.objectid ENDS WITH '-502'
RETURN u.name, u.serviceprincipalnames
ORDER BY u.name ASC
```

### 5.2 Domain Admins 中的 Kerberoastable 账户

```cypher
MATCH (u:User {hasspn: true})-[:MemberOf*1..]->(g:Group)
WHERE g.objectid =~ "(?i)S-1-5-.*-512"
RETURN u.name, u.serviceprincipalnames, g.name
```

### 5.3 AS-REP Roastable 用户

```cypher
MATCH (u:User {dontreqpreauth: true})
WHERE NOT u.objectid ENDS WITH '-502'
RETURN u.name, u.email, u.title
ORDER BY u.name ASC
```

### 5.4 具有 DCSync 权限的非特权主体

```cypher
MATCH (n:User)-[:GetChangesAll|AllExtendedRights|GenericAll|WriteDacl|Owns]->(d:Domain)
RETURN n.name AS User, n.displayname AS DisplayName
ORDER BY n.name ASC
```

### 5.5 可添加成员到高价值组的用户

```cypher
MATCH (u:User)-[:AddMember|GenericAll|GenericWrite|WriteOwner|WriteDacl|Owns]->
      (g:Group {highvalue: true})
RETURN DISTINCT u.name AS Attacker, g.name AS TargetGroup
ORDER BY g.name ASC
```

### 5.6 最短路径到 Domain Admins（3跳）

```cypher
MATCH (n:User), (g:Group {name: "DOMAIN ADMINS@CORP.LOCAL"}),
      p = shortestPath((n)-[*1..3]->(g))
WHERE NOT n.objectid ENDS WITH '-500'
RETURN p LIMIT 50
```

### 5.7 ACL 滥用路径到域控

```cypher
MATCH (n:User), (m:Computer),
      p = shortestPath((n)-[:GenericAll|GenericWrite|WriteOwner|WriteDacl|Owns|
          ForceChangePassword|AddMember*1..5]->(m))
WHERE m.objectid =~ "(?i)S-1-5-21-.*-1000"
RETURN n.name, p LIMIT 25
```

### 5.8 未受保护委派的计算机

```cypher
MATCH (c:Computer {unconstraineddelegation: true})
RETURN c.name, c.operatingsystem
ORDER BY c.name ASC
```

### 5.9 从已控节点出发的横向移动路径

```cypher
MATCH (o:Base)-[:AdminTo|CanRDP|CanPSRemote|ExecuteDCOM|SQLAdmin]->(c:Computer)
WHERE o.owned = true
RETURN o.name, c.name ORDER BY o.name ASC
```

### 5.10 密码长期未变的高价值用户

```cypher
MATCH (u:User {highvalue: true})
WHERE u.pwdlastset IS NOT NULL
RETURN u.name,
       duration.between(datetime({epochmillis: toInteger(u.pwdlastset)}), datetime()).days
         AS DaysSincePwdChange
ORDER BY DaysSincePwdChange DESC
```

---

## 6. 攻击路径分析工作流

```
┌──────────────────────────────────────────────────────────────────┐
│                 BloodHound 攻击路径分析工作流                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌─────────┐   ┌───────────┐   ┌────────┐   ┌──────────┐         │
│  │ 获得初始 │──>│ SharpHound │──>│ 导入   │──>│ 标记已控  │         │
│  │ 立足点   │   │ 数据采集   │   │ Neo4j  │   │ 节点     │         │
│  └─────────┘   └───────────┘   └────────┘   └────┬─────┘         │
│                                                   │                │
│                                                   ▼                │
│                        ┌──────────────────────────────────┐       │
│                        │      运行预置分析查询               │       │
│                        │  ○ Shortest Paths to Domain Admins│       │
│                        │  ○ Kerberoastable Accounts        │       │
│                        │  ○ AS-REP Roastable Users         │       │
│                        │  ○ ACL Abuse Paths                │       │
│                        └──────────────┬───────────────────┘       │
│                                       │                            │
│                          ┌────────────▼────────────┐              │
│                          │   发现可利用攻击路径？      │              │
│                          └──────┬────────┬────────┘              │
│                                 │ YES    │ NO                      │
│                                 ▼        ▼                        │
│                     ┌──────────────┐ ┌──────────────┐            │
│                     │ 利用路径提权到│ │ 编写自定义    │            │
│                     │ Domain Admin │ │ Cypher 查询   │            │
│                     └──────┬───────┘ └──────┬───────┘            │
│                            │                │                      │
│                            ▼                │                      │
│                     ┌──────────────┐         │                     │
│                     │  编写渗透报告  │<────────┘                     │
│                     └──────────────┘                               │
└──────────────────────────────────────────────────────────────────┘
```

---

## 7. 防御与缓解措施

### 7.1 Kerberoasting 防御

- 服务账户使用**长度 > 25 字符的完全随机密码**
- 使用**组托管服务账户（gMSA）**代替传统服务账户
- 审计并移除不必要的 SPN
- 监控 `Event ID 4769`（关注 RC4 类型的 TGS 请求）

### 7.2 AS-REP Roasting 防御

- 确保所有用户启用 Kerberos 预认证
- 审计 `userAccountControl` 中 `DONT_REQ_PREAUTH` 标志的账户
- 敏感账户使用长强密码

### 7.3 ACL 滥用防御

- 定期审计异常 DACL 配置，遵循最小权限原则
- 监控 `Event ID 5136`（目录服务对象修改）
- 使用 `AdminSDHolder` 保护特权组 ACL 不被继承

### 7.4 通用防御

- 启用 `Protected Users` 组（禁用 NTLM、RC4、委派）
- 实施 `LSA Protection`（RunAsPPL）和 Credential Guard
- 采用 **Tiering Model**：Tier 0（域控/CA/ADFS）→ Tier 1（应用服务器）→ Tier 2（用户工作站）
- **定期运行 BloodHound 自评估**，作为蓝队持续监控的一部分

---

## 8. 实践部署步骤

1. **启动 Neo4j**：`docker run -d --name neo4j-bloodhound -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/BloodHound neo4j:latest`
2. **导入数据**：将 SharpHound ZIP 文件拖入 BloodHound GUI
3. **标记已控节点**：右键已控节点 → "Mark as Owned"
4. **运行查询**（按优先级）：`Shortest Paths to Domain Admins` → `Kerberoastable Accounts` → `AS-REP Roastable Users` → `ACL Abuse Paths` → `Paths from Owned Principals`
5. **自定义查询**：根据环境特点（特定组名、计算机角色）编写 Cypher 针对性分析

---

## 9. 总结

BloodHound 将 AD 攻击路径分析从手工枚举提升到自动化图分析的高度。安全团队能够在**数分钟**内完成 AD 攻击面评估，发现手动分析难以察觉的**复杂多跳攻击链**，并以直观图形呈现安全态势。对于渗透测试人员，它是发现提权路径的效率利器；对于蓝队，它是**安全评估与对抗模拟**中不可或缺的工具。理解其背后的攻击路径逻辑，对攻防双方都有极高价值。

---

> **免责声明**
>
> 本文所述技术仅用于**合法的安全评估、渗透测试和网络安全研究**目的。未经授权对非自有系统或未获明确授权的系统使用本文中的任何技术是违法的。作者不对任何滥用本文内容导致的后果负责。读者应遵守所在国家/地区的法律法规，仅在拥有明确书面授权的环境中使用相关工具和技术。在未经授权的系统中运行 SharpHound 可能触发安全告警并可能被认定为计算机入侵行为。
