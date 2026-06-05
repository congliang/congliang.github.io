---
title: 渗透测试中的密码学：常见加密算法识别
date: 2026-05-23 20:11:08
tags:
  - 密码学
  - 渗透测试
description: 渗透测试中的密码学——Base64/Hex/MD5/AES/RSA 识别与编码/加密/哈希差异。
categories: 渗透测试
---

## 前言

在渗透测试过程中，我们时常会遇到各种编码数据、哈希散列和密文。能否快速准确地识别它们的类型，直接决定了后续破解或解码工作的效率。本文从实战角度系统梳理常见编码、哈希与加密算法的特征及识别方法，并附上 John the Ripper 与 Hashcat 的模式号速查表。

**免责声明：** 本文所涉及的技术仅供安全研究与授权测试使用。未经授权对他人系统进行渗透测试属于违法行为，由此产生的法律后果由行为人自行承担。

---

## 一、编码 vs 加密 vs 哈希

很多初学者把这三者混为一谈，但它们在本质上截然不同：

| 类型 | 是否可逆 | 是否需要密钥 | 典型用途 | 典型例子 |
|------|----------|-------------|----------|----------|
| 编码 | 是 | 否 | 数据传输、格式化 | Base64, Hex |
| 加密 | 是 | 是 | 数据保密 | AES, DES, RSA |
| 哈希 | 否 | 否 | 完整性、口令存储 | MD5, SHA256, bcrypt |

**简单记忆：** 编码是为了"传输"，加密是为了"藏"，哈希是为了"验"。编码只是换一张表来表示数据，不涉及机密；加密必须有密钥才能还原；哈希是单向函数，理论上不可还原。

---

## 二、常见编码格式及识别

### 2.1 Base64

**特征：**
- 字符集：`A-Z a-z 0-9 + /`，以 `=` 或 `==` 填充
- 长度始终是 4 的倍数
- URL Safe 变体使用 `-` 和 `_` 代替 `+` 和 `/`

**样例与识别：**
```
dXNlcm5hbWU6cGFzc3dvcmQ=
aGVsbG8gd29ybGQ=
```
正则：`^[A-Za-z0-9+/]+={0,2}$`

**场景：** HTTP Basic Auth、JWT 载荷段、电子邮件 MIME、Data URI Scheme。

### 2.2 Base32

**特征：**
- 字符集：`A-Z 2-7`（无数字 0/1/8/9），以 `=` 填充
- 长度通常是 8 的倍数

**样例：**
```
JBSWY3DPEHPK3PXP
MFRGGZDFMZTWQ2LKNNWG23Q=
```
正则：`^[A-Z2-7]+=*$`

**场景：** TOTP 密钥（Google Authenticator）、DNS 隧道。

### 2.3 Hex（十六进制）

**特征：**
- 字符集：`0-9 a-f A-F`，长度是 2 的倍数，无填充符

**样例：**
```
48656c6c6f20776f726c64
00112233445566778899aabbccddeeff
```
正则：`^[0-9a-fA-F]+$`

**场景：** 哈希值展示、二进制序列化、SQL 注入 obfuscation、XOR 编码。

---

## 三、常见哈希算法识别

### 3.1 按长度速查

| 算法 | Hex 长度 | 典型样例（输入 "hello"） |
|------|---------|------------------------|
| MD5 | 32 | `5d41402abc4b2a76b9719d911017c592` |
| NTLM | 32 | `066ddf...`（32 hex，仅靠长度与 MD5 无法区分） |
| SHA-1 | 40 | `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d` |
| SHA-224 | 56 | `e4e1b2...` |
| SHA-256 | 64 | `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824` |
| SHA-384 | 96 | |
| SHA-512 | 128 | `9b71d2...` |

**关键规律：** 每一种哈希算法都有固定的十六进制输出长度，这是识别的第一依据。

### 3.2 带前缀的现代哈希

这些算法内嵌盐值和计算轮次，识别时直接看前缀：

```
$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy  # bcrypt
$argon2id$v=19$m=65536,t=3,p=4$salt...hash...                       # Argon2id
$5$rounds=5000$salt$hash...                                          # SHA-256 Crypt
$6$rounds=5000$salt$hash...                                          # SHA-512 Crypt
$pbkdf2-sha256$10000$salt$hash...                                    # PBKDF2-HMAC-SHA256
```

前缀对照：`$2a$/2b$/2y$` = bcrypt，`$5$` = sha256crypt，`$6$` = sha512crypt，`$argon2` = Argon2。

---

## 四、对称加密算法识别

### 4.1 DES / 3DES

- **DES：** 密钥 8 字节（56bit 有效），密文是 8 字节的倍数。2017 年后已全面弃用。
- **3DES：** 密钥 8/16/24 字节，密文外观与 DES 无法直接区分，需上下文判断。

### 4.2 AES

- 分组大小固定 16 字节，密文是 16 字节的倍数
- 常以 `AES-128-CBC`、`AES-256-GCM` 等字样出现在配置或 JWT `alg` 头中
- **CBC 模式：** 前 16 字节通常为 IV，其后为密文
- **GCM 模式：** 密文 = 明文 + 16 字节认证标签
- 实战技巧：Base64 解码后是 16 的倍数但不是 8 的简单倍数 → 大概率 AES

### 4.3 RC4

流密码，密文长度等于明文长度。常见于旧版 TLS、WEP、Office 2003 文档加密。

---

## 五、非对称加密算法识别（RSA / ECC）

**RSA PEM 格式（最常见）：**
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----
```

**识别技巧：**
- 看到 `MII` 开头的 Base64 → 极大概率是 DER 编码的 PKI 材料
- `-----BEGIN` / `-----END` 是 PEM 的盔甲头部
- `ssh-rsa` + Base64 → SSH RSA 公钥
- 密文长度 = 密钥长度（1024/2048/4096 bit），即 128/256/512 字节

**ECC PEM：**
```
-----BEGIN EC PRIVATE KEY-----
-----END EC PRIVATE KEY-----
```
密钥远短于 RSA（256 bit ECC ≈ 3072 bit RSA 安全性）。

---

## 六、通用识别方法论

### 6.1 长度分析法

| 数据长度 | 可能的算法 |
|---------|-----------|
| 32 hex | MD5, NTLM |
| 40 hex | SHA-1, Cisco enable secret 5 |
| 56 hex | SHA-224 |
| 64 hex | SHA-256 |
| 96 hex | SHA-384 |
| 128 hex | SHA-512 |
| Base64 24 字符 | MD5 二进制转 Base64 |
| Base64 + `=` + 长度可变 | 编码数据或密文 |

### 6.2 上下文推断

- **HTTP Header** → Base64 (Basic Auth)、JWT、OAuth token
- **URL 参数** → URL Safe Base64 或 Hex
- **Cookie** → Base64 序列化数据或加密 Cookie
- **数据库 dump** → 对照 Hashcat wiki 判断哈希类型
- **出现 `$` 分隔符** → bcrypt / sha256crypt / sha512crypt / argon2

### 6.3 工具辅助

**CyberChef "Magic" 模式：** 拖入数据后启发式检测自动识别编码和压缩。

**hashid：**
```
hashid '5d41402abc4b2a76b9719d911017c592'
# -> MD5, MD4, NTLM, Domain Cached Credentials...
```

---

## 七、John the Ripper 哈希格式速查

John 使用 `--format=` 指定哈希类型：

| 格式名 | 算法 | 识别特征 |
|--------|------|---------|
| raw-md5 | 纯 MD5 | 32 hex |
| raw-sha1 | 纯 SHA-1 | 40 hex |
| raw-sha256 | 纯 SHA-256 | 64 hex |
| raw-sha512 | 纯 SHA-512 | 128 hex |
| nt | NTLM | 32 hex |
| lm | LM Hash | 32 hex |
| bcrypt | bcrypt | `$2a$` `$2b$` `$2y$` |
| sha512crypt | SHA-512 Crypt | `$6$` |
| sha256crypt | SHA-256 Crypt | `$5$` |
| md5crypt | MD5 Crypt | `$1$` |
| argon2 | Argon2 | `$argon2id$` |
| PBKDF2-HMAC-SHA256 | PBKDF2 | `$pbkdf2-sha256$` |
| KeePass | KeePass 数据库 | `.kdbx` 文件 |
| ZIP | Zip 压缩包 | PKZIP |
| RAR5 | RAR5 压缩包 | |
| 7z | 7-Zip 压缩包 | |
| Office | Office 文档 | `.docx` `.xlsx` |
| PDF | PDF 文件 | `.pdf` |
| bitlocker | BitLocker 磁盘 | |
| ethereum | 以太坊钱包 | `$ethereum$` |

---

## 八、Hashcat 模式号速查

Hashcat 使用 `-m` 指定哈希类型：

| 模式号 | 算法 | 备注 |
|--------|------|------|
| 0 | MD5 | 最常用 |
| 100 | SHA-1 | |
| 1400 | SHA2-256 | |
| 1700 | SHA2-512 | |
| 1000 | NTLM | Windows 本地账户 |
| 3000 | LM | 旧版 Windows |
| 3200 | bcrypt `$2*$` | Cost 可调 |
| 1800 | sha512crypt `$6$` | Linux /etc/shadow |
| 7400 | sha256crypt `$5$` | Linux /etc/shadow |
| 500 | md5crypt `$1$` | 旧版 Linux |
| 13100 | Kerberos TGS-REP | etype 23 |
| 18200 | Kerberos AS-REP | |
| 22000 | WPA-PBKDF2-PMKID+EAPOL | WPA/WPA2 握手 |
| 22001 | WPA-PMKID-PBKDF2 | PMKID |
| 11600 | 7-Zip | |
| 13600 | ZIP2（WinZip） | |
| 13000 | RAR5 | |
| 13721 | VeraCrypt | |
| 13400 | KeePass 1/2 | |
| 5600 | NetNTLMv2 | |
| 5500 | NetNTLMv1 | |
| 7500 | Kerberos AS-REQ Pre-Auth | etype 23 |

> 完整列表见 [Hashcat 官方 wiki](https://hashcat.net/wiki/doku.php?id=example_hashes)。

### 8.1 同一口令不同算法对比

输入 `P@ssw0rd`，不同算法的输出截然不同：

```
MD5:     161ebd7a450ae8a7e79a2e1bf7e3f4b5     (32 hex)
SHA-256: b03d...                              (64 hex)
NTLM:    a029b2...                            (32 hex)
bcrypt:  $2b$12$LJ3m4ys3L...                  (60 char, $前缀)
```

**核心原则：不同算法的哈希长度与结构有明确差异**，抓住这些差异是识别的关键。

---

## 九、实战案例

### 案例 1：Web 前端"加密"

前端 JS 对密码做了如下变换：

```javascript
var enc = btoa(username + ":" + password);
// 产生: dXNlcm5hbWU6cGFzc3dvcmQ=
```

这只是 Base64 **编码**，并非加密。任意工具即可解码，安全意义为零。但某些老旧系统开发者误以为这是加密，测试报告中应明确指出。

### 案例 2：数据库泄露哈希

SQL 注入获取到用户密码字段：

```
$2a$10$dskjf9283hjkdshf92837dhsjkdshf92ehjkdsf87
```

`$2a$` → bcrypt，`10` → 2^10 轮迭代。命令：
```
hashcat -m 3200 hashes.txt wordlist.txt
john --format=bcrypt hashes.txt
```

### 案例 3：WPA 握手

从 `aircrack-ng` 获取到 `.hc22000` 文件：

```
hashcat -m 22000 capture.hc22000 wordlist.txt
```

---

## 十、总结

| 目标 | 工具 | 要点 |
|------|------|------|
| 判断编码类型 | CyberChef Magic | 拖入即分析 |
| 命令行识别哈希 | hashid | 粘贴哈希值 |
| 破解哈希 | Hashcat / John | 按模式号或格式名指定 |
| 解码 | `base64 -d` / CyberChef | 注意填充与字符集 |
| 识别 PEM | `openssl rsa -text -in key.pem` | 看 PEM 头判断算法 |

三条金律：

1. **字符集定编码** —— Base64 / Base32 / Hex 的字符集完全不同
2. **长度定哈希** —— 每一种哈希算法都有固定的十六进制输出长度
3. **上下文定密文** —— 同一长度可能对应多种算法，结合来源信息推断

建议把 Hashcat 模式号表和哈希长度表贴在屏幕旁边，实践时随手翻阅。

---

> **再次重申：** 本文所述技术仅供安全研究、CTF 竞赛及合法授权渗透测试之用。任何未经授权的攻击行为均属违法，请将技术用于正确的方向。
