---
title: 代码审计：PHP 审计方法论
date: 2026-02-01 08:00:00
tags:
  - 代码审计
  - 渗透测试
description: 代码审计：PHP 审计方法论——渗透测试实战笔记，含完整攻击链路与防御方案。
categories: 渗透测试
---

## 审计思路

PHP 代码审计的核心是从**用户输入（Source）**追踪到**危险函数（Sink）**：

```
$_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER['REQUEST_URI']/file_get_contents('php://input')
    → 经过过滤/转义（可能被绕过）
    → 到达危险函数
```

---

## 危险函数速查表

| 类型 | 函数 |
|------|------|
| 代码执行 | `eval()` `assert()` `preg_replace('/e')` `create_function()` `call_user_func()` |
| 命令执行 | `system()` `exec()` `shell_exec()` `passthru()` `popen()` `proc_open()` `\`\`(反引号)` |
| 文件读取 | `file_get_contents()` `readfile()` `fopen()` `show_source()` `highlight_file()` |
| 文件包含 | `include()` `require()` `include_once()` `require_once()` |
| 文件写入 | `file_put_contents()` `fwrite()` `move_uploaded_file()` |
| SQL操作 | `mysql_query()` `mysqli_query()` `mssql_query()` `pg_query()` |
| 反序列化 | `unserialize()` |
| SSRF | `curl_exec()` `file_get_contents(url)` `fopen(url)` |
| XSS | `echo` `print` `printf` 直接输出未转义变量 |

---

## Source-Sink 追踪实战

```php
// Source: 用户输入
$id = $_GET['id'];

// 没有过滤 → Sink: SQL注入
$sql = "SELECT * FROM users WHERE id = $id";
mysql_query($sql);  // ← Sink

// Source: 用户输入
$url = $_POST['url'];
// 没有过滤 → Sink: SSRF
$content = file_get_contents($url);  // ← Sink

// Source: 文件上传
$filename = $_FILES['file']['name'];
// 没有过滤 → Sink: 路径遍历+文件写入
move_uploaded_file($_FILES['file']['tmp_name'], '/uploads/' . $filename);
```

---

## 框架审计要点

### ThinkPHP

```
- where() 直接拼接变量 → SQL注入
- field()/order() 用户可控 → SQL注入
- display()/fetch() 模板变量 → 可能SSTI
- unserialize() 用户可控 → 反序列化
```

### Laravel

```
- DB::raw() 拼接用户输入 → SQL注入
- 路由参数未校验 → 越权
- 文件上传未限制类型 → getshell
- debug模式开启 → 信息泄露
```

---

## 自动化工具

```bash
# RIPS（PHP 静态分析）
# Seay 源代码审计系统（国产，适合初学者）
# Fortify / Checkmarx（企业级）
# 手动 grep 永远最可靠
grep -rn "eval\s*(" --include="*.php" .
grep -rn "exec\s*(" --include="*.php" .
grep -rn "unserialize\s*(" --include="*.php" .
grep -rn "\$_GET\|\$_POST\|\$_REQUEST" --include="*.php" .
```

---

## 审计 Checklist

1. 全局搜索危险函数 → 逐个追溯参数来源
2. 检查全局过滤函数（`addslashes` / `htmlspecialchars` / `intval`）是否有绕过
3. 关注文件上传、文件包含、反序列化三个最高危功能
4. 框架自带的 ORM/模板引擎 → 确认是否用了安全API（如 `#{}` vs `${}`）
5. 检查 `@` 错误抑制 → 底下可能有被忽略的注入点

---

> 本文仅用于授权安全测试与学习，请勿用于非法用途。
