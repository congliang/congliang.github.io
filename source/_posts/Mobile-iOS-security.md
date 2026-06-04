---
title: 移动安全：iOS APP 安全测试
date: 2025-12-01 08:00:00
tags:
  - 渗透测试
  - 移动安全
description: 移动安全：iOS APP 安全测试——渗透测试实战笔记，含完整攻击链路与防御方案。
categories: 渗透测试
---

## 环境准备

| 工具 | 用途 |
|------|------|
| checkra1n / unc0ver | 越狱 |
| Cydia / Sileo | 包管理器（安装工具） |
| OpenSSH | SSH 连接 iPhone |
| Frida + objection | 动态插桩 |
| Hopper / IDA | 二进制逆向 |
| Burp Suite | 流量抓取 |

```bash
# 基础连接
ssh root@<iPhone_IP>
# 默认密码：alpine（务必修改）

# 安装 Frida Server
# Cydia → 添加源 https://build.frida.re → 安装 Frida
frida-ps -U    # 验证连接
```

---

## IPA 分析

IPA 即 iOS App 包，本质是 ZIP：

```bash
unzip app.ipa -d app_extracted/
# 关键文件：
#   Info.plist      — 应用配置
#   Payload/*.app/  — 二进制 + 资源
#   Frameworks/     — 嵌入的动态库
```

**二进制分析：**

```bash
# 查看 Mach-O 信息
otool -L Payload/App.app/App    # 依赖库
nm Payload/App.app/App          # 符号表
strings Payload/App.app/App     # 字符串搜索
```

---

## Info.plist 安全检查

```xml
<!-- 检查以下高风险配置 -->

<!-- 1. ATS（App Transport Security）→ 是否允许 HTTP -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>   <!-- ⚠️ 所有 HTTPS → HTTP 降级 -->
</dict>

<!-- 2. 允许任意 URL Scheme -->
<key>CFBundleURLTypes</key>  <!-- 检查 URL 处理逻辑 -->

<!-- 3. UIFileSharingEnabled → 文件共享 -->
<key>UIFileSharingEnabled</key>
<true/>  <!-- ⚠️ iTunes 可访问沙盒文件 -->
```

---

## SSL Pinning 绕过

**方法一：objection 一行绕过**

```bash
objection -g com.target.app explore
ios sslpinning disable
```

**方法二：Frida 脚本**

```javascript
// 绕过 AFNetworking / Alamofire / NSURLSession 的 SSL Pinning
var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
Interceptor.attach(SecTrustEvaluate, {
    onLeave: function(retval) { retval.replace(0); }
});
```

**方法三：SSL Kill Switch 2 (Cydia 插件)**

安装后全局绕过。

---

## Keychain 数据访问

Keychain 是 iOS 安全存储，Frida 可 Hook 读取：

```javascript
var SecItemCopyMatching = Module.findExportByName("Security", "SecItemCopyMatching");
Interceptor.attach(SecItemCopyMatching, {
    onEnter: function(args) { console.log('[+] Keychain query: ' + ObjC.Object(args[0])); },
    onLeave: function(retval) { console.log('[+] Result: ' + new ObjC.Object(retval)); }
});
```

---

## 常见漏洞

1. **不安全的本地存储** → NSUserDefaults/Realm/CoreData 明文存储敏感信息
2. **URL Scheme 劫持** → 其他 App 注册相同 Scheme 截获回调
3. **越狱检测可绕过** → Frida Hook 检测函数返回 false
4. **后台截屏泄露** → 多任务切换时 App 快照可能暴露敏感信息
5. **Pasteboard 泄露** → UIPasteboard 复制内容全局可读取

---

> 本文仅用于授权安全测试与学习，请勿用于非法用途。
