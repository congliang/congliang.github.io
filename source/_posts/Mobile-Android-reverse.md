---
title: 移动安全：Android 脱壳与逆向
date: 2025-11-15 08:00:00
tags:
  - 渗透测试
  - 移动安全
categories: 渗透测试
description: Android App 加固检测、Frida 脱壳、Xposed SSL 解绑、Smali 代码修改、Native .so 库逆向分析，以及签名验证绕过。
---

## 加固检测

先判断 App 是否加壳：

```bash
# 工具：ApkScan-PKID、GDA
# 或者直接看 classes.dex 大小 —— 加壳后通常非常小
ls -la app_extracted/classes.dex

# jadx 打开看 —— 如果只有几个壳的类（com.stub.* / com.secneo.*），就是加壳了
```

常见加固厂商：360、腾讯乐固、爱加密、梆梆、阿里聚安全、娜迦。

---

## Frida 脱壳

### 原理

加固 App 运行时，壳会在内存中解密真实 dex → 用 Frida Hook 关键函数把内存中的 dex 导出来。

```javascript
// frida_dex_dump.js
Java.perform(function() {
    var DexFile = Java.use('dalvik.system.DexFile');
    DexFile.loadDex.implementation = function(sourcePathName, outputPathName, flags) {
        console.log('[+] loadDex: ' + sourcePathName);
        return this.loadDex(sourcePathName, outputPathName, flags);
    };
});
```

```bash
frida -U -l frida_dex_dump.js -f com.target.app --no-pause
```

专用工具：**frida-dexdump** 一键脱壳：

```bash
python3 -m frida_dexdump -U -f com.target.app
```

---

## Xposed + TrustMeAlready 绕过 SSL Pinning

```bash
# 1. 安装 Xposed Framework（需要 Root 或 LSPosed）
# 2. 安装 TrustMeAlready 模块
# 3. 勾选目标 App → 重启 → 所有证书绕过
```

优点：不需要写代码，全局生效。缺点：需要 Root/Xposed。

---

## Smali 代码修改

### 场景一：绕过登录验证

反编译后找到登录成功的判断函数，修改 Smali 代码：

```smali
# 原始：if-eqz v0, :fail   # v0=0 时跳到 fail
# 修改：if-nez v0, :fail   # v0≠0 时才跳到 fail（永远不跳到 fail）
```

### 场景二：解锁付费功能

找到 `isVip()` 方法，直接改返回值：

```smali
.method public isVip()Z
    .locals 1
    const/4 v0, 0x1    # 原本是 0x0（false），改为 0x1（true）
    return v0
.end method
```

### 场景三：移除 Root 检测

```smali
# root 检测函数 → 直接 return false
.method public isRooted()Z
    .locals 1
    const/4 v0, 0x0
    return v0
.end method
```

重打包+签名：

```bash
apktool b app_smali -o mod.apk
# 使用 uber-apk-signer 或 jarsigner 签名
java -jar uber-apk-signer.jar --apks mod.apk
```

---

## Native .so 库逆向

Java 层调用了 `System.loadLibrary("native-lib")`，关键逻辑在 `.so` 里：

```bash
# IDA Pro / Ghidra 打开 libnative-lib.so
# 重点：JNI 函数名格式 Java_com_target_app_MainActivity_check
# Frida Hook Native 函数示例
```

```javascript
// Hook Native 函数
var native_check = Module.findExportByName("libnative-lib.so", "Java_com_target_app_MainActivity_check");
Interceptor.attach(native_check, {
    onEnter: function(args) { console.log('[+] check() called'); },
    onLeave: function(retval) {
        console.log('[+] Original return: ' + retval);
        retval.replace(1);  // 强制返回 true
    }
});
```

---

> 本文仅用于授权安全测试与学习，请勿用于非法用途。
