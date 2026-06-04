---
title: 移动安全：API 接口安全测试
date: 2026-01-05 08:00:00
tags:
  - 渗透测试
  - 移动安全
description: 移动安全：API 接口安全测试——渗透测试实战笔记，含完整攻击链路与防御方案。
categories: 渗透测试
---

## 抓包环境搭建

### Android 7.0+ 系统证书

Android 7+ 默认不信任用户证书，需要将 Burp CA 导入系统证书区：

```bash
# 1. 导出 Burp CA 证书（DER 格式）
# 2. 转换为 PEM: openssl x509 -inform DER -in cacert.der -out cacert.pem
# 3. 计算 hash: openssl x509 -inform PEM -subject_hash_old -in cacert.pem
# 4. 重命名: mv cacert.pem <hash>.0
# 5. adb root → adb remount → adb push <hash>.0 /system/etc/security/cacerts/
# 6. 重启设备
```

### iOS 抓包

```bash
# 1. Burp 设置代理
# 2. iPhone → 设置 → Wi-Fi → HTTP 代理 → 手动
# 3. Safari 访问 http://burpsuite 下载 CA 证书
# 4. 设置 → 通用 → 关于 → 证书信任设置 → 开启
```

---

## 流量分析流程

```mermaid
flowchart LR
    A[设置代理] --> B[绕过 SSL Pinning]
    B --> C[正常操作 App]
    C --> D[Burp 查看所有 API 请求]
    D --> E[导出 API 清单]
    E --> F[逐接口测试]
```

---

## API 测试清单

### 1. 认证与授权

```
- 删除 Authorization 头 → 是否能未授权访问？
- 替换 Token 为其他用户 → 水平越权？
- 普通用户 Token 访问管理接口 → 垂直越权？
- JWT 算法改为 none？
- Token 是否有时效？过期后能否续用？
```

### 2. 输入验证

```
- 所有参数加 ' " < > 测试注入
- 数字参数传入负数、0、极大值
- JSON 数组/对象替代字符串
- 参数缺失 → 后端默认值？
- 额外参数（mass assignment）→ 可修改敏感字段？
```

### 3. 业务逻辑

```
- 订单金额改为负数/0？
- 优惠券可重复使用？
- 跳过支付步骤直接调用成功回调？
- 修改商品 ID 获取非授权商品？
```

### 4. 信息泄露

```
- 响应中的敏感字段（password、secret、internal_ip）
- 错误信息暴露框架版本/数据库类型
- 分页 limit 设为极大值 → 全量数据导出
```

---

## 工具链

| 工具 | 场景 |
|------|------|
| Burp Suite | HTTP/HTTPS 抓包分析 |
| mitmproxy | 命令行 + Python 脚本化抓包 |
| Charles | macOS 常用代理工具 |
| Wireshark | TCP 层分析、非 HTTP 协议 |

---

> 本文仅用于授权安全测试与学习，请勿用于非法用途。
