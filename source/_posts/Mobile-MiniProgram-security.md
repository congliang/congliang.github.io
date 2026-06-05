---
title: 移动安全：小程序安全测试
date: 2026-05-07 02:28:17
tags:
  - 渗透测试
  - 移动安全
description: 移动安全：小程序安全测试——渗透测试实战笔记，含完整攻击链路与防御方案。
categories: 渗透测试
---

## 微信小程序反编译

微信小程序的包是 `.wxapkg` 格式：

```bash
# 1. 获取 wxapkg（从手机 /data/data/com.tencent.mm/MicroMsg/.../appbrand/pkg/ 提取）
# 需要 Root 权限

# 2. 使用 wxappUnpacker 反编译
git clone https://github.com/qwerty472123/wxappUnpacker
node wuWxapkg.js app.wxapkg -o output/
```

反编译后得到完整的前端源码（JS + JSON + WXML + WXSS），可直接查看业务逻辑。

---

## 源代码中的敏感信息

```bash
cd output/
# 搜索 API 端点、密钥、Token
grep -r "https\?://" --include="*.js" .
grep -rE "(api_key|secret|token|password|appid|appsecret)" --include="*.js" .
grep -r "internal" --include="*.js" .
```

常见从小程序源码中能找到的东西：
- 未公开的内部 API 地址
- 硬编码的密钥/Token
- 测试环境的域名和接口
- 数据库连接信息
- OSS/S3 的 AccessKey

---

## API 接口测试

拿到 API 列表后，直接在 Burp 里测试：

```bash
# 1. 替掉小程序的环境 → 直接发 HTTP 请求
# 2. 尝试去掉鉴权头（Token/Cookie）→ 看是否还能访问
# 3. 修改用户 ID 参数 → 测越权
# 4. 修改查询参数 → 测 SQL 注入/命令注入
```

核心思路：绕过小程序前端的校验，直接打后端 API。

---

## 支付宝小程序

支付宝小程序使用 `.apkg` 格式，反编译思路类似：

```bash
# 获取 .apkg → 用类似工具解包
# 逻辑代码在 app.js / app-service.js
```

---

## 小程序特有的安全问题

| 问题 | 说明 |
|------|------|
| 前端鉴权 | 小程序端判断用户角色，后端没校验 |
| 敏感信息硬编码 | appSecret/AccessKey 写在前端 JS |
| 隐藏页面访问 | 没有 Tab 但存在的页面 URL |
| WebSocket 泄露 | ws:// 地址暴露内网信息 |
| 二维码劫持 | 小程序码生成逻辑可被操纵 |

---

> 本文仅用于授权安全测试与学习，请勿用于非法用途。
