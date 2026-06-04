---
title: 代码审计：Node.js审计要点
date: 2026-03-15 08:00:00
tags:
  - 代码审计
  - 渗透测试
categories: 渗透测试
cover: /img/nodejs-audit-cover.png
---

## 前言

Node.js 凭借事件驱动、非阻塞 I/O 在后端领域占据重要地位。然而 JavaScript 的动态特性与庞大的 NPM 生态，使安全审计面临独特挑战。本文聚焦六大核心风险点，逐一剖析漏洞原理、审计方法与修复建议。

> **免责声明**：本文所述技术仅供安全研究和授权测试使用，请勿用于非法用途，违者后果自负。

---

## 一、危险函数调用

Node.js 核心模块中存在多个可将字符串解析为可执行代码的 API，审计时应重点排查。

### 1.1 `eval()`

全局 `eval()` 会直接执行传入的 JavaScript 字符串，无任何防护。

```javascript
// 危险：用户输入直接拼入 eval
app.post('/calc', (req, res) => {
  res.json({ result: eval(req.body.expr) });
  // payload: require('child_process').execSync('whoami').toString()
});
```

审计要点：全局搜索 `eval(`，检查参数是否包含 `req.` 来源数据。

### 1.2 `child_process.exec()` 与 `spawn()`

`exec()` 在 shell 中执行命令字符串，拼接外部输入即产生命令注入。`spawn()` 当 `options.shell` 为 `true` 时同样危险。

```javascript
// 危险：ping 功能拼接用户输入
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
  exec(`ping -c 4 ${req.query.host}`, (err, stdout) => {
    res.send(`<pre>${stdout}</pre>`);
  });
});
// 请求 /ping?host=127.0.0.1;cat /etc/passwd
```

审计要点：搜索 `exec(`、`execSync(`、`spawn(`，核实命令字符串是否包含外部变量。优先使用 `execFile()` 或以数组参数方式调用 `spawn()`。

### 1.3 `vm` 模块沙箱逃逸

`vm.runInNewContext()` 与 `vm.runInThisContext()` 虽提供沙箱，但历史上存在大量逃逸漏洞。

```javascript
// 危险：服务端沙箱执行用户代码
const vm = require('vm');
app.post('/sandbox', (req, res) => {
  vm.runInNewContext(req.body.code, vm.createContext({}));
});
// 逃逸 payload：
// this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString()
```

审计要点：非必要不应将用户代码交给 `vm` 模块。如需隔离执行，使用 `isolated-vm`。

### 1.4 动态 `require()`

拼接模块路径可导致路径穿越或加载恶意包。

```javascript
// 危险：动态加载路由
const handler = require(`./routes/${req.query.module}`); // 路径穿越 ../../evil
const mod = require(req.body.pkg);                         // 加载任意包
```

审计要点：`require()` 参数应为静态字面量或强约束白名单。

---

## 二、原型链污染（Prototype Pollution）

原型链污染是 JavaScript 特有的漏洞——在对象属性合并时未过滤 `__proto__` 和 `constructor.prototype` 键，导致攻击者污染 `Object.prototype`。

### 2.1 漏洞原理

```javascript
// 攻击者提交 JSON payload
const malicious = JSON.parse('{"__proto__": {"isAdmin": true}}');

function merge(dst, src) {
  for (let key in src) {
    if (typeof src[key] === 'object' && src[key] !== null) {
      if (!dst[key]) dst[key] = {};
      merge(dst[key], src[key]);
    } else { dst[key] = src[key]; }
  }
}
merge({}, malicious);
console.log({}.isAdmin);  // true —— 全局污染生效
```

### 2.2 危险库与版本

| 包名 | 受影响版本 | 修复版本 |
|------|-----------|----------|
| lodash (merge/defaultsDeep) | < 4.17.12 | >= 4.17.12 |
| Hoek.merge | < 4.2.1 / 5.0.3 | 升级 |
| dot-prop | < 5.1.1 | >= 5.1.1 |
| merge (npm 包) | < 2.1.1 | >= 2.1.1 |

```javascript
_.defaultsDeep({}, JSON.parse('{"__proto__": {"polluted": true}}'));
_.merge({}, JSON.parse('{"constructor": {"prototype": {"polluted": true}}}'));
```

### 2.3 审计与修复

- 搜索 `req.body`、`req.query` 是否流入 `merge`/`extend`/`Object.assign` 操作。
- 修复：使用 `Object.create(null)` 创建无原型对象；合并时过滤 `__proto__` 键；必要时 `Object.freeze(Object.prototype)`；升级受影响包至安全版本。

---

## 三、反序列化漏洞

### 3.1 `node-serialize`

该包的 `unserialize()` 使用 `eval()` 执行 `_$$ND_FUNC$$_` 标记的函数体，可直接 RCE。

```javascript
const serialize = require('node-serialize');
app.post('/profile', (req, res) => {
  res.json(serialize.unserialize(req.body.data));
});
// payload:
// {"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('whoami')}()"}
```

### 3.2 `js-yaml` 不安全加载

`load()` 默认支持 `!!js/function` 标签执行 JavaScript。应改用 `safeLoad()` 或 `load(str, { schema: JSON_SCHEMA })`。

```yaml
# yaml.load() 的恶意 payload：
!!js/function > require('child_process').execSync('whoami')
```

### 3.3 其他风险包

`cryo`、`funcster`、`serialize-to-js` 的 `unserialize` 方法同样调用 `eval`。审计时搜索 `unserialize`、`deserialize`、`fromString` 等关键字，优先使用纯数据序列化方案（`JSON.parse`）。

---

## 四、NoSQL 注入（MongoDB）

MongoDB 使用 BSON 查询语法，用户输入直接作为查询对象时，字符串匹配可被转换为逻辑操作符注入。

### 4.1 认证绕过

```javascript
// 危险：直接使用用户输入构建查询
const user = await User.findOne({ username: req.body.username, password: req.body.password });

// 攻击者发送 JSON：
// {"username": {"$ne": ""}, "password": {"$ne": ""}}
// 构造查询 { username: { $ne: "" }, password: { $ne: "" } } —— 匹配任意用户，绕过认证
```

### 4.2 `$regex` 盲注与 `$where`

```javascript
// $regex 逐字符爆破密码
{"username": "admin", "password": {"$regex": "^a"}}  // 若登录成功则密码以 a 开头

// $where 嵌入 JavaScript 表达式（风险最高）
const users = await User.find({ $where: `this.username == '${req.query.name}'` });
// payload: admin'; return 1==1;//
```

### 4.3 审计与修复

- 搜索 `.find(`、`.findOne(`、`.update(`、`.deleteOne(` 是否正确校验 `req.body` 中参数类型。
- 修复：使用 `mongo-sanitize` / `express-mongo-sanitize` 过滤 `$` 开头的键；对参数做 `typeof x === 'string'` 校验；利用 Mongoose Schema type 约束拒绝对象类型输入。

---

## 五、服务端模板注入（SSTI）

将用户输入直接拼入模板引擎的模板字符串或数据上下文，可导致任意代码执行。

### 5.1 EJS

```javascript
const ejs = require('ejs');
const html = ejs.render(`<h1>欢迎，<%= ${req.query.name} %></h1>`);
// payload: ?name=global.process.mainModule.require('child_process').execSync('whoami')
```

### 5.2 Pug

```javascript
const pug = require('pug');
const html = pug.compile(req.body.template)();
// payload: #{global.process.mainModule.require('child_process').execSync('whoami')}
```

### 5.3 Handlebars

Handlebars 本身安全度较高，但若 `lookup` helper 开启，可借助 `this.constructor.constructor` 链逃逸：

```javascript
const template = Handlebars.compile(`<body class="${req.query.theme}">`);
// payload 借助 string.sub.constructor 链获取 Function，构造 RCE
```

### 5.4 审计要点

- 搜索 `.render(`、`.compile(`，判断模板内容或数据对象是否受外部控制。
- 修复：避免将用户输入拼入模板字符串；若需用户自定义模板，使用无逻辑插值引擎（Mustache）；Handlebars 启用 `knownHelpersOnly` 模式。

---

## 六、JWT 安全风险

### 6.1 "none" 算法攻击

JWT 标准允许 `alg: "none"` 表示不签名。若 `jsonwebtoken.verify()` 未显式限制 `algorithms`，默认接受该算法。

```javascript
// 危险：未指定 algorithms
const decoded = jwt.verify(token, 'secret');

// 攻击者构造：
// Header: {"alg": "none", "typ": "JWT"}
// Payload: {"user": "admin"}
// 签名部分留空，token 形如 eyJ...In0.eyJ...fQ.
```

修复：

```javascript
jwt.verify(token, 'secret', { algorithms: ['HS256'] });
```

### 6.2 RC256/HS256 算法混淆

服务端使用 RSA 公钥验证时，若同时接受 HS256，攻击者用公钥作为 HMAC 密钥伪造 token。

```javascript
// 攻击流程：获取 publicKey → 以 publicKey 为密钥、HS256 签发恶意 token
// 服务端验证时：jwt.verify(token, publicKey) —— 公钥被当作 HMAC 密钥，签名验证通过
```

修复：显式指定 `{ algorithms: ['RS256'] }`，避免 HS 与 RS 算法混用。

### 6.3 其他审计要点

- **弱密钥**：HS256 密钥长度不低于 256 位，禁止使用 `secret`、`123456` 等。
- **`kid` 注入**：JWT Header 中 `kid` 若被用于文件路径或 SQL 拼接，可导致路径穿越或注入。
- **`jku`/`jwk` 注入**：若信任 Header 内嵌的 `jku` 或 `jwk`，攻击者可自建密钥对签发 token。
- **过期校验**：确认 `exp`、`nbf` 声明被正确校验，并实现 token 吊销机制（黑名单/版本号）。
- **`aud` 校验**：未校验 audience 可导致 token 跨系统复用。

---

## 七、综合审计 Checklist

| # | 检查项 | 搜索关键词 |
|---|--------|-----------|
| 1 | 动态代码执行 | `eval(` `new Function(` `setTimeout(`(字符串) |
| 2 | 命令执行 | `exec(` `spawn(` `child_process` |
| 3 | vm 模块执行用户代码 | `vm.runIn` `vm.createContext` |
| 4 | 动态 require | `require(` + 变量参数 |
| 5 | 不安全对象合并 | `merge(` `_.merge` `_.defaultsDeep` |
| 6 | 反序列化漏洞 | `unserialize` `deserialize` `js-yaml.load` |
| 7 | NoSQL 操作符注入 | `.find(` `.findOne(` 参数类型未校验 |
| 8 | 模板注入 | `ejs.render` `pug.compile` `Handlebars.compile` |
| 9 | JWT 校验缺失 | `.verify(` 未限定 `algorithms` |
| 10 | 依赖包安全 | `npm audit` / `snyk` / `retire.js` |

---

## 八、总结

Node.js 代码审计需兼顾语言特性（原型链、动态类型）与生态安全（NPM 供应链）。核心思路：

1. **追踪污点**：所有 `req.*` 来源视为不可信输入，跟踪其流向判断是否进入 sink（eval、exec、模板渲染等）。
2. **强制类型约束**：API 边界对参数做严格 `typeof` + 白名单校验，将攻击面缩小至可控范围。
3. **最小权限与纵深防御**：容器化用非 root 用户；依赖锁版本 + `npm audit`；WAF 拦截特征 payload。
4. **依赖持续监控**：即使业务代码通过审计，依赖树中仍可能藏有已知 CVE，建议结合 `npm audit --audit-level=high` 与 Dependabot / Snyk 持续跟踪。

---

*本文完成于 2026 年 3 月，部分漏洞细节可能随包版本升级而变化，请以最新文档为准。*
