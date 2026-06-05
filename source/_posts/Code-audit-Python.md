---
title: 代码审计：Python审计要点
date: 2026-05-18 06:16:51
tags:
  - 代码审计
  - 渗透测试
description: Python 代码审计要点——os.system/subprocess/eval/pickle/yaml 等危险函数追踪、Django/Flask 框架审计与 SSTI/SSRF 检测。
categories: 渗透测试
---

## 前言

Python 凭借简洁的语法和丰富的生态，已成为 Web 开发、自动化运维等领域的首选语言。然而便利性往往伴随安全隐患——开发者在使用某些内建函数或第三方库时，稍有不慎便会引入严重漏洞。本文从渗透测试视角梳理 Python 代码审计中的常见风险点，给出检测方法与修复建议。

> **免责声明**：本文所述技术仅供安全研究及授权测试使用。未经授权对他人系统实施攻击属违法行为，读者须自行承担一切法律责任。

---

## 一、危险函数速查

### 1.1 命令执行：`os.system()` 与 `subprocess`

`os.system()` 将字符串参数直接传给系统 Shell，参数可控即导致命令注入。`subprocess` 是官方推荐替代方案，但 `shell=True` 时同样危险：

```python
# 危险 — host=; cat /etc/passwd
os.system(f"ping -c 1 {request.args.get('host')}")
subprocess.call(f"grep {user_input} /var/log/app.log", shell=True)

# 安全 — 列表传参 + 关闭 shell
subprocess.call(["grep", user_input, "/var/log/app.log"], shell=False)
```

**审计 grep**：`os.system(`、`os.popen(`、`shell=True`。

### 1.2 代码注入：`eval()` 与 `exec()`

`eval()` 执行单个 Python 表达式并返回值，`exec()` 执行任意代码块。两者均可被利用为 RCE。

```python
# 危险：用户输入直接进入 eval
result = eval(request.form['expression'])
# expression = __import__('os').system('id')

# 危险：exec 同样可被注入
code = request.args.get('code')
exec(code)
```

即使 `eval()` 限制了 `globals`/`locals`（如 `{'__builtins__': {}}`），绕过技巧层出不穷——Python 的自省能力使得沙箱极不可靠。审计时若看到 `eval()`、`exec()`、`compile()` 参数来自用户输入，直接判定为高危。

**审计 grep**：`eval(`、`exec(`、`compile(`、`__import__(`。

### 1.3 反序列化：`pickle.loads()` 与 `yaml.load()`

`pickle` 协议在反序列化时自动调用 `__reduce__()`，可执行任意代码；PyYAML 的 `yaml.load()` 默认构造器可实例化任意对象：

```python
class Evil:
    def __reduce__(self):
        return (os.system, ('id',))

pickle.loads(request.get_data())                # RCE！
config = yaml.load(request.data)               # !!python/object/apply:os.system ['id']
config = yaml.safe_load(request.data)           # 安全替代
```

**审计 grep**：`pickle.loads(`、`yaml.load(`、`yaml.full_load(`、`dill.loads(`。同族危险库：`dill`、`cloudpickle`、`joblib`。

### 1.4 模板注入：`render_template_string()`

Flask 的 `render_template_string()` 是 SSTI 重灾区——危险在于模板字符串本身由用户输入拼接：

```python
# 危险：name 直接拼入模板，可注入 {{ config }} 或 RCE 链
return render_template_string(f'<h1>Hello {name}!</h1>')

# 安全：name 作为变量传入，不参与模板构造
return render_template_string('<h1>Hello {{name}}!</h1>', name=name)
```

**经典 RCE 载荷**：`{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}`、`{{ lipsum.__globals__['os'].popen('id').read() }}`。

**审计 grep**：`render_template_string(`、`Environment().from_string(`。

---

## 二、Web 框架审计

### 2.1 Django

**Raw SQL**：Django ORM 能屏蔽多数注入，但 `raw()`、`extra()`、`RawSQL()` 仍提供裸 SQL 入口：

```python
# 危险
User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{username}'")
# 安全 — 参数化
User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [username])
```

**XSS**：模板中 `|safe` 过滤器、`mark_safe()` 关闭 HTML 转义，审计时确认输入来源。**调试泄露**：`DEBUG=True` + 不当的 `ALLOWED_HOSTS` 导致源码泄露。

**审计 grep**：`.raw(`、`.extra(`、`RawSQL(`、`|safe`、`mark_safe(`。

### 2.2 Flask

**SSTI**：见 1.4 节。额外关注 `Environment().from_string()`。

**Debug Mode RCE**：`app.run(debug=True, host='0.0.0.0')` 时，`/console` 可获取 Shell。**密钥硬编码**：源码中硬编码 `secret_key` 导致 Session/JWT 可被伪造。

---

## 三、SSRF：requests 族库

`requests`、`urllib`、`httpx` 本身不产生漏洞——危险在于服务端将用户输入的 URL 交给它们：

```python
resp = requests.get(request.args.get('url'))   # file:///etc/passwd 或 169.254.169.254
```

**审计 grep**：`requests.get(`、`urllib.request.urlopen(`、`httpx.get(`。每项追问：URL 来自哪里？是否有协议和域名白名单？

**修复**：白名单校验协议与域名；过滤内网 IP 段（`10.0.0.0/8` 等）。

---

## 四、SQL 注入

原生驱动中最常见的注入来自字符串拼接；SQLAlchemy 的 `text()` 同样可被注入：

```python
# 危险 — f-string 拼接
cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
db.session.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))

# 安全 — 参数化
cursor.execute("SELECT * FROM users WHERE name = %s", (username,))
db.session.execute(text("SELECT * FROM users WHERE id = :uid"), {"uid": user_id})
```

**ORDER BY 注入**：这些子句不支持参数化，直接拼接字段名即漏洞，用白名单映射修复。

**审计 grep**：`.execute(f"`、`text(f"`、`.raw(`、`.extra(`。

---

## 五、文件操作漏洞

### 5.1 任意文件读取 / 上传 / Zip Slip

```python
open(request.args.get('file'), 'rb').read()       # 路径穿越：../../etc/passwd
f.save(os.path.join(UPLOAD_FOLDER, filename))     # 上传须用 secure_filename()
z.extractall('/var/app/uploads/')                 # Zip Slip：内部路径穿越
```

要点：`secure_filename()` 是否使用；上传目录是否在 Web 根内；解压前校验路径在目标目录内。

**审计 grep**：`open(`、`Path.read_text(`、`.save(`、`zipfile.ZipFile(`。

---

## 六、依赖与供应链

- 检查 `requirements.txt` / `poetry.lock` 中版本是否锁死（`==`）。
- 运行 `pip-audit` 或 `safety check --full-report` 扫描已知 CVE。
- 关注已弃用包（如 `cPickle` 已迁移至 `pickle`）。

---

## 七、审计速查表

| 类别 | 搜索关键词 | 关注点 |
|------|----------|--------|
| 命令执行 | `os.system(`, `os.popen(`, `shell=True` | 参数是否来自用户输入 |
| 代码注入 | `eval(`, `exec(`, `compile(` | 拼接用户输入 |
| 反序列化 | `pickle.loads(`, `yaml.load(`, `dill.loads(` | 数据源是否可信 |
| SSTI | `render_template_string(`, `from_string(` | 模板含用户输入 |
| SQL 注入 | `.execute(f"`, `.raw(`, `.extra(`, `text(f"` | SQL 中字符串拼接 |
| SSRF | `requests.get(`, `urllib.request.urlopen(` | URL 来自用户且无白名单 |
| 文件操作 | `open(`, `Path.read_text(`, `.save(` | 路径穿越、上传无校验 |
| 密钥泄露 | `secret_key`, `SECRET_KEY`, `password = ` | 硬编码密钥 |

---

## 八、自动化工具

| 工具 | 用途 |
|------|------|
| [Bandit](https://github.com/PyCQA/bandit) | Python AST 级静态分析，扫描常见安全模式 |
| [Semgrep](https://semgrep.dev/) | 模式匹配引擎，社区有大量 Python 规则 |
| [CodeQL](https://codeql.github.com/) | GitHub 语义分析，支持 Python |
| [pip-audit](https://pypi.org/project/pip-audit/) | 依赖漏洞扫描 |

**Bandit 示例**：
```bash
pip install bandit
bandit -r ./src -f html -o report.html
bandit -ll   # 仅输出高危/中危
```

**Semgrep SSTI 检测规则**：
```yaml
rules:
    patterns:
      - pattern: render_template_string("..." + $VAR)
      - pattern-inside: |
          def $FUNC(...):
            ...
            return render_template_string(...)
    message: "Potential SSTI: user input concatenated into template string"
    severity: ERROR
```

---

## 九、结语

Python 代码审计的核心不在背"关键词"，而在于理解**数据流如何从入口流向危险函数**。每次审计都是对"信任边界"的建模——开发者在哪划定代码边界，攻击者就在哪寻找越界的路径。

几条原则：所有用户输入都不可信；Python 沙箱不可靠；不要自己实现加密/过滤/转义；遵循最小权限原则。

希望本文能为你提供一份可操作的 Python 审计速查地图。

---

*本文首发于 [Security Blog](https://example.com)，转载请注明出处。*
