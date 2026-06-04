---
title: SRC 挖洞第一步：信息收集与资产梳理
date: 2024-11-05 08:00:00
updated: 2026-05-25 08:00:00
tags:
  - SRC
  - 信息收集
  - 资产梳理
  - 漏洞挖掘
  - 子域名
  - 指纹识别
categories: 渗透测试
description: SRC 挖洞前置工作全记录。从根域名开始，子域名爆破、证书透明日志、空间搜索引擎、Web 指纹识别、API 接口发现、JS 敏感信息提取、GitHub 泄露监控，一步步把目标资产理清楚。
---

> SRC 挖洞和打靶场最大的区别就是——靶场的攻击面是固定的，SRC 的攻击面要靠你自己找。信息收集做得越细，能摸到的入口就越多。

***

## 信息收集总流程

先把整体思路摆在这里，后面再展开每个环节：

```
                         根域名 target.com
                              │
              ┌───────────────┼───────────────┐
              │               │               │
        被动收集          字典爆破          搜索引擎
     crt.sh/Subfinder   OneForAll/        Google/Bing
     /Amass/CT日志     ksubdomain/         site:*.com
              │          massdns               │
              └───────────────┬───────────────┘
                              │
                      去重 + 存活验证
                    (httpx / httprobe)
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
    DNS解析→IP/C段      指纹识别             空间搜索引擎
    (dnsx)          WhatWeb/httpx/      Fofa/Shodan/ZoomEye
          │         Fofa/Shodan          搜C段/证书/备案
          │                   │                   │
    端口扫描                   │                   │
    Nmap/Naabu                 │                   │
          │                   │                   │
          └───────────────────┼───────────────────┘
                              │
                         目录扫描
                    dirsearch / ffuf
                              │
                    ┌─────────┼─────────┐
                    │                   │
              敏感路径/备份        JS 分析 / API 发现
                              │
          ┌───────────────────┼───────────────────┐
          │                                       │
    GitHub 泄露监控                          资产清单
    (GitDorker/TruffleHog)                  + 优先级排序
                                                   │
                                            开始漏洞挖掘
```

***

## 一、先搞清楚你要什么

### 1.1 信息收集的目标

SRC 挖洞本质上是在目标企业的互联网资产里找脆弱点。所以信息收集就是回答这几个问题：

1. 这家公司有哪些资产暴露在公网上？（域名、IP、APP、小程序...）
2. 每个资产上跑了什么服务？（Web 服务器、中间件、数据库、API...）
3. 这些服务的版本和配置有没有已知漏洞？
4. 有没有敏感信息泄露？（GitHub、配置文件、JS 代码、云存储...）

### 1.2 一条主域名出发，能做到什么程度

从 `target.com` 开始，你能摸出来的东西大致有：

- 子域名（几百到几千个不等）
- 每个子域名的 Web 应用和开放端口
- 每个 Web 应用的技术栈和框架版本
- JS 文件里的隐藏接口和 API
- GitHub 上员工泄露的代码和配置文件
- 搜索引擎、网盘、文库里不小心露出去的东西
- SSL 证书绑定的其他域名
- 组织架构里关联的其他公司和品牌

下面按流程一个一个来。

***

## 二、子域名收集

这是最基础也最核心的一步。SRC 收的域名范围通常有限制，超出主域名范围的漏洞原则上是无效的，所以子域名找得越多，攻击面越大。

### 2.1 证书透明度日志（CT）

一块 SSL 证书里通常绑了多个域名（SAN 字段）。CT 日志会记录所有被签发的证书，同品牌所有域名都能顺着翻出来。

```bash
# crt.sh —— 最常用的 CT 搜索引擎
# 浏览器直接访问：https://crt.sh/?q=%25.target.com

# 命令行批量拉取
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u > ct_subdomains.txt
```

几个 CT 源：

| 平台 | 地址 |
|------|------|
| crt.sh | `https://crt.sh/?q=%25.target.com` |
| Censys | `https://search.censys.io/certificates?q=target.com` |
| Google CT | `https://transparencyreport.google.com/https/certificates` |
| Facebook CT | `https://developers.facebook.com/tools/ct/search/` |

### 2.2 常规子域名爆破

字典爆破是最传统的方式，靠 DNS 解析来判断子域名是否存在。

#### 工具一：OneForAll（推荐，国内项目）

```bash
# 安装
git clone https://github.com/shmilylty/OneForAll.git
cd OneForAll && pip install -r requirements.txt

# 使用（调用了几十个数据源，产出比纯爆破大很多）
python3 oneforall.py --target target.com run
python3 oneforall.py --target target.com --brute True run

# 输出结果在 results/target.com.csv
```

#### 工具二：Subfinder + Amass 组合

```bash
# Subfinder —— 调被动数据源，快
subfinder -d target.com -o subfinder.txt

# Amass —— 被动 + 主动，数据源全，慢
amass enum -passive -d target.com -o amass_passive.txt
amass enum -active -d target.com -o amass_active.txt

# 合并去重
cat subfinder.txt amass_passive.txt | sort -u > subs_all.txt
```

#### 工具三：纯 DNS 字典爆破

```bash
# 用 massdns + 质量好的字典
# 子域名字典推荐：
#   https://github.com/knownsec/ksubdomain（ksubdomain 自带字典）
#   https://github.com/aboul3la/Sublist3r

# 下载个好字典
wget https://raw.githubusercontent.com/aboul3la/Sublist3r/master/subbrute/names.txt

# ksubdomain —— 国内作者写的，速度快，支持 UDP 传输
ksubdomain -d target.com -f names.txt -o ksub_result.txt

# massdns
./bin/massdns -r resolvers.txt -t A -o S names.txt | grep target.com > massdns_result.txt
```

### 2.3 搜索引擎 Hack

Google/Bing/百度也能搜出子域名和更多资产：

```bash
# Google Hacking
site:target.com
site:target.com -www -mail -test -dev
intitle:"target" site:target.com

# 搜子域名
site:*.target.com

# 搜特定路径
inurl:admin site:target.com

# 搜配置文件
inurl:config.php site:target.com
```

**搜索引擎聚合工具：**

```bash
# theHarvester —— 搜邮箱、子域名、IP、URL
theHarvester -d target.com -b google,bing,yahoo,baidu -f harvester_results.html

# 或者用浏览器开这几个搜索引擎手动搜一遍也行
```

### 2.4 子域名收集的坑

1. **泛解析（Wildcard DNS）：** 目标如果配了泛解析，你随便编一个 `abc123xyz.target.com` 都会解析成功。先发包验证，用 `dig abc123xyz.target.com` 看返回 IP 是不是同一个，如果是，做泛解析过滤。
2. **CDN / WAF 前置：** 子域名解析到 CDN IP 不代表没有漏洞，CDN 后面可能藏着真实服务器。后面用空间搜索引擎找真实 IP。
3. **内网域名：** 有些子域名只在内网解析（如 `admin.internal.target.com`），公网 DNS 查不到，但信息泄露（JS、GitHub）可能暴露它们的路径。

### 2.5 子域名二次爆破

第一轮拿到的子域名基本都比较常见。接下来根据已知资产的特征做二次操作：

```bash
# 1. 如果发现存在 test1.target.com，尝试爆破 test2、test3...dev1、uat1...
# 2. 找数字编号规律，写脚本遍历
for i in $(seq 1 200); do
    echo "test${i}.target.com" >> nums_brute.txt
done
ksubdomain -d target.com -f nums_brute.txt -o nums_result.txt

# 3. 根据品牌名 + 常见后缀（shop、pay、api、vip、m、app、h5...）生成字典
```

### 2.6 去重、存活检测、分类

```bash
# 合并且去重所有子域名
cat ct_subdomains.txt subfinder.txt amass_passive.txt ksub_result.txt \
    massdns_result.txt | sort -u | grep -v '\*' > all_subs_raw.txt

# 存活检测：HTTP 80/443 探活
cat all_subs_raw.txt | httpx -ports 80,443,8080,8443 -title -status-code \
    -tech-detect -o httpx_results.txt

# 或者用 httprobe（更轻量）
cat all_subs_raw.txt | httprobe -c 50 -t 3000 > live_subs.txt
```

这样你就有了一份"活的 + 知道是什么"的子域名清单。

***

## 三、IP 资产与端口扫描

### 3.1 DNS 解析到 IP

```bash
# 把域名全部解析成 IP
cat all_subs_raw.txt | dnsx -a -resp | tee dnsx_result.txt

# 提取 C 段（同 C 段可能是同一家公司）
cat dnsx_result.txt | awk '{print $2}' | cut -d '.' -f 1-3 | sort -u > c_segments.txt
```

### 3.2 反向 Whois / 备案查询

```bash
# 查看域名注册人/邮箱，顺藤摸瓜找其他公司
whois target.com | grep -E 'Registrant|Email|Org'

# 国内 ICP 备案查询
# https://beian.miit.gov.cn/ 手动查

# 工商信息 → 控股关系 → 子公司 → 子公司域名，这条路经常能挖出不在范围内的资产
```

### 3.3 空间搜索引擎

Fofa、Shodan、ZoomEye、Censys 各自的特点：

| 引擎 | 优势 | 常用语法 |
|------|------|---------|
| **Fofa** | 国内资产最全 | `domain="target.com"` `cert="target.com"` |
| **Shodan** | 设备/IOT 数据多 | `hostname:target.com` `ssl:target.com` |
| **ZoomEye** | 国内设备覆盖好 | `site:target.com` `cert:"target.com"` |
| **Censys** | 证书链 + 子域名递推 | `services.tls.certificates.leaf_data.subject.common_name:target.com` |

**Fofa 常用查询：**

```bash
# 搜子域名资产
domain="target.com"

# 搜 SSL 证书关联的其他域名
cert="target.com"

# 按 ICP 备案号搜（顺便找到同一备案下的其他域名）
icp="京ICP备XXXXXXXXX号"

# 搜具体应用（找同类目标）
app="泛微-EOffice"
app="致远互联-OA"
```

**Shodan CLI：**

```bash
# 搜索
shodan search "hostname:target.com"
shodan search "ssl:target.com"

# 看 IP 详情
shodan host 1.2.3.4
```

> Fofa 高级会员可以看到更多结果（默认只给 100 条）。如果没会员，用多个关键词组合查询拆开搜。

### 3.4 用 C 段 IP 反查资产

```bash
# 如果某个子域名解析到 1.2.3.4，在空间引擎里查这个 C 段
# 同 C 段其他 IP 上有跑相同业务的很可能是同公司的，即使没解析域名也算有效目标

# Fofa
ip="1.2.3.0/24"

# Shodan
net:1.2.3.0/24
```

***

## 四、Web 应用指纹识别

### 4.1 批量指纹探测

拿到存活子域名后，先搞清楚每个站跑了什么。

```bash
# httpx 可以同时检测状态码、标题、技术栈
cat live_subs.txt | httpx -status-code -title -tech-detect -follow-redirects \
    -o httpx_full.txt

# whatweb 批量
cat live_subs.txt | while read url; do
    whatweb -a 3 --color=never "$url" | tee -a whatweb_results.txt
done
```

### 4.2 针对特定 CMS / 框架

扫出来有什么框架之后，针对性地找对应漏洞：

```bash
# 举例：发现是 Struts2，直接把所有 Struts2 历史漏洞扫一遍
# 发现是 Shiro，跑 Shiro 反序列化 key
# 发现是 Fastjson，尝试各个版本的 payload
# 发现是 Weblogic / JBoss，直接搜已知 RCE
```

### 4.3 WAF 识别

```bash
# wafw00f 识别目标前面挂了什么 WAF
wafw00f http://sub.target.com

# 常见的阿里云 WAF、腾讯云 WAF、CloudFlare、安全狗、D盾，绕过姿势不一样
# 挂 WAF 不代表不能打，优先级放低，先打没 WAF 的
```

***

## 五、目录与敏感路径

### 5.1 目录扫描

```bash
# 用 dirsearch（目前最好用的目录扫工具）
python3 dirsearch.py -u http://sub.target.com \
    -e php,asp,aspx,jsp,html,bak,zip,tar.gz,old,txt \
    -t 5 --delay 0.3 -o dirsearch_results.txt

# ffuf（性能好，适合大字典）
ffuf -u http://sub.target.com/FUZZ \
    -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    -rate 5 -o ffuf_results.json
```

### 5.2 重点关注路径

SRC 挖洞时对某些路径需要特别留意：

| 路径 | 原因 |
|------|------|
| `/swagger-ui.html` | Swagger API 文档 |
| `/api/v1/docs` | API 文档 |
| `/druid/index.html` | Druid 监控页（Spring Boot） |
| `/actuator` | Spring Boot Actuator |
| `/env` | Spring Boot 环境变量 |
| `/.git/config` | Git 泄露 |
| `/phpinfo.php` | PHP 信息 |
| `/console` | Django / Flask 调试控制台 |
| `/admin` `/manage` `/system` | 管理后台 |
| `/backup` `/old` `/test` `/temp` | 备份文件 |
| `/robots.txt` | 可能包含隐藏目录 |
| `/sitemap.xml` | 站点地图 |

### 5.3 备份文件

```bash
# 常见备份后缀
# www.zip, www.tar.gz, web.tar.gz, backup.zip, backup.sql
# target.com.zip, target.com.tar.gz, 根域名作为文件名

# 用 httpx 验证是否存在
echo "http://sub.target.com/www.zip" | httpx -status-code
```

这些备份文件里可能包含源码、数据库配置文件（数据库密码）、甚至整站代码。

***

## 六、JS 文件分析

这是最近几年 SRC 挖洞的一个大金矿。前端打包越来越大，JS 里什么都有。

### 6.1 提取所有 JS 文件

```bash
# 用 katana 爬虫抓取所有 JS 引用
katana -u http://sub.target.com -jc -kf all -d 3 -o katana_urls.txt

# 筛选 JS
cat katana_urls.txt | grep '\.js' | sort -u > js_urls.txt

# 或者用 getJS
getJS --url http://sub.target.com --complete --output js_files/
```

### 6.2 JS 里的敏感信息

```bash
# 用 SecretFinder 扫 JS 里的敏感信息
python3 SecretFinder.py -i js_files/ -o js_secrets.txt

# 或手写一个简单的正则
cat js_files/*.js | grep -iP "(api_key|secret|token|password|endpoint|accesskey|bucket|appid|appkey|authorization)" > js_secrets_manual.txt
```

常见能从 JS 里挖出来的东西：

- 内部 API 接口路径（`/api/internal/user/delete` 这种）
- Access Key / Secret（阿里云 OSS、AWS S3）
- 测试环境的域名（`.dev.target.com`）
- 开发/测试账号
- Weblogic / Swagger 等其他服务的地址
- `sourcemap` 文件（`*.js.map`）可以把混淆代码还原

### 6.3 Sourcemap 还原

```bash
# 很多前端打包会漏 sourcemap，在 js 文件末尾加 .map 试试
# http://sub.target.com/static/app.js → http://sub.target.com/static/app.js.map

# 如果拿到了 sourcemap，用 restore-source-tree 还原项目结构
npx restore-source-tree app.js.map -o source_recovered/
# 然后像看源码一样翻目录
```

### 6.4 JS 里隐藏的路由

```bash
# LinkFinder —— 从 JS 里提取 URL 和路径
python3 linkfinder.py -i js_urls.txt -o linkfinder_results.html
```

提取到的内部路径和 API Endpoint 直接往 Burp 里丢，很多没有鉴权。

***

## 七、GitHub / 开源社区信息泄露

### 7.1 GitHub 监控

```bash
# GitHacker —— GitHub 泄露搜索
# 搜索关键字：target.com + password / secret / config / internal / admin / token

# GitHub Dork 常用语法
"target.com" password OR passwd OR pass
"target.com" secret OR token OR key
"target.com" config OR env OR properties
"target.com" "internal" OR "admin"
"target.com" "jdbc" OR "mysql" OR "redis" OR "mongodb"
"target.com" extension:env
"target.com" extension:properties
"target.com" extension:sql
"target.com" NOT test NOT example NOT demo

# 按组织和仓局搜
org:target
```

### 7.2 定时监控（不要做一次就跑）

```bash
# GitHub 有邮件通知功能，设置后每当有人提交含目标关键字的代码就会推送
# 用 GitDorker 自动化
python3 GitDorker.py -tf tokens.txt -q keywords.txt -o github_results.txt

# 或者用 GitRob
gitrob analyze target --no-expand-orgs
```

> **特别提醒：** GitHub 上搜到的东西，即使是公开仓库，也要确认是不是属于 SRC 收录范围。有些是员工私人 fork 出去忘了设 private，这种也能交，但要注意合规。

### 7.3 其他泄露源

```bash
# 网盘搜（百度云、阿里云盘搜索）
# 文库搜（百度文库、豆丁、道客巴巴——企业内部文档被员工上传）
# 代码分享（Pastebin、Gist）
# Docker Hub（搜索企业镜像，可能包含内网地址和凭据）
# NPM / PyPI（企业私包被误发布到公共源）
```

```bash
# Docker Hub 搜索
# https://hub.docker.com/search?q=target.com
```

***

## 八、API 接口发现与测试

### 8.1 API 从哪里找

- JS 文件里的所有路径（前面六已经搞了）
- Swagger 文档（`/swagger-ui.html`、`/api-docs`、`/v2/api-docs`）
- 抓 App 的流量（手机抓包，能翻出大量 API）
- 小程序反编译（微信开发者工具导入，也能翻出一堆接口）
- 网页的 Network 面板，正常浏览一遍把 XHR 请求全导出来

### 8.2 批量 API 未授权测试

```bash
# 拿到接口列表后
cat api_endpoints.txt | while read url; do
    # 不带 Cookie 尝试访问，看返回什么
    curl -s -o /dev/null -w "%{http_code} %{url_effective}\n" "$url"
done > api_auth_test.txt
```

重点关注返回 200 但不需要 cookie 的接口，这些很可能没有鉴权。

***

## 九、资产梳理与优先级

信息收集到一定程度上数量就上去了。接下来要整理的：

### 9.1 做一张资产清单

我习惯用 Excel 记录，字段大概这样：

| 序号 | 域名 | IP | 端口 | 状态码 | 标题 | 指纹/框架 | WAF | 备注 |
|------|------|----|------|--------|------|----------|-----|------|
| 1 | www.target.com | 1.2.3.4 | 443 | 200 | 官网首页 | Nginx + Vue | 阿里 WAF | |
| 2 | api.target.com | 1.2.3.5 | 8443 | 200 | - | Spring Boot | 无 | Swagger 泄露 |

### 9.2 优先级排序

不是所有资产都一样重要，排个序：

1. **高危优先：** 没有 WAF + 有已知漏洞版本的 CMS/框架（比如老 Weblogic → 直接打）
2. **敏感功能优先：** 登录、注册、支付、订单、API、后台入口
3. **边缘服务：** 测试环境、废弃站点、旧版系统（这些往往是最容易有漏洞的）
4. **静态页面：** 纯展示页，优先级放最低

### 9.3 信息收集自动化脚本框架

实际挖的时候可以把上面的流程串起来：

```bash
#!/bin/bash
# 一个简化的 SRC 资产收集骨架
DOMAIN=$1
OUTDIR="recon_${DOMAIN}"

mkdir -p $OUTDIR

echo "[1/7] 子域名收集（被动）"
subfinder -d $DOMAIN -o $OUTDIR/subs_passive.txt
curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" | jq -r '.[].name_value' | sort -u >> $OUTDIR/subs_crt.txt

echo "[2/7] 合并去重"
cat $OUTDIR/subs_*.txt | sort -u | grep -v '\*' > $OUTDIR/subs_all.txt

echo "[3/7] 存活探测"
cat $OUTDIR/subs_all.txt | httpx -ports 80,443,8080,8443 -title -status-code -o $OUTDIR/subs_live.txt

echo "[4/7] 指纹识别"
cat $OUTDIR/subs_all.txt | grep -E '^https?://' | httpx -tech-detect -o $OUTDIR/subs_tech.txt

echo "[5/7] 敏感文件探测"
cat $OUTDIR/subs_all.txt | grep -E '^https?://' | while read url; do
    # 只看几个最高价值的
    for path in "/swagger-ui.html" "/actuator" "/druid/index.html" "/.env" "/phpinfo.php"; do
        code=$(curl -s -o /dev/null -w "%{http_code}" "${url}${path}")
        if [ "$code" = "200" ] || [ "$code" = "302" ]; then
            echo "[!] ${url}${path} -> $code" | tee -a $OUTDIR/sensitive_hits.txt
        fi
    done
done

echo "[6/7] 端口扫描（只取常见端口）"
cat $OUTDIR/subs_all.txt | dnsx -a | awk '{print $2}' | sort -u | \
    naabu -p 80,443,8080,8443,3306,6379,27017,22,21 -rate 100 -o $OUTDIR/ports_open.txt

echo "[7/7] 汇总"
wc -l $OUTDIR/*.txt
echo "Done. 结果在 $OUTDIR/"
```

> ⚠️ 这个脚本是给你自己用的骨架，记得根据目标范围和网络环境调整速率。商业项目不要随便全自动化扫，SRC 也要看平台规则——有些平台不允许大规模扫描。

---

## 十、信息收集的实战习惯

最后说几个自己积累下来的习惯：

1. **不要只做一次。** 信息收集是持续的事情。第一轮拿到的资产打完漏洞之后，过两周重新做一轮，新上线的服务、新绑定的子域名、新提交的代码泄露都可能带出新的入口。
2. **Goby 可以帮你快速过一遍。** 把子域名全部导入 Goby，它自动扫描端口 + 服务 + 漏洞，效率比手搓高很多。
3. **JS 分析要养成肌肉记忆。** 每个站先翻 Network → JS → 搜 `api` / `secret` / `token` / `password`。三分钟的事，收益很高。
4. **做好笔记。** 每个目标单独一个文件夹，每次收集到的资产存好。同一个目标挖久了，积累的资产信息就是你的核心竞争力。
5. **收集完先看一遍有没有眼熟的。** Shiro、Fastjson、Log4j、Spring Boot Actuator、Swagger、Druid、Nacos——这些都是高危关键词，看到了优先打。
6. **看文档和帮助页。** Swagger 和 API 文档是信息泄露的重灾区——接口参数、响应格式、鉴权方式写得很清楚，不用猜。
7. **Goby 扫子域名资产的时候勾上漏洞扫描。** 它自带的 POC 库对常见的 Nday（Shiro、Fastjson、Weblogic）检测准确率不错，能帮你直接筛出高危目标。

---

> 本文仅用于授权安全测试参考。信息收集的边界感很重要——先确认 SRC 的收录范围和规则，不要超出范围操作。
