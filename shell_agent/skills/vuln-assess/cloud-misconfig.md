# 云环境错误配置检查手册

## AWS

### IMDS（实例元数据服务）

```bash
# IMDSv1（无需认证头）
curl -s http://169.254.169.254/latest/meta-data/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
curl -s http://169.254.169.254/latest/user-data/

# IMDSv2（需要 Token）
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s http://169.254.169.254/latest/meta-data/ -H "X-aws-ec2-metadata-token: $TOKEN"

# 获取到的临时凭证可用于：
# - 访问 S3 / DynamoDB / Lambda 等服务
# - 根据 IAM 角色权限进行进一步利用
```

### S3 存储桶

```bash
# 列出公开桶内容
aws s3 ls s3://bucket-name --no-sign-request

# 检查桶策略
aws s3api get-bucket-policy --bucket BUCKET_NAME --no-sign-request

# 检查 ACL
aws s3api get-bucket-acl --bucket BUCKET_NAME --no-sign-request

# 上传测试（检查写权限）
aws s3 cp test.txt s3://bucket-name/test.txt --no-sign-request

# 常见桶名模式
# {company}-backup / {company}-dev / {company}-logs
# {company}-assets / {company}-uploads / {company}-data

# 使用已获取的凭证
export AWS_ACCESS_KEY_ID=xxx
export AWS_SECRET_ACCESS_KEY=xxx
export AWS_SESSION_TOKEN=xxx
aws sts get-caller-identity
aws s3 ls
aws ec2 describe-instances
aws iam list-users
```

### IAM 权限枚举

```bash
# 当前身份
aws sts get-caller-identity

# 权限枚举
aws iam list-attached-user-policies --user-name USERNAME
aws iam list-user-policies --user-name USERNAME
aws iam get-policy-version --policy-arn ARN --version-id v1

# 自动化枚举
# enumerate-iam
python3 enumerate-iam.py --access-key KEY --secret-key SECRET

# Pacu（AWS 利用框架）
pacu
import_keys KEY SECRET
run iam__enum_permissions
run iam__privesc_scan
```

### Lambda 函数

```bash
# 列出函数
aws lambda list-functions

# 获取函数代码（可能包含密钥）
aws lambda get-function --function-name FUNC_NAME

# 获取环境变量
aws lambda get-function-configuration --function-name FUNC_NAME | jq '.Environment.Variables'
```

### EC2 安全组

```bash
# 列出安全组规则
aws ec2 describe-security-groups | jq '.SecurityGroups[] | select(.IpPermissions[].IpRanges[].CidrIp == "0.0.0.0/0")'
# 关注：对公网开放的危险端口（22/3389/445/3306/6379等）
```

---

## Azure

### 元数据服务

```bash
# IMDS
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | jq .

# 获取访问令牌
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq .

# 使用令牌
TOKEN="eyJ..."
curl -sH "Authorization: Bearer $TOKEN" "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

### Blob 存储

```bash
# 匿名访问
curl -s "https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list"

# 枚举存储账户
# 常见命名：{company}storage / {company}blob / {company}data
```

### Azure AD

```bash
# 使用 ROADtools
roadrecon auth -u user@domain.com -p password
roadrecon gather
roadrecon gui

# 使用 AzureAD PowerShell
Connect-AzureAD
Get-AzureADUser -All $true
Get-AzureADGroup -All $true
Get-AzureADApplication -All $true
```

---

## GCP

### 元数据服务

```bash
# 实例元数据
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/project/project-id
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/attributes/

# 获取项目信息
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/project/attributes/
```

### Cloud Storage

```bash
# 匿名访问
curl -s "https://storage.googleapis.com/BUCKET_NAME"
gsutil ls gs://BUCKET_NAME

# 使用凭证
gcloud auth activate-service-account --key-file=creds.json
gsutil ls
gcloud compute instances list
gcloud iam service-accounts list
```

---

## 通用云安全检查

### 凭证泄露检查

```bash
# 环境变量中的密钥
env | grep -iE "key|secret|token|password|credential"

# 配置文件
cat ~/.aws/credentials
cat ~/.azure/accessTokens.json
cat ~/.config/gcloud/credentials.db

# 代码仓库
# 搜索 AWS_ACCESS_KEY / AZURE_CLIENT_SECRET / GOOGLE_APPLICATION_CREDENTIALS
```

### Kubernetes（云托管）

```bash
# 检查 Service Account Token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# 使用 Token 访问 API Server
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces

# 检查权限
kubectl auth can-i --list

# 枚举
kubectl get pods --all-namespaces
kubectl get secrets --all-namespaces
kubectl get configmaps --all-namespaces
```

### 自动化工具

| 工具 | 云平台 | 用途 |
|---|---|---|
| ScoutSuite | AWS/Azure/GCP | 多云安全审计 |
| Prowler | AWS | AWS 安全评估 |
| CloudSploit | AWS/Azure/GCP | 云配置扫描 |
| Pacu | AWS | AWS 漏洞利用框架 |
| ROADtools | Azure AD | Azure AD 枚举 |
| GCPBucketBrute | GCP | GCS 桶枚举 |
| CloudEnum | AWS/Azure/GCP | 云资产枚举 |
