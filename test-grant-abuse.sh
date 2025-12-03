#!/bin/bash

# KMSグラント悪用検証スクリプト

echo "=== KMSグラント悪用シナリオの検証 ==="
echo ""

# スタック名を取得
STACK_NAME="PublicKmsStack"

# 出力値を取得
echo "1. スタック情報を取得中..."
KEY_ID=$(aws cloudformation describe-stacks --stack-name $STACK_NAME --query "Stacks[0].Outputs[?OutputKey=='VulnerableKeyId'].OutputValue" --output text)
ATTACKER_ROLE=$(aws cloudformation describe-stacks --stack-name $STACK_NAME --query "Stacks[0].Outputs[?OutputKey=='AttackerRoleArn'].OutputValue" --output text)
BUCKET_NAME=$(aws cloudformation describe-stacks --stack-name $STACK_NAME --query "Stacks[0].Outputs[?OutputKey=='SensitiveDataBucketName'].OutputValue" --output text)
LAMBDA_NAME=$(aws cloudformation describe-stacks --stack-name $STACK_NAME --query "Stacks[0].Outputs[?OutputKey=='AttackSimulatorLambdaName'].OutputValue" --output text)

echo "  KMS Key ID: $KEY_ID"
echo "  Attacker Role: $ATTACKER_ROLE"
echo "  Bucket: $BUCKET_NAME"
echo "  Lambda: $LAMBDA_NAME"
echo ""

# シナリオ1: 攻撃者ロールでグラントを作成
echo "2. 【攻撃シナリオ1】攻撃者ロールがグラントを作成..."
CURRENT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
GRANT_ID=$(aws kms create-grant \
  --key-id $KEY_ID \
  --grantee-principal $ATTACKER_ROLE \
  --operations Encrypt Decrypt GenerateDataKey CreateGrant \
  --query GrantId --output text 2>&1)

if [[ $? -eq 0 ]]; then
  echo "  ✓ グラント作成成功: $GRANT_ID"
  echo "  ⚠️  攻撃者が暗号化・復号化権限を取得しました"
else
  echo "  ✗ グラント作成失敗: $GRANT_ID"
fi
echo ""

# シナリオ2: グラントの連鎖作成
echo "3. 【攻撃シナリオ2】グラントを使ってさらにグラントを作成（権限の連鎖）..."
echo "  ⚠️  CreateGrant権限があれば、攻撃者は第三者にも権限を付与可能"
aws kms list-grants --key-id $KEY_ID --query "Grants[?Operations[?contains(@, 'CreateGrant')]]" --output table
echo ""

# シナリオ3: Lambda経由での攻撃シミュレーション
echo "4. 【攻撃シナリオ3】Lambda関数で攻撃をシミュレート..."
RESULT=$(aws lambda invoke --function-name $LAMBDA_NAME --payload '{}' /tmp/lambda-output.json 2>&1)
if [[ $? -eq 0 ]]; then
  echo "  Lambda実行結果:"
  cat /tmp/lambda-output.json | jq '.'
  rm /tmp/lambda-output.json
else
  echo "  ✗ Lambda実行失敗: $RESULT"
fi
echo ""

# 現在のグラント一覧を表示
echo "5. 【監査】現在のグラント一覧:"
aws kms list-grants --key-id $KEY_ID --output table
echo ""

# 推奨される対策
echo "=== 推奨される対策 ==="
echo "1. CreateGrant権限は最小限のプリンシパルにのみ付与"
echo "2. グラントに制約条件（GrantConstraints）を設定"
echo "3. CloudTrailでkms:CreateGrant APIを監視"
echo "4. 定期的にlist-grantsで不要なグラントを確認・削除"
echo "5. KMSキーポリシーで許可する操作を明示的に制限"
echo ""

# クリーンアップオプション
read -p "グラントを削除しますか？ (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  echo "グラントを削除中..."
  aws kms list-grants --key-id $KEY_ID --query "Grants[].GrantId" --output text | \
    xargs -n1 -I {} aws kms revoke-grant --key-id $KEY_ID --grant-id {}
  echo "✓ 削除完了"
fi
