import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as s3deploy from 'aws-cdk-lib/aws-s3-deployment';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as iam from 'aws-cdk-lib/aws-iam';

export class PublicKmsStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // 許可するAWSアカウントIDのパラメータ
    const allowedAccountId = new cdk.CfnParameter(this, 'AllowedAccountId', {
      type: 'String',
      description: 'AWS Account ID to grant access to the KMS key and S3 bucket',
      constraintDescription: 'Must be a valid 12-digit AWS Account ID'
    });

    // KMSキーを作成
    const key = new kms.Key(this, 'public-kms-key', {
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      description: 'KMS key vulnerable to grant abuse',
    });

    // 攻撃者ロール
    const attackerRole = new iam.Role(this, 'attacker-role', {
      assumedBy: new iam.AccountPrincipal(allowedAccountId.valueAsString),
      roleName: 'KmsGrantAttackerRole',
    });

    // 攻撃者にグラント作成権限を付与（脆弱性）
    key.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [attackerRole],
      actions: ['kms:CreateGrant', 'kms:ListGrants', 'kms:RevokeGrant', 'kms:DescribeKey'],
      resources: ['*'],
    }));

    // S3バケットを作成
    const bucket = new s3.Bucket(this, 'public-kms-bucket', {
      publicReadAccess: false,
      enforceSSL: true,
      versioned: true,

      // 作成したキーで暗号化
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: key
    });

    // 特定のアカウントにS3アクセスを許可
    bucket.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.AccountPrincipal(allowedAccountId.valueAsString)],
      actions: ['s3:GetObject', 's3:ListBucket'],
      resources: [bucket.bucketArn, bucket.arnForObjects('*')],
    }));

    // S3バケットにassets配下をデプロイ
    new s3deploy.BucketDeployment(this, 'deployAssets', {
      sources: [
        s3deploy.Source.asset('./assets/'),
      ],
      destinationBucket: bucket,
    });

    // 出力
    new cdk.CfnOutput(this, 'KeyArn', {
      value: key.keyArn,
      description: 'KMS Key ARN',
    });

    new cdk.CfnOutput(this, 'BucketName', {
      value: bucket.bucketName,
      description: 'S3 Bucket Name',
    });

    new cdk.CfnOutput(this, 'AttackerRoleArn', {
      value: attackerRole.roleArn,
      description: 'Attacker Role ARN',
    });

    new cdk.CfnOutput(this, 'AssumeRoleCommand', {
      value: `aws sts assume-role --role-arn ${attackerRole.roleArn} --role-session-name attacker`,
      description: 'Command to assume the attacker role',
    });
  }
}