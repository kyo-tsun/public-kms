#!/bin/bash

# Gitリポジトリの初期化とプッシュ

cd /home/kyonosuke/Cloudbase/public_kms

# 既存のGitリポジトリがあれば削除
rm -rf .git

# 新規初期化
git init

# すべてのファイルを追加
git add .

# コミット
git commit -m "Initial commit: KMS grant abuse testing environment"

# メインブランチに変更
git branch -M main

# リモートリポジトリを追加
git remote add origin https://github.com/kyo-tsun/public-kms.git

# プッシュ
git push -u origin main
