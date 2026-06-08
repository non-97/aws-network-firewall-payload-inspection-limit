#!/bin/bash
# ============================================================================
# gen-payload.sh
#   指定バイト数のファイルを生成し、末尾にマーカー文字列 PAYLOADCANARY を埋め込む。
#   Server EC2 上で実行する想定 (UserData で /opt/payload/gen.sh として配置済み)。
#
# 使い方:
#   ./gen-payload.sh <total_bytes> [output_dir]
#   例: ./gen-payload.sh 1572864            # 1.5MiB のファイルを生成
#       ./gen-payload.sh 1572864 /opt/payload/www
#
# 仕組み:
#   先頭を 'A' で N-13 バイト埋め、最後の 13 バイトをマーカー PAYLOADCANARY にする。
#   N がリアセンブリ深度を超えると「末尾=深度外」となり NFW がマーカーを検出できなくなる。
# ============================================================================
set -euo pipefail

N="${1:?usage: gen-payload.sh <total_bytes> [output_dir]}"
OUT_DIR="${2:-/opt/payload/www}"
MARKER="PAYLOADCANARY"
LEN=${#MARKER}

mkdir -p "$OUT_DIR"
F="${OUT_DIR}/payload_${N}.bin"

head -c "$((N - LEN))" /dev/zero | tr "\0" "A" > "$F"
printf "%s" "$MARKER" >> "$F"

echo "generated $F size=$(stat -c %s "$F") marker_at_tail (offset $((N - LEN)))"
