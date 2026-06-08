#!/bin/bash
# ============================================================================
# run-test.sh
#   Client EC2 から Server EC2 へ各サイズのファイルを curl し、NFW 経由で
#   ペイロード末尾のマーカーが検出されるかを段階的に試す。
#   Client EC2 上で実行する想定 (UserData で /opt/run-test.sh として配置済み)。
#
# 使い方:
#   ./run-test.sh <server_private_ip> [sizes...]
#   例: ./run-test.sh 10.0.2.10
#       ./run-test.sh 10.0.2.10 1048576 1310720 1572864   # 1MiB 付近を細かく
#
# 出力後、CloudWatch Logs (/nfw/payload-lab/alert) で CANARY-DETECTED が
# どのサイズまで記録されているかを確認する (scripts/check-alerts.sh)。
# ============================================================================
set -euo pipefail

SERVER="${1:?usage: run-test.sh <server_private_ip> [sizes...]}"
shift || true

if [ "$#" -gt 0 ]; then
  SIZES=("$@")
else
  SIZES=(16384 32768 65536 131072 262144 524288 1048576 1572864 2097152 3145728 4194304)
fi

echo "target server: $SERVER:8080"
echo "----------------------------------------"

# 疎通 (ICMP)
if ping -c 2 -W 2 "$SERVER" >/dev/null 2>&1; then
  echo "ping: OK (ICMP 通過)"
else
  echo "ping: NG (応答なし)"
fi

# 遮断テスト (BLOCKME を含むファイル — drop されるなら curl が失敗するはず)
echo -n "blockme.txt (drop 期待): "
if curl -s -m 10 -o /dev/null "http://$SERVER:8080/blockme.txt"; then
  echo "通過してしまった (要確認)"
else
  echo "遮断された (期待どおり)"
fi

# サイズ別ダウンロード (マーカーは末尾)
echo "----------------------------------------"
for N in "${SIZES[@]}"; do
  RES=$(curl -s -m 30 -o /dev/null -w "%{http_code} size=%{size_download} time=%{time_total}s" \
        "http://$SERVER:8080/payload_${N}.bin" || echo "ERR")
  printf "N=%-9s %s\n" "$N" "$RES"
  sleep 3
done
echo "----------------------------------------"
echo "次に CloudWatch Logs /nfw/payload-lab/alert で CANARY-DETECTED の有無を確認"
