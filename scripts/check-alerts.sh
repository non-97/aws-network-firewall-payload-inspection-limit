#!/bin/bash
# ============================================================================
# check-alerts.sh
#   NFW の ALERT ログと FLOW ログを flow_id で結合し、「フロー単位 (= 1 curl)」に
#   集約して時系列で表示する。ローカル PC で awsume 認証後に実行する想定。
#
# 3 つの数字を 1 行に並べる:
#   SIZE     : ALERTログ event.http.url ("/payload_<N>.bin") から逆算した要求サイズ
#   WIRE     : FLOWログ event.netflow.bytes。実際にワイヤを流れた総バイト (ヘッダ込み)
#   HTTPLEN  : ALERTログ event.http.length。HTTPボディとして検査できたバイト (深度)
#   CANARY(raw): sid:1000001 生 content/tcp の末尾マーカー検出 (実測では深度に縛られない)
#   HTTPBODY : sid:1000004 http.response_body のマーカー検出 (HTTP層の深度に縛られる想定)
#   さらに DEPTH (深度到達) / DROP を表示。
#
#   意図(SIZE) -> 実通信(WIRE) -> 検査範囲(HTTPLEN) の流れが 1 表で見える。
#   ALERT と FLOW は共通の flow_id で結合する。
#
# 使い方:
#   ./check-alerts.sh [minutes] [tail_count]
#   例: ./check-alerts.sh 8 8
#
#   絶対時刻で範囲指定 (過去の特定バッチを切り出す):
#     START_ISO=2026-06-08T04:09:00Z END_ISO=2026-06-08T04:11:00Z ./check-alerts.sh
#   (START_ISO 指定時は minutes より優先。END_ISO 省略時は現在まで)
#
#   注意: netflow はフロー終了後に遅れて記録されるため、FLOW 側のクエリ窓は
#   自動的に前後に広げている (start-60s, end+300s)。直近実行では netflow 反映に
#   ~90 秒かかることがある。
# ============================================================================
set -euo pipefail

MINUTES="${1:-10}"
TAIL_COUNT="${2:-0}"                            # 0 = 全件
REGION="${AWS_REGION:-ap-northeast-1}"          # スタックは東京にデプロイ
ALERT_LOG_GROUP="/nfw/payload-lab/alert"
FLOW_LOG_GROUP="/nfw/payload-lab/flow"

# ISO8601 -> epoch ミリ秒 (macOS/Linux 両対応のため python で変換)
iso_to_ms() {
  python3 -c "import datetime,sys; print(int(datetime.datetime.fromisoformat(sys.argv[1].replace('Z','+00:00')).timestamp())*1000)" "$1"
}

if [ -n "${START_ISO:-}" ]; then
  START=$(iso_to_ms "$START_ISO")
else
  START=$(($(date +%s) - MINUTES * 60))000
fi

if [ -n "${END_ISO:-}" ]; then
  END=$(iso_to_ms "$END_ISO")
else
  END=$(($(date +%s)))000
fi

# FLOW は遅延記録されるので窓を広げる
FLOW_START=$((START - 60000))
FLOW_END=$((END + 300000))

ALERT_FILE=$(mktemp)
FLOW_FILE=$(mktemp)
trap 'rm -f "$ALERT_FILE" "$FLOW_FILE"' EXIT

aws logs filter-log-events \
  --region "$REGION" --log-group-name "$ALERT_LOG_GROUP" \
  --start-time "$START" --end-time "$END" \
  --query 'events[].message' --output text > "$ALERT_FILE"

aws logs filter-log-events \
  --region "$REGION" --log-group-name "$FLOW_LOG_GROUP" \
  --start-time "$FLOW_START" --end-time "$FLOW_END" \
  --query 'events[].message' --output text > "$FLOW_FILE"

TAIL_COUNT="$TAIL_COUNT" ALERT_FILE="$ALERT_FILE" FLOW_FILE="$FLOW_FILE" python3 -c '
import sys, json, os, re

tail_count = int(os.environ.get("TAIL_COUNT", "0"))

def load(path):
    out = []
    if not path or not os.path.exists(path):
        return out
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            for token in line.split("\t"):
                token = token.strip()
                if not token:
                    continue
                try:
                    out.append(json.loads(token))
                except json.JSONDecodeError:
                    continue
    return out

# --- FLOW ログ: flow_id -> ワイヤバイト (大きい方=ダウンロード方向) ---
wire = {}
for ev in load(os.environ.get("FLOW_FILE", "")):
    f = ev.get("event", {})
    if f.get("event_type") != "netflow":
        continue
    fid = f.get("flow_id")
    b = f.get("netflow", {}).get("bytes")
    if fid is None or not isinstance(b, int):
        continue
    wire[fid] = max(wire.get(fid, 0), b)

# --- ALERT ログ: flow_id 単位に集約 ---
flows = {}
for ev in load(os.environ["ALERT_FILE"]):
    f = ev.get("event", {})
    if f.get("event_type") != "alert":
        continue
    fid = f.get("flow_id")
    sig = f.get("alert", {}).get("signature", "?")
    ts = f.get("timestamp", "?")
    http = f.get("http", {})
    m = re.search(r"payload_(\d+)\.bin", http.get("url", ""))
    size = int(m.group(1)) if m else None
    httplen = http.get("length")
    key = fid if fid is not None else (f.get("src_ip"), f.get("src_port"), f.get("dest_ip"), f.get("dest_port"))
    rec = flows.setdefault(key, {"ts": ts, "sigs": set(), "size": None, "httplen": None,
                                 "src": "?", "dst": "?", "fid": fid})
    if ts < rec["ts"]:
        rec["ts"] = ts
    rec["sigs"].add(sig)
    if size is not None:
        rec["size"] = size
    if isinstance(httplen, int):
        rec["httplen"] = httplen if rec["httplen"] is None else max(rec["httplen"], httplen)
    rec["src"] = "%s:%s" % (f.get("src_ip"), f.get("src_port"))
    rec["dst"] = "%s:%s" % (f.get("dest_ip"), f.get("dest_port"))

ordered = sorted(flows.items(), key=lambda kv: kv[1]["ts"])
if tail_count > 0:
    ordered = ordered[-tail_count:]

n_canary = n_depth = 0
for key, rec in ordered:
    sigs = rec["sigs"]
    canary  = "yes" if "CANARY-DETECTED" in sigs else "no "
    hbody   = "yes" if "CANARY-HTTP-BODY" in sigs else "no "
    depth   = "yes" if "REASSEMBLY-DEPTH-REACHED" in sigs else "no "
    drop    = " DROP" if "BLOCKME-DROPPED" in sigs else ""
    size = rec["size"] if rec["size"] is not None else "-"
    w = wire.get(rec["fid"], "-")
    httplen = rec["httplen"] if rec["httplen"] is not None else "-"
    if canary.strip() == "yes": n_canary += 1
    if depth.strip() == "yes":  n_depth += 1
    print("%s  %-21s -> %-21s  SIZE=%-10s WIRE=%-10s HTTPLEN=%-9s CANARY(raw)=%s HTTPBODY=%s DEPTH=%s%s"
          % (rec["ts"], rec["src"], rec["dst"], size, w, httplen, canary, hbody, depth, drop))

print("---- summary ----", file=sys.stderr)
print("flows                : %d" % len(ordered), file=sys.stderr)
print("CANARY-DETECTED      : %d" % n_canary, file=sys.stderr)
print("REASSEMBLY-DEPTH     : %d" % n_depth, file=sys.stderr)
'
