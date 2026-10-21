#!/usr/bin/env bash
# 现场抓一条回环 HTTP 会话（只抓本案例端口，避免采集无关流量）。
# 用法：bash input/capture_live.sh [iface]
#   iface 省略时自动从 `tshark -D` 里挑 loopback 适配器序号。
# 产物：artifacts/live.pcapng（BPF: tcp port 18321）
set -u
cd "$(dirname "$0")/.." || exit 2

PORT=18321
OUT="${OUT_DIR:-artifacts/live.pcapng}"
IFACE="${1:-}"
if [ -z "$IFACE" ]; then
    IFACE=$(tshark -D 2>/dev/null | grep -i loopback | head -1 | cut -d. -f1)
fi
if [ -z "$IFACE" ]; then
    echo "no loopback interface found (tshark -D)" >&2
    exit 2
fi
mkdir -p "$(dirname "$OUT")"
# 血案（R2 审计）：旧版直接 rm -f 覆盖 artifacts/live.pcapng，导致案例 sha 必然漂移、门禁 FAIL。
# 现在：默认不覆盖已存在的录制件；要重新录制必须显式 CAPTURE_FORCE=1（并同时重算 case.json 的 sha256）。
if [ -e "$OUT" ] && [ "${CAPTURE_FORCE:-0}" != "1" ]; then
    echo "refuse to overwrite $OUT (set CAPTURE_FORCE=1 to re-record)" >&2
    exit 2
fi
rm -f "$OUT"

python input/echo_server.py "$PORT" &
SRV=$!
sleep 1

tshark -i "$IFACE" -f "tcp port $PORT" -a duration:5 -w "$OUT" 2>artifacts/tshark-capture.err &
TS=$!
sleep 1

curl -s -o /dev/null -w 'req1 GET /v1/ping -> %{http_code}\n' "http://127.0.0.1:$PORT/v1/ping"
curl -s -o /dev/null -w 'req2 GET /v1/telemetry -> %{http_code}\n' \
     -H 'Authorization: Bearer lab-token' "http://127.0.0.1:$PORT/v1/telemetry?seq=2"
curl -s -o /dev/null -w 'req3 POST /v1/echo -> %{http_code}\n' \
     -H 'Content-Type: application/json' --data '{"temp":21.5}' \
     "http://127.0.0.1:$PORT/v1/echo"

wait $TS
RC=$?
kill $SRV 2>/dev/null
wait $SRV 2>/dev/null
ls -l "$OUT"
exit $RC
