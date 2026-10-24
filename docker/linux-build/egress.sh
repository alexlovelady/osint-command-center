#!/usr/bin/env bash
# Runs INSIDE the container (needs --cap-add NET_RAW --cap-add NET_ADMIN). Linux counterpart of scripts/egress_check.py.
#
# A fresh container runs nothing but this script, so EVERY non-loopback packet in the capture belongs to the app: attribution is exact.
#   Phase A: the real desktop shell (Xvfb + WebKitGTK) is started with the bundled backend and left idle.
#   Phase B: the bundled backend is driven through the "must not touch the network" API paths.
#   Phase C: abrupt kill of the shell (SIGKILL) must leave no backend process behind.
# Also saves a screenshot of the shell window so the packaged UI is seen rendering.
set -uo pipefail
OUT=/out/egress; mkdir -p $OUT; rm -f $OUT/*
BIN=/out/linux
export OSINTCC_DATA_DIR=/tmp/osintcc-data OSINTCC_VAULT_KEY="$(head -c 32 /dev/urandom | base64)"
export WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1 WEBKIT_DISABLE_COMPOSITING_MODE=1 LIBGL_ALWAYS_SOFTWARE=1 GDK_BACKEND=x11
mkdir -p "$OSINTCC_DATA_DIR"
ip -brief addr 2>/dev/null | tee $OUT/interfaces.txt || true
tcpdump -i any -nn -U -w $OUT/capture.pcap >/dev/null 2>$OUT/tcpdump.err &
TCP=$!
sleep 2

echo "== Phase A: desktop shell idle 60s under Xvfb"
Xvfb :99 -screen 0 1440x900x24 >/dev/null 2>&1 &
export DISPLAY=:99
sleep 2
cp $BIN/osintcc-desktop $BIN/osintcc-backend /tmp/ 2>/dev/null; chmod +x /tmp/osintcc-desktop /tmp/osintcc-backend
/tmp/osintcc-desktop >$OUT/shell.log 2>&1 &
SHELL_PID=$!
for i in $(seq 1 40); do pgrep -f osintcc-backend >/dev/null && break; sleep 1; done
echo "backend processes: $(pgrep -fc osintcc-backend)  shell alive: $(kill -0 $SHELL_PID 2>/dev/null && echo yes || echo no)"
sleep 12
import -window root $OUT/shell.png 2>/dev/null && echo "screenshot saved ($(stat -c %s $OUT/shell.png) bytes)"
ss -tlnp 2>/dev/null | grep -E "127.0.0.1" | tee $OUT/listeners.txt
sleep 48
ss -tnp 2>/dev/null > $OUT/connections-A.txt; cat $OUT/connections-A.txt | head -5

echo "== Phase C: SIGKILL the shell; the backend must die with it"
before=$(pgrep -fc osintcc-backend || true)
kill -9 $SHELL_PID
sleep 4
after=$(pgrep -fc osintcc-backend || true)
echo "backend processes before kill: $before, after: $after"
echo "$before $after" > $OUT/orphan-check.txt

echo "== Phase B: backend driven through no-network paths"
export OSINTCC_DATA_DIR=/tmp/osintcc-dataB
/tmp/osintcc-backend >$OUT/backend.out 2>$OUT/backend.err &
BE=$!
for i in $(seq 1 40); do grep -q OSINTCC_READY $OUT/backend.out 2>/dev/null && break; sleep 1; done
python3 - <<'PY' | tee $OUT/api-calls.txt
import json, re, urllib.request
line = open("/out/egress/backend.out").read().split("\n")[0]
kv = dict(x.split("=", 1) for x in line.split()[1:])
base, tok = f"http://127.0.0.1:{kv['port']}/api/v1", kv["token"]
def call(method, path, body=None):
    req = urllib.request.Request(base + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")
s, case = call("POST", "/cases", {"title": "egress", "purpose": "verify no outbound traffic"})
cid = case["id"]
res = [call("POST", f"/cases/{cid}/searches/preview", {"target": "example.com"}),
       call("POST", "/collection-plans/preview", {"case_id": cid, "target": "example.com", "reason": "egress test"}),
       call("GET", "/setup/status"), call("POST", "/setup/plan", {"ids": ["subfinder"]}), call("POST", "/updates/check"),
       call("GET", "/tools"), call("GET", "/system/doctor"), call("GET", "/ai/profiles"),
       call("PUT", "/settings", {"values": {"offline": True}}),
       call("POST", f"/cases/{cid}/searches", {"target": "example.com", "wait": True})]
print("API statuses:", [r[0] for r in res])
print("offline search outcome:", json.dumps(res[-1][1])[:300])
PY
sleep 15
kill -TERM $BE 2>/dev/null; sleep 2
kill $TCP 2>/dev/null; sleep 2

echo "== analysis"
tcpdump -nn -r $OUT/capture.pcap 2>/dev/null | wc -l | xargs echo "total packets in capture:"
tcpdump -nn -r $OUT/capture.pcap -e 2>/dev/null | grep -v " lo " | grep -v "^$" | head -20 > $OUT/non-loopback.txt || true
n=$(tcpdump -nn -r $OUT/capture.pcap not host 127.0.0.1 and not host ::1 2>/dev/null | wc -l)
echo "packets not to/from loopback: $n"
echo "$n" > $OUT/non-loopback-count.txt
tcpdump -nn -r $OUT/capture.pcap not host 127.0.0.1 and not host ::1 2>/dev/null | head -20
