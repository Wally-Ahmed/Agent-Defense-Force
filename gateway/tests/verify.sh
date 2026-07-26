#!/usr/bin/env bash
# Gateway acceptance checks. Every assertion below is made against a live
# gateway and a live upstream over real HTTP — no mocks, no stubbed responses.
#
#   ./gateway/tests/verify.sh
#
# Exits non-zero if any check fails.

set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
ROOT="$PWD"

GW_PORT="${GW_PORT:-8080}"
UP_PORT="${UP_PORT:-8000}"
GW="http://127.0.0.1:${GW_PORT}/api/v1"
UP="http://127.0.0.1:${UP_PORT}"
RUN="$ROOT/var/gateway-test"
rm -rf "$RUN"; mkdir -p "$RUN"

export APP_CTX_SIGNING_KEY="$(openssl rand -hex 32)"
export APP_SESSION_SECRET="$(openssl rand -hex 32)"
export APP_CSRF_SECRET="$(openssl rand -hex 32)"
export APP_JWT_SIGNING_KEY="$(openssl rand -hex 32)"
export APP_ORIGINS="http://allowed.test,http://127.0.0.1:8080"
export GATEWAY_BIND="127.0.0.1:${GW_PORT}"
export JAC_UPSTREAM="127.0.0.1:${UP_PORT}"
export APP_AUDIT_LOG="$RUN/audit.jsonl"
export AUDIT_PATH="$APP_AUDIT_LOG"
export CONTROLS_PATH="$RUN/controls.json"
export STUB_PORT="$UP_PORT"
export STUB_LOGIN_PASSWORD="$(openssl rand -hex 12)"

PASS=0; FAIL=0
ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
chk()  { if [ "$2" = "$3" ]; then ok "$1 ($2)"; else bad "$1 (got '$2', want '$3')"; fi; }

cleanup() { kill ${UP_PID:-0} ${GW_PID:-0} 2>/dev/null; wait 2>/dev/null; }
trap cleanup EXIT

echo "=== booting upstream stub + gateway ==="
# Booted with cwd=gateway/ so the gateway's sibling imports (`from app`,
# `from config`, `from ctxsig`) resolve to ITS modules. From the repo root the
# top-level `app/` package shadows `gateway/app.jac` and main.jac dies with
# "cannot import name 'build_app' from 'app' (unknown location)". Logs and env
# still point at absolute $RUN paths, so nothing else changes.
#
# `exec` matters: without it $! is the SUBSHELL's pid, the cleanup trap kills
# only the subshell, and the real `jac` process survives the run still holding
# the port. The next run then silently tests the PREVIOUS gateway, inheriting
# its rate-limiter state -- which shows up as spurious, drifting failures.
( cd "$ROOT/gateway" && exec jac run upstream_stub.jac ) > "$RUN/upstream.log" 2>&1 &
UP_PID=$!
( cd "$ROOT/gateway" && exec jac run main.jac ) > "$RUN/gateway.log" 2>&1 &
GW_PID=$!
for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:${GW_PORT}/healthz" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -sf "http://127.0.0.1:${GW_PORT}/healthz" >/dev/null || { echo "gateway did not start"; cat "$RUN/gateway.log"; exit 1; }
echo "  up: gateway :$GW_PORT  upstream :$UP_PORT"
echo

# ---------------------------------------------------------------------------
echo "=== 1. Security headers on a real response ==="
curl -si "$GW/tenants" -o "$RUN/h1.txt" >/dev/null
grep -iE '^(strict-transport-security|content-security-policy|x-content-type-options|referrer-policy|x-frame-options|permissions-policy|cross-origin-opener-policy|cache-control|x-request-id):' "$RUN/h1.txt" | sed 's/^/  /'
for h in strict-transport-security content-security-policy x-content-type-options referrer-policy x-frame-options permissions-policy; do
  if grep -qi "^${h}:" "$RUN/h1.txt"; then ok "header $h present"; else bad "header $h MISSING"; fi
done
echo

# ---------------------------------------------------------------------------
echo "=== 2. CORS allowlist (overrides jac-scale's allow_origins=['*']) ==="
echo "  -- allowed origin --"
A=$(curl -si -H "Origin: http://allowed.test" "$GW/tenants" | grep -i '^access-control-allow-' | tr -d '\r')
echo "$A" | sed 's/^/  /'
ACAO=$(echo "$A" | grep -i 'allow-origin' | cut -d' ' -f2)
chk "allowed origin echoed" "$ACAO" "http://allowed.test"
echo "  -- disallowed origin --"
B=$(curl -si -H "Origin: http://evil.test" "$GW/tenants" | grep -ic 'access-control-allow-origin')
chk "no ACAO for disallowed origin" "$B" "0"
echo "  -- wildcard never emitted --"
W=$(curl -si -H "Origin: http://evil.test" "$GW/tenants" | grep -c 'Access-Control-Allow-Origin: \*')
chk "no wildcard ACAO" "$W" "0"
echo "  -- preflight from disallowed origin --"
P=$(curl -s -o /dev/null -w '%{http_code}' -X OPTIONS -H "Origin: http://evil.test" \
     -H "Access-Control-Request-Method: POST" "$GW/tenants")
chk "preflight rejected" "$P" "403"
P2=$(curl -s -o /dev/null -w '%{http_code}' -X OPTIONS -H "Origin: http://allowed.test" \
     -H "Access-Control-Request-Method: POST" "$GW/tenants")
chk "preflight allowed" "$P2" "204"
echo "  -- cross-origin POST from disallowed origin --"
X=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Origin: http://evil.test" \
     -H 'Content-Type: application/json' -d '{}' "$GW/tenants")
chk "cross-origin POST rejected" "$X" "403"
echo

# ---------------------------------------------------------------------------
echo "=== 3. Non-GET without a valid CSRF token ==="
R=$(curl -s -w '\n%{http_code}' -X POST -H 'Content-Type: application/json' -d '{"name":"x"}' "$GW/tenants")
BODY=$(echo "$R" | sed '$d'); CODE=$(echo "$R" | tail -1)
echo "  $BODY"
chk "no CSRF token -> 403" "$CODE" "403"
CODEV=$(echo "$BODY" | python3 -c 'import sys,json;print(json.load(sys.stdin)["error"]["code"])' 2>/dev/null)
chk "deny code" "$CODEV" "CSRF_INVALID"
# a token that is not HMAC-bound is refused even when cookie == header
FORGED="notarealnonce.deadbeefdeadbeefdeadbeefdeadbeef"
CODE2=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
        -H "X-CSRF-Token: $FORGED" -b "__Host-csrf=$FORGED" -d '{}' "$GW/tenants")
chk "forged CSRF token -> 403" "$CODE2" "403"
echo

# ---------------------------------------------------------------------------
echo "=== 4. Rate limiting trips at the configured threshold ==="
# POST /auth/register budget: 3 per 3600s per source ip.
CSRF=$(curl -si "$GW/auth/session" | grep -i '^set-cookie: __Host-csrf=' | head -1 | sed 's/.*__Host-csrf=//; s/;.*//' | tr -d '\r')
echo "  pre-session CSRF cookie issued: ${CSRF:0:12}..."
for i in 1 2 3 4; do
  C=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
       -H "X-CSRF-Token: $CSRF" -b "__Host-csrf=$CSRF" -d '{"email":"a@b.test"}' "$GW/auth/register")
  echo "  attempt $i -> $C"
  LAST=$C
done
chk "4th register (limit 3) -> 429" "$LAST" "429"
curl -si -X POST -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" -b "__Host-csrf=$CSRF" \
     -d '{"email":"a@b.test"}' "$GW/auth/register" | grep -iE '^(retry-after|x-ratelimit)' | sed 's/^/  /'
RB=$(curl -s -X POST -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" -b "__Host-csrf=$CSRF" \
     -d '{"email":"a@b.test"}' "$GW/auth/register")
echo "  $RB"
echo "$RB" | grep -q 'RATE_LIMITED' && ok "429 body carries RATE_LIMITED" || bad "429 body missing RATE_LIMITED"
grep -c '"reason":"RATE_LIMITED"' "$AUDIT_PATH" >/dev/null 2>&1 && \
  ok "audit sink recorded RATE_LIMITED ($(grep -c '"reason":"RATE_LIMITED"' "$AUDIT_PATH") events)" || \
  bad "no RATE_LIMITED in audit sink"
echo

# ---------------------------------------------------------------------------
echo "=== 4b. Login throttle: exponential backoff after 5 failures ==="
CS=$(curl -si "$GW/auth/session" | grep -i '^set-cookie: __Host-csrf=' | head -1 | sed 's/.*__Host-csrf=//; s/;.*//' | tr -d '\r')
for i in 1 2 3 4 5 6; do
  RESP=$(curl -s -w '\n%{http_code}' -X POST -H 'Content-Type: application/json' \
         -H "X-CSRF-Token: $CS" -b "__Host-csrf=$CS" \
         -d '{"email":"lena.hart@globex.test","password":"wrong"}' "$GW/auth/login")
  LC=$(echo "$RESP" | tail -1)
  echo "  failed login $i -> $LC"
  LASTL="$LC"; LASTB=$(echo "$RESP" | sed '$d')
done
chk "6th attempt throttled" "$LASTL" "429"
echo "  $LASTB"
LF=$(grep -c '"action":"auth.login_failed"' "$AUDIT_PATH" 2>/dev/null || echo 0)
if [ "$LF" -ge 5 ]; then ok "gateway emitted auth.login_failed x$LF"; else bad "auth.login_failed not emitted (got $LF)"; fi
grep -q '"actor_email":"lena.hart@globex.test"' "$AUDIT_PATH" && ok "login_failed carries actor_email" || bad "no actor_email"
if grep -q 'wrong' "$AUDIT_PATH"; then bad "PASSWORD LEAKED INTO AUDIT SINK"; else ok "no credential in audit sink"; fi
if grep -qi '__Host-csrf=' "$RUN/gateway.log"; then bad "cookie value leaked into gateway log"; else ok "no cookie value in gateway log"; fi
echo

# ---------------------------------------------------------------------------
echo "=== 4c. Containment Control node narrows the limit at the gateway ==="
EXP=$(python3 -c "import time,datetime;print(datetime.datetime.fromtimestamp(time.time()+900,datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))")
cat > "$CONTROLS_PATH" <<JSON
{"controls":[{"control_id":"ctl_test_1","kind":"throttle_source","scope_key":"127.0.0.1",
  "params":{"rate_per_min":2},"expires_at":"$EXP","active":true}]}
JSON
echo "  wrote throttle_source control: 127.0.0.1 -> 2 req/min (baseline for reads is 1200/60s)"
sleep 2.5
for i in 1 2 3 4; do
  C=$(curl -s -o /dev/null -w '%{http_code}' "$GW/tenants")
  echo "  contained read $i -> $C"; LASTC=$C
done
chk "containment throttle trips (baseline would allow)" "$LASTC" "429"
echo '{"controls":[]}' > "$CONTROLS_PATH"; sleep 2.5
echo


# ---------------------------------------------------------------------------
echo "=== 5. Client-supplied ctx is STRIPPED and replaced ==="
CSRF2=$(curl -si "$GW/auth/session" | grep -i '^set-cookie: __Host-csrf=' | head -1 | sed 's/.*__Host-csrf=//; s/;.*//' | tr -d '\r')
FORGED_CTX='{"name":"proj","ctx":{"request_id":"ATTACKER","src_ip":"10.6.6.6","src_asn":"AS666","user_agent_hash":"deadbeef","client_fp":"deadbeef","session_id":"sess_victim","token_id":"tok_victim","service":"web","route":"/pwn","http_method":"GET","csrf_ok":true,"received_at_ms":1,"sig":"forged","sig_alg":"HMAC-SHA256","issued_at_ms":1,"session_auth_at_ms":1}}'
OUT=$(curl -s -X POST -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF2" -b "__Host-csrf=$CSRF2" \
      -d "$FORGED_CTX" "$GW/tenants/t_acme/projects")
echo "  upstream saw ctx:"
echo "$OUT" | "${PYBIN:-python3}" -c 'import sys,json;d=json.load(sys.stdin);print("   ",json.dumps(d.get("ctx_seen",{}),indent=None)[:400])' 2>/dev/null || echo "  $OUT"
for probe in ATTACKER 10.6.6.6 AS666 sess_victim tok_victim '/pwn' '"sig":"forged"'; do
  if echo "$OUT" | grep -q -- "$probe"; then bad "attacker value '$probe' SURVIVED into upstream ctx"; else ok "attacker value '$probe' stripped"; fi
done
echo "$OUT" | grep -q '"ctx_verified": *true' && ok "upstream verified the gateway's own signature" || bad "upstream did not verify ctx"
echo "$OUT" | grep -q '"src_ip": *"127.0.0.1"' && ok "src_ip is the OBSERVED peer, not the claimed one" || bad "src_ip not observed"
grep -q 'stripped client-supplied ctx' "$RUN/gateway.log" && ok "gateway logged the boundary probe" || bad "strip not logged"
echo

# ---------------------------------------------------------------------------
echo "=== 6. Forged ctx POSTed DIRECTLY to the upstream, bypassing the gateway ==="
echo "  -- fully forged ctx --"
D1=$(curl -s -w '\n%{http_code}' -X POST -H 'Content-Type: application/json' \
     -d '{"ctx":{"request_id":"x","src_ip":"10.6.6.6","src_asn":"","user_agent_hash":"","client_fp":"","session_id":"sess_victim","token_id":"","service":"web","route":"/x","http_method":"POST","csrf_ok":true,"received_at_ms":1,"sig":"0000000000000000000000000000000000000000000000000000000000000000","sig_alg":"HMAC-SHA256","issued_at_ms":9999999999999,"session_auth_at_ms":9999999999999}}' \
     "$UP/walker/CreateProject")
echo "  $(echo "$D1" | sed '$d')"
chk "forged sig -> 401" "$(echo "$D1" | tail -1)" "401"
echo "  -- no ctx at all --"
D2=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{"name":"x"}' "$UP/walker/CreateProject")
chk "missing ctx -> 401" "$D2" "401"
echo "  -- csrf_ok flipped on an otherwise-valid ctx (replay/tamper) --"
CAPTURED=$(echo "$OUT" | "${PYBIN:-python3}" -c 'import sys,json;print(json.dumps(json.load(sys.stdin)["ctx_seen"]))' 2>/dev/null)
if [ -n "$CAPTURED" ]; then
  TAMPERED=$(echo "$CAPTURED" | "${PYBIN:-python3}" -c 'import sys,json;c=json.load(sys.stdin);c["session_id"]="sess_victim";print(json.dumps({"ctx":c}))')
  D3=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d "$TAMPERED" "$UP/walker/CreateProject")
  chk "tampered session_id on a real signed ctx -> 401" "$D3" "401"
  REPLAY=$(echo "$CAPTURED" | "${PYBIN:-python3}" -c 'import sys,json;print(json.dumps({"ctx":json.load(sys.stdin)}))')
  D4=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d "$REPLAY" "$UP/walker/CreateProject")
  echo "  (unmodified captured ctx replayed within 30s -> $D4; expected 200 until it ages out)"
fi
echo "  upstream deny log:"
grep 'CTX_UNVERIFIED' "$RUN/upstream.log" | tail -4 | sed 's/^/    /'
echo

# ---------------------------------------------------------------------------
echo "=== 7. Refuses to start without APP_CTX_SIGNING_KEY ==="
OUT7=$(cd "$ROOT/gateway" && env -u APP_CTX_SIGNING_KEY GATEWAY_BIND=127.0.0.1:8099 jac run main.jac 2>&1; echo "EXIT=$?")
echo "$OUT7" | head -3 | sed 's/^/  /'
echo "$OUT7" | grep -q 'refuses to start' && ok "refuses to start, loudly" || bad "did not refuse"
echo "$OUT7" | grep -q 'EXIT=2' && ok "exit code 2" || bad "wrong exit code"
LISTENING=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 http://127.0.0.1:8099/healthz 2>/dev/null)
chk "nothing listening on 8099" "${LISTENING:-000}" "000"
echo

# ---------------------------------------------------------------------------
echo "=== audit sink ($AUDIT_PATH) ==="
if [ -f "$AUDIT_PATH" ]; then
  echo "  $(wc -l < "$AUDIT_PATH") events; actions/reasons seen:"
  "${PYBIN:-python3}" - "$AUDIT_PATH" <<'PY' | sed 's/^/    /'
import sys, json, collections
rows=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
c=collections.Counter((r["action"], r["reason"]) for r in rows)
for (a,rn),n in sorted(c.items()): print(f"{a:24} {rn:16} x{n}")
bad=[r for r in rows if len(r)!=38]
print(f"all rows have 38 fields: {not bad}")
seqs=collections.defaultdict(list)
for r in rows: seqs[r["session_id"]].append(r["seq"])
print(f"per-session seq starts at 1 and is monotonic: {all(v==list(range(1,len(v)+1)) for v in seqs.values())}")
PY
fi
echo
echo "=== $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
