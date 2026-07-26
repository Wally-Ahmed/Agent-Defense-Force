import os;
import time;
import from ctxsig { signed_ctx, verify_ctx, sign_ctx, ctx_hash }
import from fingerprint { ua_hash, client_fp, new_request_id, email_hash, redact_body }
import from audit { AuditSink, blank_event, SCHEMA_KEYS, iso_utc }
import from policy { RateLimiter, ControlSource, iso_to_ms }
import from sessions { SessionStore, mint_csrf, csrf_valid, mint_upstream_jwt, ANON_BINDING }
import from config { load_settings, resolve_route, RATE_BUDGETS }

with entry:__main__ {
    os.environ["APP_CTX_SIGNING_KEY"] = "k" * 40;
    os.environ["APP_SESSION_SECRET"] = "s" * 40;
    os.environ["APP_CSRF_SECRET"] = "c" * 40;
    os.environ["APP_JWT_SIGNING_KEY"] = "j" * 40;
    os.environ["APP_ORIGINS"] = "http://a.test,http://b.test";
    st = load_settings();
    print("settings:", st.bind_host, st.bind_port, st.upstream, st.origins, st.jwt_alg);
    print("origin_allowed:", st.origin_allowed("http://a.test"), st.origin_allowed("http://evil.test"));

    now = int(time.time() * 1000);
    base = {
        "request_id": new_request_id(), "src_ip": "192.0.2.9", "src_asn": "",
        "user_agent_hash": ua_hash("curl/8"), "client_fp": client_fp("curl/8", "en", "gzip"),
        "session_id": "sess_x", "token_id": "", "service": "web",
        "route": "/api/v1/tenants", "http_method": "GET", "csrf_ok": True,
        "received_at_ms": now, "sig_alg": "HMAC-SHA256", "issued_at_ms": now
    };
    ctx = signed_ctx(base, st.ctx_signing_key);
    print("ctx keys:", len(ctx), "sig len:", len(ctx["sig"]));
    print("verify ok:", verify_ctx(ctx, st.ctx_signing_key, now));
    bad = dict(ctx); bad["src_ip"] = "10.0.0.1";
    print("verify tampered:", verify_ctx(bad, st.ctx_signing_key, now));
    print("verify wrongkey:", verify_ctx(ctx, "z"*40, now));
    print("verify stale:", verify_ctx(ctx, st.ctx_signing_key, now + 31000));
    forged = dict(ctx); forged["sig"] = "";
    print("verify unsigned:", verify_ctx(forged, st.ctx_signing_key, now));
    extra = dict(ctx); extra["evil"] = 1;
    print("verify extrakey:", verify_ctx(extra, st.ctx_signing_key, now));
    print("ctx_hash:", ctx_hash(ctx)[:16]);

    print("route:", resolve_route("POST", "/api/v1/tenants/t_acme/projects"));
    print("route none:", resolve_route("POST", "/api/v1/nope"));

    ss = SessionStore(secret=st.session_secret);
    sess = ss.create("u_1", "a@b.test", "t_acme", "owner", now);
    ck = ss.cookie_for(sess.session_id);
    print("session lookup:", ss.lookup(ck, now)["reason"], ss.lookup("bogus.tag", now)["reason"]);
    tok = mint_csrf(st.csrf_secret, sess.session_id);
    print("csrf good:", csrf_valid(st.csrf_secret, sess.session_id, tok, tok));
    print("csrf mismatch:", csrf_valid(st.csrf_secret, sess.session_id, tok, tok + "x"));
    print("csrf wrong binding:", csrf_valid(st.csrf_secret, "other", tok, tok));
    print("jwt:", mint_upstream_jwt(ctx, st.jwt_key, "HS256", now)[:20]);

    rl = RateLimiter(controls=ControlSource(path="/nonexistent.json"));
    n = 0;
    while n < 5 { r = rl.check("192.0.2.9", "auth_register", "", now); n += 1; }
    print("rl after 5 register:", r.allowed, r.retry_after_s, r.limit, r.remaining);
    print("iso_to_ms:", iso_to_ms("2026-03-17T14:30:00Z"));

    sink = AuditSink(path="/tmp/_gw_smoke_audit.jsonl");
    ev = sink.emit({"action": "auth.login_failed", "outcome": "deny", "reason": "NO_SESSION",
                    "severity": "warn", "session_id": "sess_x", "src_ip": "192.0.2.9"});
    ev2 = sink.emit({"action": "auth.login_failed", "outcome": "deny", "reason": "NO_SESSION",
                     "severity": "warn", "session_id": "sess_x"});
    print("audit seq:", ev["seq"], ev2["seq"], "chain:", ev2["prev_event_id"] == ev["event_id"], "fields:", len(ev));
    print("keys match contract:", list(ev.keys()) == SCHEMA_KEYS);
    print("redact:", redact_body({"email": "a@b", "password": "hunter2", "n": [{"token": "x"}]}));
    print("SMOKE OK");
}
