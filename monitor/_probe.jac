# throwaway probe — verify Jac runtime features needed by escalation_policy.jac
import json;
import sys;
import math;
import hashlib;

glob:pub WINDOW_MS: int = 15000;
glob:pub PIVOT_MS: float = 1000.0;

def p95(vals: list) -> float {
    if len(vals) == 0 {
        return 0.0;
    }
    s = sorted(vals);
    k = 0.95 * (len(s) - 1);
    lo = int(math.floor(k));
    hi = int(math.ceil(k));
    if lo == hi {
        return float(s[lo]);
    }
    return float(s[lo]) + (float(s[hi]) - float(s[lo])) * (k - float(lo));
}

def hexid(a: str, b: str, t: int) -> str {
    raw = a + "|" + b + "|" + str(t);
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest();
    return "inc_" + h[0:16];
}

with entry:__main__ {
    # sets
    fired = set();
    fired.add(1);
    fired.add(5);
    other = set([5, 9]);
    u = fired | other;
    sys.stderr.write("union=" + str(sorted(list(u))) + "\n");
    sys.stderr.write("issub=" + str(3 in u) + "\n");
    sys.stderr.write("eq=" + str(u == set([1,5,9])) + "\n");

    # p95
    sys.stderr.write("p95=" + str(p95([1.0, 2.0, 3.0, 10.0])) + "\n");
    sys.stderr.write("p95empty=" + str(p95([])) + "\n");

    # hashlib
    sys.stderr.write("id=" + hexid("c_attacker", "t_acme", 1773756000000) + "\n");

    # dict + get default
    d = {};
    d["x"] = {"a": 1};
    sys.stderr.write("get=" + str(d.get("y", {})) + "\n");
    row = {"req": 3};
    sys.stderr.write("rowget=" + str(row.get("export_bytes", 0)) + "\n");

    # round / min / max
    sys.stderr.write("conf=" + str(round(min(0.98, 0.40 + 0.09*3 + 0.03*2), 4)) + "\n");
    sys.stderr.write("mx=" + str(max(1.0, 0.5)) + "\n");

    # string ops, f-string
    n = 3;
    sys.stderr.write(f"fstring n={n} v={round(1.23456,2)}\n");
    sys.stderr.write("join=" + ",".join([str(x) for x in sorted(list(u))]) + "\n");

    # stdin read + splitlines
    data = sys.stdin.read();
    cnt = 0;
    for line in data.splitlines() {
        ls = line.strip();
        if len(ls) == 0 {
            continue;
        }
        rec = json.loads(ls);
        cnt += 1;
        sys.stderr.write("line " + str(cnt) + " keys=" + str(sorted(list(rec.keys()))) + "\n");
    }
    # json.dumps
    out = {"incident_id": hexid("a","b",1), "n": cnt, "f": [], "ok": True};
    print(json.dumps(out));

    # regex?
    import re;
    m = re.match(r"^<<<UNTRUSTED>>>[\s\S]*<<</UNTRUSTED>>>$", "<<<UNTRUSTED>>>hi\nthere<<</UNTRUSTED>>>");
    sys.stderr.write("re=" + str(m is not None) + "\n");

    # while loop / list slice
    i = 0;
    ring = [1,2,3,4,5,6,7];
    ring = ring[-6:];
    while i < 2 {
        i += 1;
    }
    sys.stderr.write("ring=" + str(ring) + " i=" + str(i) + "\n");

    # sorted set of strings
    ss = set(["s_live","s_anon"]);
    sys.stderr.write("ss=" + str(sorted(list(ss))) + "\n");
}
