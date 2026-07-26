import json;
import sys;

def dflt(a: int, b: int = 5) -> int {
    if a > b {
        return a;
    } elif a == b {
        return 0;
    } else {
        return b;
    }
}

def maybe() -> int {
    return None;
}

with entry:__main__ {
    sys.stderr.write("dflt=" + str(dflt(1)) + " " + str(dflt(9, 2)) + " " + str(dflt(5)) + "\n");
    v = maybe();
    if v is None {
        sys.stderr.write("none ok\n");
    }
    rows = [];
    rows.append({"p": "b", "t": "z"});
    rows.append({"p": "a", "t": "y"});
    srt = sorted(rows, key=lambda r: any (r["p"] + "|" + r["t"]));
    sys.stderr.write("srt=" + str(srt) + "\n");
    tup = ("a", 1);
    d2 = {};
    d2[tup] = 3;
    sys.stderr.write("tupkey=" + str(d2) + "\n");
    try {
        x = int("nope");
    } except Exception as e {
        sys.stderr.write("caught=" + str(type(e).__name__) + "\n");
    }
    ss = set([3, 1]);
    key = ",".join([str(q) for q in sorted(list(ss))]);
    seen = set();
    seen.add(key);
    sys.stderr.write("seen=" + str(key in seen) + " " + str(len(ss)) + "\n");
    lst = [1, 2, 3];
    tot = 0;
    for q in lst {
        tot += q;
    }
    sys.stderr.write("sum=" + str(sum(lst)) + " " + str(tot) + "\n");
    s = "abcdef";
    sys.stderr.write("slice=" + s[0:3] + " " + str(len(s)) + "\n");
    b = True;
    if b == True {
        sys.stderr.write("boolcmp ok\n");
    }
    nested = {"a": {"b": [1, 2]}};
    sys.stderr.write("nested=" + str(nested["a"]["b"][1]) + "\n");
    sys.stderr.write(json.dumps({"k": [1, 2]}) + "\n");
}
