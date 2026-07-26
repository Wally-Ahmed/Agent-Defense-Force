# Test helper: project a single AuditEvent read from stdin and print the projection as JSON.
# Used by test_acceptance.py to prove free text does not survive projection.
import sys;
import json;
import from incident.projection { project, assert_projection_clean, boot }

with entry:__main__ {
    boot();
    rec = json.loads(sys.stdin.read());
    o = project(rec);
    assert_projection_clean(o);
    print(json.dumps(o, sort_keys=True));
}
