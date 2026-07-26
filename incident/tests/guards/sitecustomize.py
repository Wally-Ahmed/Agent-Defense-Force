"""Runtime label-leak guard.

Placed on PYTHONPATH for every acceptance replay. Python imports `sitecustomize`
automatically at interpreter start, before any project code, so the wrapper is installed
before the detector can possibly run.

Any attempt by the detection pipeline to open a path containing a label-shaped token aborts
the process with a non-zero exit. This turns "the detector never reads the labels" from a
claim into an enforced property of the run that produced the results.
"""

import builtins
import io
import os
import sys

FORBIDDEN_TOKENS = ("label", "ground_truth", "is_attack")

_real_open = builtins.open
_real_io_open = io.open
_real_os_open = os.open


def _check(path):
    try:
        p = os.fspath(path)
    except TypeError:
        return
    if isinstance(p, bytes):
        p = p.decode("utf-8", "replace")
    low = p.lower()
    for tok in FORBIDDEN_TOKENS:
        if tok in low:
            sys.stderr.write(
                "LABEL-LEAK GUARD: detection process attempted to open %r "
                "(matched forbidden token %r)\n" % (p, tok)
            )
            raise PermissionError("label-leak guard: refused to open %s" % p)


def _guarded_open(file, *a, **kw):
    _check(file)
    return _real_open(file, *a, **kw)


def _guarded_io_open(file, *a, **kw):
    _check(file)
    return _real_io_open(file, *a, **kw)


def _guarded_os_open(path, *a, **kw):
    _check(path)
    return _real_os_open(path, *a, **kw)


builtins.open = _guarded_open
io.open = _guarded_io_open
os.open = _guarded_os_open
