# COPIED FROM target/child.py (PyYAML) for the sqlparse target. Only the
# library-specific lines differ: it imports sqlparse and its call table maps
# parse/format/split to the documented sqlparse functions. Everything else
# (the audit hook, the untrusted report, os._exit) is identical.
"""The child: import PyYAML and make exactly one call on the payload.

This process runs attacker-influenced code only if the library itself runs
the payload as code, which is the bug being proven. It never decides
anything. It reports what it saw (exception type, library call stacks) to
the parent over a pipe, and the parent treats that report as untrusted:
it keeps only fields that match strict allowlists, and decides the outcome
from what it observes itself (exit status, signal, time, the marker file).
"""

import hashlib
import json
import os
import sys

ENTRY_POINTS = ("parse", "format", "split")
WATCHED = {"exec", "compile", "open", "os.system", "os.exec", "os.posix_spawn",
           "os.spawn", "subprocess.Popen", "socket.connect", "ctypes.dlopen"}
MAX_EVENTS = 40


def main():
    entry, payload_path, marker = sys.argv[1], sys.argv[2], sys.argv[3]
    report = os.fdopen(int(sys.argv[4]), "w")
    # The library never prints; anything that does is not ours to relay.
    devnull = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)

    if entry not in ENTRY_POINTS:
        os._exit(2)
    import sqlparse

    lib_dir = os.path.dirname(os.path.abspath(sqlparse.__file__)) + os.sep
    with open(payload_path, encoding="utf-8") as handle:
        payload = handle.read()
    call = {
        "parse": lambda: sqlparse.parse(payload),
        "format": lambda: sqlparse.format(payload, reindent=True),
        "split": lambda: sqlparse.split(payload),
    }[entry]

    events = []
    state = {"armed": False}

    def frames():
        found, frame = [], sys._getframe(2)
        while frame is not None:
            name = frame.f_code.co_filename
            if name.startswith(lib_dir):
                found.append("%s:%s" % (os.path.basename(name), frame.f_code.co_name))
            frame = frame.f_back
        return found

    def hook(event, args):
        if not state["armed"] or event not in WATCHED or len(events) >= MAX_EVENTS:
            return
        try:
            kind = event
            if event == "open":
                mode = args[1] if len(args) > 1 else None
                flags = args[2] if len(args) > 2 and isinstance(args[2], int) else 0
                writing = any(c in str(mode) for c in "wax+") if mode is not None else bool(
                    flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT))
                if not writing:
                    return
                kind = "write-marker" if args[0] == marker else "write-other"
            events.append({"event": kind, "library_frames": frames()[:6]})
        except Exception:
            pass

    sys.addaudithook(hook)
    result = {"returned": False, "exception_type": None, "exception_sha256": None,
              "exception_frames": [], "events": events}
    state["armed"] = True
    try:
        call()
        result["returned"] = True
    except BaseException as exc:  # what the library raised
        state["armed"] = False
        tb, where = exc.__traceback__, []
        while tb is not None:
            name = tb.tb_frame.f_code.co_filename
            if name.startswith(lib_dir):
                where.append("%s:%s" % (os.path.basename(name), tb.tb_frame.f_code.co_name))
            tb = tb.tb_next
        result["exception_type"] = type(exc).__name__
        try:
            result["exception_sha256"] = hashlib.sha256(str(exc).encode("utf-8", "replace")).hexdigest()
        except Exception:
            result["exception_sha256"] = None
        result["exception_frames"] = where[-6:]
    state["armed"] = False
    try:
        report.write(json.dumps(result))
        report.flush()
    except Exception:
        pass
    os._exit(0)


if __name__ == "__main__":
    main()
