# COPIED FROM target/harness.py (PyYAML) for the sqlparse target. Only the
# library-specific lines differ from that file: ENTRY_POINTS (parse/format/
# split), library_allowlists() imports sqlparse instead of yaml, and main()
# records the library name as sqlparse. The
# parent's isolation, limits and classify() are identical, so both targets
# are judged the same way. Keep the two files in step by hand.
"""The parent: runs one proof of concept and writes the only result record.

A proof of concept is data: a YAML payload and one entry point from a fixed
list. This process never parses the payload. It creates a fresh marker
directory, starts a child process that imports PyYAML and makes the one
declared call (child.py), and observes the child from outside: exit status,
signal, wall time, peak memory, and whether the marker file appeared.

The child's own report (exception type, library call stacks) is treated as
untrusted: if the library ran attacker code, that code runs in the child.
Only fields that match strict allowlists are kept, and the outcome never
depends on them. The one-time code that tags the result line is read from
stdin by this process and never given to the child, and this process marks
itself non-dumpable so a same-user child cannot read its memory or file
descriptors through /proc.

Protocol: the host writes a one-line nonce on stdin, mounts /poc/job.json
({"entry_point": ...}) and /poc/payload.yaml read-only, and reads exactly
one line from stdout: ``@@PROVEIT <nonce> <json>``.
"""

import builtins
import ctypes
import hashlib
import json
import os
import re
import resource
import signal
import subprocess
import sys
import threading
import time

JOB = "/poc/job.json"
PAYLOAD = "/poc/payload.yaml"
CHILD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "child.py")
MARKER_DIR = "/tmp/proveit"
MARKER = MARKER_DIR + "/marker"
ENTRY_POINTS = ("parse", "format", "split")
PAYLOAD_MAX_BYTES = 64 * 1024
CALL_SECONDS = 10
CALL_MEMORY_MB = 192
# Peak memory the parent must observe before a reported MemoryError counts.
MEMORY_EXHAUSTION_MB = CALL_MEMORY_MB // 2
# A call that ran past the wall-clock limit counts as resource exhaustion only
# if the child was actually working: a slow or overloaded host, or a child
# that waits, uses little CPU and proves nothing about the library.
BUSY_CPU_FRACTION = 0.5
EVENT_KINDS = {"exec", "compile", "write-marker", "write-other", "os.system", "os.exec",
               "os.posix_spawn", "os.spawn", "subprocess.Popen", "socket.connect", "ctypes.dlopen"}
CRASH_SIGNALS = {signal.SIGSEGV, signal.SIGBUS, signal.SIGABRT, signal.SIGFPE, signal.SIGILL}
REPORT_MAX = 256 * 1024


def make_nondumpable():
    try:
        ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE = 4
    except Exception:
        pass


def library_allowlists():
    """Every function name in PyYAML's own source, and its exception classes."""
    import sqlparse as _lib
    lib_dir = os.path.dirname(os.path.abspath(_lib.__file__))
    functions = set()
    for name in os.listdir(lib_dir):
        if not name.endswith(".py"):
            continue
        with open(os.path.join(lib_dir, name), encoding="utf-8") as handle:
            code = compile(handle.read(), name, "exec")
        stack = [code]
        while stack:
            current = stack.pop()
            functions.add("%s:%s" % (name, current.co_name))
            stack.extend(c for c in current.co_consts if hasattr(c, "co_code"))
    exceptions = {n for n in dir(builtins) if isinstance(getattr(builtins, n), type)
                  and issubclass(getattr(builtins, n), BaseException)}
    for module_name in list(sys.modules):
        if module_name == "sqlparse" or module_name.startswith("sqlparse."):
            module = sys.modules[module_name]
            for attr in dir(module):
                value = getattr(module, attr, None)
                if isinstance(value, type) and issubclass(value, BaseException):
                    exceptions.add(attr)
    return _lib.__version__, functions, exceptions


def clean_frames(frames, allowed):
    if not isinstance(frames, list):
        return [], 0
    kept = [f for f in frames if isinstance(f, str) and f in allowed]
    return kept[:6], len(frames) - len(kept)


def sanitize(report, functions, exceptions):
    """Keep only allowlisted values from the child's untrusted report."""
    clean = {"exception_type": None, "exception_sha256": None, "exception_frames": [],
             "events": [], "dropped_values": 0}
    if not isinstance(report, dict):
        return clean
    exc_type = report.get("exception_type")
    if exc_type is not None:
        clean["exception_type"] = exc_type if exc_type in exceptions else "OtherException"
    digest = report.get("exception_sha256")
    if isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest):
        clean["exception_sha256"] = digest
    clean["exception_frames"], dropped = clean_frames(report.get("exception_frames"), functions)
    clean["dropped_values"] += dropped
    events = report.get("events") if isinstance(report.get("events"), list) else []
    for event in events[:40]:
        if not isinstance(event, dict) or event.get("event") not in EVENT_KINDS:
            clean["dropped_values"] += 1
            continue
        frames, dropped = clean_frames(event.get("library_frames"), functions)
        clean["dropped_values"] += dropped
        clean["events"].append({"event": event["event"], "in_library": bool(frames), "library_frames": frames})
    return clean


def limit_child():
    memory = CALL_MEMORY_MB * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    resource.setrlimit(resource.RLIMIT_CPU, (CALL_SECONDS, CALL_SECONDS + 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run(entry, payload_bytes):
    os.mkdir(MARKER_DIR, 0o700)  # fails if it already exists: every run starts clean
    read_fd, write_fd = os.pipe()
    chunks = []

    def drain():
        total = 0
        while True:
            data = os.read(read_fd, 65536)
            if not data:
                break
            if total < REPORT_MAX:
                chunks.append(data[:REPORT_MAX - total])
            total += len(data)

    started = time.monotonic()
    child = subprocess.Popen(
        [sys.executable, "-I", CHILD, entry, PAYLOAD, MARKER, str(write_fd)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        pass_fds=(write_fd,), cwd=MARKER_DIR, env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"},
        preexec_fn=limit_child, start_new_session=True)
    os.close(write_fd)
    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    timed_out = False
    try:
        child.wait(timeout=CALL_SECONDS)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except OSError:
            pass
        child.wait()
    elapsed = time.monotonic() - started
    try:
        os.killpg(child.pid, signal.SIGKILL)  # anything the payload left running
    except OSError:
        pass
    reader.join(2)
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    peak_kb = usage.ru_maxrss
    cpu_seconds = usage.ru_utime + usage.ru_stime
    marker_created = os.path.exists(MARKER)
    try:
        report = json.loads(b"".join(chunks).decode("utf-8"))
    except Exception:
        report = None
    return {"returncode": child.returncode, "timed_out": timed_out, "seconds": round(elapsed, 3),
            "cpu_seconds": round(cpu_seconds, 3), "peak_rss_mb": round(peak_kb / 1024.0, 1),
            "marker_created": marker_created, "report": report}


def classify(observed, clean):
    rc = observed["returncode"]
    sig = -rc if rc is not None and rc < 0 else None
    if observed["marker_created"]:
        return "CODE_EXECUTION", "the marker file appeared, so the library ran the payload as code"
    if observed["timed_out"]:
        cpu = observed.get("cpu_seconds")
        if cpu is not None and cpu < CALL_SECONDS * BUSY_CPU_FRACTION:
            return "INCONCLUSIVE", ("the call ran past the %d s limit but used only %.1f s of CPU, so the host was slow "
                                    "or the child was waiting: that is not evidence of exhaustion" % (CALL_SECONDS, cpu))
        return "RESOURCE_EXHAUSTION", "the library call ran past the %d s limit, busy on the CPU" % CALL_SECONDS
    if sig in (signal.SIGKILL, signal.SIGXCPU):
        return "RESOURCE_EXHAUSTION", "the library call was killed by a resource limit (signal %d)" % sig
    if sig in CRASH_SIGNALS:
        return "CRASH", "the library call died on signal %d" % sig
    if sig is not None:
        return "INCONCLUSIVE", "the child stopped on unexpected signal %d" % sig
    if observed["report"] is None or rc != 0:
        return "INCONCLUSIVE", "the child exited %s without a report" % rc
    # The child's MemoryError alone is not evidence: code the library ran in
    # the child can write any report it likes. Count it only when this
    # process saw the child's memory actually approach the cap.
    if clean["exception_type"] == "MemoryError" and (observed["peak_rss_mb"] or 0) >= MEMORY_EXHAUSTION_MB:
        return "RESOURCE_EXHAUSTION", "the library call ran out of its %d MB memory limit (%.0f MB peak)" % (
            CALL_MEMORY_MB, observed["peak_rss_mb"])
    return "NOT_REPRODUCED", "the library call finished without code execution, crash or resource exhaustion"


def main():
    nonce = sys.stdin.readline().strip()
    sys.stdin.close()
    make_nondumpable()
    version, functions, exceptions = library_allowlists()
    record = {"library": "sqlparse", "library_version": version, "entry_point": None,
              "payload_sha256": None, "payload_bytes": None}
    try:
        with open(JOB, encoding="utf-8") as handle:
            entry = json.load(handle).get("entry_point")
        with open(PAYLOAD, "rb") as handle:
            payload = handle.read(PAYLOAD_MAX_BYTES + 1)
        record.update(entry_point=entry if entry in ENTRY_POINTS else "rejected",
                      payload_sha256=hashlib.sha256(payload).hexdigest(), payload_bytes=len(payload))
        problem = None
        if entry not in ENTRY_POINTS:
            problem = "entry point is not on the allowlist"
        elif len(payload) > PAYLOAD_MAX_BYTES:
            problem = "payload is larger than %d bytes" % PAYLOAD_MAX_BYTES
        else:
            try:
                payload.decode("utf-8")
            except UnicodeDecodeError:
                problem = "payload is not UTF-8"
        if problem:
            record.update(outcome="INVALID_PROOF", why=problem)
        else:
            observed = run(entry, payload)
            clean = sanitize(observed["report"], functions, exceptions)
            outcome, why = classify(observed, clean)
            rc = observed["returncode"]
            record.update(
                outcome=outcome, why=why, exit_code=rc if rc is not None and rc >= 0 else None,
                signal=-rc if rc is not None and rc < 0 else None, timed_out=observed["timed_out"],
                seconds=observed["seconds"], cpu_seconds=observed["cpu_seconds"], peak_rss_mb=observed["peak_rss_mb"],
                marker_created=observed["marker_created"], child_report_received=observed["report"] is not None,
                **clean)
    except Exception as exc:  # a harness fault, never the payload's doing
        record.update(outcome="INCONCLUSIVE", why="harness error: %s" % type(exc).__name__)
    os.write(1, ("@@PROVEIT %s %s\n" % (nonce, json.dumps(record, sort_keys=True))).encode())


if __name__ == "__main__":
    main()
