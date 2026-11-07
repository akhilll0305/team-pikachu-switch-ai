"""Paths, the one target project, and the rules a proof of concept must follow."""

import hashlib
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WORK_DIR = REPO_ROOT / "work"
WORK_DIR = Path(os.environ.get("PROVEIT_WORK_DIR", DEFAULT_WORK_DIR))
REPLAYS_DIR = REPO_ROOT / "reports" / "replays"
TARGET_DIR = REPO_ROOT / "target"


def _checkout_home():
    """~/.proveit/<checkout>-<hash>: everything the agents must never read.

    It holds reporter material (private/), Intake's credentials, the replay
    login and the sandbox's staging mounts. It lives in the home folder, not in
    the checkout, so the agents' configs can deny it by a path that does not
    depend on where the checkout is: Codex's permission profile says
    "~/.proveit" = "none", Claude's settings deny Read(~/.proveit/**). Docker
    Desktop and Colima share the home folder with their VM, so the staging
    mounts still work there.
    """
    key = hashlib.sha256(str(REPO_ROOT).encode("utf-8")).hexdigest()[:8]
    return Path.home() / ".proveit" / ("%s-%s" % (REPO_ROOT.name, key))


PROVEIT_HOME = Path(os.environ.get("PROVEIT_HOME") or _checkout_home())


def ensure_home():
    """Create ~/.proveit/<checkout> if needed, readable by this user only."""
    PROVEIT_HOME.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(PROVEIT_HOME, 0o700)
    return PROVEIT_HOME
LEGACY_STATE_DIR = REPO_ROOT / ".proveit"  # where versions before 2026-11-05 kept credentials

# The pinned target. PyYAML's CVE-2020-14343 is triggered by a YAML document
# alone, and the fix landed in a single release (5.3.1 vulnerable, 5.4 patched).
TARGET = {
    "name": "PyYAML",
    "package": "yaml",
    "builds": {
        "vulnerable": {"version": "5.3.1", "image": "proveit-target:vulnerable"},
        "patched": {"version": "5.4", "image": "proveit-target:patched"},
    },
}

# A proof of concept is DATA: a YAML payload plus one entry point from this
# list. The trusted harness calls the entry point on the payload; reporters
# never send code. These are the loaders PyYAML documents as safe (SafeLoader)
# or as meant to avoid code execution (FullLoader) in 5.x. The C variants are
# left out because the 5.3.1 image has no libyaml (yaml.__with_libyaml__ is
# False there), so they could not be compared across both builds.
ENTRY_POINTS = {
    "safe_load": "yaml.safe_load(payload)",
    "full_load": "yaml.full_load(payload)",
    "load:SafeLoader": "yaml.load(payload, Loader=yaml.SafeLoader)",
    "load:FullLoader": "yaml.load(payload, Loader=yaml.FullLoader)",
}
# PyYAML documents these as unsafe by design ("UnsafeLoader ... also called
# Loader for backwards compatibility"). Using them is not a vulnerability.
UNSAFE_ENTRY_POINTS = ("yaml.unsafe_load", "yaml.unsafe_load_all", "yaml.UnsafeLoader", "yaml.Loader")
PAYLOAD_MAX_BYTES = 64 * 1024

# The harness creates this directory fresh for every run. Code execution is
# proven when the file appears in it: only the library, running attacker
# input, can create it, because the reporter sends no code.
MARKER_DIR = "/tmp/proveit"
MARKER_PATH = MARKER_DIR + "/marker"

# Limits for the one library call (enforced inside the container on the child
# process), and for the container as a whole.
CALL_LIMITS = {"seconds": 10, "memory_mb": 192}
SANDBOX_LIMITS = {
    "memory": "256m",
    "pids": "64",
    "cpus": "1",
    "timeout_seconds": 20,
}

# How many times one `check` runs the payload: one after another, each in a
# brand-new container with the limits above, nothing shared between runs. All
# runs must agree for the check to have an outcome; if they differ the check
# records NOT_RELIABLY_REPRODUCED. Deliberately not an environment variable,
# so an agent's shell cannot lower it.
CHECK_RUNS = 3

# A reporter whose proofs failed this many times (closed as NOT_REPRODUCED or
# NOT_RELIABLY_REPRODUCED, or rejected at Intake; at most one per ticket) may
# have only one open report at a time until a maintainer runs clear-reporter
# (decision D-018). Never a ban. Not an environment variable.
INVALID_THRESHOLD = 2

PROOF_CONTRACT = {
    "code_execution": (
        "The payload must make the library itself execute code that creates "
        "the file `%s`. Nothing else runs in the sandbox, so the file can only "
        "appear if the library ran your input as code." % MARKER_PATH
    ),
    "denial_of_service": (
        "The payload must make the one library call run longer than %d seconds "
        "or use more than %d MB of memory. The sandbox measures both."
        % (CALL_LIMITS["seconds"], CALL_LIMITS["memory_mb"])
    ),
    "crash": (
        "The payload must make the library crash the interpreter with a native "
        "fault (a signal such as SIGSEGV), not just raise a Python exception."
    ),
    "info_leak": (
        "Information leaks are never decided automatically; a maintainer reads "
        "the evidence."
    ),
}

# The proof request lists four fields (decision D-016). affected_version is required; expected and
# actual are the reporter's own words and stay in the private report, never in the ticket.
POC_FORMAT_HELP = (
    "Send the proof as four fields (an example):\n"
    "```\n"
    "affected_version: 5.3.1\n"
    "entry_point: full_load\n"
    "payload: |\n"
    "  <YAML>\n"
    "expected: <what should happen>\n"
    "actual: <what happens>\n"
    "```\n"
    "The proof is data, not code: `entry_point` is one of %s, and `payload` is the YAML document "
    "(UTF-8, at most %d KB; a ```yaml block works too). `affected_version` is required. Python scripts "
    "are not accepted, and the loaders PyYAML documents as unsafe (unsafe_load, UnsafeLoader, Loader) "
    "are out of scope because using them is not a vulnerability."
    % (", ".join("`%s`" % k for k in ENTRY_POINTS), PAYLOAD_MAX_BYTES // 1024)
)
