"""Running one proof of concept (entry point + YAML payload) in a locked-down container."""

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import config, judge, poc, targets
from .config import SANDBOX_LIMITS, ensure_home

HARNESS_FILES = ("Dockerfile", "harness.py", "child.py")


# Every Docker call has a timeout, so a stuck daemon fails loudly instead of hanging a command.
PROBE_TIMEOUT = 20      # docker info, image inspect, docker kill
BUILD_TIMEOUT = 1800    # building an image from scratch (downloads and compiles PyYAML)


class SandboxError(RuntimeError):
    pass


def _docker(cmd, timeout, **kwargs):
    """Run one docker command with a timeout; a timeout raises SandboxError with what was running."""
    try:
        return subprocess.run(cmd, timeout=timeout, **kwargs)
    except subprocess.TimeoutExpired:
        raise SandboxError("`%s` did not finish within %d s; is Docker responding? (try `docker info`)"
                           % (" ".join(cmd[:3]), timeout)) from None


def docker_available():
    """A running Docker engine that runs Linux containers (Docker Desktop in Windows-containers mode cannot)."""
    if not shutil.which("docker"):
        return False
    try:
        probe = _docker(["docker", "info", "--format", "{{.OSType}}"], PROBE_TIMEOUT,
                        capture_output=True, text=True)
    except SandboxError:
        return False
    return probe.returncode == 0 and probe.stdout.strip().lower() == "linux"


def harness_digest(target=None):
    """Changes whenever the image's inputs change, so stale images get rebuilt.

    Hashes the target's own `target_dir`; PyYAML's stays `target/`, so its
    digest is unchanged.
    """
    target = target or targets.PYYAML
    digest = hashlib.sha256()
    for name in HARNESS_FILES:
        digest.update((target.target_dir / name).read_bytes().replace(b"\r\n", b"\n"))
    return digest.hexdigest()[:16]


def image_current(image, target=None):
    target = target or targets.PYYAML
    probe = _docker(["docker", "image", "inspect", "--format",
                     '{{ index .Config.Labels "proveit.harness" }}', image], PROBE_TIMEOUT,
                    capture_output=True, text=True)
    return probe.returncode == 0 and probe.stdout.strip() == harness_digest(target)


def image_id(image):
    """The image's content ID (sha256:...), recorded with every run so the evidence names the exact image."""
    probe = _docker(["docker", "image", "inspect", "--format", "{{.Id}}", image], PROBE_TIMEOUT,
                    capture_output=True, text=True)
    if probe.returncode != 0 or not probe.stdout.strip().startswith("sha256:"):
        raise SandboxError("could not read the image ID of %s: %s" % (image, _last_line(probe.stderr)))
    return probe.stdout.strip()


def _last_line(text):
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return lines[-1][:300] if lines else "no output from Docker"


def build(build_name=None, force=False, quiet=True, target=None):
    """Build the target images. Needs network once; runs never do."""
    target = target or targets.PYYAML
    names = [build_name] if build_name else list(target.builds)
    built = []
    for name in names:
        spec = target.builds[name]
        if image_current(spec["image"], target) and not force:
            continue
        cmd = ["docker", "build", "--build-arg", "%s=%s" % (target.build_arg, spec["version"]),
               "--label", "proveit.harness=%s" % harness_digest(target), "-t", spec["image"], str(target.target_dir)]
        # A disk-backed log avoids a blocking stdout iterator and bounds the wait
        # even when Docker goes silent or leaves an inherited output pipe open.
        with tempfile.TemporaryFile(mode="w+b") as output:
            proc = subprocess.Popen(cmd, stdout=output, stderr=subprocess.STDOUT)
            try:
                proc.wait(timeout=BUILD_TIMEOUT)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=PROBE_TIMEOUT)
                raise SandboxError("building %s took longer than %d s" % (spec["image"], BUILD_TIMEOUT)) from None
            output.seek(0)
            lines = output.read().decode("utf-8", "replace").splitlines(keepends=True)
        tail = lines[-60:]
        if not quiet:
            out_encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
            for line in lines:
                print(line.encode(out_encoding, "replace").decode(out_encoding), end="")
        if proc.returncode != 0:
            hint = ""
            if any("do not match the hashes" in line or "THESE PACKAGES DO NOT MATCH" in line for line in tail):
                hint = ("\nA download did not match its SHA-256: a corrupted download, proxy or cache, not the "
                        "Dockerfile. Retry, or run `docker builder prune` and build again.")
            raise SandboxError("building %s failed (exit %s). Last lines of Docker's output:\n%s%s" % (
                spec["image"], proc.returncode, "".join(tail).rstrip(), hint))
        built.append(spec["image"])
    return built


def docker_flags(name, poc_dir):
    """Every isolation flag a run uses. Tests reuse this list unchanged."""
    limits = SANDBOX_LIMITS
    return [
        "docker", "run", "--rm", "-i", "--name", name,
        "--network", "none",
        "--read-only",
        "--tmpfs", "/tmp:rw,size=16m,mode=1777",
        "--memory", limits["memory"], "--memory-swap", limits["memory"],
        "--pids-limit", limits["pids"],
        "--cpus", limits["cpus"],
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--env", "PYTHONDONTWRITEBYTECODE=1",
        "-v", "%s:/poc:ro" % poc_dir,
    ]


def _mount_root():
    """Where the read-only /poc mount is staged: under ~/.proveit/<checkout>/mounts, not the system temp folder.

    Docker Desktop and Colima on macOS share the home folder with their VM but
    not macOS's /var/folders temp directory, so a mount from there arrives empty.
    The staged payload is reporter material, so it lives with the rest of it,
    where neither agent may read.
    """
    root = ensure_home() / "mounts"
    root.mkdir(exist_ok=True)
    return root


def _readable_by_sandbox(folder):
    """The container runs as uid 65534; on Linux hosts it must be able to read the read-only mount."""
    os.chmod(folder, 0o755)
    for child in Path(folder).iterdir():
        os.chmod(child, 0o644)


# `docker run` itself failed (daemon error, cannot run the image, command not found): no container ran the proof.
DOCKER_START_FAILURES = (125, 126, 127)


def _remove(name):
    """Make sure a container is gone after a timeout or an error (--rm covers the normal case)."""
    for cmd in (["docker", "kill", name], ["docker", "rm", "-f", name]):
        try:
            subprocess.run(cmd, capture_output=True, timeout=PROBE_TIMEOUT)
        except (subprocess.TimeoutExpired, OSError):
            pass  # --rm and the container's own limits still end it


def _execute(cmd, stdin_text, name):
    """Run one container. Returns (exit code, stdout, stderr, timed out)."""
    try:
        proc = subprocess.run(cmd, input=stdin_text, capture_output=True, text=True,
                              timeout=SANDBOX_LIMITS["timeout_seconds"])
        return proc.returncode, proc.stdout or "", proc.stderr or "", False
    except subprocess.TimeoutExpired as exc:
        _remove(name)
        out, err = exc.stdout or "", exc.stderr or ""
        decode = lambda b: b.decode(errors="replace") if isinstance(b, bytes) else b  # noqa: E731
        return None, decode(out), decode(err), True
    except OSError as exc:
        raise SandboxError("could not start docker: %s" % exc) from None


def invalid_record(entry_point, payload, build_name, why, target=None):
    target = target or targets.PYYAML
    data = payload.encode("utf-8", "surrogatepass") if isinstance(payload, str) else (payload or b"")
    spec = target.builds[build_name]
    return {"outcome": "INVALID_PROOF", "why": why, "build": build_name, "image": spec["image"],
            "target": target.key, "target_name": target.name,
            "target_version": spec["version"], "entry_point": entry_point if entry_point in target.entry_points else "rejected",
            "payload_sha256": hashlib.sha256(data).hexdigest(), "payload_bytes": len(data), "ran": False}


def run_poc(entry_point, payload, build_name="vulnerable", target=None):
    """Run one payload against one build, in one new container. Returns the record the harness's parent wrote.

    Raises SandboxError when Docker could not start the container at all: that
    is an infrastructure problem, never an outcome.
    """
    target = target or targets.PYYAML
    problem = target.validate(entry_point, payload)
    if problem:
        return invalid_record(entry_point, payload, build_name, poc.PROBLEMS[problem], target)
    spec = target.builds[build_name]
    if not image_current(spec["image"], target):
        if not target.lazy_build:
            raise SandboxError("image %s is missing; build it with `python -m proveit build --target %s`"
                               % (spec["image"], target.key))
        build(build_name, target=target)
    iid = image_id(spec["image"])
    nonce = secrets.token_hex(16)
    name = "proveit-run-%s" % nonce[:12]
    with tempfile.TemporaryDirectory(prefix="proveit-", dir=_mount_root()) as tmp:
        poc_dir = Path(tmp)
        (poc_dir / "job.json").write_text(json.dumps({"entry_point": entry_point}), encoding="utf-8")
        (poc_dir / "payload.yaml").write_bytes(payload.encode("utf-8"))
        _readable_by_sandbox(poc_dir)
        exit_code, stdout, stderr, timed_out = _execute(docker_flags(name, poc_dir) + [spec["image"]], nonce + "\n", name)

    prefix = "@@PROVEIT %s " % nonce
    lines = [line for line in stdout.splitlines() if line.startswith(prefix)]
    if not lines and not timed_out and exit_code in DOCKER_START_FAILURES:
        _remove(name)
        raise SandboxError("docker could not start the container (exit %s): %s" % (exit_code, _last_line(stderr)))
    if len(lines) == 1:
        record = json.loads(lines[0][len(prefix):])
    else:
        record = {"outcome": "INCONCLUSIVE",
                  "why": "the sandbox timed out" if timed_out else "the harness did not return exactly one record"}
    record.update({"build": build_name, "image": spec["image"], "image_id": iid, "container": name,
                   "target": target.key, "target_name": target.name,
                   "target_version": spec["version"], "container_exit_code": exit_code,
                   "container_timed_out": timed_out, "ran": True})
    return record


def run_check(entry_point, payload, build_name="vulnerable", runs=None, target=None):
    """One check: the payload runs `runs` times (config.CHECK_RUNS), one after another, each in a new container.

    Returns the combined record (judge.combine). If Docker cannot start any
    one of the runs, the whole check is abandoned with SandboxError and
    nothing is returned to record: an infrastructure error is never an outcome.
    """
    target = target or targets.PYYAML
    runs = config.CHECK_RUNS if runs is None else runs
    records = []
    for n in range(1, runs + 1):
        try:
            record = run_poc(entry_point, payload, build_name, target=target)
        except SandboxError as exc:
            raise SandboxError("could not start sandbox run %d of %d: %s. No outcome was recorded." % (n, runs, exc)) from None
        if not record.get("ran"):
            return judge.combine([record])  # an invalid proof is refused on the host: no container runs at all
        record["run"] = n
        records.append(record)
    return judge.combine(records)


def run_probe(code, build_name="vulnerable", timeout=None, target=None):
    """Tests only: run Python code in a container with exactly the flags a PoC run gets."""
    spec = (target or targets.PYYAML).builds[build_name]
    name = "proveit-probe-%s" % secrets.token_hex(6)
    with tempfile.TemporaryDirectory(prefix="proveit-", dir=_mount_root()) as tmp:
        _readable_by_sandbox(tmp)
        cmd = docker_flags(name, tmp) + ["--entrypoint", "python", spec["image"], "-I", "-c", code]
        exit_code, stdout, _, timed_out = _execute(cmd, "", name)
    return {"exit_code": exit_code, "output": stdout, "timed_out": timed_out}
