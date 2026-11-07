"""Stand-in for the `proveit` package inside the reproducer's working folder.

The Switch template starts the Reproducer in agents/reproducer/. There, `python -m
proveit ...` finds this folder first (Python puts the working folder at the
front of the module search path for `-m`). This stub:

1. points the package's search path at the real proveit/ in the checkout, so
   the command works without PYTHONPATH. On 2026-11-07 the Switch-managed
   Skeptic's `python -m proveit evidence` failed with "No module named
   proveit": its session did not apply PYTHONPATH from the agent's config.
2. fixes this folder's role, so the CLI's agent limits hold even when the
   session's environment variables are missing. Without them the CLI would
   treat the shell as a human maintainer.

The real package is found from this file's location, never from the
environment, so it works wherever the checkout is.
"""

import os

ROLE = "reproducer"

# The folder decides the role. An environment variable can't widen it.
os.environ["PROVEIT_ACTOR"] = "agent"
os.environ["PROVEIT_AGENT"] = ROLE
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")

_ROOT = os.path.dirname(os.path.abspath(__file__))
while True:
    _REAL = os.path.join(_ROOT, "proveit")
    if os.path.isfile(os.path.join(_REAL, "cli.py")):
        break
    _PARENT = os.path.dirname(_ROOT)
    if _PARENT == _ROOT:
        raise ImportError("Prove It's package was not found above %s; is this folder inside a Prove It checkout?" % __file__)
    _ROOT = _PARENT
__path__ = [_REAL]
__file__ = os.path.join(_REAL, "__init__.py")
with open(__file__, encoding="utf-8") as _handle:
    exec(compile(_handle.read(), __file__, "exec"))
