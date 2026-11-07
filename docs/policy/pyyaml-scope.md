# PyYAML scope policy

> **Role:** What Prove It treats as a PyYAML vulnerability, and what it rejects as out of scope. Intake enforces this before any sandbox run (decision D-015 in [context.md](../../context.md#key-decisions)); the Skeptic uses the `out_of_scope_api` reason code for anything that slips past.

## Threat model

An application loads YAML it did not write (untrusted input) through a PyYAML entry point. The attacker controls only that YAML document: not the application's code, not the loader it chose, not the files, network or environment around it.

A report is a vulnerability when that document alone makes PyYAML do something the entry point is documented not to do: run code, crash the interpreter, or exhaust the time or memory of the one call.

## In scope

The entry points meant for untrusted or general input, as allowlisted in `proveit/config.py`:

- `yaml.safe_load` and `yaml.load(..., Loader=yaml.SafeLoader)`
- `yaml.full_load` and `yaml.load(..., Loader=yaml.FullLoader)`

`full_load` is in scope because it is documented as avoiding arbitrary code execution; CVE-2020-14343 (replay 01) is exactly a case where it did not. PyYAML's own wiki warns that FullLoader still had exploits in 5.3.1, which is the bug, not a reason to rule it out.

## Out of scope

- `yaml.unsafe_load`, `yaml.unsafe_load_all`, `yaml.load(..., Loader=yaml.UnsafeLoader)` and `yaml.load(..., Loader=yaml.Loader)`. PyYAML documents these as unsafe for untrusted input, so code execution through them is the documented behaviour, not a vulnerability:
  - [PyYAML Documentation](https://pyyaml.org/wiki/PyYAMLDocumentation): "Warning: It is not safe to call `yaml.load` with any data received from an untrusted source!"
  - [PyYAML wiki: yaml.load(input) Deprecation](https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation): "`UnsafeLoader` (also called `Loader` for backwards compatability)", "The original Loader code that could be easily exploitable by untrusted data input."
- Any other loader PyYAML documents as unsafe for untrusted input.
- Proofs that need network access, other files, environment variables, or code instead of data. The sandbox has no network, a read-only file system and no host environment, and a proof is a YAML payload only.

The C loaders (`CSafeLoader`, `CFullLoader` and so on) are not out of scope, but they cannot be compared across both pinned builds here (the 5.3.1 image has no libyaml), so Intake refuses them with a different reason.

## What Intake does

A proof that names an out-of-scope entry point never reaches the sandbox. The reporter gets this fixed answer, naming the entry point by its canonical name, never in the reporter's own words:

> R-NNN: yaml.unsafe_load is documented by PyYAML as unsafe for untrusted input, so it is out of scope (see the scope policy). Can you show the issue with safe_load or full_load?

The reporter can reply in the same thread with a corrected proof. Verified offline (`tests/test_scope.py`), not yet live.
