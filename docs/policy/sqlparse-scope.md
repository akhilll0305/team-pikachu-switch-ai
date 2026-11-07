# sqlparse scope policy

> **Role:** What Prove It treats as a sqlparse vulnerability, and what it rejects. Intake enforces this before any sandbox run (decision D-015 applies per target); the Skeptic uses the room's scope-policy doc. This is the second target (U4), verified offline, not yet live.

## Threat model

An application passes SQL it did not write (untrusted input) to a documented sqlparse function. The attacker controls only that SQL text: not the application's code, not the function it chose, not the files, network or environment around it.

A report is a vulnerability when that text alone makes sqlparse do something the function is not meant to do: exhaust the time or memory of the one call, crash the interpreter, or run code. sqlparse is a parser, so the realistic class is resource exhaustion — [CVE-2023-30608](https://github.com/andialbrecht/sqlparse/security/advisories/GHSA-rrm6-wvj7-cwh2) (replay 101) is a regular-expression denial of service (ReDoS) in the string-literal lexer.

## In scope

The documented top-level functions, as allowlisted in `proveit/targets.py`:

- `sqlparse.parse` — "Parse the given SQL statement string and return a tuple of `sqlparse.sql.Statement` instances."
- `sqlparse.format` — "Format the given SQL statement string according to the given options."
- `sqlparse.split` — "Split the given SQL statement string into a list of individual statements."

These are the three functions in sqlparse's documented top-level API ([sqlparse documentation, "Split and Format SQL Statements" / API reference](https://sqlparse.readthedocs.io/en/latest/api/)). CVE-2023-30608 reproduces through them because they all run the lexer.

## Out of scope

**sqlparse documents nothing as unsafe for untrusted input, so the out-of-scope entry-point list is empty.** It is a parser with no loader that is meant to execute input:

- [PyPI / documentation](https://pypi.org/project/sqlparse/): "sqlparse is a non-validating SQL parser module for Python."

A proof that names anything other than `parse`, `format` or `split` — including an internal module such as `sqlparse.lexer` or `sqlparse.engine.*` — is refused as **not an allowed entry point** (the `unknown_entry_point` reason), not as "out of scope". Those internals are not part of the documented API, so Prove It neither tests nor reasons about them.

Also out of scope, as for every target: proofs that need network access, other files, environment variables, or code instead of data. The sandbox has no network, a read-only file system and no host environment, and a proof is a UTF-8 text payload only (at most 64 KB).

## What Intake does

A proof that names a function Prove It does not allow never reaches the sandbox. The reporter is told the entry point is not on the allowlist and asked for one of `parse`, `format` or `split`. The reporter can reply in the same thread with a corrected proof. Verified offline (`tests/test_second_target.py`), not yet live.
