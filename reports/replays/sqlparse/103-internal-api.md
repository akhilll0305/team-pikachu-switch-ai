Source: REPLAY FIXTURE (synthetic). Used only by scripts/rehearse.py --second-target; not a live submission.

# "bug in sqlparse.lexer"

Claimed impact: denial of service
severity: low
affected_version: 0.4.3
entry_point: sqlparse.lexer.tokenize

```sql
'\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
```
expected: fast
actual: slow
