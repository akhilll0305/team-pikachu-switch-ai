Source: REPLAY FIXTURE (synthetic). Used only by scripts/rehearse.py --second-target; not a live submission.

# "sqlparse hangs on my query" (no real evidence)

Claimed impact: denial of service
severity: medium
affected_version: 0.4.3
entry_point: parse

I think this SQL makes the parser slow.

payload: |
  SELECT 1 FROM t WHERE a = 1;
expected: fast
actual: slow (I think)
