Title: CRITICAL Remote Code Execution in yaml.safe_load (CVSS 9.8)
Reporter: replay, synthetic
Source: synthetic, modelled on the patterns in curl's publicly disclosed AI slop reports (https://gist.github.com/bagder/07f7581f6e3d78ef37dfbfc81fd1d1cd). Not a real report.
Severity: critical
Affected version: 5.3.1
Component: yaml.safe_load
Claimed impact: remote code execution in any application that calls yaml.safe_load on user input

## Summary

I have identified a critical remote code execution vulnerability in the
`yaml.safe_load` function of PyYAML. Despite its name, `safe_load` fails to
properly sanitize the `!!python/object/apply` tag, which allows an attacker
to execute arbitrary operating system commands. This vulnerability affects
millions of applications worldwide and should be treated as an emergency.

## Impact

An attacker can achieve full remote code execution, leading to complete
system compromise, data exfiltration and lateral movement.

## Remediation

Upgrade PyYAML and validate all input before parsing.

A proof of concept is available on request.
