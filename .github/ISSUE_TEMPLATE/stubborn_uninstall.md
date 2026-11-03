---
name: Stubborn Program Report
about: Report a program or remnants that obliterator failed to remove
title: "[UNINSTALL FAILED]: "
labels: stubborn-target, bug
assignees: ''
---

## Target Program
- Application name and publisher:
- Installer type (MSI, Inno, NSIS, Store, Portable, Custom):
- Installation directory path:

## Environment
- Windows Version & Build (`winver` or output from `obliterator --diagnose`):
- obliterator version (`obliterator --version`):
- Running in elevated administrator prompt: [Yes / No]

## Dry-run Plan Output
Run the dry-run command with JSON output and paste the output below:
```
obliterator "<target_name_or_path>" --dry-run --json
```

```json
<paste JSON output here>
```

## System Diagnostics
Generate a sanitized system diagnostics report by running:
```
obliterator --diagnose diagnostics.txt
```
(Usernames and personal IDs are automatically masked as `<user>` and `<user-sid>`).

Please attach `diagnostics.txt` or paste relevant sections here:
```
<paste diagnostics.txt here>
```

## Failure Details
- Exact error message or exit code:
- What remained on disk or in the registry after execution:
- Did any process refuse to terminate, or did any service recreate itself:
