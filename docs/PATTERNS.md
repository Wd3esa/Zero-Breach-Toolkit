# Optional Candiru file patterns

The toolkit includes an optional check for Candiru files. The default scan does not run it.

## What it checks

`--patterns` scans local file bytes with two unchanged published Candiru rules:
Microsoft's 2021 DevilsTongue hijack-DLL rule and Malpedia's automatically
generated DevilsTongue rule. The latter was derived from unpacked files or
memory dumps. A new date on a rule does not establish coverage of a new campaign.
Neither rule proves infection, execution, or coverage of every Candiru build.
This mode does not acquire or scan running memory, decrypt payloads, inspect
phone backups, or add Pegasus detection.

## Setup

The default scanner still requires only Python's standard library. Pattern
scanning additionally requires Python 3.9+ and the pinned official YARA-X 1.21.0
wheel. `requirements-patterns.txt` pins all published wheel SHA-256 values and
rejects source builds. Install into a dedicated environment during setup:

```text
python -m venv .venv
<venv-python> -m pip install -r requirements-patterns.txt
<venv-python> scan/zero-breach-triage.py --patterns
```

The scanner never installs packages, downloads rules, or contacts sample/IOC
servers. Without the requested engine it reports UNKNOWN with an explicit gap.
Python 3.8 remains supported for the default checks.

## Choosing what to scan

`--pattern-path ABSOLUTE_PATH` can be repeated to choose files or folders for
the pattern check. Without it, the check uses the existing file-hash roots.
It limits only the pattern check: browser, hash and host checks keep their
usual scope. `--quick` skips hashes but still runs explicitly requested patterns.
Relative, redirected and cloud-recall paths are refused. Windows UNC paths and
remote drives are refused. On POSIX systems, a network-mounted directory can
look like an ordinary absolute path and may be read; use operating-system
network isolation when strict offline operation is required. Files are eligible
regardless of extension. Per-file size and time limits, traversal and
total-byte limits, directory exclusions, unreadable files and other coverage
gaps are described in the module output. A limit is never treated as a completed
clean check.

## Reading a match

The JSON evidence grade is `file-pattern`, separate from exact hash evidence
(`on-disk`). The human report asks for review and preserves rule authorship,
source and licence. A pattern match needs investigation; it is not a measured
detection rate or proof of broad Candiru coverage. Rule provenance and original
texts are under `third_party/candiru/`; these rules are not covered by the IOC
feed's CC0 grant.
