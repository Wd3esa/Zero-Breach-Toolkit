# Contributing

Thank you for helping. This tool is run by people at real risk, so a few rules are
strict. They are what keep it trustworthy.

## Running the tests

The default scanner uses the standard library. Install pytest to run the complete test
suite; optional engine/backup fixtures require their separately pinned dependencies.

```
cd scan && python -m pytest -q
```

Every change must keep the suite green. New behaviour needs a test.

Before publishing, run `python tools/release_check.py --require-patterns` in
the virtual environment with the pinned optional engine installed. This builds
and tests the download against controlled fixtures without scanning your own
browser profiles.

## Rebuilding the generated files

The STIX/MISP feeds, the blocklists, the indicator checksum and the single-file
build are all generated from `iocs/adfection_iocs.txt`. After changing indicators,
regenerate everything with one command and commit the result:

```
python build/build.py
```

The build is deterministic: a fresh clone produces a byte-identical `dist/zero-breach-triage.py`.
Run `python build/build.py --check` to check tracked artifact drift, and the release
check to verify reproducibility. These are currently local checks; a repository CI
workflow has not been configured yet.

## Adding artifact readers

Use the shared [reader registry](scan/READERS.md). A new reader supplies its
interface, platform/scope selection and coverage metadata in one registration;
the builder and CLI dispatch use that same definition. Synthetic regressions
must preserve evidence distinctions and prove that hostile inputs stay bounded.

## Adding indicators: read this first

A bad indicator is worse than a missing one: a false match can send an innocent
person to a crisis helpline. So:

- **Only attacker-controlled infrastructure.** Never add a compromised victim
  site, and never add a domain that is, or could be, a real organisation's own
  domain. When in doubt, leave it out.
- **Verify against the primary report**, not news coverage. Put the source in the
  fourth column.
- **No IP addresses from old reporting.** Cloud IPs get reassigned to innocent
  tenants; an undated IP match is noise. The existing `candiru-ip` tier carries
  this caveat.
- **Hashes must be SHA-256.** The scanner computes SHA-256; a SHA-1 would be
  misread as a domain.
- **Update the `# as-of:` date** in the indicator file header when you change the
  set, and rerun `build/build.py`.

## Design rules the code is held to

These are enforced by tests, not convention. A change that breaks one will fail the suite.

- **Never contact an indicator.** The scan's Python socket guard blocks direct
  DNS and network calls. It is not an OS network sandbox: POSIX network mounts
  and concurrent filesystem changes require OS isolation for strict offline use.
  The separate `--update` command downloads indicators from a fixed allow-list.
  Guided Android acquisition also downloads and runs a pinned collector after consent.
  Neither network operation is invoked during an offline scan.
- **Measured, never inferred.** A check that could not run is a reported gap, never
  a clean result.
- **Query only what is needed.** Cookie queries select host metadata and
  timestamps, not values. Temporary snapshots copy complete database bytes;
  the scanner does not decrypt browser credentials.
- **Precision over coverage.** An unsigned binary in a user-writable path is not a
  finding. Alarms that mean nothing teach people to ignore the tool.
- **Read-only default scanning, no administrator, no telemetry, Python 3.8+.**
  Optional pattern and encrypted-backup support have separate dependencies.

## Style

Match the surrounding code. Comments explain *why*, not *what*. Keep the plain
language of the report text. A frightened non-technical person reads it.

## Questions

Not sure about something, or want to talk through a change before you build it? Reach the project on **Telegram**: https://t.me/+t9gq13mSKcE4NGI0.
