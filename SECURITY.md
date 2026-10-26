# Security policy

Zero Breach Toolkit is run by people who may be targeted by a state-grade adversary, so
its own integrity matters as much as what it detects.

## Reporting a problem

If you find a security issue in the toolkit itself, please report it privately
rather than opening a public issue. That includes any way to make it leak data,
contact the network during a scan, read more than it should, misreport a result,
or anything else that could put a user at risk.

- Open a **private security advisory** on this repository (the "Security" tab →
  "Report a vulnerability"), or
- message the project on Telegram: https://t.me/+t9gq13mSKcE4NGI0

For a security report, prefer the private advisory; use Telegram if you cannot.

Please include what you found, how to reproduce it, and the impact. We will
acknowledge, investigate, and credit you if you wish.

## What is in scope

- The scanner reading, decrypting, or transmitting anything it should not.
- Any path that makes the scanner touch the network during a scan.
- A result that could be wrong in a way that misleads a user (a false "clean", a
  mislabelled severity, a missed gap).
- The update path (`--update`) fetching from outside its allow-list, or a tampered
  or changed cached indicator file being accepted at scan time.
- The build producing a file that does not match its source.

## What is not a vulnerability

- **A clean result is not a guarantee.** The tool states this itself. Spyware of
  this grade is built to defeat retrospective checks; "it did not find a real
  infection" is a known, documented limitation, not a bug.
- A false *alarm* on a benign indicator match is a tuning issue. Please report it
  as a normal issue; it is not a security vulnerability.

## For users: verifying the tool

Do not run a security tool on trust. Every release will publish the SHA-256 of
its files, and the single-file build is reproducible: you can rebuild
`dist/zero-breach-triage.py` from source and confirm it matches. Every signed release also supplies detached GPG signatures
under ArchiveGenocide's established release key. Check the complete fingerprint
against the official publisher page before trusting a downloaded key. See
[docs/VERIFYING.md](docs/VERIFYING.md).

## Handling indicators responsibly

The indicator set is curated to avoid false alarms against real people. Curation
excludes known compromised victim sites and ambiguous legitimate domains. Historical domains can later change ownership. If you believe an
indicator here is wrong, or would match legitimate traffic, that is worth
reporting: a false positive from this tool can send an
innocent person to a crisis helpline.
