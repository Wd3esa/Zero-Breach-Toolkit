# Zero Breach Toolkit - scanner

See the [project README](../README.md) for current installation, Android collection
support and scope. Optional Candiru pattern dependencies and limits are documented in
[PATTERNS.md](../docs/PATTERNS.md).

A local, read-only check for published mercenary spyware indicators,
with explicit reporting of missing evidence and checks that could not run.

On Linux and macOS, run `python3 scan/zero-breach-triage.py` from the project
root, or `sh scan/run-scan.sh`. Browser/file checks and selected native startup
configuration readers are available. Windows live checks are selected only on
Windows. Copied Prefetch/Amcache files can be checked with targeted scope;
compressed Prefetch currently needs Windows.

## What it tells you, and what it cannot

It answers two questions honestly:

1. Are the published indicators present in the places this machine can actually
   be checked?
2. What evidence survives, and what could not be checked? Manual DNS-history
   setup is documented below.

**A clean result means "no known indicators were found in the places that can be
checked." It does not mean the device is clean.** Spyware of this grade is
purpose-built to defeat exactly this class of check. The tool says so on every
run, and it reports a check that *could not run* as `UNKNOWN`, never as clean:
a gap and a clean result are different answers and are never merged.

If you have a concrete reason to suspect this machine, the answer is expert
forensics, not this tool:

- [Access Now Digital Security Helpline](https://www.accessnow.org/help/)
- [Amnesty International Security Lab](https://securitylab.amnesty.org/)
- [The Citizen Lab](https://citizenlab.ca/)

## Running it

No dependencies beyond Python 3.8+. No installation.

```
cd scan
python -X utf8 zero-breach-triage.py
```

```
python zero-breach-triage.py [--quick] [--phone FOLDER] [--json PATH] [--share-json PATH] [--iocs PATH]
```

| flag | effect |
|---|---|
| *(none)* | interactive start menu; noninteractive input runs the standard check |
| `--no-menu` | disable start and follow-up menus |
| `--post-menu` | inspect evidence, review gaps and export after an explicit interactive scan |
| `--report PATH` | also save the readable report |
| `--evidence-bundle PATH` | create a new private, unencrypted ZIP of reports and provenance |
| `--evidence-file PATH` | explicitly add an original local file to the evidence ZIP; repeatable |
| `--quick` | skip file fingerprinting (~halves the runtime). The skip is reported as a gap, not as clean. |
| `--json PATH` | also write the machine-readable report |
| `--share-json PATH` | write counts, scope labels, verdict and fixed advice without target paths, artifact text or indicator values |
| `--iocs PATH` | use an explicit indicator file instead of the curated sets and downloaded cache; repeatable |
| `--update` | separately refresh published sources in the local cache |
| `--phone FOLDER` | read an AndroidQF folder or experimental local iPhone backup |
| `--patterns` | opt-in, bounded check against two published Candiru file rules; requires Python 3.9+ and the pinned optional YARA-X wheel |
| `--pattern-path ABSOLUTE_PATH` | file or folder for the optional pattern check; repeatable and requires `--patterns` |

Exit codes: `0` no actionable matches and no recorded gaps; `2` matches beyond saved
references; `3` no actionable matches but evidence or indicator sources were incomplete;
`1` setup/argument/output error; `4` left the start menu without scanning or creating a
scan report. References remain visible and use `0` or `3`. This release changes no system
settings and needs no administrator for default checks. `--scan-type full` broadens file
and app-cache coverage in the usual roots. `--scan-type targeted --target PATH` confines
checks to selected paths; repeat targets as needed. `--preview` shows scope without scanning.
`--extended-windows` reads additional existing logs without enabling them or elevating.
`--phone-guide android|ios` provides preparation steps; `--backup-password` privately prompts
for encrypted phone backups. See [coverage](../docs/COVERAGE.md) for what each check reads
and its limits.
Locked SQLite databases may be copied to temporary snapshots, which are removed
after use. `--json PATH` writes the report you request.

### Modules

| module | what it reads |
|---|---|
| `browser` | history, cookies, favicons, HTTP cache, LevelDB and Service Worker caches across Chrome / Edge / Brave / Vivaldi / Chromium (every profile) and Firefox. Locked databases are copied before being opened. |
| `hash` | SHA-256 of candidate files under AppData, ProgramData, both Temps, Downloads, Desktop, Documents and Public, against the sample hashes in the IOC set. |
| `host` | per-user COM registrations (this chain's documented persistence), the DNS resolver cache, up to 50,000 recent retained DNS-history events on Windows, and the hosts file. Older retained events are an explicit gap. |
| `patterns` (optional) | file bytes checked against two published Candiru research rules; without an explicit pattern path, safely checks up to 128 local user-writable COM server files first. A match needs investigation and cannot confirm infection. |

Why the browser module looks at the cache and not just history: history records
only top-level navigations, and an ad is a subresource inside an iframe. A real
impression would never appear in history. The cache, cookie stores and LevelDB
files do record subresource origins, and they are short-lived, which is part of
the honest answer about how far back any of this can see.

## Turning on DNS history (the one thing worth doing for next time)

The single biggest finding from the reference machine was that
`Microsoft-Windows-DNS-Client/Operational` **is disabled by default on Windows**.
On a normal machine there is therefore no DNS history at all, which is why the
2024–2025 window in which the Al Jazeera devices were hit cannot be checked
retrospectively. That cannot be fixed backwards. It can be fixed forwards, in one
command, and the report prints it for you when it finds the log disabled:

```
# in an Administrator PowerShell
wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true /ms:67108864
```

`/e:true` turns the log on; `/ms` sizes it to 64 MB so it holds months rather
than hours. Turn it back off with the same line and `/e:false`. This protects
nothing and tells you nothing about the past; it just means a future scan has a
record to search instead of an empty attic.

The scanner does not enable DNS logging or alter system configuration. The command above
is a separate manual choice and only affects future records.

## Rules the code is held to

- **Never contact an indicator.** No DNS resolution, ping, HTTP or WHOIS of any
  indicator, ever. Resolving a C&C domain announces a possible victim to the
  people running it. A runtime guard blocks Python network calls. Local-path
  guards reject redirected paths and Windows remote drives; POSIX network mounts
  can appear local and may be read. Certificate verification that could
  retrieve data is disabled. The guard is not an OS network sandbox. Automated
  checks reject network-capable imports; `urllib.parse` is
  permitted solely for lexical URL parsing.
- **No telemetry.** None, of any kind.
- **Measured, never inferred.** If a check could not run, it is `UNKNOWN`.
- **Precision over coverage.** An unsigned binary in a user-writable path is not
  a finding; plenty of honest software looks like that. Fourteen scary findings
  that mean nothing teach people to ignore the tool.
- **Read-only by default**, and nothing writes without an explicit flag.
- **No administrator** required for the default scan.

## Tests

```
cd scan
python -X utf8 -m pytest -q
```

## Emitters

`../build/emit_stix.py` and `../build/emit_misp.py` turn the same curated IOC
file into a STIX 2.1 bundle and a MISP event, written to `../dist/`. STIX because
Amnesty's **MVT** already does mobile forensics well and consumes it; the right
move is to hand MVT users the indicators, not to rebuild MVT. MISP because
institutions deploy by policy: one newsroom admin importing one event protects
everyone behind the gateway.

Delivery-tier ad infrastructure is deliberately *not* marked `to_ids` in the MISP
event. An ad impression is not proof of infection, and shipping it as a detection
signature would bury an analyst in false positives.

## Attribution

The indicators come from The Citizen Lab's *Exposing AdFection* (2026-10-15) and
Confiant's companion *ADINT* report. **Neither is affiliated with this tool and
neither endorses it.** Their report is the source; the tool is not theirs.


`--collect-android DIR` is an experimental, explicit network/acquisition command, separate from scanning.
It downloads a pinned official AndroidQF collector, verifies its SHA-256 and asks for the
owner's consent before launching. Plaintext archives are extracted and checked locally;
`--age-recipient-file PATH` supplies public recipients for encrypted archives retained for
separate analysis. A successful encrypted acquisition is not a completed scan.
Requested encryption refuses plaintext output before extraction. Age-envelope framing is
checked, but recipient/authentication verification requires separate decryption. Failed
acquisitions retain original/partial output, which may be unencrypted; inspect the reported folder.
