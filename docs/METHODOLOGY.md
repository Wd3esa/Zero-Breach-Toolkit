# Methodology

How the toolkit decides what to check, how strong each kind of evidence is, and what it
learned from other forensic tools. Methods and facts only were learned from those tools:
**no code was read into or copied into this project** (several are under copyleft licences).

## Principles

1. **Never contact an indicator.** A scan blocks Python socket calls and refuses redirected
   paths and Windows remote drives. `--update` downloads from fixed official sources;
   separately invoked guided Android acquisition downloads its pinned collector after
   owner consent. This is not an OS network sandbox; see [PRIVACY.md](../PRIVACY.md).
2. **A check that could not run is a gap, never a clean result.** Every report lists what
   it could not check. Incomplete evidence or downloaded sources produce exit `3` when
   there are no actionable matches; findings take precedence with exit `2` while retaining gaps.
3. **Evidence is graded.** The same indicator means very different things in different
   places: a spyware file's fingerprint on disk is conclusive; the address in a saved web
   page is usually an article about the spyware. The grade, not the number of matches,
   decides the advice.
4. **Hunches are not findings.** Things the tool cannot judge on its own go under "worth a
   look", each with its usual, ordinary explanation, and never change the result.

## Evidence grades (strongest first)

| Grade | Meaning |
|---|---|
| on-disk | a file has the fingerprint of a published spyware sample |
| on-device | an app, signing certificate, file or setting researchers name is on the phone |
| file-pattern | a published detection rule matched a file (a lead, not proof) |
| persistence | the name is registered to start automatically |
| ran-command | a command or script that names it ran here (Win+R, PowerShell log) — may be a researcher's own command |
| execution-record | a historical execution record names an executable; its file contents and resolved path are not established |
| inventory-record | a historical file inventory names it; execution and current presence are not established |
| contacted | the device demonstrably talked to it (a cookie it set, a secure-connection record, a download from it) |
| device-log | the phone's own system logs name it |
| received | an SMS contains the indicator; opening or following it is not established |
| dns-record | a name lookup was recorded; contact unverified |
| attempted | something tried to reach it and was blocked |
| configured | it appears in local configuration |
| referenced | it appears in saved content — usually NOT contact |

## What we learned from other tools

**MVT (Mobile Verification Toolkit) and Amnesty's forensic method.** Which phone records
carry evidence: on Android, the app list with fingerprints and signing certificates,
properties, settings, files and system logs; on iPhone, backup records such as data-usage
process names, browser history, messages and configuration profiles. MVT also raises
heuristic flags (sideloaded apps, risky permissions, crash logs). On an ordinary phone such
flags usually have a harmless cause, some of them produced by the collection itself. Hence two
rules here: heuristics are only ever "worth a look", and the check recognises its own footprint
(for example, USB debugging being on because the collection needed it).

**Process names are platform-specific.** The process-name lists evaluated for this release
come from iPhone investigations, where spyware imitated Apple's service names, and some of
those names are ordinary Android services (`gatekeeperd` is Android's lock-screen service).
The Android check therefore does not compare process names; the experimental iPhone backup reader does.

**Stalkerware lists name companies.** Domain lists of commercial phone-monitoring apps
include the companies' ordinary websites (Microsoft Family Safety's among them). On a
computer such a domain is therefore never a spyware finding: a visit is "worth a look", a
mention is only counted. On a phone, where stalkerware runs, it stays a finding.

**Kaspersky's iShutdown method.** An iPhone's shutdown log, inside a "sysdiagnose" archive
the person can create themselves, records processes that delayed a reboot; some spyware
families leave traces there. The experimental iPhone reader checks supported shutdown
client records and rotations. Directory anomalies are leads to confirm with other evidence;
delays and path names alone do not establish infection.

**Velociraptor's documentation and Sigma rules: where Windows keeps evidence.** An
ordinary account can read: the Win+R history, the shim cache, the
Windows 11 program-launch list, Microsoft Defender's log and the PowerShell log. These are
in the default scan. Additional saved-input and persistence readers now cover PSReadLine,
Explorer TypedPaths, Run/RunOnce, Startup files, task actions and services. Existing Sysmon
and Security events are opt-in with `--extended-windows`; access may require administrator
rights. Bounded Prefetch and Amcache readers now supplement these checks; BAM and SRUM
remain unimplemented.

**Design notes.**
- Windows' launch list records programs started through the desktop shell.
- Most of Defender's "settings changed" events are its own housekeeping, so exclusions are
  read separately and listed first.
- Desktop apps' raw web caches are most of their data and hold only "referenced"
  evidence. The default scan reads their supported cookies,
  history and storage and reports skipped caches as a gap. `--scan-type full` includes these caches.

## Result and source limits

Platform selection comes from the shared built-in reader registry. Browser and file
fingerprinting readers run on supported desktop platforms; live Windows readers run only
on Windows, and Linux/macOS startup readers run on their respective platforms. Explicit
targeted scope can include copied Windows execution artifacts on any platform. Registration
is source-controlled, not an input-file plugin loader; see [scan/READERS.md](../scan/READERS.md).

Reference-only matches are kept as context, with their own verdict and counts. They do not
trigger preservation advice or exit `2`; coverage gaps still produce exit `3`. Matches to
indicators that every listing publisher has withdrawn are treated the same way under their
own `WITHDRAWN_ONLY` verdict, because their grade may still record real contact and calling
them references would understate it. Each STIX object's newest version decides, so a stale
cached copy of an active bundle cannot outvote that publisher's later withdrawal. Versions
belong to one object: a publisher revoking one indicator object does not withdraw a
different, still active object it publishes for the same value.

A Chromium history entry counts as contact only when this browser made a visit. Visits
that history sync copied from another device are kept as references, with a worth-a-look
note to check that device. History imported from another browser on the same computer
counts as local. Browser databases are read only from real tables: a view or recursive
query, which no browser writes, is refused, and each database has a time limit. Both
produce a coverage gap, not a clean result.

Some matching choices are deliberate and worth knowing. An IP indicator is bounded by digits
and dots on both sides but not by letters, so a dotted quad written inside text such as
`v1.2.3.4` still matches; the evidence grade, not the match, decides how much it means, and a
mention in saved content stays a reference. When the same value arrives from several files,
the first file's tier and confidence are kept and the curated file is loaded first, so a
hand-reviewed tier is never overwritten by a feed's. Confidence is provenance only and
never changes a verdict.
Missing, rejected, stale or undated downloaded sources are reported as coverage gaps.
Freshness uses curated content dates and successful feed verification times, never file
modification times. Refreshing a source does not mean its historical indicators are newly observed.

The Windows compatibility/launch readers cover ShimCache and the Windows 11 launch list.
ShimCache alone establishes presence, not execution; the tool does not use its file-modification
time as a launch time. Hashing has explicit extension, size and directory limits described in
[README.md](../README.md). Task parsing examines action fields rather than descriptions.
Supported Startup batch commands and Internet Shortcut URLs are persistence configuration;
comments and arbitrary embedded text remain references. Batch reading removes carriage
returns and separates physical lines only at line feeds. Ordinary REM comments consume
their line; the supported `rem /? & command` form is a help command followed by a command.
Unsupported pipes, redirection, general chaining, continuation and control flow produce
gaps without discarding previously recognized commands. A literal command with unresolved
argument expansion, such as `start "" "%APPDATA%\x.exe" URL`, retains its literal launch
configuration evidence and a gap for the unresolved expansion. Variables are never expanded.
Continuation lines stay together; unsupported control flow leaves the remaining block/file
uninterpreted. This is a limited reader, not a CMD interpreter or proof of execution.
Unparsed REM punctuation variants affect their own logical line; subsequent recognized
commands remain evidence. Continued `::` labels and BOM-marked UTF-16 batch files remain
reference text with a gap. Continuation recognition accounts for quoted carets and the
extra physical line consumed after an escaped newline followed by a blank line.

Startup `.lnk` files are parsed as bounded binary metadata using Microsoft's
[MS-SHLLINK specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/).
Recognized literal relative paths, local/network LinkInfo paths and command-line arguments
are configuration evidence, not proof of the resolved target or execution. Descriptions,
working-directory and icon strings remain references. Environment-path strings are retained
literally with a gap for expansion. IDLists are structurally bounded but not resolved;
unfamiliar extra blocks and flags remain gaps. Unicode strings are supported; ANSI strings
accept only their unambiguous ASCII subset. Malformed shortcuts produce references and a gap,
never guessed launch findings. Nested volume/network fields and string extents are validated;
overlapping LinkInfo fields are conservatively unsupported. The parser does not access a shortcut's target, share, icon or
working directory, call shell APIs, or expand environment variables.

Other unknown Startup formats produce gaps; only `.txt`, `.md`, `.log` and `.ini` are accepted
as reference documents without launch interpretation. Saved console/Explorer input remains
reference evidence. Nothing discovered in a task, registry value or history record is executed.

PSReadLine discovery uses its default Windows directory and includes host-specific history
filenames. Large histories are read from the newest end, with omitted older records reported.
Custom history paths are outside scope. Absent optional history is distinguished from an
unreadable existing file. Deleted historical program files remain counted and explained as
coverage limitations; only surviving files can be fingerprinted. Unreadable existing files
remain gaps. Shared registry values are deduplicated across views.

Prefetch checks validate supported SCCA headers, section extents, executable basenames,
file metrics, run counts and timestamps. A complete basename with a nonzero run count and
recorded time can match a file-name indicator as `execution-record`. A file metric may
name a DLL or another accessed file; even a matching basename does not establish the
executed program's full path, so metric matches remain references. Truncated names and
incomplete run metadata retain references and coverage gaps. On Windows, supported MAM04
compression uses the system decompressor with bounded output; other compression variants
and compressed Prefetch on other platforms are gaps.

Amcache checks read allocated records in clean supported registry hives, including modern
`Root\InventoryApplicationFile` paths and legacy `Root\File` records. Matching file
identities are `inventory-record`, not proof of execution or present-day file contents.
The reader does not mount hives, replay transaction logs, carve deleted cells or treat
Amcache's FileId as a full-file hash. Dirty hives, unsupported schemas and inconsistent
records are gaps. Neither reader opens a program path taken from an artifact. Binary
input, record counts, decoded text and total work are bounded; earlier findings survive
later unsupported records where recovery is possible.

Linux startup inspection reads immediate entries in standard autostart directories,
systemd service directories and readable cron configuration. The desktop reader recognizes
a narrow literal `Exec` grammar with optional double quotes. It does not use shell parsing,
expand field codes or resolve executable search paths. Unsupported quoting, escapes and
substitutions remain references with a gap. Explicitly disabled or conditional entries
remain references. Systemd and cron content remains reference evidence because unit
activation, drop-ins, overrides and shell interpretation are not resolved.

macOS startup inspection reads standard LaunchAgent/LaunchDaemon XML and binary property
lists. A valid labelled entry's literal `Program`, or first `ProgramArguments` element,
can match an exact executable-path indicator as configured evidence unless explicitly
disabled. This does not resolve external launchd overrides or establish activation or
execution. Arbitrary arguments and network strings remain references. Modern managed
login items, journal/unified logs, shell profiles and memory are outside these readers.
Permissions, redirections, malformed input and exhausted entry/byte limits produce gaps;
retained files are still checked when an enumeration limit is reached.

Default file fingerprinting also uses platform-specific roots. Linux includes ordinary
user folders, `.local/bin`, XDG configuration/data locations and temporary directories;
macOS includes ordinary user folders, application/support locations, launch directories
and temporary directories. Alongside the Windows candidate extensions, Unix candidates
include extensionless files, executable files, `.so`/versioned shared libraries, `.dylib`
and supported script extensions. Selection does not execute or load them. Full and targeted
scans accept all file extensions; the 120 MiB limit and access restrictions still apply.
Standard Linux browser paths honor absolute XDG configuration/cache overrides. Arbitrary
filesystem links remain refused; exact root-owned macOS `/var`, `/tmp` and `/etc` aliases
are validated against their expected `/private` locations.

History, favicon and download-chain readers grade an HTTP(S) URL's host separately from its
path, query, fragment, user information and surrounding title. A more specific indicator in
reference text cannot erase a recorded contact with the host; a parent reference beside a
child-host contact remains reference evidence. Download-chain host matches are attempted-contact
evidence; completed or received-byte metadata supports contacted evidence. Neither grade proves
execution or infection. Withdrawn-only indicator provenance changes summary advice to
historical review; independently unwithdrawn sources retain their applicable recommendation.

## Verification

See [VERIFYING.md](VERIFYING.md) to check that the file you downloaded was built from this
source.


## Added format readers and context

The iPhone reader uses a local manifest index and explicitly supported SQLite schemas. It
never joins a filesystem path taken from a backed-up app: source files are selected only by
validated hexadecimal manifest IDs. Encrypted records use the supplied password, backup
keybag class keys, RFC 3394 key unwrapping and per-file AES-CBC. Selected inert attributed-message encodings are decoded; unsupported
encoded bodies and binary fields remain gaps. Message, browser-visit and process records use bounded pages of integer
SQLite row IDs. At most 16 payloads are read together; if that read fails, each row is retried
independently. Oversized or undecodable rows are skipped with specific reasons while retaining
readable neighbours. Repeated iPhone gaps are counted once per check and reason;
the reason includes its occurrence count and skipped-record totals remain available.
An unreadable row index or broader database corruption can still stop that artifact;
the tool does not claim arbitrary database repair or deleted-record recovery.
Required artifacts are looked up separately from the bounded manifest filename sweep.
Views, virtual tables and generated columns are refused; database operations, returned field
sizes and per-artifact text processing have limits. Each SQLite query has its own 10-second
and 20-million-VM-operation budget (checked every 1,000 operations); elapsed time between
queries does not consume a later lookup's budget. Exhaustion identifies a query limit,
not a missing artifact. Row, byte and per-artifact processing-time caps bound the overall
work, including per-row recovery queries; there is no shared wall-clock deadline for the
whole backup. Payloads skipped for exceeding the text limit do not spend the searched-text budget.
Validated committed WAL records are replayed on temporary copies. Damaged/unsupported
WALs remain gaps; encrypted root-manifest WALs lack separate key metadata and are not replayed.
Temporary plaintext copies are removed after use;
cleanup is not secure erasure. The Android file inventory is streamed with a separate 1 GiB
input limit and a 4 MiB individual-record buffer limit.

Additional iPhone browser checks use exact manifest locations and physical tables:

- Chrome: `AppDomain-com.google.chrome`,
  `Library/Application Support/Google/Chrome/Default/History`; `urls` and `visits` tables.
  A local visit requires `visit_source` provenance of `1` (including a missing source row
  defaulting to `1`) and an absent, NULL or empty `originator_cache_guid`. Without the
  `visit_source` table, URLs remain references and an explicit provenance gap is recorded.
- Firefox: `AppDomainGroup-group.org.mozilla.ios.Firefox`, `profile.profile/browser.db`;
  the historical `history(id,url)` and `visits(siteID,date,is_local)` schema. Only integer
  `is_local=1` establishes local-visit provenance. Missing provenance keeps references and
  records a gap. Other schemas are unsupported.

Both require actual visit records, not merely a URL or bookmark entry. Host/reference grading
uses the same separation as desktop browsers. An absent optional browser database is ignored;
a present unreadable, unsupported, truncated or damaged-WAL artifact produces gaps. iPhone hit provenance identifies the original
backup blob rather than a temporary decrypted file.

The shared iPhone source layer also accepts explicitly selected extracted filesystems and
sysdiagnose directories/TAR archives. New artifact readers use it for bounded access,
temporary database replay and source/member hashes. Generic cache/metadata strings remain
references; typed records retain their narrower meaning. See [IPHONE.md](IPHONE.md) for
implemented schemas, security bounds, provenance and unsupported formats.

Android process inventories accept the legacy text format and a JSON array of objects with
a positive integer `pid` and a `command_line` string array. Only the first command-line element
is compared with app identifiers, allowing an Android `:service` suffix. Arguments and
environment text are not application identities, and iPhone process-name indicators are not
applied to Android. Null/empty command lines and malformed records are counted as skipped
with explicit gaps. Duplicate app findings across JSON and text are suppressed.

The separate Android intrusion reader inspects already decrypted `intrusion_logs` or
`intrusion-logs` exports: newline-JSON `.txt` records and supported ZIP members. It validates
typed `dns_event`, `connect_event` and supported `security_event` payloads before matching
their fields. DNS hostnames and returned addresses are `dns-record`; a TCP connection
event is a `device-log` attempt whose success is unverified. Neither is upgraded to
contacted evidence. Supported process-start records describe historical activity, not
current installation or file presence. Unsupported security tags remain gaps.

Duplicate validated events are suppressed. File/member counts, JSON line sizes, expanded
bytes, event counts and processing time are bounded. Archive members are read without
extracting paths; links, unsafe names, unsupported encryption/compression and oversized
indexes are refused. Invalid rows produce gaps while readable later rows remain available.
The reader neither enables logging, accesses a live phone nor decrypts an encrypted export.

Android backup encryption was implemented from the format described by AOSP's
[backup writer](https://github.com/aosp-mirror/platform_frameworks_base/blob/master/services/backup/java/com/android/server/backup/fullbackup/PerformAdbBackupTask.java)
and [password/checksum routines](https://github.com/aosp-mirror/platform_frameworks_base/blob/master/services/backup/java/com/android/server/backup/utils/PasswordUtils.java).
Apple describes the [backup keybag](https://support.apple.com/guide/security/keybags-for-data-protection-sec6483d5760/web).
The independent iOS implementation uses the format notes published by
[ios-backup-crypt](https://pkg.go.dev/github.com/novkostya/ios-backup-crypt/internal/keybag)
and [golemine](https://github.com/pmeenan/golemine/blob/main/docs/iOS-Backup-Format.md).
Firefox binary HSTS slots follow Mozilla's documented
[DataStorage format](https://github.com/mozilla/gecko-dev/blob/master/security/manager/ssl/data_storage/src/lib.rs);
checksums, fixed field widths and HSTS state are validated before interpreting host keys.
No source code from these projects was copied.

STIX publisher assertions preserve dates, explicit platform labels and withdrawal flags.
They do not establish an indicator's current ownership, independent confirmation, or a
campaign's duration. Correlation groups exact matching indicators across distinct artifact
locations, removes exact duplicate records, and orders available timestamps. It never
changes evidence grades, verdicts or recommended actions. See [COVERAGE.md](COVERAGE.md).


Guided acquisition is a separate, explicit operation. `--collect-android` pins AndroidQF
v1.8.3 and its official release digests, verifies downloaded bytes before execution, and
requires interactive owner consent. It does not search PATH for an existing collector.
Plaintext ZIP extraction rejects traversal, links, device filenames, duplicate outputs and
oversized members. Public age recipients can be supplied through `--age-recipient-file`;
encrypted output is retained for separate decryption. Collector code was not copied or bundled.
Official release metadata: https://github.com/mvt-project/androidqf/releases/tag/v1.8.3.

## Inspection and private handoff

Interactive follow-up reads the completed report: it displays individual findings and their
evidence grades, coverage gaps and fixed next steps. It does not rescan, execute evidence or
open links. An optional readable report, full JSON and minimal sharing summary are saved
independently. Output errors do not turn an incomplete save into a successful scan result.
Quitting the start menu reports that nothing was checked and returns exit `4`, without a
scan verdict. A completed scan with gaps remains partial even when it has no findings.

Evidence export is explicit. A private, **unencrypted** ZIP contains full JSON, a readable
report, the minimal sharing summary, an integrity manifest and only additional regular local
files selected by the person. Report strings never select source files. The preview lists
the selected paths and sizes before interactive confirmation; no archive is uploaded or
existing archive overwritten. Limits are 64 MiB per selected file, 128 selected files and
256 MiB total payload including reports. Report outputs are refused when they would replace
selected source evidence, including files beneath a selected input directory.

The manifest records tool/version, scope, scan start/completion times, export activity and
SHA-256 hashes of archive payload members. Effective parsed indicator records have a canonical
SHA-256 fingerprint; this is not a hash of the original feed files. Selected source files are
copied at export time, with before/after file metadata checks. They are not retained scan
snapshots, and live SQLite files may need separately selected sidecars. These hashes establish
subsequent archive integrity, not original authenticity, infection or a transaction-consistent
forensic image. Private export contents should be reviewed and transferred through a secure
channel agreed with the recipient.
