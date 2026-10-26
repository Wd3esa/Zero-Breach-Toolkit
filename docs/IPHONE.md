# Local iPhone evidence (experimental)

These readers analyze already acquired local evidence. They do not unlock a phone,
create a backup, download from iCloud, or run MVT.

## Input choices

Use the phone menu, or add these arguments to the source or standalone scanner:

| Evidence | Arguments |
|---|---|
| Finder / Apple Devices / iTunes backup | `--phone FOLDER` or `--phone FOLDER --ios-input backup` |
| Encrypted local backup | `--phone FOLDER --backup-password` (private terminal prompt) |
| Extracted filesystem rooted above `private/var` or `var` | `--phone ROOT --ios-input filesystem` |
| Sysdiagnose directory or TAR/TAR.GZ | `--phone PATH --ios-input sysdiagnose` |

Add `--preview` to inspect the chosen scope without scanning. Add `--json REPORT`
for source/record provenance and explicit coverage gaps. Select the backup directory
containing Manifest.plist and Manifest.db, not the parent directory holding several
devices. Directory/archive names supplied to sysdiagnose are inventoried within
bounds; only selected artifact filenames are parsed.

[Apple documents](https://support.apple.com/108353) why encrypted local backups can
include additional history. Decryption requires the owner's password and the
optional dependency in `requirements-backups.txt`. Nothing is installed automatically.
Legacy SHA-1 and two-stage SHA-256/SHA-1 key derivation, class keys and independently
wrapped artifact keys are supported. Wrong passwords, missing
classes, bad wrapped keys and missing payloads are gaps. No password recovery is
provided. AES-CBC does not authenticate source evidence.

## Supported records

Readers require physical SQLite tables and supported columns. Optional columns may
be absent; this can reduce dates or metadata. A matching filename alone does not
validate the database. The following describes the implemented subset, not every
schema used by every iOS/app release.

| Artifact | Supported interpretation |
|---|---|
| Manifest and Info.plist | File inventory; installed application IDs; recorded iOS version |
| SMS `message` | Plain text or supported inert NSKeyedArchiver / limited NSArchiver-v4 attributed text; Apple-epoch seconds/nanoseconds; only integer incoming direction is `received` |
| SMS `handle`, `attachment` | Correspondent IDs and recorded attachment metadata; attachments are not opened |
| Safari History | Visit records in the legacy path and `Library/Safari/Profiles/*/History.db`; visit URL host separated from reference text |
| Chrome / Firefox | Default and discovered supported profiles; existing local-visit provenance rules remain |
| DataUsage / filesystem netusage | `ZPROCESS` names, optional bundle IDs and process timestamps; no arbitrary SQL/schema guessing |
| Safari BrowserState | `tabs.url`, optional title; saved references |
| WebKit statistics | `observed_domains.registrableDomain`; saved references |
| URL cache | `cfurl_cache_response.request_key`; references, without inferring successful contact |
| WhatsApp | `ZWAMESSAGE` text, integer direction, optional date/sender; outgoing text stays a reference |
| TCC | `access` client/service plus supported grant columns; configuration is not execution |
| Calls / Calendar / Interactions | Supported `ZCALLRECORD`, `CalendarItem`, `ZINTERACTIONS` columns; identifiers and text, without inferring an exploit |
| Shortcuts | `ZSHORTCUT` names and inert plist action strings; activation/execution unverified |
| ADDaily analytics | `netUsageBaseline` process tuples beginning with a plist date, plus explicit process/bundle fields |
| Profiles / profile events | Literal plist references and PayloadUUID/PayloadIdentifier fields; current activation unverified |
| Location clients / app metadata | Supported client and bundle identifiers; recorded metadata only |
| Global preferences | Recorded `LDMGlobalEnabled` state; no assertion about current Lockdown Mode |
| WebKit resource plists | Literal string references; unsupported typed layouts are gaps |
| Shutdown logs and numbered rotations | Structured remaining-client PID/path/UUID records; following SIGTERM Unix time; unusual directories produce leads only |
| Crash reports | IPS metadata/body JSON identities and legacy Process/Path lines; crashes alone do not establish exploitation |

Unsupported attributed-body encodings are not searched as arbitrary bytes. Attribute
strings cannot be mistaken for message text. The typedstream decoder is limited and
does not cover every variant.
Deleted records, attachment contents, generalized WebKit storage decoding, unified
logs, binary sysdiagnose plugins, full application inventories outside supported
metadata and arbitrary encrypted containers remain outside coverage.

## Evidence integrity and limits

Original evidence is opened for reading only. SQLite main files and independently
decrypted WAL sidecars are copied into temporary local storage. WAL headers, salts,
page sizes and rolling checksums are checked against SQLite's
[published format](https://sqlite.org/fileformat.html#walformat). SQLite replays the
validated committed prefix on the copies. Damaged/truncated tails produce gaps;
earlier readable evidence survives. Valid uncommitted tails and older salt epochs
are not committed records. SHM is regenerated. An encrypted root Manifest.db WAL
has no independent artifact key in this interface and is explicitly not replayed.
This does not repair arbitrary corruption or create a coherent acquisition from
files changing during the scan.

Paths from backup databases select only validated hexadecimal blob IDs. Filesystem
links/reparse points and unsafe archive names are refused. Archive members are
stored under opaque temporary names, never extracted to supplied paths. Duplicate
member names are refused as ambiguous. Sparse/special entries are unsupported.

Limits include 256 MiB per artifact, 16 MiB before property-list decoding,
1 GiB of artifact reads, 200,000 inventory entries,
32 directory levels, 256 additional artifacts, 4 GiB streamed TAR expansion and a
60-second archive traversal budget. SQLite fields, queries, rows and text have
separate limits. Hitting a bound produces a gap. Reading the same source again for
another supported table counts toward the byte budget.

`hits[].provenance` records the original source/member, SHA-256 of bytes read,
input format, encryption flag, parser ID, record locator and available raw timestamp;
database findings also include the WAL hash when read. An encrypted artifact hash
identifies its ciphertext, not the temporary plaintext. Inventory/Info findings can
have less provenance than parsed artifact findings. Hashes do not authenticate a
device, prove acquisition completeness or establish compromise. Full reports are
private; the sharing summary omits these fields.

Temporary plaintext is removed on normal completion and handled exceptions.
Cleanup failure is a gap. Process termination/power loss can leave temporary files;
removal is not secure erasure. Use protected local storage for sensitive evidence.

## References

The shutdown interpretation is informed by the
[original research](https://securelist.com/shutdown-log-lightweight-ios-malware-detection-method/111734/)
and [format documentation](https://github.com/libyal/dtformats/blob/main/documentation/Apple%20Unified%20Logging%20and%20Activity%20Tracing%20formats.asciidoc).
The implementation is independent; no MVT or iShutdown code is bundled.
