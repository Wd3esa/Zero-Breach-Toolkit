# Module contract: build against this

Development extension: `ctx.patterns` explicitly enables the optional `patterns`
module; `ctx.pattern_paths` supplies absolute local paths for that module only.
The Windows host module supplies bounded `ctx.pattern_candidate_paths` from
local, user-writable per-user COM server registrations when pattern paths are
not explicitly selected; the pattern module rechecks each path before reading.
The default checks remain standard-library-only. The optional module uses the
pinned YARA-X engine without downloads, writes or sample execution. Its hits use
`file-pattern` evidence and `candiru-pattern` tier, never exact-hash claims.

Each scan module is a file in `zbtriage/modules/` registered once in
`zbtriage/readers.py`. Its `ReaderSpec` supplies selection, bundle suffix,
optional helper files and coverage descriptions. Both entry points use the same
dispatcher; the builder and hermetic test stubs derive their module lists from
this registry. See [READERS.md](READERS.md) for the extension procedure.
Every module defines:

```python
NAME = "browser"   # or "hash", "host", "deep"

def run(ctx) -> ModuleResult:
    ...
```

- `ctx` is `zbtriage.context.ScanContext`: `ctx.iocs` (an `IocSet`),
  `ctx.deep` (bool), `ctx.emit(str)` for progress (goes to stderr, never print
  to stdout from a module; stdout is the final human report).
- Return `zbtriage.result.ModuleResult`.

## IocSet (zbtriage/iocs.py): what modules read

- `ctx.iocs.network_strings` → sorted lower-case list of domain + IP strings for
  substring matching in artifacts. **Never resolve or connect to these.**
- `ctx.iocs.hashes` → list of `Indicator` with `.value` (lower-case sha256).
- `ctx.iocs.lookup(value)` → the `Indicator` for a matched string, or None;
  use it to attach `.tier` / `.confidence` provenance to each Hit.

## ModuleResult (zbtriage/result.py): how to report

- `r = ModuleResult(NAME)`
- On every hit: `r.add_hit(Hit(indicator=ioc, location=path, detail=ctx, tier=..., confidence=...))`
  — get tier/confidence from `ctx.iocs.lookup(ioc)`.
- `r.checked`, `r.skipped` are running integer counts (files/DBs examined; items skipped).
- `r.submetrics` is a dict of named counts for the report, e.g.
  `{"sqlite": 28, "blob": 44634}`.
- **Record each sub-check's fate (this is the D3 contract):**
  - `r.ran("dns-cache")` when a sub-check executed (even if it found nothing).
  - `r.could_not_run("dns-log", "operational log disabled")` when it could not.
  A module with any `could_not_run` becomes PARTIAL/UNKNOWN automatically; do
  NOT report a clean sub-check that never actually ran.
- `r.note("free text")` for extra context.

## Hard rules (doctrine)

- **D2: never contact an indicator.** No `socket`, `urllib`, `requests`, DNS
  resolution, ping, HTTP, WHOIS: nothing. The scan already runs inside a guard
  that raises `NetworkContactAttempt` if you try; do not work around it. Reading
  the LOCAL OS DNS cache (already-resolved entries) via a `subprocess` call to a
  system tool is allowed and resolves nothing.
- **Read-only.** A module must not create, modify or delete anything on the host
  (temp copies of locked DBs in the system temp dir, cleaned up, are the only
  writes permitted).
- **Never crash the run.** Catch per-item errors (locked file, permission
  denied, unreadable DB), count them as `skipped`, and continue. A skipped item
  is not a clean item.
- Match is case-insensitive substring for domains/IPs; exact hex compare for hashes.

## Platform

The registry selects applicable readers for Windows, Linux and macOS. Windows
live host/traces/execution readers are not selected on Unix; Unix startup readers
are not selected on Windows. Supplied Prefetch/Amcache files can be parsed on any
host, except compressed Prefetch which currently requires Windows. If a selected
reader cannot run, return a ModuleResult whose checks are `could_not_run`
with reason "not supported on <platform>", never a fake CLEAN.

## Machine contract (for scripts and AI assistants) - added 2026-10-25

Defined in `zbtriage/contract.py`; pinned by `tests/test_contract.py`.

- **Schema 1.6 / exit codes:** 0 no actionable matches and no recorded gaps; 1 error;
  2 actionable matches; **3 no actionable matches but evidence or downloaded sources
  were incomplete**. Reference-only verdicts are `REFERENCES_ONLY` (0) and
  `REFERENCES_ONLY_WITH_GAPS` (3). When every serious-grade match is to an indicator its
  publishers have withdrawn, the verdict is `WITHDRAWN_ONLY` (0) or
  `WITHDRAWN_ONLY_WITH_GAPS` (3). Unknown evidence grades still count as actionable.
  `hits_total` counts all matches and is `findings_total + withdrawn_total +
  references_total`. A reference-only or withdrawn-only result does not request
  preservation of the device. Withdrawal is decided per publisher by its newest version
  (STIX `modified`); one current active listing from any publisher keeps a match actionable.
  `confidence` (primary/secondary) is provenance only: it never changes the verdict, the
  exit code or the next steps.
  **4 means the person quit the start menu without scanning**; no scan report or verdict
  exists. Acquisition/help/preview command exits remain distinct from scan verdicts.
- **Indicator coverage:** missing/refused sources and loaded sources with stale or unknown
  verification dates appear in `coverage.not_checked` under `indicators/indicator-sources`.
  `ioc_set.freshness_unknown` preserves unknown component dates even when another set has a
  known age. Filesystem modification times are not freshness evidence.
- **Sharing:** `--share-json PATH` writes a separate `report_type: sharing-summary` document
  containing counts, verdict and fixed advice. It deliberately omits all artifact text,
  indicator values, paths, profiles and timestamps; it is not a full evidence report.
- **`--describe`** prints JSON without scanning: every check kind, what it reads, blind spots,
  exit codes, evidence grades, tiers, and the fixed caveat / advice catalogues.
- **JSON report additions:** `schema_version`, `exit_code`, `coverage` (checked / not_checked
  with reasons), `must_relay` (fixed caveats chosen by verdict - relay verbatim),
  `next_steps` (fixed catalogue, chosen by the strongest recommended action),
  `content_trust` (fields holding text from the scanned machine or a third-party feed),
  `instructions_for_assistants`.
- **Never** build caveats or advice from scanned text. Scanned text goes only into the fields
  listed in `content_trust.untrusted_fields`, after `sanitize_untrusted()` (control and bidi
  characters replaced, length capped).
- A new check name must be added to `contract.CHECK_CATALOGUE`; the test fails otherwise.


Schema 1.2 introduced optional `scope`, `correlations`, and per-hit `indicator_context` /
`context_cautions`, plus derived withdrawal flags. Compared with the committed schema 1.0,
schema 1.1 introduced `REFERENCES_ONLY` (exit 0) and `REFERENCES_ONLY_WITH_GAPS` (exit 3);
reference-only matches no longer return exit 2. Missing indicator sources now produce gaps.
Schema 1.3 retains those scan verdict rules and adds the no-scan menu exit. Schema 1.4 added
reader descriptions, the host platform and explicit not-applicable reasons. Schema 1.5 adds
`WITHDRAWN_ONLY` (exit 0), `WITHDRAWN_ONLY_WITH_GAPS` (exit 3), `verdict.withdrawn_total`, the
`withdrawn-only` relay line and the `withdrawn` timeline kind: a match to an indicator every
publisher has withdrawn no longer returns exit 2 or asks for the device to be preserved. Context holds
publisher assertions, not executable guidance; it is untrusted data. Correlations include
module/hit indices, artifact counts, original grades, stage labels and dates. They group
shared indicators, not inferred causal chains, and do not strengthen the verdict. Full
reports retain source-by-source indicator gaps; readable reports group missing-source lines
with a `--update` instruction. Minimal sharing summaries exclude artifact/context text and
target paths, but include allow-listed scope (`scan_type`, `phone`, `cancelled`) and a fixed
targeted-scan caveat. Exit 0 describes the selected scope, never an entire-device guarantee.
An ordinary target without a browser profile makes browser artifact checks inapplicable.
Absent optional Windows history and deleted historical program files are explained limitations;
unreadable existing artifacts remain gaps. Counts of unavailable historical files are retained.

Full JSON, sharing JSON and `--report PATH` readable-text writes are independent and use a
temporary file beside the destination followed by replacement. Readable files are UTF-8;
unencodable code points are escaped. JSON strings and keys use ASCII escapes, preserving unusual Windows
filename code points, including lone surrogates, in a valid UTF-8 file. Readable output shows
unencodable characters as escapes. Serialization errors in one output do not suppress attempts
to write the other output and display the readable report. Output errors return 1 even when a scan verdict exists; a saved
document's `exit_code` describes its scan verdict. A failed sharing write does not prevent
the full report write. The first interruption during report finalization retries that operation;
a further interruption can stop it. Module/between-module cancellation preserves completed
evidence with an explicit remaining-checks gap. Forced termination cannot guarantee recovery.

New scopes: default; full (broader extensions/subdirectories and app caches in usual roots);
targeted (selected files/folders/drives/browser profiles only); browser (only this account's
browser profiles and built-in Chromium app profiles, with the `browser-only` relay line).
`--phone` selects AndroidQF
or experimental iPhone evidence. `--ios-input` explicitly selects backup, extracted
filesystem or sysdiagnose input. `--preview` and `--phone-guide` exit without scanning.
Cancellation preserves the active module's accumulated findings and records an explicit gap.


`--collect-android DIR` is a separate opt-in network/acquisition command with interactive
owner consent. On plaintext success it sets the phone scope and runs the scanner. On encrypted
acquisition success it reports that no scan ran and exits 0 without a scan report; do not
interpret this acquisition exit as a scanner verdict. `--age-recipient-file` accepts public
age1 recipients only. The scan report's `exit_code` contract applies only to completed/partial
scan reports, not collector download or acquisition operations.

The explicit updater uses the same escaped, atomic JSON writer and safe console output.
A requested update-summary write failure returns exit 1 even if all indicator downloads
succeeded. This report handling does not trigger or authorize an update during a scan.

Repeated iPhone failures are aggregated by check and reason. A repeated reason includes its
occurrence count; module `skipped` still counts skipped records. Coverage gaps count reported
check/reason entries, not unreadable messages. The readable gap list also groups identical
reasons. Unsupported or oversized payloads remain gaps even when later rows are read. Message,
Safari, process and supported Chrome/Firefox readers page integer row IDs; failed bounded
payload batches are retried row by row. Unreadable indexes can still stop an artifact.

The optional `ios:chrome-history` and `ios:firefox-history` checks require their fixed backup
paths and supported physical schemas. Absent optional databases do not add gaps. Existing
unreadable databases and missing local-visit provenance do. Browser matches without local
visit provenance remain references. `Hit.artifact` identifies the original backup blob.
Schema 1.6 adds optional `Hit.provenance` source/member hashes, parser/record locators,
input format, encryption state and raw timestamps, plus `scope.ios_input` for explicit
backup/filesystem/sysdiagnose selection. Empty provenance is valid for existing readers.
These fields are untrusted and private; they are sanitized and excluded from the sharing
summary. A source hash is not a claim of device authenticity. iPhone database findings
can include a WAL hash; the source files are never rewritten. See
[../docs/IPHONE.md](../docs/IPHONE.md) for the bounded format contract and limitations.
Android JSON process inventories accept `pid` and `command_line`; only the first command's
app identifier is matched, not arbitrary arguments or iPhone process-name indicators.

## Interactive workflow and evidence export

The start menu requires interactive stdin and stderr and no scan selection on the command
line. Selecting a scan there enables the post-scan menu. `--post-menu` enables it for an
explicit interactive scan; `--no-menu` disables menus and cannot be combined with
`--post-menu`. Piped stdin never prompts. Quitting the start menu returns `4`; finishing the
post-scan menu retains the scan verdict unless an output operation failed. The latter menu
reads the completed report, exposes evidence/gaps and saves explicitly chosen outputs. It
does not run another scan, execute recorded text, open links or upload data.

Schema 1.3 scan finalization adds `scan_state` (`completed` or `partial`), `completed_at`
and `indicator_fingerprints` to the full report. A partial state covers recorded gaps or
cancellation; it does not erase findings. The fingerprint hashes sorted compact ASCII JSON effective indicator records,
separated by LF, with combined and per-source SHA-256 values. It describes parsed indicator
content, not the original feed-file bytes. These private provenance fields are omitted
from the minimal sharing summary.

`--evidence-bundle PATH` exports a new **unencrypted private ZIP**. Repeat `--evidence-file PATH`
to select original local files deliberately; source paths are never inferred from report
strings. Without selected files, the archive contains the full JSON report, readable report,
minimal sharing summary and manifest. The selection preview shows private paths and sizes.
Interactive export asks for confirmation; explicit CLI export flags specify the selection.
No upload or automatic transmission occurs.

The exporter refuses existing archive destinations, redirected/non-local source paths,
non-regular files, duplicate selections and exceeded limits. Limits are 128 selected files,
64 MiB per selected file, and 256 MiB total payload including reports; report members have a
32 MiB limit each. Output paths cannot replace selected source inputs or their descendants.
Archives use numbered artifact member names, with source paths recorded only as manifest
metadata. SHA-256 covers every payload member; `manifest.json` has no self-hash. The manifest
records tool/version, scope, scan start/completion, indicator fingerprints, export events and
source metadata before/after copying. An interrupted or failed export leaves no published ZIP.

Files are copied at export time, not from retained scan snapshots. Sidecars must be selected
explicitly when needed; exporting a live database is not a transaction-consistent acquisition.
Integrity hashes cannot authenticate the original device, establish infection or prove that
source bytes had not changed before export. The ordinary locality-guard limitations still apply.


## Registry and evidence additions (schema 1.4)

`--describe` includes `readers`, with each built-in reader's name, module,
platforms, modes and optional switch. `modules` retains the coverage catalogue.
Scan scope includes `host_platform`; excluded platform readers are inapplicable,
not failed Windows checks on another operating system.

Two additional evidence grades distinguish historical Windows records:

- `execution-record`: the supported Prefetch record identifies an executable
  basename with a nonzero run count/time. A matching name does not establish
  file contents, infection or current presence. Referenced DLLs remain references.
- `inventory-record`: supported Amcache inventory identifies a file name/path.
  This does not establish execution or that the file remains on disk. Amcache's
  truncated-file SHA-1 is not compared with full-file SHA-256 indicators.

Both grades require interpretation and are actionable matches, not infection
verdicts. Android intrusion DNS uses `dns-record`; connection attempts and typed
process-start records use `device-log`. A connection event can describe failure.
Unix literal executable configuration uses `configured`; arbitrary arguments,
comments and unverified systemd/cron command text remain `referenced`.


Schema 1.4 also adds module status `NOT_APPLICABLE` and `inapplicable_reason`.
This explicitly identifies absent optional input (for example no intrusion-log
export, or no Prefetch/Amcache in selected targets). It records no successful
parser check and does not add a failure gap. The label cannot suppress hits,
failed checks, skipped records or observed data. An unexpected empty module
without an explicit inapplicability reason remains `UNKNOWN` and a coverage gap.
