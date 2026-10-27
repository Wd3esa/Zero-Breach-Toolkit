# Zero Breach Toolkit

**A free, open-source check for traces of known mercenary spyware** (Pegasus, Predator,
Graphite, Candiru and others) on your computer and your Android phone.

- **Read-only analysis.** It does not modify source evidence or system settings. It writes
  temporary database snapshots and requested reports.
- **No intentional network requests during scans.** It never looks up spyware addresses
  and has no upload feature. Python network calls are blocked and redirected paths are
  refused. This is not an operating-system network sandbox; see [PRIVACY.md](PRIVACY.md).
- **Honest.** It tells you what it found, how strong the evidence is, and, just as
  plainly, what it could *not* check. A clean result is never presented as proof
  that you are safe.

Made by **archivegenocide**. Built on [Zero Breach](https://github.com/interplains/zero-breach).

> **If you think you are being targeted right now, get expert help first.** You do
> not need to run this tool before asking. Journalists, activists, human-rights
> defenders and civil society can contact the
> [Access Now Digital Security Helpline](https://www.accessnow.org/help/) (free, 24/7,
> many languages) or [Amnesty International's Security Lab](https://securitylab.amnesty.org/get-help/).

---

## What it checks

**On a Windows computer** (no administrator rights needed):

| Where | What it looks for |
|---|---|
| Browsers: Chrome, Edge, Brave, Vivaldi, Chromium, Firefox | spyware addresses in history, cookies, connection records, site storage and caches, per browser profile |
| Desktop apps with a built-in Chromium browser, discovered under AppData | supported history, cookie and storage records; raw app web caches are skipped and reported as a gap |
| Downloaded files | the website each file came from (the "Mark of the Web" Windows stamps on downloads) |
| The Win+R box | commands people were tricked into pasting by fake "verify you are human" pages |
| Microsoft Defender's history | threats it caught, protection being switched off, folders excluded from scanning |
| PowerShell's log | scripts that named a spyware address, or downloaded and ran code |
| Programs listed by Windows | existing files named in the shim cache and Windows 11 launch list, compared with published sample fingerprints; these are not a complete execution history |
| Prefetch and Amcache | supported Prefetch executable-name records and Amcache file inventory; referenced program files are never opened by these readers |
| Selected user folders | fingerprints of candidate files with supported extensions, within size and directory limits |
| DNS cache, DNS history, hosts file, COM and startup/task/service registrations | known spyware indicators in supported network and persistence records; not an exhaustive persistence audit |

Prefetch name matches use `execution-record` evidence: they do not identify the file's
contents or establish its full path. Amcache matches use `inventory-record`: inventory
does not prove execution or that the file still exists. Locked or unsupported records are gaps.

Computer checks can find published infrastructure or file traces; they cannot determine
whether a phone is infected. The default hash check covers `.dll`, `.exe`, `.sys`, `.ocx`,
`.cpl`, `.scr`, `.tmp`, `.dat`, `.bin` and `.ax` files up to 120 MiB in selected folders.
It skips cache/dependency directories in default mode. Targeted mode accepts selected
drives, folders and arbitrary files, subject to the same size and access limits.

**On an Android phone:** reads a collection made with
[AndroidQF](https://github.com/mvt-project/androidqf) (it never talks to the phone itself):

- installed and **running** apps, their fingerprints and signing certificates;
- the install history — an app that was **installed and later removed** still shows;
- the phone's system records, logs and crash records;
- supported, already decrypted intrusion logs, when present: DNS lookups, TCP connection
  attempts and structured process-start events. A connection attempt does not prove success;
- links in **SMS messages** (from the SMS backup AndroidQF offers to take);
- apps installed outside an app store, each with what it can do (read SMS, use the
  microphone, read notifications, resist uninstalling...) and when it arrived;
- signs of a modified phone: unlocked bootloader, debug build, security protection off.

It recognises the collection's own traces (USB debugging, the debugging shell's
permissions) and never reports them as suspicious.

**Linux and macOS:** supported Chromium-family and Firefox profiles, file fingerprints,
and bounded startup configuration checks run without requiring administrator access.
Linux checks standard autostart `.desktop` entries, systemd `.service` files and readable
cron configuration. macOS checks standard LaunchAgent and LaunchDaemon property lists.
These inspect saved configuration; they do not determine which jobs are enabled or ran.
Network strings remain references. Exact known executable paths in supported launch
configuration can be findings, with activation and execution explicitly unverified.

Unix file checks include extensionless files, executable files, native libraries and
scripts in selected application, user and temporary folders. Default directories and
candidate rules vary by platform; the 120 MiB file limit remains. Windows-only live checks
are omitted on Linux/macOS. Copied supported Prefetch and Amcache files can be selected in
targeted mode on any platform; compressed Prefetch requires Windows.
Experimental local iPhone backup checks are available; see below.

### Indicators

About **12,400 published indicators from 25 sources**: Amnesty International's Security Lab,
the [Mobile Verification Toolkit](https://github.com/mvt-project/mvt-indicators) project,
the Citizen Lab and Echap's stalkerware research, plus a hand-curated set from Citizen Lab
reports (Candiru / DevilsTongue and Paragon's Graphite), every line cited. The curated set
works offline; `--update` downloads the rest from a fixed list of official sources.

---

## Install and run

You need **Python 3.8 or newer** ([python.org](https://www.python.org/downloads/)). No
administrator rights and no extra packages. On macOS and Linux use `python3` instead of
`python`.

```
git clone https://github.com/interplains/Zero-Breach-Triage-Toolkit.git
cd Zero-Breach-Triage-Toolkit
```

Without git, use **Code → Download ZIP** on GitHub and extract it. On Windows you can then
double-click `scan\run-scan.cmd`: it opens the start menu and saves the readable and JSON
reports in the `findings` folder next to the toolkit. Those reports contain private details
from your computer; keep them off shared and synced folders.

```
python -X utf8 scan/zero-breach-triage.py --update        # download the published indicators (separate network step)
python -X utf8 scan/zero-breach-triage.py                 # check this computer
python -X utf8 scan/zero-breach-triage.py --quick         # faster: skips file fingerprinting
python -X utf8 scan/zero-breach-triage.py --phone FOLDER  # check an Android phone (see below)
python -X utf8 scan/zero-breach-triage.py --json report.json
python -X utf8 scan/zero-breach-triage.py --share-json summary.json  # minimal summary for sharing
```

On Linux or macOS, the terminal launcher accepts the same options:

```sh
sh scan/run-scan.sh
sh scan/run-scan.sh --quick
```

Run `--update` first and again every few weeks: new indicators are published regularly.
**Close your browsers and chat apps before scanning.** Open apps lock some of their files,
and the report will tell you which ones it could not read.

### Verify what you run

This project is anonymous, so do not take its word for anything, and do not look for a
certificate. Verification here rests on what you can reproduce, not on who published it.

Running from source, as above, means every line the tool executes is in the clone: nothing
is compiled, and nothing is fetched in order to run.

The single `zero-breach-triage.py` file attached to a release is generated from this same
source, so you can rebuild it and compare:

```
python build/bundle.py
python -c "import hashlib; print(hashlib.sha256(open('dist/zero-breach-triage.py','rb').read()).hexdigest())"
```

The size and SHA-256 published with each release are authoritative. At the time of writing
the build is **790,748 bytes**, SHA-256
`951e60c0f75fd9a6108e2395994f3c4f53f4044ab3c64e8a4631f9b58b8abf7e`. Two consecutive rebuilds
produce that same file. A rebuild that matches tells you the published file contains
this source and nothing else.

**There is no signed Windows program, and none is planned while the project stays
anonymous:** code-signing certificates require a named legal identity. If you build an `.exe`
from this source yourself, expect Windows SmartScreen to warn about it and some antivirus
products to flag it: it is unsigned and has no download reputation, and PyInstaller output
is not byte-reproducible, so the comparison above does not apply to it. Running from source
avoids all of that. See
[docs/VERIFYING.md](docs/VERIFYING.md).

### Checking an Android phone

1. Install [AndroidQF](https://github.com/mvt-project/androidqf/releases) on your computer.
2. On the phone, turn on *Developer options* and *USB debugging*, connect it, and accept the prompt.
3. Run AndroidQF. Current releases write a ZIP archive; extract it locally and locate the folder containing `packages.json`. Older collections may already be folders.
4. Run `python -X utf8 scan/zero-breach-triage.py --phone <that folder>`.
5. **Turn USB debugging off again** and revoke the computer's authorisation.

The collection holds private information about the phone. Keep it on your computer.

**Guided acquisition (experimental):** run `--collect-android LOCAL_OUTPUT_FOLDER`. It downloads official
AndroidQF v1.8.3, verifies its pinned SHA-256, asks for the device owner's explicit consent,
and runs the collector's interactive prompts. After a successful plaintext acquisition it
extracts the archive locally and checks the resulting collection. Acquisition changes phone
state and saves private records; it is separate from read-only scanning. The current Windows
collector is unsigned; the pinned digest verifies the publisher's release bytes, not an
independent audit of the collector.

How that download is handled, since it is the only point at which this tool runs a program
it did not ship: the asset name and the expected digest are both fixed in the source, the
file is fetched over HTTPS from the publisher's release with redirects restricted to an
allow-list, and its SHA-256 is computed while downloading. **If the digest does not match,
the acquisition is refused and nothing is executed.** The collector is written to a
temporary directory, run directly rather than through a shell, with `ADB_`, `ANDROID_ADB_`,
`LD_` and `DYLD_` variables removed from its environment and `PATH` reset to the system
directory, and it is deleted when the command finishes. Nothing is downloaded or run unless
you invoke this command and confirm consent at the terminal.

If you prefer to install AndroidQF yourself, follow the five steps above and skip this
command entirely; the tool never needs to fetch anything. Note that its publisher ships
the Windows build unsigned, so a browser download of it will carry the usual "not commonly
downloaded" warning and Windows SmartScreen will prompt on first run.

Add `--age-recipient-file PATH` to supply public age1 recipients. A plaintext result is
refused when encryption was requested. An encrypted result must have a supported age
envelope and no unexpected accompanying files; format checks cannot authenticate its
contents or verify the recipient without the owner's identity. It is saved for separate
decryption and analysis; no scan or all-clear is produced. On failure, inspect the reported
acquisition folder: original or partial records are retained and may be unencrypted.
The command can finish successfully after saving such an archive, even though no scan ran.
Private age identity files are not accepted by this option.

Use `--phone-guide android` for preparation instructions and `--phone FOLDER --preview`
to list artifact availability before checking. For an AES-encrypted `backup.ab`, add
`--backup-password`: the password is requested privately at the terminal, never as an
argument or report field. Age-encrypted acquisition archives must first be decrypted with
the owner's identity using the separate age tool; this scanner does not launch it.

### Checking local iPhone evidence (experimental)

Run `--phone-guide ios`, then select a local Finder, Apple Devices or iTunes backup folder
containing `Manifest.plist` and `Manifest.db`. Use `--phone FOLDER --preview` before scanning
with `--phone FOLDER`. Add `--backup-password` for encrypted backups. Encryption requires the
optional `cryptography` Python package already installed in your environment; nothing is
installed automatically. The supported version is cryptography 46.0.5. To install that optional
dependency in your chosen Python environment, run `python -m pip install -r requirements-backups.txt`.

The reader checks supported SMS (including selected encoded bodies), Safari profiles,
data-usage processes, application records and optional Chrome/Firefox history. Additional
readers cover supported message/attachment metadata, WhatsApp, browser state, URL caches,
WebKit statistics, permissions, calls, calendar, interactions, Shortcuts, configuration,
analytics and diagnostic records. Known local browser visits are distinguished from
synced/imported records; unknown origin remains a reference with a gap.

For already acquired evidence, use `--phone ROOT --ios-input filesystem` for an extracted
filesystem, or `--phone PATH --ios-input sysdiagnose` for a directory or TAR/TAR.GZ archive.
These choices are also in the phone menu. Supported shutdown rotations and crash records
are checked; unusual paths alone are investigation leads. This does not acquire a device.

Committed SQLite WAL records are validated and replayed on temporary copies, including
independently encrypted backup sidecars. JSON findings retain source hashes and record
locators. Unsupported encodings/schemas, damaged WALs, exhausted limits, unavailable
protection classes and encrypted Manifest.db WALs remain explicit gaps. See
[docs/IPHONE.md](docs/IPHONE.md) for exact support and limits.
Unreadable message, browser-visit and process payloads are isolated when their row indexes
remain readable; later records are still checked. Repeated gaps are counted and grouped.

### Choosing the scope

- `--scan-type default` uses the computer checks and file candidates supported on your platform.
- `--scan-type full` also reads desktop-app raw web caches and hashes all file extensions
  in the usual roots, including subdirectories normally pruned. It is broader, not a scan
  of every drive, account or possible artifact. The 120 MiB file limit remains.
- `--scan-type targeted --target PATH` reads only selected files, directories, drives or
  supported browser profiles. Repeat `--target` for several locations. Explicitly selected
  files are hashed regardless of extension. Supported copied Prefetch/Amcache artifacts
  inside the selected scope are also read. Live system registry/log checks are outside this scope.
- `--scan-type browser` reads only this account's browser profiles and the desktop apps with
  a built-in Chromium browser: history, cookies, site storage, caches and connection records,
  checked against every loaded list, including the ad-campaign addresses. Large browser
  caches can still take several minutes. Files, startup entries, DNS, registry and system
  events are not read.
- `--preview` prints the proposed scope without scanning. File hashing reports progress.
  Ctrl+C stops the scan and reports findings already collected with an incomplete-coverage gap.
- `--extended-windows` opts into existing Sysmon and Security process events. It does not
  enable logging or elevate privileges. If access is denied, an optional second pass from
  an administrator terminal can read records that the ordinary account could not.

Windows checks now also read saved console/Explorer input and startup/task/service
registrations. Saved input is not proof of successful execution. Related-record groups
link the same indicator across distinct artifacts, preserve original evidence grades and
show available dates; they do not declare a causal attack sequence. Publisher validity,
platform and withdrawal labels are retained as context, including historical matches.
Startup launch interpretation supports recognizable batch commands and Internet Shortcut
URLs. Unsupported syntax and unresolved expansions produce gaps while retaining recognized
command evidence. Shell Link (`.lnk`) checks read supported literal target/argument metadata
without resolving or opening the target. Unsupported IDLists, blocks and expansions remain gaps.
Other unknown launch formats also produce gaps;
ordinary reference documents and comment text do not establish execution.

See [the coverage table](docs/COVERAGE.md) before relying on a particular check.

### Start menu and follow-up

Opening the tool in a terminal without selecting a check shows a menu. Enter starts the
standard check; 0 quits without scanning. Choose a full check, a browsers-only check,
selected files/folders or a phone collection from the same menu. Scripts with
noninteractive input do not see it; `--no-menu` explicitly disables menus.

The browsers entry also offers a test of whether your browser blocks ads. That test can
only run inside a browser, so the tool asks first and then hands the address of the
ArchiveGenocide test page to your default browser. The browser goes online for it; the
tool does not. See [PRIVACY.md](PRIVACY.md).

After a menu-selected check, inspect findings and references, review coverage gaps and next
steps, save reports, or prepare a private evidence bundle. `--post-menu` requests this
follow-up after an explicit command-line scan. The report is displayed before those choices.
The Windows launcher keeps prompts visible and saves both readable and JSON reports.

`--report PATH` saves the readable report independently of `--json` and `--share-json`.
Reports cannot replace existing files within a selected evidence folder or the selected
input files. Choose a new output filename. No retained baseline snapshots are created.

### Private evidence handoff

`--evidence-bundle PATH` creates a **new, unencrypted private ZIP** containing the full JSON
report, readable report, minimal sharing summary and integrity manifest. Repeat
`--evidence-file PATH` to include original local files you deliberately select. Report text
never chooses files to copy, and nothing is uploaded or sent to a helpline.

```text
python scan/zero-breach-triage.py --scan-type targeted --target SUSPICIOUS_FILE --report report.txt --json report.json --evidence-bundle evidence.zip --evidence-file SUSPICIOUS_FILE
```

Here `SUSPICIOUS_FILE` is the path of one file. `--evidence-file` takes files, not folders.

The interactive follow-up previews the contents and asks before creating the archive.
Command-line export options explicitly request the export and print its preview. Each
original file is limited to 64 MiB, with at most 128 originals and 256 MiB total payload.
The archive refuses overwrite and includes SHA-256 payload hashes, tool version, scope,
times and fingerprints of the effective parsed indicator sets. Hashes establish subsequent
integrity, not original-device authenticity. Originals are copied at export time and may
differ from the earlier scan; live databases may need separately selected sidecars.
Use the minimal summary for initial contact, and share the full archive only through a
secure route agreed with the recipient.


---

## Reading the result

The report starts with a short **summary**: what was found, what it means, what to do,
and what could not be checked. Everything below it is the evidence.

- **Findings** come with an *evidence grade*. "A known spyware file is on this machine"
  or "an app researchers name is on this phone" is strong. "A saved web page mentions the
  address" is weak — usually an article *about* the spyware. The grade, not the number of
  matches, decides what to do.
- **Worth a look** lists things the tool cannot judge on its own (a sideloaded app, a
  command that downloaded code, an antivirus exclusion), each with its usual, ordinary
  explanation. They are **not** findings.
- **In time order** lists every dated finding and item, so you can see what came first.
- **What could not be checked.** Read this part. A check that could not run has not
  cleared anything.

Exit codes for scripts: `0` no actionable matches and no recorded coverage gaps;
`2` a match beyond a saved reference; `3` no actionable matches but checks or indicator
sources were incomplete; `1` a setup, argument or output error; `4` the start menu was
closed without scanning (no verdict or report). Reference-only matches remain visible and use
`0` or `3`, depending on gaps. None of these results proves a device is safe.

## What it cannot do

- It only finds **published** indicators. New or unpublished spyware will not be found.
- Spyware is often rebuilt for each target, and many traces expire within weeks.
- An Android check sees only what the collection contains; an iPhone check sees only supported artifacts in the supplied local evidence. Neither is a full phone examination.
- It does not replace a forensic examination by experts. If you are worried, ask for help.

## Privacy

`--update` downloads indicator sources. The separate, explicit `--collect-android` command
downloads a pinned official collector after consent. Ordinary scans remain offline. Full reports can
contain usernames, profile names, file paths, browsing details, SMS senders and message
excerpts. Keep them private. `--share-json summary.json` writes counts, scope labels, the verdict and
fixed advice, omitting artifact text, indicator values and dates. It is an initial summary,
not forensic evidence; review it before sharing. See [PRIVACY.md](PRIVACY.md).

## For scripts and AI assistants

`--describe` prints, as JSON, every check the tool runs, what each reads and cannot see,
the exit codes and the rules for relaying a result. `--json` writes a machine-readable
report with fields an assistant must relay to the person, the next steps it may give, and
which fields hold untrusted text from the scanned machine. See
[scan/CONTRACT.md](scan/CONTRACT.md).

A ready-to-use [Zero Breach Toolkit skill](skills/zero-breach-triage/SKILL.md) is included
for assistants that support skills. Add the `skills/zero-breach-triage` folder to your
assistant's skill directory, or have it read that file. It covers scope selection,
encrypted-backup prompts, offline operation, report interpretation and evidence privacy.
It is supplied in the repository; it is not installed into your assistant automatically.

## Tested platforms

Tested on the platforms it supports: **Windows, macOS, Linux, Android** (AndroidQF
collections) **and iPhone** (local backups). See [docs/COVERAGE.md](docs/COVERAGE.md) for what
each check reads and its limits.

Built-in readers share a registry for platform selection, coverage descriptions and the
single-file build. See [scan/READERS.md](scan/READERS.md) to extend the toolkit.

## Credits

Indicators are the work of **Amnesty International's Security Lab**, **the Citizen Lab**,
the **MVT project** and **Echap**.

## Licence

Code, including the generated scanner: **Apache License 2.0** ([LICENSE](LICENSE)).
The curated indicator files in `iocs/` and generated indicator exports in `dist/`:
**CC0 1.0**, public domain ([iocs/LICENSE.md](iocs/LICENSE.md)). Optional bundled research
rules retain their separate licences in [third_party/candiru](third_party/candiru/README.md).
Indicator lists downloaded by `--update` remain under their publishers' terms and are not
part of this repository.
