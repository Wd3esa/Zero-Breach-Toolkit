# Changelog

## Unreleased

- A report never replaces an existing file in a folder the hash check reads, including a
  file that looks like an earlier report (0.1.2 trusted such files; their content could be
  forged). Choose a new filename instead.
- Invisible formatting characters (zero-width spaces and joiners, direction marks) are
  removed from the readable report and from text handed to an assistant, so scanned text
  cannot hide anything; the JSON report keeps the raw evidence.
- iPhone: one unreadable security analytics record no longer stops the rest of that file.

## 0.1.2 (2026-10-27)

iPhone
- Accounts looked up by iMessage and FaceTime (`idstatuscache.plist`) are checked against
  published operator email addresses.
- Safari's and Chromium browsers' favicon stores are checked.
- Sites that stored data in an app's web view (LocalStorage, IndexedDB and the iOS 16+
  `origin` files) are checked.
- File-system extractions: security-framework analytics records (calling processes and
  hosts) are checked.

Computers
- macOS: folders blocked by macOS privacy protection (Safari's records and others) are
  reported as such, with the Full Disk Access fix, instead of "close the browser". The
  README now says to grant Terminal Full Disk Access first.
- File fingerprint gaps say why: permission denied, over 120 MB, or unreadable. Links,
  such as app framework aliases, are no longer counted as missed files.
- Opera's own bookmark folders (speed dial, trash, unsorted) are read.
- Safari download records in an unexpected layout keep their addresses as references and
  are reported as not fully checked.
- Windows: download-origin records that cannot be read, and folders below the depth
  limit, are reported as not checked.
- A report can no longer replace an existing file in a folder the hash check reads (an
  earlier report of this tool still can be).

Android
- Files without a valid fingerprint are reported as `android:file-hashes`, so a
  collection made without AndroidQF's "hash files" option is no longer complete by path
  alone.

Updates and reports
- `--update` shows each source's SHA-256 and the total number of indicators; an
  interrupted update leaves every finished source usable.
- Reports name the tool `zero-breach-toolkit`; a long browser phase prints a progress
  line; suppressed phone-monitoring mentions are named in the note.

## 0.1.1 (2026-10-27)

The project is now called Zero Breach Toolkit: the repository is `Zero-Breach-Toolkit` and
the single file is `zero-breach-toolkit.py`. Old links redirect.

iPhone
- Encrypted backups from real devices are read correctly. Files whose recorded size
  differs from the copied data (live databases) and iCloud-only files no longer fail.
- Supports the table layouts used by iOS 15 to 18 for WebKit statistics, Calendar,
  Shortcuts and Calls; Safari tabs and iCloud tabs; the iOS 18 network-usage database.
- Installed configuration profiles and profile install history; calendar participants;
  privacy-permission clients compared as process names; connection records of
  Chromium-based iPhone browsers and Brave's site list.
- Sysdiagnose: memory-pressure, stackshot and text reports, running processes and
  installation logs (apps installed as developer builds are listed as worth a look).
- Fewer false gaps on real phones, and every record limit that is reached is reported.

Computers
- More browsers on Windows, macOS and Linux: Chrome, Edge and Brave beta/dev/canary
  channels, Opera, Opera GX, Arc, Yandex, LibreWolf, Waterfox, Floorp, Zen, Pale Moon and
  Tor Browser.
- macOS: Safari cookies, HSTS, tabs, iCloud tabs, cache, bookmarks, downloads, Top Sites
  and closed tabs; Terminal session history; desktop apps such as Signal; launch items
  matched by process name. The hosts file is checked on macOS and Linux.
- Desktop-app discovery has no fixed depth limit.
- Reports never replace existing files in app data or app cache folders.

Android
- Process lists from older AndroidQF versions, MMS text, and only received messages
  graded "received". Certificate coverage counts SHA-256 and SHA-1 separately.

Safety and reliability
- `--update` refuses a list whose indicator count suddenly falls by more than half (or to
  zero) and keeps the previous copy, so a broken or tampered source cannot quietly make
  scans look clean. Update requests use a generic user agent.
- PowerShell loads modules only from Windows' own folder.
- On Windows, one check that fails no longer stops the others; it is listed as not checked.
- A DNS-log lookup answered only with a block address is graded as a blocked attempt.
- Repeated Safari downloads of the same address are graded per download. Reports cannot
  overwrite Safari's sandbox or cookie files. Malformed iPhone connection data is a gap for
  that file only.
- Paths in colon- or comma-separated lists are matched on macOS and Linux; Chromium
  profiles with custom folder names are found.

Reports and guides
- The summary counts each indicator once, with the number of places it was recorded.
- Step-by-step phone guides (`--phone-guide android|ios`), including how to answer
  AndroidQF's questions, and clearer install steps in the README.

## 0.1.0 (2026-10-27)

First version of Zero Breach Toolkit, built on Zero Breach.

- Indicators from 25 published sources (Amnesty International Security Lab, the MVT
  project, the Citizen Lab, Echap) via `--update`, plus a hand-curated, cited set for
  Candiru / DevilsTongue and Paragon's Graphite that works offline. STIX 2, MISP CSV and
  list formats; downloads verified and refused if changed afterwards.
- Windows checks without administrator rights: browsers and desktop apps with a built-in
  browser (found automatically), Mark of the Web on downloads, Win+R history, Microsoft
  Defender's history, the PowerShell log, programs Windows recorded as having run
  (fingerprinted wherever they are), file fingerprints, DNS cache and history, hosts file,
  per-user auto-start registrations.
- Windows execution and inventory evidence: Prefetch files, Amcache records, and auto-start
  shortcuts read for the program they point at without opening or resolving the target.
  Amcache entries are reported as inventory, never as proof that something ran or is still
  present.
- Linux and macOS: auto-start desktop entries, service units and readable cron files;
  LaunchAgent and LaunchDaemon settings. Literal program paths can be evidence; command
  arguments and unverified commands remain references.
- Android: `--phone FOLDER` reads an AndroidQF collection: installed and running apps,
  fingerprints, signing certificates, install/uninstall history, system services' state,
  logs, crash records and SMS links (new grade "received"); sideloaded apps listed with
  what they can do and when they were installed; signs of a modified phone. The
  collection's own footprint is recognised. Decrypted intrusion logs are read where the
  format is supported: DNS lookups, connection attempts and app starts.
- Android guided acquisition, experimental and separate from scanning: `--collect-android`
  downloads the official AndroidQF release pinned to its SHA-256, refuses it if the digest
  does not match, asks the device owner for consent at the terminal, then checks the
  collection it produced. Installing AndroidQF yourself remains fully supported.
- iPhone, experimental: `--phone FOLDER` reads a local Finder, Apple Devices or iTunes
  backup: SMS and Safari records, data-usage processes and applications, optional Chrome
  and historical Firefox history. Encrypted backups are supported with `--backup-password`.
  Synced and imported records are distinguished from local visits.
- Report: graded evidence, a "worth a look" section that never changes the result, a
  timeline, grouped gaps, exit code 3 for "nothing found but checks were missing".
- Saved reports and follow-up: `--report` writes the readable report to a file, and a menu
  after the scan explains what was found, saves reports and minimal summaries, and can
  export a private evidence bundle: a new ZIP holding the reports, the originals you
  explicitly choose, the scope and times, and a SHA-256 for every file in it. The manifest
  does not claim the originals are authentic. Output guards refuse to overwrite anything
  the scan read. Piped input never prompts, and `--no-menu` turns the menus off.
- Start menu for people who open the tool without arguments, shown only at a terminal.
- Machine contract for scripts and AI assistants: `--describe`, JSON fields to relay,
  untrusted-text marking. Report schema 1.4 adds reader descriptions, the host platform,
  execution and inventory records, and states explicitly when an optional input was absent
  and why. None of that can hide a finding, an error or a gap. Schema 1.5 adds the
  `WITHDRAWN_ONLY` verdicts and `withdrawn_total`.
- Withdrawn indicators are not findings: when every publisher that lists a matched
  indicator has withdrawn it, the result is `WITHDRAWN_ONLY` (exit 0, or 3 with gaps) and the
  person is not told to preserve the device. Each publisher's newest version decides, and
  one current active listing anywhere keeps a match actionable.
- Hand-written indicator lists refuse loopback, private, link-local, multicast and reserved
  addresses, so a list cannot match ordinary local traffic. The RFC 5737 and RFC 3849
  documentation ranges stay allowed, because they never occur on a real network and test
  lists rely on them; published feeds still refuse those as well.
- Domain names containing `ß` or a final sigma are refused rather than stored in the form
  older IDNA produces, which is not what browsers record and can name a different domain.
- A hosts-file or DNS-cache entry that points an indicator at any loopback or unspecified
  address, such as `127.0.0.2` or `::ffff:127.0.0.1`, is recognised as a block. Only
  `127.0.0.1` and a few fixed spellings were before, so other blocks were reported as findings.
- A Chromium history row with no recorded visit is a reference, not contact.
- Withdrawals are decided per STIX object. One publisher revoking one indicator object no
  longer withdraws a different, still active object it publishes for the same value, which
  could turn a real contact match into `WITHDRAWN_ONLY` with exit 0.
- A stalkerware match in decrypted Android intrusion logs stays a phone finding. The
  computer rule that turns stalkerware company sites into "worth a look" had treated it as
  a web visit; phone readers are now taken from the reader registry, not a hand-kept list.
- A Chromium visit synced from another device is no longer called contact by this
  computer. It is kept as a reference with a "worth a look" note to check that device.
- A browser database that reads through a view or a recursive query, which no browser
  writes, is refused as a gap, and each database read has a time limit. A 4 KiB crafted
  History file could previously keep the scan running indefinitely.
- New `--scan-type browser`: reads only this account's browser profiles and desktop apps
  with a built-in browser. The report says so, and adds a `browser-only` line that must be
  passed on. The start menu has a matching "browsers only" entry, which also offers a test
  of whether your browser blocks ads. The test page opens in your browser only after you
  say yes; the tool itself still makes no request.
- One file with a malformed Mark of the Web address no longer stops the rest of the Windows
  trace checks, and one ambiguous iPhone record no longer stops the backup reader. A changed
  Defender exclusion is reported, not only a newly added one.
- Built-in readers share one registry for platform selection, coverage descriptions and the
  single-file build; no outside plugins are loaded.
- Fast: one-pass matching of domains and addresses, parallel file fingerprinting.
- Welcome banner for people at a terminal (`--no-banner` to hide it).
- Verifiable instead of signed: `python build/bundle.py` rebuilds the single-file scanner
  from this source, and every rebuild produces a byte-identical file. There is no signed
  Windows program; see
  [docs/VERIFYING.md](docs/VERIFYING.md).
