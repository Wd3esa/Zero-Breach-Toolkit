# Ideas and improvements (uncommitted notes)

Collected during review. None of these changes behavior on real inputs today; each is a
hardening or cleanup. Priority order as listed.

## 1. Make `Hit` construction keyword-only / add a field-order guard (highest value)

`scan/zbtriage/result.py:114-123` — the `Hit` dataclass is built positionally in several
modules (`Hit(indicator, location, detail, tier, confidence, source, evidence=...)`). The
code's own comment warns that inserting a field before `evidence` "would silently shift
every grade into this slot."

- Convert the positional callers to all-keyword arguments (or make the dataclass
  keyword-only from `evidence` onward).
- Add a test that asserts the field order, so a future edit that shifts grades fails the
  suite instead of silently mis-grading.

This is insurance against the exact class of bug the tool's first priority (wrong
evidence grades) depends on.

## 2. Tighten the correlation artifact-normalization regex

`scan/zbtriage/evidence.py:112` — `re.sub(r":record \d+$|:\d+$", ...)` is meant to collapse
"row 1 / row 2" of one physical artifact, but the `:\d+$` arm also strips a real trailing
`:digits` (a URL port, an iOS record-id suffix on a path). Consequence is cosmetic only:
`evidence_correlations` never strengthens the verdict. But it can group two genuinely
separate files into one "RELATED RECORDS" line.

- Match only the known row-suffix shapes (e.g. `:record \d+`) rather than any trailing
  `:digits`.

## 3. Drop the dead `evidence` parameter on `scan_blobs`

`scan/zbtriage/modules/browser.py:1865` — `scan_blobs(label, root, evidence)` never uses
`evidence`; the callers pass `EV_CONTACTED` for origin-keyed stores but the function always
grades `EV_REFERENCED` (correct for a raw byte search). Removing the parameter and the
misleading `EV_CONTACTED` callsites (`:2275`) stops a future edit re-adding a contact grade
where it cannot be justified.

## 4. Align the iPhone keybag SHA-1 fallback guard with the SHA-256 round

`scan/zbtriage/backupcrypto.py:100-103` — the SHA-256 round is guarded (`if salt_tag ==
b"DPSL" and salt_tag not in header: continue`) but the SHA-1 round reads `SALT`/`ITER`
unconditionally. Real keybags carry both steps, so this does not fire on real devices, but
a keybag carrying only `DPSL`/`DPIC` would raise a confusing "missing keybag number" instead
of a clean "unsupported keybag".

- Skip the SHA-1 round when `SALT`/`ITER` are absent, matching the SHA-256 guard, and
  report the keybag as unsupported rather than malformed.

## Later / smaller (no urgency)

- `readers.py:85` — the `host` reader runs on macOS/Linux (hosts file only) but its
  catalogue still advertises Windows-only sources (COM, DNS cache/log, known paths).
  Wording mismatch only; no detection impact.
- `feeds.py` — `--update` replaces data files before rewriting the manifest; an
  interrupted update leaves a refused cache until a full re-update. Safe, but a per-source
  rollback would recover more cheaply. (A count-drop guard was already added in 0.1.1.)

## Checked and confirmed correct (do not re-open)

- IOC matching boundary rules and fast-path/reference equivalence.
- `netguard`, local-path/link refusal, PowerShell env/cwd pinning (no untrusted string is
  ever interpolated into a `-Command`).
- Per-check isolation in `host`, `android`, `posix`, `patternscan`, `traces`, and per-artifact
  in `ios`.
- Menu consent gating, pinned+checksum-verified AndroidQF acquisition, bounded ZIP/age
  handling, and `--share-json` redaction.
