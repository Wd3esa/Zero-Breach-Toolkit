"""Hunt known sample hashes across the user-writable parts of this machine.

Citizen Lab (and others) publish SHA-256 hashes for the Windows payloads this
infrastructure delivers. Hashing every file on C: would take hours, so this
scans the locations an implant DLL actually lands in, plus anything the user
downloaded, and compares each file's digest against the sample hashes carried in
the IOC set.

A clean result means "none of these exact files are in these locations" - nothing
more. Each sample is one build; another victim's payload would hash differently,
which is why a clean hash scan is never a clean bill of health (D1/D3).

Contract: defines NAME and run(ctx) -> ModuleResult. Read-only, stdlib only, no
network (D2) - hashing a local file resolves nothing.
"""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
import io
import os
import stat
import sys

from ..result import Hit, ModuleResult, EV_ON_DISK
from ..localpaths import path_problem, walk_local

NAME = "hash"

# Only file types a payload plausibly ships as. Keeps the walk cheap and avoids
# hashing the user's documents and media for no reason.
EXTS = (".dll", ".exe", ".sys", ".ocx", ".cpl", ".scr", ".tmp", ".dat", ".bin", ".ax")

# Files larger than this are almost certainly not the implant; skipping them
# (counted as skipped, never as clean) keeps the scan from stalling on big blobs.
MAX_BYTES = 120 * 1024 * 1024

# Directory names pruned from the walk: browser/code caches, dependency trees and
# the Windows component store - huge, noisy, and not where an implant DLL lands.
PRUNE_DIRS = (
    "cache", "cache_data", "gpucache", "code cache", "node_modules",
    ".git", "servicepackfiles", "winsxs",
)


def _roots():
    """The user-writable locations an implant actually drops into, filtered to
    those that exist on this host. Matches the proof-of-concept exactly."""
    user = os.path.expanduser("~")
    roots = [
        os.environ.get("APPDATA", ""),
        os.environ.get("LOCALAPPDATA", ""),
        os.environ.get("PROGRAMDATA", ""),
        os.environ.get("TEMP", ""),
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp"),
        os.path.join(user, "Downloads"),
        os.path.join(user, "Desktop"),
        os.path.join(user, "Documents"),
        r"C:\Users\Public",
    ]
    if sys.platform.startswith("linux"):
        config = os.environ.get("XDG_CONFIG_HOME", "")
        data = os.environ.get("XDG_DATA_HOME", "")
        roots = [os.path.join(user, name) for name in
                 ("Downloads", "Desktop", "Documents", ".local/bin")]
        roots += [config if os.path.isabs(config) else os.path.join(user, ".config"),
                  data if os.path.isabs(data) else os.path.join(user, ".local/share"),
                  "/tmp", "/var/tmp"]
    elif sys.platform == "darwin":
        roots = [os.path.join(user, name) for name in
                 ("Downloads", "Desktop", "Documents", "Applications", "Library/Application Support",
                  "Library/LaunchAgents")]
        roots += ["/Applications", "/Library/LaunchAgents", "/Library/LaunchDaemons", "/private/tmp", "/private/var/tmp"]
    # De-duplicate by resolved, case-normalised path, then drop any root that is
    # nested inside another. %TEMP% is %LOCALAPPDATA%\Temp on a default install,
    # so without this every file under Temp is hashed twice - inflating the
    # coverage counts and reporting one real sample as two separate hits.
    resolved = []
    for raw in roots:
        if not raw:
            continue
        # Do not resolve links or test existence before the locality guard.
        norm = os.path.normcase(os.path.normpath(raw))
        if norm not in resolved:
            resolved.append(norm)
    kept = []
    for r1 in resolved:
        if any(r1 != r2 and r1.startswith(r2 + os.sep) for r2 in resolved):
            continue  # r1 lives inside another root; walking that one covers it
        kept.append(r1)
    return kept


def _hs_candidate(path, filename):
    """Platform default selection; full/targeted scans already select all files.

    Extensionless ELF/Mach-O and scripts are common on Unix. Include all
    extensionless files plus native libraries/scripts and executable files,
    without opening a candidate merely to guess its format.
    """
    if filename.lower().endswith(EXTS):
        return True
    if not (sys.platform.startswith("linux") or sys.platform == "darwin"):
        return False
    lower = filename.lower()
    if (not os.path.splitext(filename)[1] or lower.endswith((".so", ".dylib", ".sh", ".bash", ".zsh", ".py", ".pl"))
            or ".so." in lower):
        return True
    # stat errors belong in the normal guarded hashing path, where they become
    # explicit gaps rather than silently excluding a possible executable.
    try:
        return bool(os.stat(path, follow_symlinks=False).st_mode & 0o111)
    except OSError:
        return True


# Files fingerprinted at once. Reading and hashing release the interpreter lock,
# so threads give a real speed-up without a second process.
_WORKERS = max(2, min(8, (os.cpu_count() or 2)))


def _hash_one(full):
    """(path, hex digest or None, size). None = could not be fingerprinted
    (refused path, over the size cap, locked or unreadable) - counted as a gap
    by the caller, never as clean."""
    try:
        problem = path_problem(full)
        if problem:
            return full, None, 0
        if os.path.getsize(full) > MAX_BYTES:
            return full, None, 0
        digest, size = _sha256(full)
        return full, digest, size
    except OSError:
        return full, None, 0


def _sha256(full):
    """SHA-256 of a file, read in 1 MiB chunks so a large file never loads whole
    into memory. Returns (hex_digest, size) or raises OSError for the caller to
    count as skipped."""
    problem = path_problem(full)
    if problem:
        raise PermissionError(13, problem, full)
    info = os.stat(full, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        raise OSError("not a regular file")
    size = info.st_size
    h = hashlib.sha256()
    read_bytes = 0
    with io.open(full, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            read_bytes += len(chunk)
            if read_bytes > MAX_BYTES:
                raise OSError("file exceeded hash read limit")
            h.update(chunk)
    return h.hexdigest(), read_bytes


def _hash_outcomes(candidates, ctx):
    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        for start in range(0, len(candidates), 128):
            ctx.emit("[hash] fingerprinted {} / {} candidates".format(start, len(candidates)))
            yield from pool.map(_hash_one, candidates[start:start + 128])


def run(ctx) -> ModuleResult:
    r = ModuleResult(NAME)
    # Publish the result straight away so that if anything below raises,
    # the CLI can still recover whatever was found before the failure
    # instead of discarding it (see ScanContext.partial).
    ctx.partial = r

    # Build the hex-digest -> Indicator map once so each file is a single dict
    # lookup. The hashes come from the IOC set, never hardcoded (ctx.iocs.hashes).
    targets = {ind.value: ind for ind in ctx.iocs.hashes}

    # D3: with nothing to compare against we cannot claim CLEAN. State the gap
    # and stop - an empty target set is UNKNOWN for this check, not clean.
    if not targets:
        r.could_not_run("hash-compare", "no sample hashes in the indicator set")
        return r

    ctx.emit("[hash] looking for {} known sample hash(es)".format(len(targets)))

    for root in (ctx.targets or _roots()):
        problem = path_problem(root)
        if problem:
            r.could_not_run("root:" + root, problem)
            continue
        selected_file = bool(ctx.targets) and os.path.isfile(root)
        if not selected_file and not os.path.isdir(root):
            if ctx.targets:
                r.could_not_run("root:" + root, "target disappeared or is not a regular file/directory")
            continue
        # The full path, not the basename: %TEMP% and %SystemRoot%\Temp both end
        # in "Temp", and two roots collapsing to one name would make the check
        # list lie about what was actually covered.
        #
        # The verdict for this root is decided AFTER the walk, not before it.
        # Marking it as a check that ran up front meant a root where every
        # candidate file failed to open still counted as a clean, completed
        # check: nothing was fingerprinted, nothing was reported, and the scan
        # said CLEAN with no gap. A file that could not be read has not been
        # cleared of anything (D3).
        ctx.emit("[hash] scanning {} ...".format(root))
        tally = {"hashed": 0, "candidates": 0, "unreadable": 0}

        def _walk_err(exc, _r=r, _t=tally):
            # An unreadable subtree would otherwise vanish silently from os.walk.
            _r.skipped += 1
            _t["unreadable"] += 1

        candidates = [root] if selected_file else []
        for dirpath, dirs, files in ([] if selected_file else walk_local(root, onerror=_walk_err)):
            # Prune noisy / huge subtrees in place so os.walk never descends them.
            if not ctx.full and not ctx.targets:
                dirs[:] = [d for d in dirs if d.lower() not in PRUNE_DIRS]
            for fn in files:
                if ctx.full or ctx.targets or _hs_candidate(os.path.join(dirpath, fn), fn):
                    candidates.append(os.path.join(dirpath, fn))
        tally["candidates"] += len(candidates)

        # Fingerprinting is file reading plus hashing, both of which release
        # Python's interpreter lock, so several files are done at once. Results
        # are consumed in the original walk order, so the report is identical to
        # the one-at-a-time version (2026-10-25: 7 min for 45k files before).
        for full, digest, size in _hash_outcomes(candidates, ctx):
            if digest is None:
                # Locked, permission-denied, refused or over the size cap:
                # skipped, never clean (D3).
                r.skipped += 1
                tally["unreadable"] += 1
                continue

            tally["hashed"] += 1
            r.checked += 1
            r.submetrics["files_hashed"] = r.submetrics.get("files_hashed", 0) + 1
            r.submetrics["bytes_hashed"] = r.submetrics.get("bytes_hashed", 0) + size

            ind = targets.get(digest)
            if ind is not None:
                # EV_ON_DISK is the whole point: a file whose fingerprint
                # matches a published sample is conclusive. Without an
                # evidence grade the report defaulted it to "referenced" and
                # told the reader it was "probably not a sign of compromise" -
                # over a known spyware binary sitting on their disk.
                r.add_hit(Hit(
                    indicator=digest,
                    location=full,
                    detail="this file's SHA-256 matches a published sample: "
                           + ind.value,
                    tier=ind.tier,
                    confidence=ind.confidence,
                    source=ind.source,
                    family=ind.family,
                    evidence=EV_ON_DISK,
                ))
                ctx.emit("[hash] !! MATCH {} ({})".format(full, ind.value))

        # Now say honestly what this root amounted to.
        name = "root:" + root
        if tally["hashed"]:
            r.ran(name)
            if tally["unreadable"]:
                r.could_not_run(
                    name + " (partial)",
                    "{} of {} candidate file(s) under this root could not be "
                    "read or were too large to fingerprint, so they were not "
                    "compared against the known hashes".format(
                        tally["unreadable"], tally["candidates"]))
        elif tally["candidates"] or tally["unreadable"]:
            # Candidates existed but not one could be fingerprinted: this root
            # was not searched at all, however many files it holds.
            r.could_not_run(
                name,
                "no file under this root could be fingerprinted ({} candidate "
                "file(s) unreadable)".format(tally["unreadable"]))
        else:
            # Walked cleanly, held nothing to fingerprint. Genuinely covered.
            r.ran(name)

    return r
