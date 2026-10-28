"""Refuse Windows remote drives and filesystem redirections before reads.

Checks are conservative and use lstat so a reparse point is inspected rather
than followed. POSIX network mounts cannot always be distinguished from local
paths here. This is not a sandbox against concurrent filesystem changes.
"""

import os
import posixpath
import stat
import sys


def local_temp_dir():
    """Select a local temp directory without tempfile's write-probing fallback."""
    candidates = [os.environ.get(key, "") for key in ("TMPDIR", "TEMP", "TMP")]
    if sys.platform == "win32":
        candidates.extend(os.path.join(base, "Temp") for base in
                          (os.environ.get("LOCALAPPDATA", ""),
                           os.environ.get("SystemRoot", "")) if base)
    else:
        candidates.extend(("/tmp", "/var/tmp", "/private/tmp"))
    for candidate in candidates:
        if candidate and not path_problem(candidate) and os.path.isdir(candidate):
            return candidate
    raise PermissionError("no safe local temporary directory is available")


def path_problem(path):
    """Return why a path cannot safely be inspected, or an empty string."""
    path = os.fspath(path)
    if not os.path.isabs(path):
        return "relative path cannot be classified as local"
    if ".." in path.replace("\\", "/").split("/"):
        return "parent-directory traversal cannot be classified as local"
    if sys.platform == "win32":
        s = path.replace("/", "\\")
        if s.startswith("\\\\"):
            return "UNC or device path was not opened"
        drive, _tail = os.path.splitdrive(s)
        if len(drive) != 2 or drive[1] != ":":
            return "path does not name an absolute local drive"
        try:
            import ctypes
            kind = ctypes.windll.kernel32.GetDriveTypeW(drive + "\\")
        except (AttributeError, OSError):
            return "drive locality could not be established"
        if kind not in (2, 3, 5, 6):  # removable, fixed, CD-ROM, RAM disk
            return "drive is remote or its locality is unknown"

    drive, tail = os.path.splitdrive(path)
    current = drive + os.sep
    # Windows accepts both separators, so both must split the path, or a junction
    # in a forward-slash path would never be inspected. On POSIX a backslash is an
    # ordinary filename character.
    if sys.platform == "win32":
        tail = tail.replace("/", "\\")
    parts = [p for p in tail.split(os.sep) if p]
    for index, part in enumerate(parts):
        current = os.path.join(current, part)
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return ""  # caller handles a genuinely absent artifact
        except OSError as exc:
            return "cannot safely inspect {}: {}".format(current, exc)
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & 0x400):
            # macOS exposes its standard /var, /tmp and /etc directories through
            # root-owned aliases into /private. These exact system aliases are
            # safe to validate lexically; arbitrary user links remain refused.
            # readlink reads the link itself and does not traverse its target.
            # Apple's signed cryptexes (Safari's and WebKit's launch agents live
            # in the App one) are reached the same way, through root-owned
            # links into the Preboot volume.
            aliases = {"/var": "/private/var", "/tmp": "/private/tmp",
                       "/etc": "/private/etc",
                       "/System/Cryptexes/App": "/System/Volumes/Preboot/Cryptexes/App",
                       "/System/Cryptexes/OS": "/System/Volumes/Preboot/Cryptexes/OS"}
            target = aliases.get(current) if sys.platform == "darwin" else None
            if (target and stat.S_ISLNK(info.st_mode)
                    and getattr(info, "st_uid", None) == 0):
                try:
                    link = os.readlink(current)
                except OSError as exc:
                    return "cannot inspect system alias {}: {}".format(current, exc)
                # Apple's links commonly use 'private/var', relative to '/', or
                # '../../System/Volumes/...' relative to the link's folder.
                # Accept only spellings that name exactly the expected target.
                relative = posixpath.normpath(posixpath.join(posixpath.dirname(current), link))
                if link in (target, target.lstrip("/")) or relative == target:
                    canonical = os.path.join(target, *parts[index + 1:])
                    return path_problem(canonical)
            return "symlink or reparse point was not followed: {}".format(current)
    return ""


WALK_LINK_REFUSED = "symlink or reparse point was not followed"
WALK_SPECIAL_REFUSED = "special filesystem entry was not opened"
WALK_CLOUD_SKIPPED = "folder is stored only in iCloud and was not downloaded"
# macOS marks iCloud placeholders ("Optimise Mac Storage") with this flag; reading or
# listing one makes macOS download it first, which can stall a scan for hours.
SF_DATALESS = 0x40000000


def walk_local(root, onerror=None):
    """Top-down os.walk equivalent that never classifies a link by following it.

    The caller can prune the yielded dirs list in place, as with os.walk.
    Refused entries are delivered to onerror as PermissionError instances whose
    strerror is WALK_LINK_REFUSED or WALK_SPECIAL_REFUSED; any other error is a
    folder or entry that could not be read.
    """
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            problem = path_problem(current)
            if problem:
                raise PermissionError(13, problem, current)
            dirs, files = [], []
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if (stat.S_ISLNK(info.st_mode)
                                or getattr(info, "st_file_attributes", 0) & 0x400):
                            raise PermissionError(13, WALK_LINK_REFUSED, entry.path)
                        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                            raise PermissionError(13, WALK_SPECIAL_REFUSED, entry.path)
                        if stat.S_ISDIR(info.st_mode) and getattr(info, "st_flags", 0) & SF_DATALESS:
                            raise PermissionError(13, WALK_CLOUD_SKIPPED, entry.path)
                        (dirs if stat.S_ISDIR(info.st_mode) else files).append(entry.name)
                    except OSError as exc:
                        if onerror:
                            onerror(exc)
        except OSError as exc:
            if onerror:
                onerror(exc)
            continue
        yield current, dirs, files
        pending.extend(os.path.join(current, d) for d in reversed(dirs))


def open_evidence_db(path):
    """Open the tool's private temporary copy of an evidence database, hardened
    the same way for every reader: schema-defined functions and views are not
    trusted, nothing can be written, and string/blob, column and expression
    sizes are bounded so a hostile database cannot exhaust memory or the stack.
    Callers query only; the live original is never opened here."""
    import sqlite3
    con = sqlite3.connect(path)
    try:
        con.execute("PRAGMA trusted_schema=OFF")
        con.execute("PRAGMA query_only=ON")
        con.execute("PRAGMA mmap_size=0")
        if hasattr(con, "setlimit"):  # Python 3.11+
            con.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 2 * 1024 * 1024)
            con.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 256)
            con.setlimit(sqlite3.SQLITE_LIMIT_EXPR_DEPTH, 100)
    except sqlite3.Error:
        con.close()
        raise
    return con
