"""Bounded literal Linux/macOS startup configuration inspection.

No command is executed, no referenced program is opened, and configuration
presence does not establish activation or execution. Network text is only a
reference; an exact published executable path can support configuration evidence.
"""
from __future__ import annotations

import configparser
import json
import os
import plistlib
import re
import stat
import sys
import xml.parsers.expat

from ..localpaths import path_problem
from ..result import Hit, ModuleResult, EV_CONFIGURED, EV_REFERENCED

NAME = "unix-host"
_UX_FILE_CAP = 1024 * 1024
_UX_COUNT_CAP = 4096
_UX_TOTAL_CAP = 32 * 1024 * 1024


def _ux_roots():
    home = os.path.expanduser("~")
    cfg = os.environ.get("XDG_CONFIG_HOME", "")
    cfg = cfg if os.path.isabs(cfg) else os.path.join(home, ".config")
    if sys.platform.startswith("linux"):
        return [
            ("linux-autostart", os.path.join(cfg, "autostart"), "desktop"),
            ("linux-autostart", "/etc/xdg/autostart", "desktop"),
            ("linux-systemd-units", os.path.join(cfg, "systemd", "user"), "unit"),
            ("linux-systemd-units", "/etc/systemd/user", "unit"),
            ("linux-systemd-units", "/etc/systemd/system", "unit"),
            ("linux-systemd-units", "/usr/lib/systemd/user", "unit"),
            ("linux-systemd-units", "/usr/lib/systemd/system", "unit"),
            ("linux-cron", "/etc/crontab", "cron-file"),
            ("linux-cron", "/etc/cron.d", "cron"),
            ("linux-cron", "/var/spool/cron/crontabs", "user-cron"),
            ("linux-cron", "/var/spool/cron", "user-cron"),
        ]
    if sys.platform == "darwin":
        return [("macos-launch-items", p, "plist") for p in (
            os.path.join(home, "Library", "LaunchAgents"),
            "/Library/LaunchAgents", "/Library/LaunchDaemons",
            "/System/Library/LaunchAgents", "/System/Library/LaunchDaemons")]
    return []


def _ux_read(path):
    problem = path_problem(path)
    if problem:
        raise OSError(problem)
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_size > _UX_FILE_CAP:
        raise OSError("not a regular file or exceeds configuration size limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise OSError("configuration changed before reading")
        data = stream.read(_UX_FILE_CAP + 1)
        after = os.fstat(stream.fileno())
    if len(data) > _UX_FILE_CAP or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise OSError("configuration changed or exceeded read limit")
    return data


def _ux_program(command):
    # Desktop Exec is not shell syntax. Recognize only literal tokens with
    # optional double quotes. Escapes and field substitutions need the desktop
    # specification's expansion rules; keep those commands as references.
    token = r'''"[^"\\%`$\r\n]*"|[^\s"'\\%`$><~|&;*?#()=]+'''
    command = command.strip()
    if not re.fullmatch("(?:" + token + ")(?:[ \t]+(?:" + token + "))*", command):
        return ""
    first = re.match(token, command).group(0)
    return first[1:-1] if first.startswith('"') else first


def _ux_fields(data, kind):
    """Return (text, exact executable paths, limitation); no target access."""
    if kind == "plist":
        doc = plistlib.loads(data)
        if not isinstance(doc, dict):
            raise ValueError("launch item is not a dictionary")
        argv, program = doc.get("ProgramArguments", []), doc.get("Program", "")
        if not isinstance(program, str) or not isinstance(argv, list) or not all(isinstance(v, str) for v in argv):
            raise ValueError("unsupported launch program fields")
        disabled = doc.get("Disabled", False)
        if not isinstance(disabled, bool):
            raise ValueError("unsupported Disabled field")
        # Other fields are metadata, not literal commands. Avoid recursive input
        # traversal and do not infer executables from arbitrary nested strings.
        text = "\n".join([program] + argv)
        labelled = isinstance(doc.get("Label"), str) and bool(doc["Label"])
        return text, [] if disabled or not labelled else [program or (argv[0] if argv else "")], ""
    text = data.decode("utf-8-sig", "strict")
    if "\x00" in text:
        raise ValueError("NUL in text configuration")
    if kind == "desktop":
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.optionxform = str
        parser.read_string(text)
        if parser.defaults():
            raise ValueError("unsupported inherited desktop keys")
        if not parser.has_section("Desktop Entry"):
            raise ValueError("missing Desktop Entry section")
        section = parser["Desktop Entry"]
        command = section.get("Exec", "")
        # Conditions and overrides are not resolved. Mark only unconditional
        # literal Application entries as configured executable paths.
        conditional = any(section.get(k, "") for k in ("OnlyShowIn", "NotShowIn", "TryExec"))
        enabled = (section.get("Type") == "Application" and
                   section.get("Hidden", "false") == "false" and
                   section.get("DBusActivatable", "false") == "false" and
                   section.get("X-GNOME-Autostart-enabled", "true") == "true" and not conditional)
        program = _ux_program(command)
        limitation = "unsupported desktop Exec syntax retained as references" if command and not program else ""
        return text, [program] if enabled and program else [], limitation
    # Unit activation, masking, drop-ins and variable expansion are deliberately
    # not resolved. Unit and cron text therefore supports references only.
    return text, [], ""


def _ux_match(result, ctx, path, text, programs):
    for ind in ctx.iocs.search(text.lower()):
        result.add_hit(Hit(ind.value, path,
            "Indicator text in startup configuration; contact and execution are unverified.",
            tier=ind.tier, confidence=ind.confidence, source=ind.source,
            family=ind.family, kind=ind.type, evidence=EV_REFERENCED, artifact=path))
    for ind in ctx.iocs.indicators:
        if ind.type != "file-path" or not ind.value.startswith("/"):
            continue
        # General typed lookup is case-insensitive for historical consumers.
        # Unix paths need the publisher's original case, including every value
        # retained when differently cased STIX records share a normalized key.
        originals = set()
        for encoded in ind.contexts:
            try:
                context = json.loads(encoded)
            except (TypeError, ValueError):
                continue
            value = context.get("case_sensitive_value") if isinstance(context, dict) else None
            if isinstance(value, str) and value.startswith("/"):
                originals.add(value)
        originals = sorted(originals or {ind.value})
        configured_paths = [value for value in originals if value in programs]
        matched_paths = configured_paths or [value for value in originals
            if re.search(r"(?<![^\s\"'=])" + re.escape(value) + r"(?=$|[\s\"';])", text)]
        if not matched_paths:
            continue
        configured = bool(configured_paths)
        result.add_hit(Hit(ind.value, path,
            ("Literal executable path matches a published indicator; activation and execution are unverified."
             if configured else "Published path appears in startup configuration; active executable use is unverified.")
            + " Exact path: " + matched_paths[0],
            tier=ind.tier, confidence=ind.confidence, source=ind.source,
            family=ind.family, kind=ind.type,
            evidence=EV_CONFIGURED if configured else EV_REFERENCED, artifact=path))


def run(ctx):
    result = ModuleResult(NAME)
    ctx.partial = result
    roots = _ux_roots()
    if not roots:
        result.could_not_run("unix-host-platform", "Linux/macOS startup readers are not applicable on this platform")
        return result
    total = count = 0
    seen = set()
    for check, root, kind in roots:
        failures = 0
        try:
            problem = path_problem(root)
            if problem:
                raise OSError(problem)
            info = os.lstat(root)
            if kind == "cron-file":
                candidates = [root]
            else:
                if not stat.S_ISDIR(info.st_mode):
                    raise OSError("configuration root is not a directory")
                candidates = []
                with os.scandir(root) as entries:
                    for entry in entries:
                        count += 1
                        if count > _UX_COUNT_CAP:
                            result.skipped += 1
                            result.could_not_run(check, "configuration entry count limit reached; retained entries still inspected")
                            break
                        suffix = {"desktop": ".desktop", "plist": ".plist", "unit": ".service"}.get(kind)
                        if suffix and not entry.name.endswith(suffix):
                            continue
                        # Subdirectories and unit activation links are not followed.
                        if entry.is_dir(follow_symlinks=False):
                            continue
                        candidates.append(entry.path)
            for path in candidates:
                if path in seen:
                    continue
                seen.add(path)
                try:
                    data = _ux_read(path)
                    total += len(data)
                    if total > _UX_TOTAL_CAP:
                        raise OSError("total configuration read limit reached")
                    text, programs, limitation = _ux_fields(data, kind)
                    _ux_match(result, ctx, path, text, programs)
                    result.checked += 1
                    if limitation:
                        failures += 1
                        result.skipped += 1
                except (OSError, ValueError, configparser.Error, plistlib.InvalidFileException,
                        xml.parsers.expat.ExpatError, OverflowError, RecursionError):
                    failures += 1
                    result.skipped += 1
                if total > _UX_TOTAL_CAP:
                    break
            result.ran(check)
            if failures:
                result.could_not_run(check, "{} configuration file(s) unreadable, refused, oversized or unsupported under {}".format(failures, root))
        except FileNotFoundError:
            result.ran(check)  # known root absent, not an unreadable root
        except OSError as exc:
            result.skipped += 1
            result.could_not_run(check, "{}: {}".format(root, exc))
        if total > _UX_TOTAL_CAP or count > _UX_COUNT_CAP:
            result.could_not_run("unix-host-limits", "remaining startup roots were not inspected after the safety limit")
            break
    result.note("Startup configuration only: no commands or referenced programs were opened or executed. Network strings are references, not contact.")
    result.note("Scope: immediate standard startup directories; unit drop-ins, activation links, cron scripts, shell profiles, other users' homes and modern managed login items are not resolved. Permissions and local filesystem redirections can leave gaps.")
    return result
