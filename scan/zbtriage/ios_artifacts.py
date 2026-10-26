"""Independent, bounded iPhone artifact readers and discovery.

Schema selection is explicit and conservative. A matching string is not promoted
to contact or execution merely because it occurs in a cache, plist or attachment.
Format/availability references are documented in docs/IPHONE.md.
"""
import datetime
import json
import os
import plistlib
import re
import sqlite3
import time

from .ios_sources import _is_plist
from .result import Lead, EV_REFERENCED, EV_RECEIVED, EV_DEVICE_LOG, EV_CONFIGURED

_IA_ARTIFACT_LIMIT = 256


def ios_exact_identity(indicator, value):
    """Respect publisher case for Unix names, even after feed normalization."""
    if not isinstance(value, str):
        return False
    originals = []
    for context in indicator.contexts:
        try:
            record = json.loads(context)
            original = record.get("case_sensitive_value", indicator.value) if isinstance(record, dict) else indicator.value
            if isinstance(original, str):
                originals.append(original)
        except (ValueError, TypeError):
            continue
    return value in (originals or [indicator.value])


def ios_history_specs(source, base_specs, gap):
    """Discover known profile layouts; never follow paths taken from app rows."""
    specs = list(base_specs) if source.kind == "backup" else []
    seen = {(s[1], s[2]) for s in specs}
    found = set()
    for domain, path in source.entries:
        match = None
        if source.kind == "backup":
            safari_domain = domain in ("HomeDomain", "AppDomain-com.apple.mobilesafari",
                                        "AppDomainGroup-group.com.apple.safari")
            if safari_domain and re.fullmatch(r"Library/Safari/(?:Profiles/[^/]+/)?History\.db", path):
                match = base_specs[1]
            elif domain == "AppDomain-com.google.chrome" and re.fullmatch(
                    r"Library/Application Support/Google/Chrome/(?:Default|Profile \d+)/History", path):
                match = base_specs[3]
            elif domain.startswith("AppDomainGroup-group.org.mozilla.ios.Firefox") and re.fullmatch(
                    r"(?:profile\.[^/]+|Profiles/[^/]+)/browser\.db", path):
                match = base_specs[4]
        elif source.kind == "filesystem":
            clean = path.removeprefix("private/") if hasattr(path, "removeprefix") else path[8:] if path.startswith("private/") else path
            if clean == "var/mobile/Library/SMS/sms.db":
                match = base_specs[0]
            elif re.fullmatch(r"var/mobile/Library/Safari/(?:Profiles/[^/]+/)?History\.db", clean):
                match = base_specs[1]
            elif clean in ("var/wireless/Library/Databases/DataUsage.sqlite", "var/networkd/netusage.sqlite"):
                match = base_specs[2]
            elif re.fullmatch(r"var/mobile/Containers/Data/Application/[^/]+/Library/Application Support/Google/Chrome/(?:Default|Profile \d+)/History", clean):
                match = base_specs[3]
        if match:
            found.add(match[0])
            if (domain, path) not in seen:
                if len(specs) >= _IA_ARTIFACT_LIMIT:
                    gap("ios:input", "browser/process artifact discovery limit reached")
                    break
                seen.add((domain, path))
                specs.append((match[0], domain, path) + match[3:-1] + (True,))
    # A modern Safari profile can replace the legacy location. Do not manufacture
    # a missing legacy-artifact gap when a supported alternate has been found.
    if source.kind == "backup" and "ios:safari" in found:
        specs = [s for s in specs if s[0] != "ios:safari" or (s[1], s[2]) in source.entries]
    if source.kind == "filesystem":
        for check in ("ios:messages", "ios:safari", "ios:processes"):
            if check not in found:
                gap(check, "supported artifact was not present in this filesystem extraction")
    return specs


def _ia_iso(value):
    if isinstance(value, datetime.datetime):
        return value.isoformat() if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc).isoformat()
    if not isinstance(value, str) or len(value) > 128:
        return ""
    try:
        text = value.strip().replace("Z", "+00:00")
        parsed = datetime.datetime.fromisoformat(text)
        # Do not silently interpret a timezone-free log as local scanner time.
        return parsed.isoformat() if parsed.tzinfo else ""
    except ValueError:
        return ""


def _ia_walk(obj):
    pending, count = [((), obj)], 0
    while pending:
        path, value = pending.pop()
        count += 1
        if count > 20000 or len(path) > 24:
            raise ValueError("structured artifact node/depth limit reached")
        if isinstance(value, dict):
            pending.extend((path + (str(k),), v) for k, v in value.items())
        elif isinstance(value, list):
            pending.extend((path + (str(n),), v) for n, v in enumerate(value))
        elif isinstance(value, (str, datetime.datetime, int, float)):
            yield path, value


def _ia_artifact_kind(domain, path, kind):
    base = path.rsplit("/", 1)[-1]
    low = path.lower()
    # Backup domains constrain app-owned formats. Direct extractions supply
    # physical paths instead; their interpretation still requires a schema.
    mobile = kind != "backup" or domain in ("HomeDomain", "RootDomain", "WirelessDomain",
                                            "SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles")
    if mobile and base == "sms.db":
        return "messages-extra"
    if (kind != "backup" or "safari" in domain.lower() or domain == "HomeDomain") and base == "BrowserState.db":
        return "browser-state"
    if base == "observations.db" and ("webkit" in low or "resourceloadstatistics" in low):
        return "webkit-statistics"
    if base == "Cache.db":
        return "url-cache"
    if base == "ChatStorage.sqlite" and (kind != "backup" or "whatsapp" in domain.lower()):
        return "whatsapp"
    if mobile and base == "TCC.db":
        return "permissions"
    if mobile and base == "CallHistory.storedata":
        return "calls"
    if mobile and base in ("Calendar.sqlitedb", "Calendar.sqlite"):
        return "calendar"
    if mobile and base == "interactionC.db":
        return "interactions"
    if mobile and base == "Shortcuts.sqlite":
        return "shortcuts"
    if mobile and base == "com.apple.osanalytics.addaily.plist":
        return "analytics"
    if mobile and base == "clients.plist" and "locationd" in low:
        return "location-clients"
    if mobile and base == ".GlobalPreferences.plist":
        return "preferences"
    if "configurationprofiles" in low and base.endswith((".plist", ".mobileconfig")):
        return "profile-events" if "event" in base.lower() else "profiles"
    if base == "iTunesMetadata.plist":
        return "app-metadata"
    if ("webkit" in low or "safari" in low) and base.endswith(".plist") and "resource" in base.lower():
        return "webkit-session"
    if re.fullmatch(r"shutdown\.log(?:\.\d+)?", base, re.I):
        return "shutdown"
    if base.endswith((".ips", ".crash")):
        return "crashes"
    return ""


def ios_additional_artifacts(source, ctx, r, gap, query, tables, columns, records, hit, apple_time):
    """Parse selected input artifacts, retaining each readable neighbour on error."""
    processed = 0
    found = set()
    deadline = time.monotonic() + 90

    def emit(ind, key, check, record_id, detail, grade=EV_REFERENCED, observed="", raw_time=""):
        if ind is None:
            return
        origin = source.provenance.get(key, {})
        hit(r, ind, key[0] + "/" + key[1] + ":record " + str(record_id), detail,
            grade, observed, origin.get("source", source.root))
        r.hits[-1].provenance = dict(origin, record_id=str(record_id),
            parser=check + "/1", raw_timestamp=str(raw_time)[:128])
        if (key[0], key[1] + "-wal") in source.provenance:
            r.hits[-1].provenance["wal_sha256"] = source.provenance[(key[0], key[1] + "-wal")]["sha256"]

    def text_matches(text, key, check, record_id, detail, grade=EV_REFERENCED, observed="", raw_time=""):
        if not isinstance(text, str):
            if text is not None:
                r.skipped += 1
                gap(check, "unsupported non-text field")
            return
        try:
            size = len(text.encode("utf-8"))
        except UnicodeError:
            r.skipped += 1
            gap(check, "undecodable text field was not searched")
            return
        if size > 65536:
            r.skipped += 1
            gap(check, "artifact text field exceeds the limit")
            return
        for ind in ctx.iocs.search(text.lower()):
            emit(ind, key, check, record_id, detail, grade, observed, raw_time)
        for ind in ctx.iocs.of_type("email"):
            if re.search(r"(?<![\w.+-])" + re.escape(ind.value) + r"(?![\w.-])", text, re.I):
                emit(ind, key, check, record_id, detail, grade, observed, raw_time)

    def typed(value, types, key, check, record_id, detail, grade, observed="", raw_time=""):
        if not isinstance(value, str) or len(value) > 65536:
            return
        for typ in types:
            for ind in ctx.iocs.of_type(typ):
                if typ in ("file-path", "file-name", "process"):
                    matches = ios_exact_identity(ind, value)
                else:
                    matches = value.lower() == ind.value.lower()
                if matches:
                    emit(ind, key, check, record_id, detail, grade, observed, raw_time)

    def sql_rows(key, check, table, required, optional=()):
        con = source.open_database(*key, check)
        try:
            tables(con, (table,))
            cols = columns(con, table)
            if not {x.lower() for x in required} <= cols:
                raise ValueError("unsupported " + table + " schema; required columns missing")
            selected = list(required) + [x if x.lower() in cols else "NULL" for x in optional]
            sql = "SELECT " + ",".join(selected) + " FROM " + table
            byte_count = 0
            for row_id, row in records(con, sql, table, cols, r, gap,
                                       min(deadline, time.monotonic() + 10), check, "record"):
                byte_count += sum(len(v) if isinstance(v, bytes) else len(v.encode("utf-8", "replace")) if isinstance(v, str) else 8 for v in row)
                if byte_count > 16 * 1024 * 1024:
                    raise ValueError("artifact row payload budget reached")
                yield row_id, row
        finally:
            con.close()

    def sql_artifact(key, kind, check):
        layouts = {
            "browser-state": ("tabs", ("url",), ("title",)),
            "webkit-statistics": ("observed_domains", ("registrableDomain",), ("lastSeen",)),
            "url-cache": ("cfurl_cache_response", ("request_key",), ("time_stamp",)),
            "whatsapp": ("ZWAMESSAGE", ("ZTEXT", "ZISFROMME"), ("ZMESSAGEDATE", "ZFROMJID")),
            "permissions": ("access", ("client", "service"), ("auth_value", "allowed", "last_modified")),
            "calls": ("ZCALLRECORD", ("ZADDRESS",), ("ZDATE", "ZORIGINATED")),
            "calendar": ("CalendarItem", ("title",), ("notes", "url", "start_date")),
            "interactions": ("ZINTERACTIONS", ("ZBUNDLEID",), ("ZSTARTDATE", "ZENDDATE")),
            "shortcuts": ("ZSHORTCUT", ("ZNAME", "ZWORKFLOWACTIONS"), ("ZCREATIONDATE",)),
        }
        for row_id, row in sql_rows(key, check, *layouts[kind]):
            try:
                if kind == "whatsapp":
                    if type(row[1]) is not int or row[1] not in (0, 1):
                        raise ValueError("message direction is unsupported")
                    text_matches(row[0], key, check, row_id, "message text; opening is unverified",
                                 EV_RECEIVED if row[1] == 0 else EV_REFERENCED, apple_time(row[2]), row[2])
                    typed(row[3], ("email",), key, check, row_id, "message sender identifier", EV_DEVICE_LOG)
                elif kind == "permissions":
                    granted = row[2] == 2 if row[2] is not None else row[3] == 1
                    typed(row[0], ("app-id", "file-path"), key, check, row_id,
                          "TCC client record for " + str(row[1])[:100] + "; consent and execution unverified",
                          EV_CONFIGURED if granted else EV_REFERENCED)
                    if row[2] is None and row[3] is None:
                        gap(check, "permission decision column unavailable; records remain references")
                elif kind == "interactions":
                    typed(row[0], ("app-id",), key, check, row_id,
                          "application identifier in interaction records", EV_DEVICE_LOG, apple_time(row[1]), row[1])
                elif kind == "shortcuts":
                    text_matches(row[0], key, check, row_id, "saved Shortcut name; execution unverified")
                    if not isinstance(row[1], bytes):
                        raise ValueError("unsupported Shortcut actions encoding")
                    actions = _is_plist(row[1])
                    for field, value in _ia_walk(actions):
                        if isinstance(value, str):
                            text_matches(value, key, check, str(row_id) + "/" + "/".join(field),
                                         "saved Shortcut action text; activation and execution unverified")
                else:
                    for field_index, value in enumerate(row):
                        if field_index == 0 or isinstance(value, (str, bytes)):
                            text_matches(value, key, check, row_id,
                                         "stored " + kind + " field; local contact/execution is unverified")
                    if kind == "calls":
                        typed(row[0], ("email",), key, check, row_id, "identifier in a call record",
                              EV_DEVICE_LOG, apple_time(row[1]), row[1])
                r.checked += 1
            except (ValueError, UnicodeError, plistlib.InvalidFileException, RecursionError) as exc:
                r.skipped += 1
                gap(check, str(exc))

    def message_extras(key):
        specs = (("ios:message-handles", "handle", ("id",), ("service",)),
                 ("ios:message-attachments", "attachment", ("filename",), ("mime_type", "created_date")))
        for check, table, required, optional in specs:
            try:
                # Older/plain fixture schemas may genuinely not have these
                # optional tables. Unsupported present schemas remain gaps.
                con = source.open_database(*key, check)
                try:
                    with query(con, "SELECT 1 FROM sqlite_master WHERE name=?", (table,)) as cur:
                        exists = cur.fetchone() is not None
                finally:
                    con.close()
                if not exists:
                    continue
                for row_id, row in sql_rows(key, check, table, required, optional):
                    try:
                        text_matches(row[0], key, check, row_id,
                                     "message metadata; receipt, opening and execution are unverified")
                        if table == "handle":
                            typed(row[0], ("email",), key, check, row_id,
                                  "identifier in message handle records", EV_DEVICE_LOG)
                        else:
                            typed(row[0], ("file-path",), key, check, row_id,
                                  "attachment path recorded in metadata; file contents unverified", EV_REFERENCED)
                        r.checked += 1
                    except (ValueError, UnicodeError) as exc:
                        r.skipped += 1
                        gap(check, str(exc))
                r.ran(check)
            except (ValueError, OSError, sqlite3.Error) as exc:
                gap(check, "message metadata unreadable: " + str(exc))

    def plist_artifact(key, kind, check):
        doc = _is_plist(source.artifact(*key))
        if not isinstance(doc, (dict, list)):
            raise ValueError("unsupported property-list root")
        recognized = 0
        # ADDaily's process map stores a plist date first in each usage tuple.
        # Treat other layouts as unsupported, rather than guessing an epoch.
        if kind == "analytics" and isinstance(doc, dict) and "netUsageBaseline" in doc:
            baseline = doc["netUsageBaseline"]
            if not isinstance(baseline, dict):
                gap(check, "unsupported netUsageBaseline map")
            else:
                for name, usage in baseline.items():
                    if not isinstance(usage, list) or not usage or not isinstance(usage[0], datetime.datetime):
                        gap(check, "unsupported netUsageBaseline record")
                        continue
                    recognized += 1
                    typed(name, ("process",), key, check, "netUsageBaseline/" + name,
                          "process identity in recorded network-usage baseline; executable contents unverified",
                          EV_DEVICE_LOG, _ia_iso(usage[0]), str(usage[0]))
        if kind == "location-clients" and isinstance(doc, dict):
            for name, client in doc.items():
                if not isinstance(client, dict):
                    gap(check, "unsupported location client record")
                    continue
                if "LocationTimeStopped" in client or "Authorized" in client:
                    recognized += 1
                    typed(name, ("app-id",), key, check, name,
                          "identifier in location-service client metadata; execution unverified", EV_DEVICE_LOG,
                          apple_time(client.get("LocationTimeStopped")), client.get("LocationTimeStopped", ""))
        for field, value in _ia_walk(doc):
            name = field[-1] if field else ""
            location = "/".join(field)
            if isinstance(value, str):
                text_matches(value, key, check, location, "stored " + kind + " text; execution/contact unverified")
            if kind in ("profiles", "profile-events") and name in ("PayloadUUID", "PayloadIdentifier"):
                recognized += 1
                typed(value, ("profile-id",), key, check, location,
                      "profile identifier in supplied configuration records; current activation unverified",
                      EV_CONFIGURED if kind == "profiles" else EV_DEVICE_LOG)
            elif kind == "analytics" and name in ("processName", "procName", "process"):
                recognized += 1
                typed(value, ("process",), key, check, location,
                      "process identity in analytics record; executable contents unverified", EV_DEVICE_LOG)
            elif kind in ("analytics", "app-metadata", "location-clients") and name in ("bundleID", "bundleId", "softwareVersionBundleId"):
                recognized += 1
                typed(value, ("app-id",), key, check, location,
                      "application identifier in " + kind + " records", EV_DEVICE_LOG)
            elif kind == "preferences" and name == "LDMGlobalEnabled" and type(value) in (int, bool):
                recognized += 1
                r.note("Backup records Lockdown Mode as " + ("enabled" if value else "disabled")
                       + "; backup-time metadata does not establish current protection.")
            elif kind == "webkit-session" and isinstance(value, str) and name.lower() in ("url", "requesturl", "resourceurl"):
                recognized += 1
            r.checked += 1
        if not recognized:
            gap(check, "unrecognized typed property-list schema; only literal references were searched")

    def log_artifact(key, kind, check):
        raw = source.artifact(*key)
        if len(raw) > 32 * 1024 * 1024:
            raise ValueError("diagnostic log byte limit reached")
        text = raw.decode("utf-8", "strict")
        if kind == "crashes" and key[1].endswith(".ips"):
            # Apple .ips files commonly use a metadata JSON line and a body JSON
            # document. Parse with raw_decode rather than assuming one object.
            decoder, pos, objects = json.JSONDecoder(), 0, []
            matched_schema = False
            while pos < len(text):
                while pos < len(text) and text[pos].isspace():
                    pos += 1
                if pos == len(text):
                    break
                if len(objects) >= 2:
                    raise ValueError("unsupported IPS document sequence")
                obj, pos = decoder.raw_decode(text, pos)
                if not isinstance(obj, dict):
                    raise ValueError("unsupported IPS root")
                objects.append(obj)
                index = len(objects) - 1
                when = obj.get("captureTime", obj.get("timestamp", ""))
                for field, types in (("procName", ("process",)), ("procPath", ("file-path",)), ("bundleID", ("app-id",))):
                    if isinstance(obj.get(field), str):
                        matched_schema = True
                        typed(obj[field], types, key, check, str(index) + "/" + field,
                              "identity recorded in a crash report; a crash alone is not an exploit",
                              EV_DEVICE_LOG, _ia_iso(when), when)
                r.checked += 1
            if not matched_schema:
                raise ValueError("unsupported IPS identity schema")
            return
        recognized, heuristic = 0, False
        pending_shutdown_hits = []
        for index, line in enumerate(text.splitlines()):
            if index >= 200000 or time.monotonic() > deadline:
                raise ValueError("diagnostic log record/time limit reached")
            if len(line) > 65536:
                gap(check, "oversized diagnostic record was not searched")
                continue
            if kind == "crashes":
                match = re.fullmatch(r"Process:\s+(.+?)\s+\[\d+\]\s*", line)
                path = re.fullmatch(r"Path:\s+(/\S+)\s*", line)
                if match or path:
                    recognized += 1
                    typed((match or path).group(1), ("process",) if match else ("file-path",),
                          key, check, index + 1, "identity in a crash record; exploitation unverified", EV_DEVICE_LOG)
            else:
                flush = re.fullmatch(r"\s*SIGTERM:\s*\[(\d+(?:\.\d+)?)\]\s*All buffers flushed\s*", line)
                if flush:
                    recognized += 1
                    try:
                        when = datetime.datetime.fromtimestamp(float(flush.group(1)), datetime.timezone.utc).isoformat()
                    except (ValueError, OverflowError, OSError):
                        when = ""
                        gap(check, "shutdown timestamp outside supported range")
                    for item in pending_shutdown_hits:
                        item.observed = when
                        item.provenance["raw_timestamp"] = flush.group(1)
                    pending_shutdown_hits.clear()
                client = re.fullmatch(r"\s*(?:-\s*)?remaining client pid:\s*\d+\s+\((/[^\r\n]+)/[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\)\s*", line)
                if client:
                    recognized += 1
                    value, before = client.group(1), len(r.hits)
                    typed(value, ("file-path",), key, check, index + 1,
                          "path in a shutdown client record; current presence and executable contents unverified", EV_DEVICE_LOG)
                    typed(value.rsplit("/", 1)[-1], ("process",), key, check, index + 1,
                          "process basename in a shutdown client record; executable contents unverified", EV_DEVICE_LOG)
                    pending_shutdown_hits.extend(r.hits[before:])
                    heuristic = heuristic or value.startswith(("/private/var/db/", "/private/var/tmp/"))
                elif "remaining client pid:" in line:
                    gap(check, "unsupported shutdown client record; it was not searched")
            r.checked += 1
        if not recognized:
            raise ValueError("no supported diagnostic identity records; log schema may differ")
        if pending_shutdown_hits:
            gap(check, "shutdown records have no following supported flush timestamp; identities retained without dates")
        if heuristic:
            r.add_lead(Lead(check, key[1], "Shutdown records contain a process path under a research-relevant temporary/database directory.",
                           "Legitimate services also use these directories. A shutdown delay or path alone does not establish spyware."))

    for key in source.entries:
        kind = _ia_artifact_kind(*key, source.kind)
        if not kind:
            continue
        check = "ios:" + kind
        found.add(kind)
        if processed >= _IA_ARTIFACT_LIMIT or time.monotonic() > deadline:
            gap("ios:input", "additional artifact count/time limit reached; remaining artifacts were not searched")
            break
        processed += 1
        try:
            if kind == "messages-extra":
                message_extras(key)
                continue
            if kind in ("shutdown", "crashes"):
                log_artifact(key, kind, check)
            elif kind in ("analytics", "profiles", "profile-events", "location-clients", "preferences", "app-metadata", "webkit-session"):
                plist_artifact(key, kind, check)
            else:
                sql_artifact(key, kind, check)
            r.ran(check)
        except (ValueError, OSError, sqlite3.Error, TypeError, plistlib.InvalidFileException, RecursionError) as exc:
            r.skipped += 1
            gap(check, "artifact unreadable or unsupported: " + str(exc))
    if source.kind == "sysdiagnose" and not found:
        gap("ios:input", "no supported diagnostic artifacts were present; archive inventory is not a forensic all-clear")
    r.submetrics["ios_additional_artifacts"] = processed
