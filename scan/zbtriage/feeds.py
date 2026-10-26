"""Official published indicator sources, and the `--update` command.

The scan itself never touches the network (netguard.no_network). Updating the
indicator sets is a separate, explicit step that downloads ONLY from the fixed
list below - the sources Amnesty International's MVT project indexes, plus three
older Amnesty publications MVT does not list - into a per-user cache. Several of
these repositories carry no licence, so they are fetched from the original
source at the user's request (as MVT itself does) rather than redistributed.

Safety rules, each enforced in code and pinned by tests/test_feeds.py:
  - only https://raw.githubusercontent.com/<allow-listed owner>/... ; a redirect
    anywhere else is refused;
  - every download is size-capped, must not be an HTML page, and must parse
    into at least one usable indicator BEFORE it replaces the cached copy - a
    failed download keeps the previous good copy;
  - the SHA-256 of every cached file is recorded in a manifest and re-checked
    when a scan loads it, so an edited or corrupted cache file is refused;
  - an indicator is never resolved or contacted: these are text files.
"""

from __future__ import annotations

import csv
import dataclasses
import datetime
import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Dict, List, Optional, Tuple

from . import __version__
from .iocs import (TYPE_DOMAIN, TYPE_IP, TYPE_SHA256, Indicator, IocError, IocSet,
                   infer_type, load_any)
from .localpaths import path_problem
from .stix import TIER_INFRA, TIER_INFRA_IP, TIER_SAMPLE, _normalise

RAW = "https://raw.githubusercontent.com/"
ALLOWED_OWNERS = ("mvt-project/mvt-indicators/", "AmnestyTech/investigations/",
                  "AssoEchap/stalkerware-indicators/", "citizenlab/malware-indicators/")
ALLOWED_PREFIXES = tuple(RAW + o for o in ALLOWED_OWNERS)
MAX_DOWNLOAD = 64 * 1024 * 1024
TIMEOUT_S = 60


def _src(sid, name, owner_repo_branch, path, fmt, cite, category="mercenary",
         family=""):
    return {"id": sid, "name": name, "url": RAW + owner_repo_branch + path,
            "format": fmt, "cite": cite, "category": category, "family": family}


# Snapshot of mvt-project/mvt-indicators/indicators.yaml (19 entries, read
# 2026-10-25), plus four Amnesty folders that index does not include.
SOURCES: List[Dict[str, str]] = [
    _src("amnesty-pegasus-2021", "NSO Group Pegasus", "AmnestyTech/investigations/master/",
         "2021-07-18_nso/pegasus.stix2", "stix2", "Amnesty International (2021)"),
    _src("mvt-predator", "Intellexa Predator", "mvt-project/mvt-indicators/main/",
         "intellexa_predator/predator.stix2", "stix2",
         "Meta, Amnesty International, Citizen Lab, Cisco, Inside Story, iVerify"),
    _src("mvt-rcs-lab", "RCS Lab", "mvt-project/mvt-indicators/main/",
         "2022-06-23_rcs_lab/rcs.stix2", "stix2", "Google, Lookout"),
    _src("echap-stalkerware", "Stalkerware (154 apps)", "AssoEchap/stalkerware-indicators/master/",
         "generated/stalkerware.stix2", "stix2", "ECHAP", category="stalkerware"),
    _src("amnesty-android-campaign-2023", "Mercenary spyware campaign (Android)",
         "AmnestyTech/investigations/master/", "2023-03-29_android_campaign/malware.stix2",
         "stix2", "Amnesty International, Google"),
    _src("mvt-quadream-kingspawn", "QuaDream KingSpawn", "mvt-project/mvt-indicators/main/",
         "2023-04-11_quadream/kingspawn.stix2", "stix2", "Citizen Lab, Microsoft"),
    _src("mvt-operation-triangulation", "Operation Triangulation", "mvt-project/mvt-indicators/main/",
         "2023-06_01_operation_triangulation/operation_triangulation.stix2", "stix2",
         "Kaspersky Lab"),
    _src("mvt-wyrmspy-dragonegg", "WyrmSpy and DragonEgg", "mvt-project/mvt-indicators/main/",
         "2023-07-25_wyrmspy_dragonegg/wyrmspy_dragonegg.stix2", "stix2", "Lookout"),
    _src("amnesty-wintego-helios-2024", "Wintego Helios", "AmnestyTech/investigations/master/",
         "2024-05-02_wintego_helios/wintego_helios.stix2", "stix2", "Amnesty International"),
    _src("amnesty-novispy-2024", "NoviSpy (Serbia)", "AmnestyTech/investigations/master/",
         "2024-12-16_serbia_novispy/novispy.stix2", "stix2", "Amnesty International"),
    _src("mvt-eaglemsgspy", "EagleMsgSpy", "mvt-project/mvt-indicators/main/",
         "2024-12-25_eaglemsgspy/eaglemsgspy.stix2", "stix2", "Lookout"),
    _src("mvt-candiru", "Candiru (DevilsTongue)", "mvt-project/mvt-indicators/main/",
         "candiru/candiru.stix2", "stix2", "Microsoft, Recorded Future"),
    _src("mvt-residentbat", "ResidentBat", "mvt-project/mvt-indicators/main/",
         "ResidentBat/residentbat.stix2", "stix2", "Reporters Without Borders, RESIDENT.NGO"),
    _src("mvt-cellebrite", "Cellebrite", "mvt-project/mvt-indicators/main/",
         "cellebrite/cellebrite.stix2", "stix2", "Citizen Lab"),
    _src("mvt-darksword", "DarkSword", "mvt-project/mvt-indicators/main/",
         "2026-03-30_darksword/darksword.stix2", "stix2",
         "Google Threat Intelligence Group, iVerify, Lookout"),
    _src("mvt-coruna", "Coruna", "mvt-project/mvt-indicators/main/",
         "2026-03-03_coruna_cryptowaters/coruna.stix2", "stix2",
         "Google Threat Intelligence Group, iVerify"),
    _src("mvt-morpheus", "Morpheus", "mvt-project/mvt-indicators/main/",
         "2026-04-23_ips_morpheus/morpheus.stix2", "stix2", "Osservatorio Nessuno"),
    _src("mvt-btmob", "BTMOB", "mvt-project/mvt-indicators/main/",
         "2026-05-26_btmob/btmob.stix2", "stix2", "ESET, Cyble Research, Zimperium"),
    _src("mvt-spyrtacus", "Spyrtacus", "mvt-project/mvt-indicators/main/",
         "2026-04-09_sio_spyrtacus/spyrtacus.stix2", "stix2", "Osservatorio Nessuno"),
    # Not in MVT's index:
    _src("amnesty-nso-2018", "NSO Group (2018)", "AmnestyTech/investigations/master/",
         "2018-08-01_nso/indicators.csv", "csv-domain-ip",
         "Amnesty International (2018-08-01), NSO Group infrastructure", family="Pegasus"),
    _src("amnesty-nso-morocco-2019", "NSO Group (Morocco, 2019)",
         "AmnestyTech/investigations/master/", "2019-10-10_nso_morocco/domains.txt",
         "domains-txt", "Amnesty International (2019-10-10), Morocco", family="Pegasus"),
    _src("amnesty-cytrox-2021", "Cytrox (Predator, 2021)", "AmnestyTech/investigations/master/",
         "2021-12-16_cytrox/cytrox.stix2", "stix2",
         "Meta, Citizen Lab, Amnesty International (2021-12-16)", family="Predator"),
    _src("amnesty-finfisher-2020", "FinFisher / FinSpy (Gamma Group)",
         "AmnestyTech/investigations/master/", "2020-09-25_finfisher/domains.txt",
         "domains-txt",
         "Amnesty International (2020-09-25), FinSpy for Windows, Android and Linux",
         family="FinSpy"),
    # Citizen Lab's indicator repository (MISP CSV exports), Israeli vendors only:
    _src("citizenlab-nso-2016", "NSO Group (Trident / Ahmed Mansoor, 2016)",
         "citizenlab/malware-indicators/master/", "201608_NSO_Group/iocs.csv", "misp-csv",
         "The Citizen Lab, 'The Million Dollar Dissident' (2016-08)", family="Pegasus"),
    _src("citizenlab-cyberbit-2017", "Cyberbit (Ethiopia, 2017)",
         "citizenlab/malware-indicators/master/", "201712_Cyberbit/iocs.csv", "misp-csv",
         "The Citizen Lab, 'Champing at the Cyberbit' (2017-12)",
         family="Cyberbit PC Surveillance System"),
    _src("citizenlab-kingdom-2018", "NSO Group (The Kingdom Came to Canada, 2018)",
         "citizenlab/malware-indicators/master/", "201810_TheKingdomCameToCanada/iocs.csv",
         "misp-csv", "The Citizen Lab, 'The Kingdom Came to Canada' (2018-10)", family="Pegasus"),
    _src("citizenlab-nso-mexico-exploit-2017", "NSO Group (Reckless Exploit, Mexico, 2017)",
         "citizenlab/malware-indicators/master/", "201706_RecklessExploit/iocs.csv", "misp-csv",
         "The Citizen Lab, 'Reckless Exploit' (2017-06), Mexico", family="Pegasus"),
    _src("citizenlab-nso-mexico-redux-2017", "NSO Group (Reckless Redux, Mexico, 2017)",
         "citizenlab/malware-indicators/master/", "201706_RecklessRedux/iocs.csv", "misp-csv",
         "The Citizen Lab, 'Reckless Redux' (2017-06), Mexico", family="Pegasus"),
    _src("citizenlab-nso-insider-2017", "NSO Group (Insider Information, Mexico, 2017)",
         "citizenlab/malware-indicators/master/", "201707_InsiderInfo/indicators.csv", "misp-csv",
         "The Citizen Lab, 'Insider Information' (2017-07), Mexico", family="Pegasus"),
]

MANIFEST = "manifest.json"
_EXT = {"stix2": ".stix2", "csv-domain-ip": ".csv", "domains-txt": ".txt",
        "misp-csv": ".misp.csv"}

# MISP attribute types -> our kinds. URLs contribute their host name. MD5 and
# SHA-1 sample hashes are counted as not applicable: the file check computes
# SHA-256 only.
_MISP_KINDS = {"domain": TYPE_DOMAIN, "hostname": TYPE_DOMAIN, "ip-dst": TYPE_IP,
               "ip-src": TYPE_IP, "sha256": TYPE_SHA256, "url": "url"}


# --- where the cache lives ----------------------------------------------------

def default_cache_dir() -> str:
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "ZeroBreachTriage", "indicators")
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Caches/zero-breach-triage/indicators")
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return os.path.join(base, "zero-breach-triage", "indicators")


# --- plain-list formats (the older Amnesty publications) ------------------------

def load_list(path: str, fmt: str, source: str, family: str) -> IocSet:
    """A domains.txt (one per line) or a 'domain_name,ip_address' CSV, with the
    same validation as STIX imports. Refused values are counted, not scanned."""
    found: Dict[Tuple[str, str], Indicator] = {}
    refused: Dict[str, int] = {}
    not_applicable: Dict[str, int] = {}

    def add(raw: str, kind: str) -> None:
        raw = (raw or "").strip().strip('"')
        if not raw:
            return
        if kind == TYPE_DOMAIN and infer_type(raw.lower().rstrip(".")) == TYPE_IP:
            kind = TYPE_IP
        value, problem = _normalise(kind, raw)
        if problem:
            refused[problem] = refused.get(problem, 0) + 1
            return
        tier = (TIER_INFRA_IP if kind == TYPE_IP else
                TIER_SAMPLE if kind == TYPE_SHA256 else TIER_INFRA)
        found.setdefault((kind, value), Indicator(value, tier, "primary", kind, source, family))

    with io.open(path, encoding="utf-8-sig", errors="replace") as fh:
        if fmt == "domains-txt":
            for line in fh:
                line = line.split("#", 1)[0]
                add(line, TYPE_DOMAIN)
        elif fmt == "csv-domain-ip":
            for row in csv.DictReader(fh):
                add(row.get("domain_name", ""), TYPE_DOMAIN)
                add(row.get("ip_address", ""), TYPE_IP)
        elif fmt == "misp-csv":
            for row in csv.DictReader(fh):
                mtype = (row.get("type") or "").strip().lower()
                kind = _MISP_KINDS.get(mtype)
                if kind is None:
                    not_applicable[mtype or "?"] = not_applicable.get(mtype or "?", 0) + 1
                elif kind == "url":
                    host = urllib.parse.urlsplit((row.get("value") or "").strip()).hostname
                    add(host or "", TYPE_DOMAIN)
                else:
                    add(row.get("value", ""), kind)
        else:
            raise IocError("{}: unknown list format {!r}".format(path, fmt))
    if not found:
        raise IocError("{}: no usable indicator in this list".format(path))
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = None
    s = IocSet(sorted(found.values(), key=lambda i: (i.value, i.type)), os.path.abspath(path), mtime)
    s.sets = [{"path": os.path.abspath(path), "format": fmt, "usable": len(found),
               "device_indicators": {}, "refused_invalid": dict(sorted(refused.items())),
               "not_applicable_to_this_scan": dict(sorted(not_applicable.items())),
               "families": {family: len(found)}}]
    return s


def _load_source_file(src: Dict[str, str], path: str) -> IocSet:
    cite = "{} ({})".format(src["cite"], src["name"])
    if src["format"] == "stix2":
        loaded = load_any(path, source=cite, family=src.get("family", ""), allow_empty=False)
    else:
        loaded = load_list(path, src["format"], cite, src.get("family", ""))
    if src.get("category") == "stalkerware":
        # The list names commercial phone-monitoring apps - including
        # family-safety apps people install knowingly (Life360, Microsoft Family
        # Safety, Kaspersky Safe Kids, Bark, Qustodio) - and their companies'
        # ordinary websites. EVERY kind (domains, app ids, certificates,
        # samples) is tiered apart, so no match can be presented as mercenary
        # spyware; the report asks whether the person knows about the app
        # instead. Indicators are immutable:
        # rebuild the set, keeping what load() recorded about the file.
        retiered = IocSet([dataclasses.replace(i, tier="stalkerware")
                           for i in loaded.indicators],
                          loaded.source_path, loaded.source_mtime)
        retiered.asof = loaded.asof
        retiered.sets = getattr(loaded, "sets", [])
        return retiered
    return loaded


# --- downloading ----------------------------------------------------------------

def url_allowed(url: str) -> bool:
    return isinstance(url, str) and url.startswith(ALLOWED_PREFIXES) and ".." not in url


class _AllowListRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not url_allowed(newurl):
            raise urllib.error.URLError("refused redirect outside the allow-list: {}"
                                        .format(newurl[:120]))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch(url: str) -> bytes:
    if not url_allowed(url):
        raise IocError("refused: not an allow-listed indicator source: {}".format(url))
    opener = urllib.request.build_opener(_AllowListRedirect())
    req = urllib.request.Request(url, headers={
        "User-Agent": "zero-breach-triage/{} (indicator update)".format(__version__)})
    with opener.open(req, timeout=TIMEOUT_S) as resp:
        data = resp.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise IocError("download larger than {:,} bytes - refused".format(MAX_DOWNLOAD))
    return data


def _looks_like_html(data: bytes) -> bool:
    head = data[:512].lstrip().lower()
    return head.startswith((b"<!doctype html", b"<html", b"<head", b"<body"))


def _feed_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_manifest(cache: str) -> Dict[str, Dict[str, object]]:
    path = _feed_local_path(cache, MANIFEST)
    try:
        with io.open(path, encoding="utf-8") as fh:
            raw = fh.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("manifest exceeds size limit")
        doc = json.loads(raw)
        sources = doc.get("sources") if isinstance(doc, dict) else None
        if not isinstance(sources, dict):
            raise ValueError("manifest sources must be an object")
        return sources
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, RecursionError) as exc:
        raise IocError("indicator manifest could not be read: {}".format(exc))


def _feed_local_path(cache: str, name: str) -> str:
    path = os.path.join(os.path.abspath(cache), name)
    problem = path_problem(path)
    if problem:
        raise IocError("indicator cache path refused: " + problem)
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            raise IocError("indicator cache entry is not a regular file")
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise IocError("indicator cache entry cannot be inspected: {}".format(exc))
    return path


def _write_manifest(cache: str, entries: Dict[str, Dict[str, object]]) -> None:
    final = _feed_local_path(cache, MANIFEST)
    fd, tmp = tempfile.mkstemp(dir=cache, prefix=".manifest.")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"tool": "zero-breach-triage", "version": __version__,
                   "sources": entries}, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, final)


def update(cache: Optional[str] = None, sources: Optional[List[Dict[str, str]]] = None,
           fetch: Callable[[str], bytes] = _fetch,
           emit: Callable[[str], None] = lambda s: None) -> Dict[str, object]:
    """Download every source; keep the previous copy of any that fails.
    Returns a summary: per source ok / unchanged / failed, with counts."""
    cache = cache or default_cache_dir()
    problem = path_problem(os.path.abspath(cache))
    if problem:
        raise IocError("indicator cache {}: {}".format(cache, problem))
    os.makedirs(cache, exist_ok=True)
    manifest = read_manifest(cache)
    results = []
    for src in (sources if sources is not None else SOURCES):
        name = src["id"] + _EXT[src["format"]]
        entry = {"id": src["id"], "name": src["name"], "url": src["url"]}
        try:
            final = _feed_local_path(cache, name)
            data = fetch(src["url"])
            if _looks_like_html(data):
                raise IocError("got a web page, not an indicator file")
            digest = _feed_sha256(data)
            old = manifest.get(src["id"])
            checked = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
            intact = False
            if isinstance(old, dict) and old.get("file") == name and old.get("sha256") == digest:
                try:
                    with open(final, "rb") as fh:
                        intact = _feed_sha256(fh.read(MAX_DOWNLOAD + 1)) == digest
                except OSError:
                    pass
            if intact:
                old["checked_utc"] = checked
                entry.update(status="unchanged", indicators=old.get("indicators"))
                results.append(entry)
                emit("[=] {} unchanged".format(src["name"]))
                continue
            fd, tmp = tempfile.mkstemp(dir=cache, prefix=".dl.", suffix=_EXT[src["format"]])
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            try:
                parsed = _load_source_file(src, tmp)    # parse BEFORE replacing
            except Exception:
                os.unlink(tmp)
                raise
            os.replace(tmp, final)
            manifest[src["id"]] = {
                "file": name, "url": src["url"], "format": src["format"],
                "name": src["name"], "cite": src["cite"], "category": src["category"],
                "family": src.get("family", ""), "sha256": digest, "bytes": len(data),
                "fetched_utc": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
                "checked_utc": checked,
                "indicators": len(parsed)}
            entry.update(status="updated", indicators=len(parsed))
            emit("[+] {}: {} indicators".format(src["name"], len(parsed)))
        except Exception as exc:          # one bad source must not stop the rest
            entry.update(status="failed", error=str(exc)[:300],
                         kept_previous=src["id"] in manifest)
            emit("[!] {} failed: {}".format(src["name"], str(exc)[:160]))
        results.append(entry)
    _write_manifest(cache, manifest)
    failed = [r for r in results if r["status"] == "failed"]
    return {"cache": cache, "sources": results, "failed": len(failed),
            "ok": len(results) - len(failed)}


# --- loading the cache for a scan ----------------------------------------------

def cached_sets(cache: Optional[str] = None) -> Tuple[List[IocSet], Dict[str, object]]:
    """IocSets from every verified cached source, plus a status block for the
    report. A file whose SHA-256 no longer matches the manifest is REFUSED (it
    was edited or corrupted after download) and reported, never scanned."""
    cache = cache or default_cache_dir()
    sets: List[IocSet] = []
    status = {"cache": cache, "downloaded": False, "loaded": [],
              "refused": [], "missing": []}
    by_id = {s["id"]: s for s in SOURCES}
    try:
        manifest = read_manifest(cache)
    except IocError as exc:
        status["refused"].append({"id": "manifest", "reason": str(exc)})
        status["missing"] = sorted(by_id)
        return sets, status
    status["downloaded"] = bool(manifest)
    status["missing"] = sorted(set(by_id) - set(manifest))
    for sid, meta in sorted(manifest.items()):
        src = by_id.get(sid)
        if src is None:
            status["refused"].append({"id": sid, "reason": "not a known source"})
            continue
        # The source catalogue, never the manifest, chooses the file to open.
        name = sid + _EXT[src["format"]]
        if not isinstance(meta, dict) or meta.get("file") != name:
            status["refused"].append({"id": sid, "reason": "invalid manifest entry or filename"})
            continue
        try:
            path = _feed_local_path(cache, name)
            with open(path, "rb") as fh:
                data = fh.read(MAX_DOWNLOAD + 1)
        except IocError as exc:
            status["refused"].append({"id": sid, "reason": str(exc)})
            continue
        except OSError:
            status["missing"].append(sid)
            continue
        if _feed_sha256(data) != meta.get("sha256"):
            status["refused"].append({"id": sid, "reason": "file changed since download"})
            continue
        try:
            loaded = _load_source_file(src, path)
            refreshed = meta.get("checked_utc") or meta.get("fetched_utc")
            try:
                when = datetime.datetime.strptime(refreshed, "%Y-%m-%dT%H:%M:%SZ")
                if when > datetime.datetime.utcnow():
                    raise ValueError("future refresh time")
                loaded.verified_at = when
            except (TypeError, ValueError):
                loaded.verified_at = None
            sets.append(loaded)
            status["loaded"].append({"id": sid, "fetched_utc": meta.get("fetched_utc"),
                                     "checked_utc": meta.get("checked_utc"),
                                     "age_days": loaded.age_days(),
                                     "freshness_unknown": loaded.has_unknown_age(),
                                     "stale": loaded.is_stale(),
                                     "indicators": len(loaded)})
        except Exception as exc:
            status["refused"].append({"id": sid, "reason": str(exc)[:200]})
    return sets, status


def update_command(cache: Optional[str], json_path: Optional[str]) -> int:
    """The `--update` command for both entry points (source CLI and single
    file). Prints a short summary; exit 0 only if every source succeeded."""
    from .report import write_json, _report_console
    try:
        if json_path and path_problem(os.path.abspath(json_path)):
            raise IocError("--json must be a path on a local disk")
        summary = update(cache, emit=lambda s: _report_console(s, sys.stderr))
    except IocError as exc:
        _report_console("error: {}".format(exc), sys.stderr)
        return 1
    except OSError as exc:
        # Disk, not network: the cache folder could not be created or written.
        _report_console("error: the indicator cache could not be written ({}). Nothing was "
                        "changed; choose a writable folder with --indicator-cache.".format(
                            exc.strerror or type(exc).__name__), sys.stderr)
        return 1
    _report_console("Indicator sets in {}: {} up to date, {} failed.".format(
        summary["cache"], summary["ok"], summary["failed"]), sys.stdout)
    for r in summary["sources"]:
        if r["status"] == "failed":
            _report_console("  FAILED {}: {}{}".format(r["name"], r.get("error", ""),
                  " (previous copy kept)" if r.get("kept_previous") else ""), sys.stdout)
    if json_path:
        try:
            write_json(summary, json_path)
        except (OSError, ValueError, TypeError) as exc:
            _report_console("could not write {}: {}".format(json_path, exc), sys.stderr)
            return 1
    return 0 if summary["failed"] == 0 else 1
