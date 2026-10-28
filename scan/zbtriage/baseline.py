"""Offline comparison of this scan against a previously saved JSON report.

A person who is being targeted is told to run this tool again after taking
action, and to re-check periodically. On its own the tool answers "what is on
this machine now?" but not "what is *different* from last time?" - which is the
question that actually matters once there is a prior result to compare with.

`--baseline PATH` answers it. Given a JSON report saved earlier with `--json`,
it reports which indicator matches and worth-a-look items are NEW since then,
which have CLEARED (were present before, absent now) and which PERSIST.

Doctrine fit:

* D2 (never contact an indicator). This compares two LOCAL JSON files. It opens
  no socket and resolves nothing; it runs outside the scan the same way the
  report writers do, over data already on disk.
* Read-only. It changes nothing on the machine and never edits either report.
* D1 (a clean result is not a clean bill of health). A CLEARED item is never
  presented as proof that spyware was removed: an indicator can disappear
  because a log rolled over, a file was touched, or the scope differs between
  the two runs. The wording and the scope notes say so.

The comparison is additive. It attaches a `baseline` block to the report and
renders a section; it does NOT change the scan's verdict or the machine
exit-code contract, which continue to describe the current scan alone.
"""

from __future__ import annotations

import io
import json
import os
from typing import Any, Dict, List, Optional, Tuple

# A full --json report of a deep scan can be large, but not unbounded.
MAX_BASELINE_BYTES = 64 * 1024 * 1024


class BaselineError(ValueError):
    """The baseline file is missing, too large, malformed, or not comparable."""


def load_baseline(path: str) -> Dict[str, Any]:
    """Read and validate a previously saved JSON report for comparison.

    Fails fast and clearly: the caller loads this BEFORE a scan so a bad path
    never wastes the fifteen minutes of a scan.
    """
    full = os.path.abspath(path)
    try:
        if not os.path.isfile(full):
            raise BaselineError("baseline report not found: {}".format(path))
        if os.path.getsize(full) > MAX_BASELINE_BYTES:
            raise BaselineError("baseline report is larger than {:,} bytes - refused"
                                .format(MAX_BASELINE_BYTES))
        with io.open(full, encoding="utf-8") as fh:
            document = json.load(fh)
    except (OSError, ValueError) as exc:
        if isinstance(exc, BaselineError):
            raise
        raise BaselineError("baseline report could not be read: {}".format(exc))
    if not isinstance(document, dict):
        raise BaselineError("baseline report is not a JSON object")
    if document.get("report_type") == "sharing-summary" or "modules" not in document:
        # A --share-json summary holds only counts, never individual findings,
        # so there is nothing to match item by item.
        raise BaselineError(
            "baseline has no per-finding detail to compare - save the baseline "
            "with --json (the full report), not --share-json")
    if not isinstance(document.get("modules"), dict):
        raise BaselineError("baseline report is malformed: 'modules' is not an object")
    return document


def _norm(value: Any) -> str:
    return " ".join(str(value or "").split())


def _hit_key(module: str, hit: Dict[str, Any]) -> Tuple[str, str, str]:
    """Stable identity for an indicator match across runs.

    Deliberately excludes the observed time (it can jitter between runs) and any
    count, keeping only what names the same observation: which check saw it,
    which indicator, and where.
    """
    return (module, _norm(hit.get("indicator")), _norm(hit.get("location")))


def _lead_key(module: str, lead: Dict[str, Any]) -> Tuple[str, str, str]:
    return (module, _norm(lead.get("what")), _norm(lead.get("location")))


def _index(document: Dict[str, Any], kind: str, key_fn):
    """Map identity key -> (module, item) for every hit or lead in a document."""
    index: Dict[Tuple[str, str, str], Tuple[str, Dict[str, Any]]] = {}
    modules = document.get("modules")
    if not isinstance(modules, dict):
        return index
    for name, module in modules.items():
        if not isinstance(module, dict):
            continue
        items = module.get(kind) or []
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict):
                # First writer wins, so a later duplicate key never hides an
                # earlier distinct observed/evidence value.
                index.setdefault(key_fn(name, item), (name, item))
    return index


def _hit_entry(module: str, hit: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "module": module,
        "indicator": hit.get("indicator", ""),
        # Carried so the report can defang a network indicator the same way the
        # detail section does (an app id is not an address and is left alone).
        "kind": hit.get("kind", ""),
        "evidence": hit.get("evidence") or "unclassified",
        "location": hit.get("location", ""),
        "observed": hit.get("observed", ""),
        "withdrawn_only": bool(hit.get("withdrawn_only")),
    }


def _lead_entry(module: str, lead: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "module": module,
        "what": lead.get("what", ""),
        "location": lead.get("location", ""),
        "observed": lead.get("observed", ""),
    }


def _scope_notes(baseline: Dict[str, Any], current: Dict[str, Any]) -> List[str]:
    notes: List[str] = []
    b_scope = baseline.get("scope") or {}
    c_scope = current.get("scope") or {}
    b_type, c_type = b_scope.get("scan_type"), c_scope.get("scan_type")
    if b_type and c_type and b_type != c_type:
        notes.append(
            "The two checks used different scopes ({} then {}). Items shown as "
            "cleared may simply be outside the current scope, and new items may "
            "be newly in scope rather than newly present.".format(b_type, c_type))
    if bool(b_scope.get("phone")) != bool(c_scope.get("phone")):
        notes.append("One check looked at phone evidence and the other did not; "
                     "phone items will appear entirely as new or as cleared.")
    if baseline.get("scan_state") == "partial" or current.get("scan_state") == "partial":
        notes.append("At least one check was partial (cancelled or with gaps), so "
                     "some differences may reflect what was not examined.")
    if baseline.get("schema_version") != current.get("schema_version"):
        notes.append("The baseline was written by a different report version "
                     "(schema {} vs {}); comparison is best-effort.".format(
                         baseline.get("schema_version"), current.get("schema_version")))
    return notes


def compare(baseline: Dict[str, Any], current: Dict[str, Any],
            baseline_path: str = "") -> Dict[str, Any]:
    """Compare a prior report (baseline) with the current one. Pure function.

    Returns a block describing new / cleared / persisting indicator matches and
    worth-a-look items, plus counts and the caveats a reader needs to interpret
    them. Never mutates either document.
    """
    base_hits = _index(baseline, "hits", _hit_key)
    cur_hits = _index(current, "hits", _hit_key)
    base_leads = _index(baseline, "leads", _lead_key)
    cur_leads = _index(current, "leads", _lead_key)

    new_findings, cleared_findings, persisting_findings = [], [], []
    changed_evidence = 0
    for key, (module, hit) in cur_hits.items():
        if key in base_hits:
            entry = _hit_entry(module, hit)
            base_grade = base_hits[key][1].get("evidence") or "unclassified"
            if base_grade != entry["evidence"]:
                entry["baseline_evidence"] = base_grade
                changed_evidence += 1
            persisting_findings.append(entry)
        else:
            new_findings.append(_hit_entry(module, hit))
    for key, (module, hit) in base_hits.items():
        if key not in cur_hits:
            cleared_findings.append(_hit_entry(module, hit))

    new_leads, cleared_leads, persisting_leads = [], [], []
    for key, (module, lead) in cur_leads.items():
        (persisting_leads if key in base_leads else new_leads).append(
            _lead_entry(module, lead))
    for key, (module, lead) in base_leads.items():
        if key not in cur_leads:
            cleared_leads.append(_lead_entry(module, lead))

    def _sort_findings(rows):
        rows.sort(key=lambda r: (r["module"], r["indicator"], r["location"]))
        return rows

    def _sort_leads(rows):
        rows.sort(key=lambda r: (r["module"], r["what"], r["location"]))
        return rows

    block = {
        "baseline_path": baseline_path,
        "baseline_completed_at": baseline.get("completed_at"),
        "baseline_version": (baseline.get("tool") or {}).get("version"),
        "schema_match": baseline.get("schema_version") == current.get("schema_version"),
        "new_findings": _sort_findings(new_findings),
        "cleared_findings": _sort_findings(cleared_findings),
        "persisting_findings": _sort_findings(persisting_findings),
        "new_leads": _sort_leads(new_leads),
        "cleared_leads": _sort_leads(cleared_leads),
        "persisting_leads": _sort_leads(persisting_leads),
        "notes": _scope_notes(baseline, current),
    }
    block["counts"] = {
        "new_findings": len(new_findings),
        "cleared_findings": len(cleared_findings),
        "persisting_findings": len(persisting_findings),
        "changed_evidence": changed_evidence,
        "new_leads": len(new_leads),
        "cleared_leads": len(cleared_leads),
        "persisting_leads": len(persisting_leads),
    }
    return block
