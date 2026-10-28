"""Offline baseline comparison (--baseline): what changed since a prior report.

The comparison is additive: it must report new / cleared / persisting items
correctly, defang network indicators it echoes, never present a cleared item as
proof of removal, and never change the scan's verdict or exit code.
"""
import copy
import datetime
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from zbtriage.iocs import Indicator, IocSet, TYPE_DOMAIN, TYPE_IP
from zbtriage.result import Hit, Lead, ModuleResult, EV_PERSISTENCE, EV_REFERENCED
from zbtriage.report import build_document, render_human
from zbtriage import baseline
from zbtriage.baseline import compare, load_baseline, BaselineError


NOW = datetime.datetime(2026, 1, 1, 12, 0, 0)


def _doc(hits=(), leads=(), module="host"):
    """Build a real report document from hits/leads, via the normal pipeline."""
    values = [h.indicator for h in hits] or ["placeholder.invalid"]
    iocs = IocSet([Indicator(v, "cc", "primary", TYPE_DOMAIN) for v in values],
                  "fixture", None)
    result = ModuleResult(module)
    for h in hits:
        result.add_hit(h)
    for lead in leads:
        result.add_lead(lead)
    return build_document(iocs, [result], NOW)


def _hit(indicator, location, detail="detail", evidence=EV_PERSISTENCE,
         kind="domain", observed=""):
    return Hit(indicator, location, detail, tier="cc", evidence=evidence,
               kind=kind, observed=observed)


def _lead(what, location, check="sideload"):
    return Lead(check, location, what, usual_reason="usually harmless")


class TestCompare(unittest.TestCase):
    def test_new_cleared_persisting_findings(self):
        stays = _hit("stays.invalid", "/a")
        goes = _hit("goes.invalid", "/b")
        arrives = _hit("arrives.invalid", "/c")
        base = _doc(hits=[stays, goes])
        cur = _doc(hits=[stays, arrives])
        block = compare(base, cur)
        c = block["counts"]
        self.assertEqual((c["new_findings"], c["cleared_findings"], c["persisting_findings"]),
                         (1, 1, 1))
        self.assertEqual(block["new_findings"][0]["indicator"], "arrives.invalid")
        self.assertEqual(block["cleared_findings"][0]["indicator"], "goes.invalid")
        self.assertEqual(block["persisting_findings"][0]["indicator"], "stays.invalid")

    def test_location_is_part_of_identity(self):
        # Same indicator seen at a new location is a new finding, not a persist.
        base = _doc(hits=[_hit("same.invalid", "/old")])
        cur = _doc(hits=[_hit("same.invalid", "/new")])
        block = compare(base, cur)
        self.assertEqual(block["counts"]["new_findings"], 1)
        self.assertEqual(block["counts"]["cleared_findings"], 1)
        self.assertEqual(block["counts"]["persisting_findings"], 0)

    def test_observed_time_does_not_break_identity(self):
        base = _doc(hits=[_hit("x.invalid", "/a", observed="2026-01-01 00:00:00")])
        cur = _doc(hits=[_hit("x.invalid", "/a", observed="2026-02-02 09:09:09")])
        block = compare(base, cur)
        self.assertEqual(block["counts"]["persisting_findings"], 1)
        self.assertEqual(block["counts"]["new_findings"], 0)

    def test_evidence_change_is_flagged_not_double_counted(self):
        base = _doc(hits=[_hit("g.invalid", "/a", evidence=EV_REFERENCED)])
        cur = _doc(hits=[_hit("g.invalid", "/a", evidence=EV_PERSISTENCE)])
        block = compare(base, cur)
        self.assertEqual(block["counts"]["persisting_findings"], 1)
        self.assertEqual(block["counts"]["new_findings"], 0)
        self.assertEqual(block["counts"]["changed_evidence"], 1)
        entry = block["persisting_findings"][0]
        self.assertEqual(entry["baseline_evidence"], EV_REFERENCED)
        self.assertEqual(entry["evidence"], EV_PERSISTENCE)

    def test_new_and_cleared_leads(self):
        stays = _lead("sideloaded app A", "/pkgA")
        goes = _lead("sideloaded app B", "/pkgB")
        arrives = _lead("sideloaded app C", "/pkgC")
        base = _doc(leads=[stays, goes])
        cur = _doc(leads=[stays, arrives])
        block = compare(base, cur)
        c = block["counts"]
        self.assertEqual((c["new_leads"], c["cleared_leads"], c["persisting_leads"]),
                         (1, 1, 1))
        self.assertEqual(block["new_leads"][0]["what"], "sideloaded app C")

    def test_identical_reports_show_no_change(self):
        # Nothing new or cleared; the still-present items count as persisting.
        cur = _doc(hits=[_hit("x.invalid", "/a")], leads=[_lead("app", "/p")])
        block = compare(copy.deepcopy(cur), cur)
        c = block["counts"]
        for key in ("new_findings", "cleared_findings", "changed_evidence",
                    "new_leads", "cleared_leads"):
            self.assertEqual(c[key], 0, "{} should be 0".format(key))
        self.assertEqual(c["persisting_findings"], 1)
        self.assertEqual(c["persisting_leads"], 1)

    def test_scope_difference_is_noted(self):
        base = _doc(hits=[_hit("x.invalid", "/a")])
        cur = _doc(hits=[_hit("x.invalid", "/a")])
        base["scope"] = {"scan_type": "browser"}
        cur["scope"] = {"scan_type": "full"}
        block = compare(base, cur)
        self.assertTrue(any("different scopes" in n for n in block["notes"]))

    def test_schema_mismatch_flagged(self):
        base = _doc(hits=[_hit("x.invalid", "/a")])
        cur = _doc(hits=[_hit("x.invalid", "/a")])
        base["schema_version"] = "0.0.0-old"
        block = compare(base, cur)
        self.assertFalse(block["schema_match"])
        self.assertTrue(any("different report version" in n for n in block["notes"]))

    def test_compare_does_not_mutate_inputs(self):
        base = _doc(hits=[_hit("x.invalid", "/a")])
        cur = _doc(hits=[_hit("y.invalid", "/b")])
        base_copy, cur_copy = copy.deepcopy(base), copy.deepcopy(cur)
        compare(base, cur)
        self.assertEqual(base, base_copy)
        self.assertEqual(cur, cur_copy)


class TestLoadBaseline(unittest.TestCase):
    def _write(self, obj):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def test_round_trips_a_real_report(self):
        doc = _doc(hits=[_hit("x.invalid", "/a")])
        loaded = load_baseline(self._write(doc))
        self.assertIn("modules", loaded)

    def test_missing_file(self):
        with self.assertRaises(BaselineError):
            load_baseline("/no/such/baseline-xyz.json")

    def test_rejects_sharing_summary(self):
        path = self._write({"report_type": "sharing-summary", "verdict": {}})
        with self.assertRaises(BaselineError) as ctx:
            load_baseline(path)
        self.assertIn("--json", str(ctx.exception))

    def test_rejects_object_without_modules(self):
        with self.assertRaises(BaselineError):
            load_baseline(self._write({"verdict": {}}))

    def test_rejects_non_object(self):
        with self.assertRaises(BaselineError):
            load_baseline(self._write([1, 2, 3]))


class TestRenderAndContract(unittest.TestCase):
    def test_render_shows_changes_and_defangs_new_indicator(self):
        base = _doc(hits=[_hit("old-c2.invalid", "/a")])
        cur = _doc(hits=[_hit("new-c2.invalid", "/b", kind="domain")])
        cur["baseline"] = compare(base, cur, baseline_path="prev.json")
        text = render_human(cur)
        self.assertIn("CHANGES SINCE YOUR LAST CHECK", text)
        # The newly-appeared network indicator must be defanged, never live.
        self.assertIn("new-c2[.]invalid", text)
        self.assertNotIn("new-c2.invalid", text)

    def test_cleared_item_carries_the_not_removed_caveat(self):
        base = _doc(hits=[_hit("gone.invalid", "/a")])
        cur = _doc(hits=[])
        cur["baseline"] = compare(base, cur)
        text = render_human(cur)
        self.assertIn("CLEARED", text)
        self.assertIn("NOT proof that spyware was removed", text)

    def test_baseline_does_not_change_verdict_or_exit_code(self):
        # Attaching a baseline block must not alter the machine contract.
        base = _doc(hits=[_hit("x.invalid", "/a")])
        cur = _doc(hits=[_hit("y.invalid", "/b")])
        exit_before = cur["exit_code"]
        verdict_before = copy.deepcopy(cur["verdict"])
        cur["baseline"] = compare(base, cur)
        self.assertEqual(cur["exit_code"], exit_before)
        self.assertEqual(cur["verdict"], verdict_before)

    def test_render_without_baseline_block_is_unaffected(self):
        cur = _doc(hits=[_hit("x.invalid", "/a")])
        text = render_human(cur)
        self.assertNotIn("CHANGES SINCE YOUR LAST CHECK", text)


if __name__ == "__main__":
    unittest.main()
