"""The macOS host checks: launchd items, the hosts file and download sources.

Hermetic on every platform: all three locations are replaced by temp-dir fixtures,
so the suite never reads the tester's real auto-start items or download record.
"""

from __future__ import annotations

import os
import plistlib
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path[:0] = [os.path.dirname(os.path.dirname(__file__)), os.path.dirname(__file__)]

from test_browser_launch import TEST_DOMAIN
from adint_scan import iocs as iocmod
from adint_scan.context import ScanContext
from adint_scan.modules import host
from adint_scan.result import (EV_CONFIGURED, EV_CONTACTED, EV_PERSISTENCE,
                               EV_REFERENCED, ModuleResult)

# 2024-01-01T00:00:00 as seconds since 2001-01-01.
STAMP_2024 = 725760000.0
PRIVATE_ADDRESS = "https://private-unrelated.invalid/secret-file.zip"


class MacosHostBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="machost_")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        ioc_path = os.path.join(self.tmp, "iocs.txt")
        with open(ioc_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("{}\tdelivery\tprimary\ttest-source\n".format(TEST_DOMAIN))
        self.ctx = ScanContext(iocs=iocmod.load(ioc_path), emit=lambda _m: None)
        self.result = ModuleResult("host")
        self.agents = os.path.join(self.tmp, "LaunchAgents")
        self.hosts = os.path.join(self.tmp, "hosts")
        self.record = os.path.join(self.tmp, "QuarantineEventsV2")
        for name, value in (("_launch_dirs", lambda: [self.agents]),
                            ("_hosts_path", lambda: self.hosts),
                            ("_download_sources_path", lambda: self.record)):
            patcher = patch.object(host, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def checks(self, ran):
        return {c.name for c in self.result.checks if c.ran is ran}


class TestLaunchItems(MacosHostBase):
    def item(self, name, content, fmt=plistlib.FMT_XML):
        os.makedirs(self.agents, exist_ok=True)
        path = os.path.join(self.agents, name)
        with open(path, "wb") as fh:
            fh.write(content if isinstance(content, bytes)
                     else plistlib.dumps(content, fmt=fmt))
        return path

    def test_indicator_in_arguments_is_persistence(self):
        for fmt in (plistlib.FMT_XML, plistlib.FMT_BINARY):
            self.result = ModuleResult("host")
            path = self.item("job.plist", {
                "Label": "job", "ProgramArguments": ["/bin/x", "https://" + TEST_DOMAIN + "/a"]},
                fmt)
            host._check_launch_items(self.result, self.ctx)
            self.assertEqual(len(self.result.hits), 1)
            self.assertEqual(self.result.hits[0].evidence, EV_PERSISTENCE)
            self.assertEqual(self.result.hits[0].location, path)

    def test_indicator_nested_in_environment_is_found(self):
        self.item("job.plist", {"EnvironmentVariables": {"U": [{"x": TEST_DOMAIN}]}})
        host._check_launch_items(self.result, self.ctx)
        self.assertEqual(len(self.result.hits), 1)

    def test_unfamiliar_job_is_not_a_finding(self):
        self.item("com.example.job.plist", {"Label": "x", "Program": "/tmp/unsigned"})
        host._check_launch_items(self.result, self.ctx)
        self.assertFalse(self.result.hits)
        self.assertEqual(self.checks(True), {"launch-items"})
        self.assertEqual(self.result.submetrics["launch_items"], 1)

    def test_missing_folder_is_not_a_gap(self):
        host._check_launch_items(self.result, self.ctx)
        self.assertEqual(self.checks(True), {"launch-items"})
        self.assertFalse(self.checks(False))

    def test_damaged_item_is_a_gap_and_others_are_still_read(self):
        self.item("bad.plist", b"not a plist")
        self.item("good.plist", {"Program": TEST_DOMAIN})
        host._check_launch_items(self.result, self.ctx)
        self.assertEqual(len(self.result.hits), 1)
        self.assertEqual(self.checks(False), {"launch-items (partial)"})

    def test_oversized_item_is_a_gap(self):
        self.item("big.plist", b"x" * (host._LAUNCH_ITEM_MAX_BYTES + 1))
        host._check_launch_items(self.result, self.ctx)
        self.assertEqual(self.checks(False), {"launch-items"})

    def test_too_deep_item_is_a_gap_not_a_crash(self):
        deep = TEST_DOMAIN
        for _ in range(host._PLIST_MAX_DEPTH + 2):
            deep = [deep]
        self.item("deep.plist", {"x": deep})
        host._check_launch_items(self.result, self.ctx)
        self.assertEqual(self.checks(False), {"launch-items"})

    @unittest.skipIf(sys.platform == "win32", "symlinks need privileges on Windows")
    def test_link_is_not_followed(self):
        target = os.path.join(self.tmp, "target.plist")
        with open(target, "wb") as fh:
            fh.write(plistlib.dumps({"Program": TEST_DOMAIN}))
        os.makedirs(self.agents)
        os.symlink(target, os.path.join(self.agents, "link.plist"))
        host._check_launch_items(self.result, self.ctx)
        self.assertFalse(self.result.hits)
        self.assertEqual(self.checks(False), {"launch-items"})

    def test_refused_folder_is_a_gap(self):
        os.makedirs(self.agents)
        with patch.object(host.os, "scandir",
                          side_effect=PermissionError(1, "Operation not permitted")):
            host._check_launch_items(self.result, self.ctx)
        self.assertEqual(self.checks(False), {"launch-items"})
        self.assertFalse(self.checks(True))


class TestHostsFile(MacosHostBase):
    def write(self, text):
        with open(self.hosts, "w", encoding="utf-8") as fh:
            fh.write(text)

    def test_real_address_is_configured(self):
        self.write("127.0.0.1 localhost\n203.0.113.9 {}\n".format(TEST_DOMAIN))
        host._check_hosts(self.result, self.ctx)
        self.assertEqual(self.result.hits[0].evidence, EV_CONFIGURED)

    def test_blocking_entry_is_not_a_finding(self):
        self.write("0.0.0.0 {}\n".format(TEST_DOMAIN))
        host._check_hosts(self.result, self.ctx)
        self.assertFalse(self.result.hits)
        self.assertEqual(self.result.submetrics["hosts_blocked_indicators"], 1)


class TestHostsPathByPlatform(unittest.TestCase):
    def test_macos_and_windows_paths(self):
        with patch.object(host.platform, "system", return_value="Darwin"):
            self.assertEqual(host._hosts_path(), "/etc/hosts")
        with patch.object(host.platform, "system", return_value="Windows"), \
                patch.dict(host.os.environ, {"SystemRoot": "R"}):
            self.assertEqual(host._hosts_path(),
                             os.path.join("R", "System32", "drivers", "etc", "hosts"))


class TestDownloadSources(MacosHostBase):
    def database(self, *rows):
        con = sqlite3.connect(self.record)
        con.execute("CREATE TABLE LSQuarantineEvent (LSQuarantineDataURLString TEXT, "
                    "LSQuarantineOriginURLString TEXT, LSQuarantineTimeStamp REAL, "
                    "LSQuarantineAgentName TEXT)")
        con.executemany("INSERT INTO LSQuarantineEvent VALUES (?, ?, ?, 'Safari')", rows)
        con.commit()
        con.close()

    def run_check(self):
        host._check_download_sources(self.result, self.ctx)
        return self.result

    def test_file_from_indicator_is_contact_with_date(self):
        self.database(("https://{}/a.zip".format(TEST_DOMAIN), None, STAMP_2024))
        hit = self.run_check().hits[0]
        self.assertEqual(hit.evidence, EV_CONTACTED)
        self.assertEqual(hit.observed, "2024-01-01T00:00:00")

    def test_origin_page_on_indicator_is_contact(self):
        self.database(("https://cdn.invalid/a.zip",
                       "https://{}/page".format(TEST_DOMAIN), STAMP_2024))
        self.assertEqual(self.run_check().hits[0].evidence, EV_CONTACTED)

    def test_mention_in_address_is_only_a_reference(self):
        self.database(("https://cdn.invalid/a.zip?ref=" + TEST_DOMAIN, None, STAMP_2024))
        hit = self.run_check().hits[0]
        self.assertEqual(hit.evidence, EV_REFERENCED)
        self.assertEqual(hit.observed, "")

    def test_unmatched_records_never_reach_the_output(self):
        self.database((PRIVATE_ADDRESS, PRIVATE_ADDRESS, STAMP_2024))
        result = self.run_check()
        self.assertFalse(result.hits)
        self.assertNotIn("private-unrelated", repr(result.to_dict()))
        self.assertEqual(result.submetrics["download_records"], 1)

    def test_oldest_record_reaches_the_report(self):
        self.database((PRIVATE_ADDRESS, None, STAMP_2024), (PRIVATE_ADDRESS, None, None))
        reach = self.run_check().reach["download-sources"]
        self.assertTrue(reach["earliest"].startswith("2024-01-01"))
        self.assertIn("2 download records", reach["basis"])

    def test_impossible_date_is_ignored_not_fatal(self):
        self.database(("https://{}/a".format(TEST_DOMAIN), None, 1e300))
        result = self.run_check()
        self.assertEqual(result.hits[0].observed, "")
        self.assertNotIn("download-sources", result.reach)
        self.assertEqual(self.checks(True), {"download-sources"})

    def test_no_record_is_not_a_gap_but_says_so(self):
        result = self.run_check()
        self.assertEqual(self.checks(True), {"download-sources"})
        self.assertTrue(any("no download record" in n for n in result.notes))

    def test_unusable_database_is_a_gap_and_leaves_no_copy(self):
        with open(self.record, "wb") as fh:
            fh.write(b"not a database")
        scratch = os.path.join(self.tmp, "scratch")
        os.makedirs(scratch)
        with patch.dict(os.environ, {"TMPDIR": scratch, "TEMP": scratch, "TMP": scratch}):
            self.run_check()
        self.assertEqual(self.checks(False), {"download-sources"})
        self.assertEqual(os.listdir(scratch), [])

    def test_source_file_is_unchanged_and_no_copy_remains(self):
        self.database((PRIVATE_ADDRESS, None, STAMP_2024))
        with open(self.record, "rb") as fh:
            before = fh.read()
        scratch = os.path.join(self.tmp, "scratch")
        os.makedirs(scratch)
        with patch.dict(os.environ, {"TMPDIR": scratch, "TEMP": scratch, "TMP": scratch}):
            self.run_check()
        with open(self.record, "rb") as fh:
            self.assertEqual(before, fh.read())
        self.assertEqual(os.listdir(scratch), [])


class TestRunOnMacos(MacosHostBase):
    def run_module(self):
        with patch.object(host.platform, "system", return_value="Darwin"):
            return host.run(self.ctx)

    def test_runs_macos_checks_and_keeps_windows_ones_as_gaps(self):
        with open(self.hosts, "w", encoding="utf-8") as fh:
            fh.write("127.0.0.1 localhost\n")
        result = self.run_module()
        ran = {c.name for c in result.checks if c.ran}
        gaps = {c.name for c in result.checks if not c.ran}
        self.assertEqual(gaps, {"com-persistence", "dns-cache", "dns-log", "known-paths"})
        self.assertEqual(ran, {"launch-items", "hosts-file", "download-sources"})

    def test_missing_hosts_file_is_a_gap(self):
        gaps = {c.name for c in self.run_module().checks if not c.ran}
        self.assertIn("hosts-file", gaps)

    def test_one_failing_check_does_not_cost_the_others(self):
        with patch.object(host, "_check_launch_items", side_effect=RuntimeError("boom")):
            result = self.run_module()
        reasons = {c.name: c.reason for c in result.checks if not c.ran}
        self.assertIn("boom", reasons["launch-items"])
        self.assertTrue(any(c.ran and c.name == "download-sources" for c in result.checks))

    def test_other_platforms_stay_unsupported(self):
        with patch.object(host.platform, "system", return_value="Linux"):
            result = host.run(self.ctx)
        self.assertFalse(any(c.ran for c in result.checks))


if __name__ == "__main__":
    unittest.main()
