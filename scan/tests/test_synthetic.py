"""A synthetic positive must be detected by each module.

SPEC-scanner.md, testing requirements: "A synthetic positive (place a benign
file whose hash is in a test IOC set; add a test domain to a browser cache) must
be detected by each module."

A clean-machine test only proves the modules return without finding anything,
which a `return ModuleResult(NAME)` stub would also do. These tests plant a
known indicator in a fake tree and assert each module actually finds it, with
its provenance attached and the status rolled up to HITS.

Hermetic: the indicator is a reserved-TLD domain (`.invalid`, RFC 2606) that can
never resolve, the hash is of a file this test created, and every path is inside
a temp dir. Nothing on the real machine is read or written:
  - the hash module is pointed at the temp tree by monkeypatching `_roots`
  - the browser module reads `LOCALAPPDATA`/`APPDATA` into module-level globals
    at IMPORT time, so its `CHROMIUM_ROOTS` / `ROAMING` / `LOCAL` attributes are
    monkeypatched directly; patching os.environ would be too late to matter.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adint_scan import iocs as iocmod                     # noqa: E402
from adint_scan.context import ScanContext                # noqa: E402
from adint_scan.modules import browser, hashscan          # noqa: E402
from adint_scan.result import CLEAN, HITS, ModuleResult    # noqa: E402

# RFC 2606 reserved TLD: it is unregistrable, so even a bug that tried to
# resolve this could not reach anyone.
TEST_DOMAIN = "synthetic-test-indicator.invalid"
PAYLOAD_BYTES = b"MZ\x90\x00 synthetic adint-scan test payload, not malware\n"
PAYLOAD_SHA256 = hashlib.sha256(PAYLOAD_BYTES).hexdigest()


def write_ioc_file(path, domain=TEST_DOMAIN, sha256=PAYLOAD_SHA256):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# synthetic test indicator set\n")
        fh.write("{}\tdelivery\tprimary\n".format(domain))
        fh.write("{}\tsample\tprimary\n".format(sha256))
    return iocmod.load(path)


def quiet_ctx(ioc_set):
    return ScanContext(iocs=ioc_set, emit=lambda _m: None)


class SyntheticBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="adint_syn_")
        self.iocs = write_ioc_file(os.path.join(self.tmp, "iocs.txt"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def assert_hit_implies_hits_status(self, result):
        """No module may ever report CLEAN for a run that found something."""
        self.assertIsInstance(result, ModuleResult)
        if result.hits:
            self.assertEqual(result.status, HITS)
            self.assertNotEqual(result.status, CLEAN)


class TestHashModuleSyntheticPositive(SyntheticBase):
    def setUp(self):
        super().setUp()
        self.scan_root = os.path.join(self.tmp, "fakeroot")
        os.makedirs(self.scan_root)
        self.payload = os.path.join(self.scan_root, "payload.dll")
        with open(self.payload, "wb") as fh:
            fh.write(PAYLOAD_BYTES)
        # Point the module at the fake tree only — never at the real machine.
        self._real_roots = hashscan._roots
        hashscan._roots = lambda: [self.scan_root]

    def tearDown(self):
        hashscan._roots = self._real_roots
        super().tearDown()

    def test_sanity_extension_is_one_the_module_hashes(self):
        self.assertTrue(self.payload.lower().endswith(hashscan.EXTS))

    def test_known_sample_hash_is_detected_exactly_once(self):
        r = hashscan.run(quiet_ctx(self.iocs))
        self.assertEqual(len(r.hits), 1,
                         "the synthetic sample must be found, exactly once")
        hit = r.hits[0]
        self.assertEqual(hit.indicator, PAYLOAD_SHA256)
        self.assertEqual(os.path.normcase(hit.location),
                         os.path.normcase(self.payload))
        # Provenance comes from the IOC set, not from the module.
        self.assertEqual(hit.tier, "sample")
        self.assertEqual(hit.confidence, "primary")
        self.assertIn(PAYLOAD_SHA256, hit.detail)
        self.assertEqual(r.status, HITS)
        self.assertEqual(r.status, "HITS")
        self.assert_hit_implies_hits_status(r)

    def test_root_that_was_walked_is_recorded_as_a_check_that_ran(self):
        r = hashscan.run(quiet_ctx(self.iocs))
        self.assertTrue(any(c.ran and self.scan_root in c.name
                            for c in r.checks))
        self.assertGreaterEqual(r.checked, 1)
        self.assertGreaterEqual(r.submetrics.get("files_hashed", 0), 1)

    def test_non_matching_file_is_clean_not_a_hit(self):
        with open(os.path.join(self.scan_root, "benign.dll"), "wb") as fh:
            fh.write(b"something else entirely")
        r = hashscan.run(quiet_ctx(self.iocs))
        self.assertEqual(len(r.hits), 1)
        self.assertEqual(r.submetrics["files_hashed"], 2)

    def test_empty_hash_target_set_is_unknown_not_clean(self):
        # D3: nothing to compare against is a gap, never a clean result.
        domain_only = write_ioc_file(
            os.path.join(self.tmp, "domains.txt"), sha256="a" * 64)
        domain_only.indicators = [i for i in domain_only.indicators
                                  if i.type != iocmod.TYPE_SHA256]
        r = hashscan.run(quiet_ctx(domain_only))
        self.assertEqual(r.status, "UNKNOWN")
        self.assertNotEqual(r.status, CLEAN)


class TestBrowserModuleSyntheticPositive(SyntheticBase):
    def setUp(self):
        super().setUp()
        self.root = os.path.join(self.tmp, "User Data")
        self.profile = os.path.join(self.root, "Default")
        cache_dir = os.path.join(self.profile, "Cache", "Cache_Data")
        os.makedirs(cache_dir)

        # (1) blob path: the HTTP cache entry, where a subresource ad impression
        # would actually survive (history only records top-level navigations).
        self.cache_file = os.path.join(cache_dir, "f_000001")
        with open(self.cache_file, "wb") as fh:
            fh.write(b"\x00\x01HTTP/1.1 200 OK\nhost: " +
                     TEST_DOMAIN.encode("ascii") + b"\n\x00\x02")

        # (2) sqlite path: a real History database with the urls table.
        self.history = os.path.join(self.profile, "History")
        con = sqlite3.connect(self.history)
        con.execute("CREATE TABLE urls (url TEXT, title TEXT)")
        con.execute("INSERT INTO urls VALUES (?, ?)",
                    ("https://" + TEST_DOMAIN + "/ad?id=1", "synthetic page"))
        con.commit()
        con.close()

        # Redirect every module-level path global at the fake tree. These are
        # read from the environment AT IMPORT TIME, so os.environ is useless.
        self.empty = os.path.join(self.tmp, "empty")
        os.makedirs(self.empty)
        self._saved = (browser.CHROMIUM_ROOTS, browser.ROAMING, browser.LOCAL,
                       browser.FIREFOX_ROOTS, browser.SAFARI_LIBRARY)
        browser.CHROMIUM_ROOTS = [("test", self.root)]
        browser.ROAMING = self.empty
        browser.LOCAL = self.empty
        browser.SAFARI_LIBRARY = ""
        browser.FIREFOX_ROOTS = []   # hermetic: never read the real Firefox

    def tearDown(self):
        (browser.CHROMIUM_ROOTS, browser.ROAMING, browser.LOCAL,
         browser.FIREFOX_ROOTS, browser.SAFARI_LIBRARY) = self._saved
        super().tearDown()

    def test_detects_the_domain_in_both_sqlite_and_blob_artifacts(self):
        r = browser.run(quiet_ctx(self.iocs))
        self.assertTrue(r.hits, "the synthetic domain must be detected")

        sqlite_hits = [h for h in r.hits if h.detail.startswith("history:")]
        blob_hits = [h for h in r.hits if "binary match" in h.detail]
        self.assertGreaterEqual(len(sqlite_hits), 1,
                                "the sqlite (History) path must detect it")
        self.assertGreaterEqual(len(blob_hits), 1,
                                "the cache-blob path must detect it")

        self.assertEqual(os.path.normcase(sqlite_hits[0].location),
                         os.path.normcase(self.history))
        self.assertEqual(os.path.normcase(blob_hits[0].location),
                         os.path.normcase(self.cache_file))
        for h in r.hits:
            self.assertEqual(h.indicator, TEST_DOMAIN)
            self.assertEqual((h.tier, h.confidence), ("delivery", "primary"))

        # Counts scanned, not just hits, so a result is auditable.
        self.assertGreaterEqual(r.submetrics["sqlite"], 1)
        self.assertGreaterEqual(r.submetrics["blob"], 1)
        self.assertEqual(r.status, HITS)
        self.assert_hit_implies_hits_status(r)

    def test_installed_root_is_recorded_as_a_check_that_ran(self):
        # Checks are now recorded per (browser label, artifact kind) rather than
        # one blanket check per installed browser, so that a locked artifact
        # becomes a visible gap instead of being swallowed into a clean result.
        # This fake tree has a readable History and a readable cache blob, so the
        # "history" and "blobs" kinds for the "test" browser must both have run.
        r = browser.run(quiet_ctx(self.iocs))
        names = [c.name for c in r.checks]
        self.assertIn("test:history", names)
        self.assertIn("test:blobs", names)
        self.assertTrue(any(c.name.startswith("test:") for c in r.checks))
        self.assertTrue(all(c.ran for c in r.checks),
                        "nothing in this readable tree should be a gap")

    def test_clean_tree_finds_nothing_and_stays_clean(self):
        empty_root = os.path.join(self.tmp, "Empty User Data", "Default")
        os.makedirs(os.path.join(empty_root, "Cache", "Cache_Data"))
        browser.CHROMIUM_ROOTS = [("test", os.path.dirname(empty_root))]
        r = browser.run(quiet_ctx(self.iocs))
        self.assertEqual(r.hits, [])
        self.assertEqual(r.status, CLEAN)

    def test_corrupt_sqlite_file_does_not_crash_the_module(self):
        # A path that exists but is not a database. sqlite may notice at connect
        # or at first query, so the only contract asserted is "did not raise"
        # and "still returned a ModuleResult".
        with open(os.path.join(self.profile, "Favicons"), "wb") as fh:
            fh.write(os.urandom(4096))
        try:
            r = browser.run(quiet_ctx(self.iocs))
        except Exception as exc:                       # pragma: no cover
            self.fail("browser.run raised on a corrupt sqlite file: {!r}"
                      .format(exc))
        self.assertIsInstance(r, ModuleResult)
        # The real positives must still be found despite the bad file.
        self.assertTrue(r.hits)
        self.assert_hit_implies_hits_status(r)


class TestNoModuleReportsCleanWhenItFoundSomething(SyntheticBase):
    """Cross-module invariant, stated once more as its own assertion."""

    def test_every_module_with_a_hit_reports_hits(self):
        results = []

        scan_root = os.path.join(self.tmp, "h")
        os.makedirs(scan_root)
        with open(os.path.join(scan_root, "payload.dll"), "wb") as fh:
            fh.write(PAYLOAD_BYTES)
        real_roots = hashscan._roots
        hashscan._roots = lambda: [scan_root]
        try:
            results.append(hashscan.run(quiet_ctx(self.iocs)))
        finally:
            hashscan._roots = real_roots

        root = os.path.join(self.tmp, "ud")
        cache = os.path.join(root, "Default", "Cache", "Cache_Data")
        os.makedirs(cache)
        with open(os.path.join(cache, "f_000001"), "wb") as fh:
            fh.write(TEST_DOMAIN.encode("ascii"))
        empty = os.path.join(self.tmp, "none")
        os.makedirs(empty)
        saved = (browser.CHROMIUM_ROOTS, browser.ROAMING, browser.LOCAL,
                 browser.FIREFOX_ROOTS, browser.SAFARI_LIBRARY)
        browser.CHROMIUM_ROOTS = [("test", root)]
        browser.ROAMING = empty
        browser.LOCAL = empty
        browser.SAFARI_LIBRARY = ""
        browser.FIREFOX_ROOTS = []
        try:
            results.append(browser.run(quiet_ctx(self.iocs)))
        finally:
            (browser.CHROMIUM_ROOTS, browser.ROAMING, browser.LOCAL,
             browser.FIREFOX_ROOTS, browser.SAFARI_LIBRARY) = saved

        for r in results:
            self.assertTrue(r.hits, "{}: synthetic positive not detected"
                            .format(r.name))
            self.assertEqual(r.status, HITS,
                             "{}: reported {} despite {} hit(s)"
                             .format(r.name, r.status, len(r.hits)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
