"""Safari is searched on macOS, graded like other browsers, and its cookie values stay unread.

Hermetic: the ~/Library is a temp dir built here, and the cookie file is written
to the published Cookies.binarycookies layout with a sentinel where the value goes.
"""

from __future__ import annotations

import os
import pathlib
import sqlite3
import struct
import sys
import unittest
from unittest.mock import patch

sys.path[:0] = [os.path.dirname(os.path.dirname(__file__)), os.path.dirname(__file__)]

from test_browser_launch import BrowserLaunchBase, TEST_DOMAIN
from adint_scan.modules import browser
from adint_scan.result import CLEAN, EV_CONTACTED, EV_REFERENCED, UNKNOWN

SENTINEL = "SENTINEL-COOKIE-VALUE"
# 2024-01-01T00:00:00 as seconds since 2001-01-01.
VISIT_2024 = 725760000.0


def cookie_record(host, name=b"sid", value=SENTINEL.encode(), created=VISIT_2024):
    strings = host.encode() + b"\0" + name + b"\0/\0" + value + b"\0"
    at = browser._SAFARI_COOKIE_RECORD_MIN
    host_at, name_at = at, at + len(host) + 1
    path_at = name_at + len(name) + 1
    value_at = path_at + 2
    size = at + len(strings)
    head = struct.pack("<IIII", size, 0, 0, 0)
    head += struct.pack("<IIII", host_at, name_at, path_at, value_at)
    head += b"\0" * 8 + struct.pack("<dd", created + 1000, created)
    return head + strings


def cookie_file(*records):
    table = 8 + 4 * len(records)
    offsets, body, position = [], b"", table
    for record in records:
        offsets.append(position)
        body += record
        position += len(record)
    page = struct.pack("<II", 0x100, len(records))
    page += struct.pack("<{}I".format(len(records)), *offsets) + body
    return b"cook" + struct.pack(">I", 1) + struct.pack(">I", len(page)) + page


class SafariBase(BrowserLaunchBase):
    def setUp(self):
        super().setUp()
        self.library = os.path.join(self.tmp, "Library")
        os.makedirs(self.library)
        self.container = os.path.join(self.library, "Containers", "com.apple.Safari",
                                      "Data", "Library")
        browser.CHROMIUM_ROOTS = []
        browser.SAFARI_LIBRARY = self.library

    def history(self, url, title="page", visited=VISIT_2024, folder=None):
        folder = folder or os.path.join(self.library, "Safari")
        os.makedirs(folder, exist_ok=True)
        con = sqlite3.connect(os.path.join(folder, "History.db"))
        con.execute("CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT)")
        con.execute("CREATE TABLE history_visits (id INTEGER PRIMARY KEY, "
                    "history_item INTEGER, visit_time REAL, title TEXT)")
        con.execute("INSERT INTO history_items VALUES (1, ?)", (url,))
        if visited is not None:
            con.execute("INSERT INTO history_visits VALUES (1, 1, ?, ?)",
                        (visited, title))
        con.commit()
        con.close()

    def cookies(self, data, folder=None):
        folder = folder or os.path.join(self.container, "Cookies")
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, "Cookies.binarycookies")
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def scan(self):
        return browser.run(self.ctx)


class TestLocation(unittest.TestCase):
    def test_only_macos_has_a_safari_library(self):
        for platform in ("win32", "linux"):
            with patch.object(browser.sys, "platform", platform):
                self.assertEqual(browser._safari_library(), "")
        with patch.object(browser.sys, "platform", "darwin"), \
                patch.object(browser.os.path, "expanduser", lambda _p: "/Users/u"):
            self.assertEqual(browser._safari_library(),
                             os.path.join("/Users/u", "Library"))


class TestHistory(SafariBase):
    def test_visited_host_is_contact_with_its_date(self):
        self.history("https://{}/x".format(TEST_DOMAIN))
        result = self.scan()
        self.assertEqual(len(result.hits), 1)
        self.assertEqual(result.hits[0].evidence, EV_CONTACTED)
        self.assertEqual(result.hits[0].observed, "2024-01-01T00:00:00")

    def test_indicator_in_query_string_is_only_a_reference(self):
        self.history("https://research.invalid/?q=" + TEST_DOMAIN)
        self.assertEqual(self.scan().hits[0].evidence, EV_REFERENCED)

    def test_item_without_a_visit_is_only_a_reference(self):
        self.history("https://{}/x".format(TEST_DOMAIN), visited=None)
        self.assertEqual(self.scan().hits[0].evidence, EV_REFERENCED)

    def test_safari_profile_history_names_the_profile(self):
        folder = os.path.join(self.library, "Safari", "Profiles", "WORK")
        self.history("https://{}/x".format(TEST_DOMAIN), folder=folder)
        self.assertEqual(self.scan().hits[0].profile, "WORK")

    def test_unsupported_schema_is_a_gap(self):
        folder = os.path.join(self.library, "Safari")
        os.makedirs(folder)
        sqlite3.connect(os.path.join(folder, "History.db")).close()
        result = self.scan()
        self.assertEqual(result.status, UNKNOWN)
        self.assertTrue(any(not c.ran and c.name == "safari:history"
                            for c in result.checks))

    def test_source_database_is_unchanged(self):
        self.history("https://{}/x".format(TEST_DOMAIN))
        files = [p for p in pathlib.Path(self.library).rglob("*") if p.is_file()]
        before = {str(p): p.read_bytes() for p in files}
        self.scan()
        self.assertEqual(before, {str(p): p.read_bytes() for p in files})


class TestCookies(SafariBase):
    def test_host_is_contact_and_value_is_never_output(self):
        self.cookies(cookie_file(cookie_record("." + TEST_DOMAIN)))
        result = self.scan()
        self.assertEqual(len(result.hits), 1)
        self.assertEqual(result.hits[0].evidence, EV_CONTACTED)
        self.assertEqual(result.hits[0].observed, "2024-01-01T00:00:00")
        self.assertIn("name sid", result.hits[0].detail)
        self.assertNotIn(SENTINEL, repr(result.to_dict()))

    def test_parser_returns_no_value(self):
        records = list(browser._safari_cookie_records(
            cookie_file(cookie_record("a.invalid"))))
        self.assertEqual(records, [("a.invalid", "sid", VISIT_2024)])

    def test_indicator_only_in_value_is_not_a_hit(self):
        self.cookies(cookie_file(cookie_record("clean.invalid",
                                               value=TEST_DOMAIN.encode())))
        result = self.scan()
        self.assertFalse(result.hits)
        self.assertEqual(result.status, CLEAN)

    def test_cookie_age_reaches_the_report(self):
        self.cookies(cookie_file(cookie_record("clean.invalid")))
        result = self.scan()
        self.assertTrue(result.reach["cookies"]["earliest"].startswith("2024-01-01"))

    def test_impossible_date_is_ignored_not_fatal(self):
        self.cookies(cookie_file(cookie_record("." + TEST_DOMAIN, created=1e300)))
        result = self.scan()
        self.assertEqual(result.hits[0].observed, "")
        self.assertTrue(any(c.ran and c.name == "safari:cookies" for c in result.checks))

    def test_other_file_type_is_a_gap(self):
        self.cookies(b"not a cookie file")
        result = self.scan()
        self.assertEqual(result.status, UNKNOWN)
        self.assertTrue(any(not c.ran and c.name == "safari:cookies"
                            for c in result.checks))

    def test_damage_keeps_earlier_hits_and_reports_a_gap(self):
        good = cookie_record("." + TEST_DOMAIN)
        data = cookie_file(good, good)
        # Point the second record's length past the end of its page.
        second = 12 + 16 + len(good)   # file header, page header and offsets, first record
        damaged = data[:second] + struct.pack("<I", 10 ** 6) + data[second + 4:]
        self.cookies(damaged)
        result = self.scan()
        self.assertEqual(len(result.hits), 1)
        self.assertTrue(any(not c.ran and c.name == "safari:cookies"
                            for c in result.checks))

    def test_truncated_file_is_a_gap(self):
        self.cookies(cookie_file(cookie_record("a.invalid"))[:20])
        self.assertEqual(self.scan().status, UNKNOWN)

    def test_older_store_is_read_only_without_the_current_one(self):
        self.cookies(cookie_file(cookie_record("." + TEST_DOMAIN)),
                     os.path.join(self.library, "Cookies"))
        self.assertEqual(len(self.scan().hits), 1)
        self.cookies(cookie_file(cookie_record("clean.invalid")))
        self.assertFalse(self.scan().hits)


class TestCacheAndAccess(SafariBase):
    def test_cache_match_is_only_a_reference(self):
        cache = os.path.join(self.container, "Caches", "com.apple.Safari", "WebKitCache")
        os.makedirs(cache)
        with open(os.path.join(cache, "Resource"), "wb") as fh:
            fh.write(b"https://" + TEST_DOMAIN.encode() + b"/ad.js")
        result = self.scan()
        self.assertEqual(result.hits[0].evidence, EV_REFERENCED)
        self.assertEqual(result.submetrics["blob"], 1)

    def test_refused_folder_is_a_gap_with_the_real_reason(self):
        denied = os.path.join(self.library, "Safari")
        os.makedirs(denied)
        real = os.listdir

        def listdir(path):
            if path == denied:
                raise PermissionError(1, "Operation not permitted", path)
            return real(path)

        with patch.object(browser.os, "listdir", listdir), \
                patch.object(browser.sys, "platform", "darwin"):
            result = self.scan()
        self.assertEqual(result.status, UNKNOWN)
        gap = next(c for c in result.checks if not c.ran)
        self.assertEqual(gap.name, "safari:history")
        self.assertIn("Safari data could not be read", gap.reason)
        self.assertIn("Full Disk Access", gap.reason)

    def test_no_safari_data_is_neither_a_finding_nor_a_gap(self):
        result = self.scan()
        self.assertFalse(result.hits)
        self.assertFalse(result.checks)


if __name__ == "__main__":
    unittest.main()
