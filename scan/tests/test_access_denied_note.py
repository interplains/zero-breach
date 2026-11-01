"""A refused read is only called a lock when something actually reports a lock.

On macOS, privacy protection refuses a browser's folder with EPERM even when the
browser is closed. The report used to say the browser "was running" and to close
it, so someone who had already closed it had no way forward and the browser stayed
unchecked. Hermetic: the exceptions are constructed and every path is in a temp dir.
"""

from __future__ import annotations

import errno
import os
import sqlite3
import sys
import unittest
from unittest.mock import patch

sys.path[:0] = [os.path.dirname(os.path.dirname(__file__)), os.path.dirname(__file__)]

from test_browser_launch import BrowserLaunchBase
from adint_scan.modules import browser
from adint_scan.result import UNKNOWN

CHROME = "/Users/u/Library/Application Support/Google/Chrome"
LOCK_TEXT = "was running"
MACOS_HINT = "Full Disk Access"


class _SharingViolation(PermissionError):
    winerror = 32


def _denied(code=errno.EPERM, reason="Operation not permitted", path=CHROME):
    return PermissionError(code, reason, path)


class TestLockedNoteWording(unittest.TestCase):
    def note(self, exc, platform="darwin", path=CHROME):
        with patch.object(browser.sys, "platform", platform):
            return browser._locked_note(path, exc)

    def test_macos_refusal_is_not_called_a_lock(self):
        note = self.note(_denied())
        self.assertNotIn(LOCK_TEXT, note)
        self.assertIn("Chrome", note)
        self.assertIn("Operation not permitted", note)
        self.assertIn(MACOS_HINT, note)

    def test_macos_hint_needs_macos(self):
        note = self.note(_denied(), platform="linux")
        self.assertNotIn(LOCK_TEXT, note)
        self.assertNotIn(MACOS_HINT, note)

    def test_macos_hint_needs_eperm(self):
        note = self.note(_denied(errno.EACCES, "Permission denied"))
        self.assertNotIn(LOCK_TEXT, note)
        self.assertNotIn(MACOS_HINT, note)

    def test_windows_sharing_violation_is_still_a_lock(self):
        exc = _SharingViolation(errno.EACCES, "used by another process", CHROME)
        self.assertIn(LOCK_TEXT, self.note(exc, platform="win32"))

    def test_sqlite_lock_is_still_a_lock(self):
        exc = sqlite3.OperationalError("database is locked")
        self.assertIn(LOCK_TEXT, self.note(exc))

    def test_folder_name_does_not_read_as_a_lock(self):
        path = "/Users/u/blocked/Google/Chrome"
        self.assertNotIn(LOCK_TEXT, self.note(_denied(path=path), path=path))

    def test_refused_path_keeps_its_own_reason(self):
        reason = "symlink or reparse point was not followed: " + CHROME
        note = self.note(_denied(errno.EACCES, reason))
        self.assertIn(reason, note)
        self.assertNotIn(LOCK_TEXT, note)


class TestRefusedFolderIsReported(BrowserLaunchBase):
    def test_refused_browser_folder_is_a_gap_with_the_real_reason(self):
        root = os.path.join(self.tmp, "Google", "Chrome")
        os.makedirs(root)
        with patch.object(browser, "chromium_profiles", side_effect=_denied(path=root)):
            result = self.run_chromium(root)
        self.assertEqual(result.status, UNKNOWN)
        gap = next(c for c in result.checks if not c.ran)
        self.assertEqual(gap.name, "test:profiles")
        self.assertIn("Operation not permitted", gap.reason)
        self.assertNotIn(LOCK_TEXT, gap.reason)


if __name__ == "__main__":
    unittest.main()
