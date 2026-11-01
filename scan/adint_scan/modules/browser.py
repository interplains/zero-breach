"""Search this machine's browser artifacts for AdFection / Candiru IOC domains.

Why several artifact types and not just history: browser HISTORY only records
top-level navigations, and an ad is a subresource inside an iframe. A real
AdFection impression would almost certainly never appear in history. The HTTP
cache, the cookie stores and the local-storage LevelDB files do record
subresource origins, so they are where a retrospective trace would actually
survive.

Read-only. Databases are copied before being opened, because a running browser
holds a write lock on them; the copy is opened and the temp dir is always
cleaned up. No network, ever (CONTRACT D2) - needles are matched as plain
substrings and never resolved.

Honest gaps (CONTRACT D3). A browser's databases are often locked because the
browser is running. That is NOT a clean result, it is a gap: there was somewhere
to look and we could not look there. So this module tracks, per (browser label,
artifact kind), whether at least one profile could actually be read. A kind that
was present somewhere but could never be read is reported with
`r.could_not_run(...)`, which the verdict reads as a gap - rather than being
silently swallowed into a clean roll-up. A kind that is simply ABSENT (the
browser never created that artifact) is not a gap and is recorded as nothing at
all. A browser whose every database was locked therefore rolls up to
PARTIAL/UNKNOWN with those gaps named, never to CLEAN.
"""

from __future__ import annotations

import base64
import datetime
import errno
import hashlib
import io
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from urllib.parse import urlsplit
from ..localpaths import local_temp_dir, path_problem, walk_local

from ..result import (Hit, ModuleResult, EV_ON_DISK, EV_PERSISTENCE,
                      EV_CONTACTED, EV_ATTEMPTED, EV_CONFIGURED, EV_REFERENCED)

NAME = "browser"

LOCAL = os.environ.get("LOCALAPPDATA", "")
ROAMING = os.environ.get("APPDATA", "")


def _chromium_roots():
    """Chromium user-data roots as (label, path), chosen by platform.

    The label names the browser in each per-artifact sub-check, so an
    installed-but-clean browser is recorded distinctly from an absent one, and a
    locked artifact names the browser it belongs to. Tests override the roots by
    patching CHROMIUM_ROOTS / FIREFOX_ROOTS directly (not by patching LOCAL /
    ROAMING), so the suite is hermetic on every platform, never the tester's own
    browser.
    """
    home = os.path.expanduser("~")
    if sys.platform == "win32":
        return [
            ("chrome", os.path.join(LOCAL, "Google", "Chrome", "User Data")),
            ("edge", os.path.join(LOCAL, "Microsoft", "Edge", "User Data")),
            ("brave", os.path.join(LOCAL, "BraveSoftware", "Brave-Browser",
                                   "User Data")),
            ("chromium", os.path.join(LOCAL, "Chromium", "User Data")),
            ("vivaldi", os.path.join(LOCAL, "Vivaldi", "User Data")),
        ]
    if sys.platform == "darwin":
        asup = os.path.join(home, "Library", "Application Support")
        return [
            ("chrome", os.path.join(asup, "Google", "Chrome")),
            ("edge", os.path.join(asup, "Microsoft Edge")),
            ("brave", os.path.join(asup, "BraveSoftware", "Brave-Browser")),
            ("chromium", os.path.join(asup, "Chromium")),
            ("vivaldi", os.path.join(asup, "Vivaldi")),
        ]
    if sys.platform.startswith("linux"):
        cfg = os.path.join(home, ".config")
        var = os.path.join(home, ".var", "app")
        snap = os.path.join(home, "snap")
        return [
            ("chrome", os.path.join(cfg, "google-chrome")),
            ("chromium", os.path.join(cfg, "chromium")),
            ("brave", os.path.join(cfg, "BraveSoftware", "Brave-Browser")),
            ("edge", os.path.join(cfg, "microsoft-edge")),
            ("vivaldi", os.path.join(cfg, "vivaldi")),
            ("vivaldi-snapshot", os.path.join(cfg, "vivaldi-snapshot")),
            # snap packaging
            ("chromium-snap", os.path.join(snap, "chromium", "common", "chromium")),
            # flatpak packaging
            ("chrome-flatpak", os.path.join(var, "com.google.Chrome", "config",
                                            "google-chrome")),
            ("brave-flatpak", os.path.join(var, "com.brave.Browser", "config",
                                           "BraveSoftware", "Brave-Browser")),
            ("chromium-flatpak", os.path.join(var, "org.chromium.Chromium",
                                              "config", "chromium")),
            ("vivaldi-flatpak", os.path.join(var, "com.vivaldi.Vivaldi",
                                             "config", "vivaldi")),
        ]
    return []


# Computed at import so the test-suite can monkeypatch this attribute directly.
CHROMIUM_ROOTS = _chromium_roots()

# Firefox (profiles_dir, cache_dir) pairs. None means "derive from the platform
# at run() time"; tests set an explicit list so the suite never reads the real
# profile on any OS (the Windows branch of _firefox_roots used to be the only one
# the tests could neutralise, which let the suite read the tester's real Firefox
# on macOS/Linux).
FIREFOX_ROOTS = None


def _firefox_roots():
    """Firefox (profiles_dir, cache_dir) pairs by platform.

    Evaluated at run() time so the Windows pair reflects the current LOCAL /
    ROAMING globals (which the tests override to neutralise it). Returns [] on a
    platform with no known Firefox location.
    """
    home = os.path.expanduser("~")
    if sys.platform == "win32":
        return [(os.path.join(ROAMING, "Mozilla", "Firefox", "Profiles"),
                 os.path.join(LOCAL, "Mozilla", "Firefox", "Profiles"))]
    if sys.platform == "darwin":
        return [(os.path.join(home, "Library", "Application Support", "Firefox",
                              "Profiles"),
                 os.path.join(home, "Library", "Caches", "Firefox", "Profiles"))]
    if sys.platform.startswith("linux"):
        return [
            (os.path.join(home, ".mozilla", "firefox"),
             os.path.join(home, ".cache", "mozilla", "firefox")),
            # snap packaging
            (os.path.join(home, "snap", "firefox", "common", ".mozilla",
                          "firefox"),
             os.path.join(home, "snap", "firefox", "common", ".cache", "mozilla",
                          "firefox")),
            # flatpak packaging
            (os.path.join(home, ".var", "app", "org.mozilla.firefox", ".mozilla",
                          "firefox"),
             os.path.join(home, ".var", "app", "org.mozilla.firefox", ".cache",
                          "mozilla", "firefox")),
        ]
    return []


# Largest browser database we will snapshot, siblings included. Real History /
# Cookies files are tens of MB; 1 GiB leaves generous headroom.
_MAX_SNAPSHOT_BYTES = 1024 * 1024 * 1024


def copy_locked(path):
    """Copy a possibly-locked SQLite db (plus -wal/-shm/-journal) to a temp dir.

    A running browser holds a write lock on the live file, so we snapshot it and
    its write-ahead-log / journal siblings into the system temp dir and open the
    copy read-only. The caller removes the temp dir in a finally once it has the
    returned path; if the snapshot itself fails the caller never receives a path,
    so this function removes its own temp dir before re-raising (no leak).

    Returns (path_to_copy, incomplete) where `incomplete` lists the sibling
    suffixes that existed but could not be copied. A non-empty list means the
    snapshot is missing data the live database has."""
    problem = path_problem(path)
    if problem:
        raise PermissionError(13, problem, path)
    # Refuse an implausibly large database before copying anything. A profile
    # database the attacker can write could otherwise fill the temp drive - an
    # unbounded write by a tool that promises it only reads - and then exhaust
    # memory when its rows are read. Checked before mkdtemp so a refusal never
    # leaves a temp directory behind; the caller records it as a gap.
    try:
        total = os.path.getsize(path) + sum(
            os.path.getsize(path + sfx) for sfx in ("-wal", "-shm", "-journal")
            if os.path.exists(path + sfx))
    except OSError:
        total = 0   # let the copy below surface the real error
    if total > _MAX_SNAPSHOT_BYTES:
        raise OSError(27, "database is {:,} bytes, over the {:,}-byte snapshot "
                      "limit, so it was not copied".format(
                          total, _MAX_SNAPSHOT_BYTES), path)
    tmpdir = tempfile.mkdtemp(prefix="bscan_", dir=local_temp_dir())
    try:
        base = os.path.join(tmpdir, os.path.basename(path))
        shutil.copy2(path, base)
        # A failed sibling copy is NOT cosmetic. A write-ahead log holds rows
        # that are committed but not yet folded into the main file, so losing it
        # silently drops the MOST RECENT evidence - exactly the rows that matter
        # for a campaign someone is checking for right now. Report which ones
        # failed so the caller can record a gap instead of reading a short file
        # and calling it clean (D3).
        incomplete = []
        for suffix in ("-wal", "-shm", "-journal"):
            if path_problem(path + suffix):
                incomplete.append(suffix)
                continue
            if os.path.exists(path + suffix):
                try:
                    shutil.copy2(path + suffix, base + suffix)
                except OSError:
                    incomplete.append(suffix)
        return base, incomplete
    except BaseException as exc:
        # The one place that makes the temp dir is also the one place that
        # removes it when it never hands it over. A failed copy may already
        # contain cookie values, so deletion failure must reach the report.
        if not _discard_snapshot(tmpdir):
            exc.snapshot_leftover = tmpdir
        raise


def _discard_snapshot(tmpdir, con=None):
    """Close the open handle, then delete the snapshot - and check it is gone.

    These temp copies are byte-for-byte duplicates of browser databases, cookie
    VALUES included, even though the queries only read metadata. Windows refuses
    to delete a file that an open SQLite connection still holds, and
    shutil.rmtree(ignore_errors=True) swallows that refusal without a word - so
    the copies survived in %TEMP% after every scan. A tool that leaves copies of
    your cookies behind is worse than no tool, so the handle is closed first and
    the removal is verified rather than assumed. Returns True if the directory
    is gone."""
    if con is not None:
        try:
            con.close()
        except Exception:
            pass
    shutil.rmtree(tmpdir, ignore_errors=True)
    if os.path.exists(tmpdir):
        # One retry: on Windows an antivirus or indexer can hold a file open for
        # a moment after the handle closes.
        shutil.rmtree(tmpdir, ignore_errors=True)
    return not os.path.exists(tmpdir)


def _chromium_profile_names(user_data):
    """Map profile folder -> display name, from the browser's own Local State.

    Chromium calls profile folders "Default", "Profile 1", "Profile 7"..., which
    is meaningless to a person with several accounts. Local State holds the name
    they actually see in the browser, which is what makes a finding
    actionable: "the cookie is in Bubbles" rather than "the cookie is in
    Profile 1".

    Only the display name is read. The signed-in email address is in the same
    structure and is deliberately left alone - the name is enough to identify
    the account, and a report may be forwarded to other people.
    """
    out = {}
    path = os.path.join(user_data, "Local State")
    if path_problem(path):
        return out
    try:
        with io.open(path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    # RecursionError is not a ValueError. A Local State file of 200,000 nested
    # brackets - about 400 KB, writable without admin - made json.load raise it
    # before a single profile was read, and the whole browser module was lost.
    # Malformed is malformed: fall back to folder names, keep scanning.
    except (OSError, ValueError, RecursionError, MemoryError):
        return out
    profile = data.get("profile", {}) if isinstance(data, dict) else {}
    if not isinstance(profile, dict):
        return out
    cache = profile.get("info_cache", {})
    if not isinstance(cache, dict):
        return out
    for folder, info in cache.items():
        if isinstance(info, dict) and info.get("name"):
            out[folder] = str(info["name"])
    return out


# Files that mark a directory as a real Firefox profile (as opposed to a sibling
# folder like Crash Reports / Pending Pings / Profile Groups that lives in the
# same root on Linux). Any one is enough.
_FF_PROFILE_MARKERS = ("prefs.js", "places.sqlite", "cookies.sqlite",
                       "favicons.sqlite", "SiteSecurityServiceState.txt",
                       "cert9.db", "key4.db", "logins.json")


def _firefox_ini(profiles_dir):
    """Parse Firefox's profiles.ini. Returns ({folder_basename: display_name},
    {folder basenames that profiles.ini lists as profiles}).

    profiles.ini sits INSIDE profiles_dir on Linux (~/.mozilla/firefox) but one
    level ABOVE it on Windows/macOS (...\\Firefox\\Profiles). Try both, so names
    resolve on every platform; the first readable one wins.
    """
    names, known = {}, set()

    def flush(sec):
        path = sec.get("Path")
        if path:
            base = os.path.basename(path.replace("/", os.sep).rstrip(os.sep))
            known.add(base)
            if sec.get("Name"):
                names[base] = sec["Name"]

    for ini in (os.path.join(profiles_dir, "profiles.ini"),
                os.path.join(os.path.dirname(profiles_dir), "profiles.ini")):
        if path_problem(ini):
            continue
        section = {}
        try:
            with io.open(ini, encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    line = raw.strip()
                    if line.startswith("["):
                        flush(section)
                        section = {}
                    elif "=" in line:
                        key, value = line.split("=", 1)
                        section[key.strip()] = value.strip()
            flush(section)
            break
        except OSError:
            continue
    return names, known


def _is_ff_profile_dir(path):
    """True if `path` looks like a real Firefox profile (holds a marker file)."""
    for marker in _FF_PROFILE_MARKERS:
        full = os.path.join(path, marker)
        problem = path_problem(full)
        if problem:
            raise PermissionError(13, problem, full)
        try:
            os.lstat(full)
            return True
        except FileNotFoundError:
            continue
    return False


def _fmt_time(conv, raw):
    """Render an artifact timestamp, or "" if it is missing or unreadable."""
    if not raw:
        return ""
    try:
        return conv(int(raw)).isoformat(timespec="seconds")
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


# ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION: another process holds the file.
_WINDOWS_LOCK_ERRORS = (32, 33)


def _locked_note(path, exc):
    """A locked database is the most common non-error a user will see, so say
    what it means and what to do rather than printing a raw errno.

    A running browser causes this two ways: the OS refuses the snapshot with a
    sharing violation (Windows error 32 or 33), or SQLite reports "database is
    locked" when the copy is opened. Both mean the same thing to the person
    reading the report: close the browser and run again.

    Every other refusal is NOT a lock. macOS privacy protection refuses a closed
    browser's folder with EPERM, and telling that person to close a browser that
    is not open sends them in circles while the browser stays unchecked. The
    reason comes from strerror rather than str(exc), which also holds the path:
    a folder named "blocked" must not read as a locked database."""
    reason = getattr(exc, "strerror", None) or str(exc)
    leftover = getattr(exc, "snapshot_leftover", "")
    cleanup_warning = (
        " WARNING: temporary snapshot cleanup failed; a copy of browser data "
        "may remain at {}. Remove this temporary directory when its files can "
        "be released.".format(leftover) if leftover else "")
    browser_name = "the browser"
    lowered = path.lower()
    for marker, label in (("bravesoftware", "Brave"), ("vivaldi", "Vivaldi"),
                          ("google", "Chrome"), ("microsoft", "Edge"),
                          ("mozilla", "Firefox")):
        if marker in lowered:
            browser_name = label
            break
    if (getattr(exc, "winerror", None) in _WINDOWS_LOCK_ERRORS
            or "locked" in reason.lower()):
        return ("{} was running, so one of its databases was locked and could "
                "not be checked ({}). Close {} and run again to cover it."
                .format(browser_name, os.path.basename(path), browser_name)
                + cleanup_warning)
    if (isinstance(exc, PermissionError)
            or getattr(exc, "errno", None) in (errno.EPERM, errno.EACCES)):
        hint = ""
        if sys.platform == "darwin" and getattr(exc, "errno", None) == errno.EPERM:
            hint = (" macOS privacy protection can cause this. Run the scan in "
                    "the Terminal app and allow access if asked. If it is still "
                    "refused, give Terminal Full Disk Access in System Settings "
                    "> Privacy & Security, and turn that off after the scan.")
        return ("{} data could not be read ({}): {}. Its database is not "
                "reported as locked, so closing {} may not help.{}".format(
                    browser_name, os.path.basename(path), reason,
                    browser_name, hint) + cleanup_warning)
    return "could not read {}: {}".format(path, exc) + cleanup_warning


def _is_schema_drift(exc):
    """True for the benign "this browser version lacks that table/column" error,
    as opposed to real corruption or a lock. Only the former is safe to skip."""
    msg = str(exc).lower()
    return "no such table" in msg or "no such column" in msg


def _hsts_fingerprint(host):
    """Chromium stores HSTS hostnames as base64(sha256(DNS wire form)).

    The wire form is each label prefixed by its length, terminated by a zero
    byte: "a.example" -> b"\\x01a\\x07example\\x00". Hashing our indicators the
    same way lets us match an EXACT hostname without ever learning any other
    host the person visited - the file is deliberately a one-way set, and this
    respects that. It also means zero substring false positives.

    The length byte must count the BYTES that are hashed, not the str length.
    Indicator domains are ASCII (punycode) at load time, so ascii-encoding each
    label is exact; a stray non-ASCII label is idna-encoded instead, so the
    prefix and the payload always agree.
    """
    wire = b""
    for label in host.strip(".").lower().split("."):
        try:
            payload = label.encode("ascii")
        except UnicodeEncodeError:
            payload = label.encode("idna")
        wire += bytes([len(payload)]) + payload
    wire += b"\x00"
    return base64.b64encode(hashlib.sha256(wire).digest()).decode("ascii")


def _host_of(origin):
    """Host part of an origin like "https://example.org:443"."""
    s = str(origin).strip()
    try:
        # urlsplit is a lexical parser; it never resolves or opens a URL.
        parsed = urlsplit(s if "://" in s or s.startswith("//") else "//" + s)
        return (parsed.hostname or "").lower()
    except ValueError:
        return ""


def _host_matches(host, ioc_set):
    """Exact host match, or a subdomain of an indicator. Not a substring test:
    these artifacts give us a real hostname, so we can compare properly."""
    host = host.lower().strip(".")
    ind = ioc_set.lookup(host)
    if ind is not None:
        return ind
    # MOST specific wins, not first-found. The indicator set holds both parents
    # and children (powerium.net and qa-noas.powerium.net), and iteration order
    # is the file's order, so returning the first match could hand back the
    # parent while most_specific() - which callers use to pick the hit - keeps
    # the child. The two then disagree, the "is this the host?" comparison
    # fails, and a genuine contact is downgraded to a mere reference.
    best = None
    for candidate in ioc_set.indicators:
        if candidate.type == "domain" and host.endswith("." + candidate.value):
            if best is None or len(candidate.value) > len(best.value):
                best = candidate
    return best


def chromium_profiles(user_data):
    """Every Default / Guest / Profile* directory under a Chromium user-data root.

    Raises OSError if the root exists but cannot be enumerated (a bad ACL); the
    caller turns that into a gap for this one root rather than aborting the whole
    module."""
    problem = path_problem(user_data)
    if problem:
        raise PermissionError(13, problem, user_data)
    if not os.path.isdir(user_data):
        return []
    out = []
    for name in os.listdir(user_data):
        p = os.path.join(user_data, name)
        if name == "Default" or name == "Guest Profile" or name.startswith("Profile"):
            out.append(p)
    return out


def run(ctx) -> ModuleResult:
    r = ModuleResult(NAME)
    r.submetrics["sqlite"] = 0
    r.submetrics["blob"] = 0
    # Publish the result straight away so that if anything below raises,
    # the CLI can still recover whatever was found before the failure
    # instead of discarding it (see ScanContext.partial).
    ctx.partial = r

    # Matching itself lives in IocSet.search / search_bytes, so the boundary
    # rules (a domain must not match inside a longer name, an IP must not match
    # inside a longer number) exist in exactly one place for every module.

    # Modification times of every cache/LevelDB file searched, used at the end to
    # report the actual age of the oldest surviving artifact.
    seen_mtimes = []
    # Creation times of the oldest cookie in each cookie store. Cookies outlive the
    # cache by a long way, so leaving them out would understate the window.
    cookie_times = []
    # How many cookie STORES were actually read. The reach "basis" count must be
    # the number of stores, not len(cookie_times) (which is inflated by one entry
    # per matching cookie plus one per store).
    cookie_stores = [0]
    # Whether any history query actually returned rows. reach["history"] is only
    # populated when it did, so an empty result never advertises a window the
    # scan did not actually observe.
    history_rows = [False]

    # Which profile is currently being scanned, so every hit can name the
    # account it came from. Updated as the walk moves between profiles.
    current = {"name": ""}

    # --- per (browser label, artifact kind) outcome ------------------------
    #
    # Each (label, kind) records whether ANY profile could read that artifact.
    #   ok     - at least one profile read this artifact successfully (a lock in
    #            a different profile is a note, not a whole-kind gap)
    #   fail   - present but unreadable, and no profile has read it yet
    #   absent - never recorded; the browser never created it (not a gap)
    # Insertion order is preserved so the checks list is stable.
    kinds = {}

    def _touch(label, kind):
        key = (label, kind)
        if key not in kinds:
            kinds[key] = {"ok": False, "reason": "", "failures": []}
        return kinds[key]

    def mark_ok(label, kind):
        _touch(label, kind)["ok"] = True

    def mark_fail(label, kind, reason):
        # Every failure is kept, with the profile it happened in. Keeping only a
        # single flag let one readable profile mask another profile's locked
        # database: the kind was reported as a check that ran, and the scan came
        # out CLEAN with no gap at all. That is precisely the collapse of UNKNOWN
        # into CLEAN that D3 forbids, so the failures are now carried through to
        # the rollup individually.
        entry = _touch(label, kind)
        if not entry["reason"]:
            entry["reason"] = reason
        entry["failures"].append((current["name"], reason))

    def chrome_time(us):
        # Chromium stores microseconds since 1601-01-01 (the Windows epoch).
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=us)

    def unix_us_time(us):
        # Firefox stores microseconds since 1970-01-01.
        return datetime.datetime.fromtimestamp(us / 1e6)

    def record_hit(path, ind, detail, evidence=EV_REFERENCED, observed=""):
        # Attach tier/confidence/source provenance from the IOC set to every hit,
        # plus how strong the artifact makes it (see Hit.evidence).
        r.add_hit(Hit(indicator=ind.value, location=path, detail=detail,
                      tier=ind.tier, confidence=ind.confidence,
                      source=ind.source, evidence=evidence, observed=observed,
                      profile=current["name"]))

    def open_db(path, label, kind):
        """Snapshot and open a possibly-locked SQLite db read-only.

        Returns (con, tmp) on success, or None. A truly absent file (artifact not
        present for this profile) is NOT a gap and returns None silently; every
        other failure records a could-not-read for this (label, kind) - which is
        promoted to a gap only if no profile ever reads it. The db is not counted
        as checked here; that happens only once rows are actually read."""
        problem = path_problem(path)
        if problem:
            r.skipped += 1
            mark_fail(label, kind, "{}: {}".format(path, problem))
            return None
        try:
            os.stat(path)
        except FileNotFoundError:
            return None  # artifact simply absent for this profile
        except OSError as exc:
            r.skipped += 1
            note = _locked_note(path, exc)
            r.note(note)
            mark_fail(label, kind, note)
            return None
        try:
            tmp, incomplete = copy_locked(path)
        except OSError as exc:
            # A locked db we could not even snapshot is a gap, not a clean item.
            r.skipped += 1
            note = _locked_note(path, exc)
            r.note(note)
            mark_fail(label, kind, note)
            return None
        try:
            con = sqlite3.connect(tmp)
        except sqlite3.Error as exc:
            if not _discard_snapshot(os.path.dirname(tmp)):
                exc.snapshot_leftover = os.path.dirname(tmp)
            r.skipped += 1
            note = _locked_note(path, exc)
            r.note(note)
            mark_fail(label, kind, note)
            return None
        if incomplete:
            # The main file opened, but a write-ahead log or journal that the
            # live database HAS could not be copied. Whatever was committed
            # there is missing from this snapshot - and that is the newest
            # evidence, not the oldest. Reading the short file and calling it
            # clean would be a false negative, so this is a gap.
            note = ("{}: snapshot is incomplete - could not copy {} alongside "
                    "it, so recently written rows may be missing from this "
                    "read".format(os.path.basename(path), ", ".join(incomplete)))
            r.note(note)
            mark_fail(label, kind, note)
        con.text_factory = lambda b: b.decode("utf-8", "replace")
        return con, tmp

    def _count_db():
        r.submetrics["sqlite"] += 1
        r.checked += 1

    def scan_history(label, path, flavour):
        """History / moz_places, host-graded.

        A history row whose URL HOST is the indicator means the browser actually
        went there, so it grades as contacted and carries the row's own visit
        date as the observed time (when the schema records it). A match only in
        the query string or page title is a reference - often a search for the
        name - so it stays referenced. Chromium's download records live in the
        same db and stay referenced (a saved path/URL, not proof of contact)."""
        kind = "history"
        opened = open_db(path, label, kind)
        if opened is None:
            return
        con, tmp = opened
        read_ok = False
        failed = False
        try:
            if flavour == "chromium":
                table, visit_col, conv = "urls", "last_visit_time", chrome_time
            else:
                table, visit_col, conv = ("moz_places", "last_visit_date",
                                          unix_us_time)
            try:
                present = {row[1] for row in
                           con.execute("PRAGMA table_info({})".format(table))}
            except sqlite3.Error as exc:
                present = set()
                if not _is_schema_drift(exc):
                    mark_fail(label, kind, _locked_note(path, exc))
                    failed = True

            if not failed and "url" not in present:
                mark_fail(label, kind, "the history store has no supported URL "
                          "column, so navigation history could not be searched")
                failed = True
            if not failed and "url" in present:
                cols = ["url"]
                if "title" in present:
                    cols.append("title")
                if visit_col in present:
                    cols.append(visit_col)
                if flavour == "firefox" and "visit_count" in present:
                    cols.append("visit_count")
                try:
                    rows = con.execute("SELECT {} FROM {}".format(
                        ", ".join(cols), table)).fetchall()
                except sqlite3.Error as exc:
                    rows = None
                    if not _is_schema_drift(exc):
                        mark_fail(label, kind, _locked_note(path, exc))
                        failed = True
                if rows is not None:
                    read_ok = True
                    if rows:
                        history_rows[0] = True
                    for row in rows:
                        rec = dict(zip(cols, row))
                        url = str(rec.get("url") or "")
                        title = str(rec.get("title") or "")
                        blob = (url + " " + title).lower()
                        observed = _fmt_time(conv, rec.get(visit_col))
                        # Firefox's places database also stores never-visited
                        # bookmarks. A URL row alone does not establish a visit.
                        has_visit = flavour != "firefox"
                        if flavour == "firefox":
                            for raw in (rec.get(visit_col), rec.get("visit_count")):
                                try:
                                    has_visit = has_visit or int(raw or 0) > 0
                                except (TypeError, ValueError, OverflowError):
                                    pass
                        host_ind = _host_matches(_host_of(url), ctx.iocs)
                        for ind in ctx.iocs.most_specific(ctx.iocs.search(blob)):
                            if (has_visit and host_ind is not None
                                    and host_ind.value == ind.value):
                                record_hit(path, ind, "history: " + blob[:160],
                                           EV_CONTACTED, observed)
                            else:
                                record_hit(path, ind, "history: " + blob[:160],
                                           EV_REFERENCED)

            if flavour == "chromium" and not failed:
                try:
                    rows = con.execute(
                        "SELECT current_path, tab_url, referrer "
                        "FROM downloads").fetchall()
                except sqlite3.Error as exc:
                    rows = None
                    if not _is_schema_drift(exc):
                        mark_fail(label, kind, _locked_note(path, exc))
                        failed = True
                if rows is not None:
                    read_ok = True
                    for row in rows:
                        blob = " ".join(str(c) for c in row
                                        if c is not None).lower()
                        for ind in ctx.iocs.most_specific(ctx.iocs.search(blob)):
                            record_hit(path, ind, "download: " + blob[:160],
                                       EV_REFERENCED)

            if not failed:
                # Opened and queried without corruption: this artifact was read.
                mark_ok(label, kind)
                if read_ok:
                    _count_db()
        finally:
            # Close the handle BEFORE removing, or Windows keeps the copy.
            if not _discard_snapshot(os.path.dirname(tmp), con):
                r.note("could not remove the temporary snapshot of {} - a copy "
                       "may remain in the system temp directory"
                       .format(os.path.basename(path)))

    def scan_favicons(label, path, flavour):
        """Favicons. For Chromium, a favicon URL whose stored bitmap is present
        and non-empty means the browser actually fetched the icon from that host
        (contacted); a row with no image is only a reference. For Firefox the
        presence of a moz_icons entry already means the icon was fetched, so it
        grades as contacted."""
        kind = "favicons"
        opened = open_db(path, label, kind)
        if opened is None:
            return
        con, tmp = opened
        try:
            if flavour == "chromium":
                sql = ("SELECT favicons.url, "
                       "CASE WHEN favicon_bitmaps.image_data IS NOT NULL "
                       "AND length(favicon_bitmaps.image_data) > 0 "
                       "THEN 1 ELSE 0 END "
                       "FROM favicons "
                       "LEFT JOIN favicon_bitmaps "
                       "ON favicons.id = favicon_bitmaps.icon_id")
                graded = True
            else:
                sql = "SELECT icon_url FROM moz_icons"
                graded = False
            try:
                rows = con.execute(sql).fetchall()
            except sqlite3.Error as exc:
                mark_fail(label, kind, _locked_note(path, exc))
                return
            mark_ok(label, kind)
            _count_db()
            for row in rows:
                if graded:
                    url, has_bitmap = row[0], row[1]
                    ev = EV_CONTACTED if has_bitmap else EV_REFERENCED
                else:
                    url, ev = row[0], EV_CONTACTED
                blob = str(url or "").lower()
                # Anchor to the HOST, the same way history does. A stored bitmap
                # proves the browser fetched that icon - from the icon URL's own
                # host. An indicator sitting in the query string of an otherwise
                # innocent favicon URL proves contact with the innocent host, not
                # with the indicator, so it must not be graded as contact.
                host_ind = _host_matches(_host_of(blob), ctx.iocs)
                for ind in ctx.iocs.most_specific(ctx.iocs.search(blob)):
                    anchored = (host_ind is not None
                                and host_ind.value == ind.value)
                    record_hit(path, ind, "favicon: " + blob[:160],
                               ev if anchored else EV_REFERENCED)
        finally:
            # Close the handle BEFORE removing, or Windows keeps the copy.
            if not _discard_snapshot(os.path.dirname(tmp), con):
                r.note("could not remove the temporary snapshot of {} - a copy "
                       "may remain in the system temp directory"
                       .format(os.path.basename(path)))

    def scan_cookies(label, path, flavour):
        """Cookies get their own reader because they are the richest artifact
        here, and the generic row-to-string match throws away the two things a
        person actually needs: WHEN the cookie was set, and WHICH page they were
        on when it happened.

        Chromium partitions third-party cookies by top-level site, so
        `top_frame_site_key` names the site that was being visited when an ad
        tracker set its cookie. For an ad-delivered indicator that is the single
        most useful field in the whole scan - it turns "something was contacted"
        into "this happened on that site, on that date".

        The store is not counted as checked until rows are in hand: every early
        exit (unreadable schema, no usable columns, a failed SELECT) is a gap, so
        a locked cookie store - the common case, because the browser is open -
        shows up as such rather than as a clean, empty result.
        """
        kind = "cookies"
        opened = open_db(path, label, kind)
        if opened is None:
            return
        con, tmp = opened
        try:
            # Only ask for columns this database actually has. Cookie schemas
            # differ across browser versions and forks, and a single missing
            # column would otherwise fail the whole query and silently lose the
            # richest artifact in the scan.
            table = "cookies" if flavour == "chromium" else "moz_cookies"
            try:
                present = {row[1] for row in
                           con.execute("PRAGMA table_info({})".format(table))}
            except sqlite3.Error as exc:
                r.skipped += 1
                mark_fail(label, kind, _locked_note(path, exc))
                return
            if flavour == "chromium":
                candidates = ["host_key", "name", "creation_utc",
                              "last_access_utc", "top_frame_site_key"]
                conv = chrome_time
            else:
                candidates = ["host", "name", "creationTime", "lastAccessed"]
                conv = unix_us_time
            wanted = [c for c in candidates if c in present]
            host_column = "host_key" if flavour == "chromium" else "host"
            if host_column not in wanted:
                r.skipped += 1
                mark_fail(label, kind,
                          "the cookie store {} had no supported host column, "
                          "so its cookie origins could not be searched"
                          .format(os.path.basename(path)))
                return
            sql = "SELECT {} FROM {}".format(", ".join(wanted), table)
            try:
                rows = con.execute(sql).fetchall()
            except sqlite3.Error as exc:
                r.skipped += 1
                mark_fail(label, kind, _locked_note(path, exc))
                return

            # Rows are in hand: now the store genuinely counts as read.
            mark_ok(label, kind)
            _count_db()
            cookie_stores[0] += 1

            for row in rows:
                record = dict(zip(wanted, row))
                host = str(record.get("host_key") or record.get("host") or "")
                for ind in ctx.iocs.most_specific(ctx.iocs.search(host.lower())):
                    created = _fmt_time(conv, record.get("creation_utc")
                                        or record.get("creationTime"))
                    seen = _fmt_time(conv, record.get("last_access_utc")
                                     or record.get("lastAccessed"))
                    partition = str(record.get("top_frame_site_key") or "").strip()
                    bits = ["cookie set by {}".format(host),
                            "name {}".format(record.get("name") or "?")]
                    if partition:
                        bits.append("set while visiting {}".format(partition))
                    if created:
                        bits.append("first set {}".format(created))
                    if seen and seen != created:
                        bits.append("last used {}".format(seen))
                    elif seen:
                        bits.append("never used again after that")
                    record_hit(path, ind, "; ".join(bits), EV_CONTACTED,
                               created or seen)
                    if created:
                        cookie_times.append(conv(int(
                            record.get("creation_utc")
                            or record.get("creationTime"))))
            # Oldest cookie overall, for the time-coverage section.
            col = "creation_utc" if flavour == "chromium" else "creationTime"
            if col in present:
                try:
                    raw = con.execute(
                        "SELECT MIN({0}) FROM {1} WHERE {0} > 0".format(
                            col, table)).fetchone()
                    if raw and raw[0]:
                        cookie_times.append(conv(int(raw[0])))
                except (sqlite3.Error, ValueError, OverflowError, OSError):
                    pass
        finally:
            # Close the handle BEFORE removing, or Windows keeps the copy.
            if not _discard_snapshot(os.path.dirname(tmp), con):
                r.note("could not remove the temporary snapshot of {} - a copy "
                       "may remain in the system temp directory"
                       .format(os.path.basename(path)))

    def scan_blobs(label, root, evidence):
        """Substring-search binary files (HTTP cache, LevelDB) for the needles.

        Raw bytes do not distinguish origin keys from saved page content. Every
        match here is referenced, even when it looks like a complete origin URL.

        A directory that exists and can be walked is a successful check of the
        "blobs" kind, even if it holds no files (a present-but-empty cache is a
        legitimately clean cache). A subtree that could not be walked at all, or a
        file too large to hold in memory, is a gap - never dropped silently."""
        kind = "blobs"
        problem = path_problem(root)
        if problem:
            r.skipped += 1
            mark_fail(label, kind, "{}: {}".format(root, problem))
            return
        try:
            os.stat(root)
        except FileNotFoundError:
            return  # artifact absent for this profile — not a gap
        except OSError as exc:
            r.skipped += 1
            r.note(_locked_note(root, exc))
            mark_fail(label, kind, _locked_note(root, exc))
            return

        failures = []

        def onerror(exc):
            # os.walk swallows directory errors unless we catch them here.
            failures.append("could not enumerate {}: {}".format(
                getattr(exc, "filename", root), exc))
            r.skipped += 1
            r.note("could not enumerate {}: {}".format(
                getattr(exc, "filename", root), exc))

        read_any = False
        for dirpath, _dirs, files in walk_local(root, onerror=onerror):
            for fn in files:
                full = os.path.join(dirpath, fn)
                try:
                    problem = path_problem(full)
                    if problem:
                        raise PermissionError(13, problem, full)
                    st = os.stat(full)
                except OSError as exc:
                    r.skipped += 1
                    r.note("could not read {}: {}".format(full, exc))
                    failures.append("could not stat {}: {}".format(full, exc))
                    continue
                if st.st_size > 400 * 1024 * 1024:
                    r.skipped += 1  # too large to search — a gap, not clean
                    r.note("{} is larger than 400 MB and was not searched"
                           .format(full))
                    failures.append("{} exceeds the 400 MB search limit".format(full))
                    continue
                try:
                    with io.open(full, "rb") as fh:
                        data = fh.read()
                    lowered = data.lower()
                except MemoryError:
                    # read() then .lower() needs two copies; a file that will not
                    # fit is recorded as a gap, not pretended to be searched.
                    r.skipped += 1
                    failures.append("{} could not fit in memory".format(full))
                    continue
                except OSError as exc:
                    r.skipped += 1  # unreadable file — a gap, not clean
                    r.note("could not read {}: {}".format(full, exc))
                    failures.append("could not read {}: {}".format(full, exc))
                    continue
                # Oldest cache artifact = how far back this check can possibly see.
                # Browsers recycle the cache continuously, so this is a measured
                # window, not a guess, and it is usually far shorter than people
                # assume.
                seen_mtimes.append(st.st_mtime)
                r.submetrics["blob"] += 1
                r.checked += 1
                read_any = True
                for ind in ctx.iocs.search_bytes(lowered):
                    # Local Storage / Session Storage / Service Worker entries
                    # are KEYED BY ORIGIN, which is why a match there was graded
                    # as contact. But this is a raw byte search over the whole
                    # file, and these stores also hold page CONTENT - a saved
                    # article, a quoted report. An indicator inside a stored
                    # value proves someone read about this campaign, not that
                    # the device talked to it, and telling a journalist who read
                    # the Citizen Lab report that their device "demonstrably
                    # communicated with" spyware infrastructure is the worst
                    # kind of false alarm. A URL-looking string is not enough
                    # to identify a structured origin key, so retain a reference.
                    record_hit(full, ind,
                               "binary match in cache/leveldb; raw bytes do not "
                               "establish whether this is an origin or saved content",
                               EV_REFERENCED)

        if read_any or not failures:
            mark_ok(label, kind)
        if failures:
            mark_fail(label, kind,
                      "{} item(s) under {} were not searched: {}"
                      .format(len(failures), root, "; ".join(failures[:3])))

    def scan_connection_records(label, prof):
        """The two long-lived records of hosts the browser actually CONNECTED to.

        Why these matter more than the cache: the HTTP cache is recycled within
        weeks and a byte match in it may only be page content mentioning a name.
        These two files instead record that a connection happened, they survive
        far longer, and HSTS even carries the date it was observed.

        TransportSecurity - HSTS state. An entry exists because that host served
        an HSTS header over HTTPS. Hostnames are stored hashed, so we hash our
        indicators and compare; we never learn anything about other hosts.

        Network Persistent State - plaintext origins of servers the browser has
        connected to, plus hosts with broken alternative services.
        """
        net_dir = os.path.join(prof, "Network")

        ts_path = os.path.join(net_dir, "TransportSecurity")
        ts_present = True
        try:
            problem = path_problem(ts_path)
            if problem:
                raise PermissionError(13, problem, ts_path)
            os.stat(ts_path)
        except FileNotFoundError:
            ts_present = False
        except OSError as exc:
            r.skipped += 1
            mark_fail(label, "hsts", _locked_note(ts_path, exc))
            ts_present = False
        if ts_present:
            try:
                with io.open(ts_path, encoding="utf-8", errors="replace") as fh:
                    data = json.load(fh)
                if not isinstance(data, dict):
                    raise ValueError("HSTS state must be an object")
                entries = data.get("sts", [])
                # Shape-check rather than trust: a file whose "sts" is a number
                # rather than a list made len() raise TypeError, which escaped
                # the (OSError, ValueError) handler below, propagated out of the
                # module and cost every hit already collected. A malformed
                # artifact is a gap for THIS artifact, never a crash.
                if not isinstance(entries, list):
                    raise ValueError(
                        "unexpected shape: 'sts' is {}, expected a list"
                        .format(type(entries).__name__))
                r.submetrics["hsts_entries"] = (
                    r.submetrics.get("hsts_entries", 0) + len(entries))
                r.checked += len(entries)
                mark_ok(label, "hsts")
                if entries:
                    held = {}
                    for e in entries:
                        if not isinstance(e, dict) or not isinstance(e.get("host"), str):
                            raise ValueError("HSTS entry must contain a host string")
                        held[e["host"]] = e
                    for ind in ctx.iocs.indicators:
                        if ind.type != "domain":
                            continue
                        e = held.get(_hsts_fingerprint(ind.value))
                        if e is None:
                            continue
                        when = ""
                        try:
                            when = datetime.datetime.fromtimestamp(
                                float(e.get("sts_observed"))).isoformat(
                                    timespec="seconds")
                        except (TypeError, ValueError, OverflowError, OSError):
                            pass
                        record_hit(
                            ts_path, ind,
                            "HSTS state recorded for this exact host - the "
                            "browser received an HSTS header from it over HTTPS"
                            + (" (observed {})".format(when[:10]) if when else ""),
                            EV_CONTACTED, when)
            except (OSError, ValueError, RecursionError, MemoryError) as exc:
                r.skipped += 1
                mark_fail(label, "hsts", _locked_note(ts_path, exc))

        nps_path = os.path.join(net_dir, "Network Persistent State")
        nps_present = True
        try:
            problem = path_problem(nps_path)
            if problem:
                raise PermissionError(13, problem, nps_path)
            os.stat(nps_path)
        except FileNotFoundError:
            nps_present = False
        except OSError as exc:
            r.skipped += 1
            mark_fail(label, "connection-records", _locked_note(nps_path, exc))
            nps_present = False
        if nps_present:
            try:
                with io.open(nps_path, encoding="utf-8", errors="replace") as fh:
                    data = json.load(fh)
                if not isinstance(data, dict):
                    raise ValueError("network state must be an object")
                net = data.get("net", {})
                if not isinstance(net, dict):
                    raise ValueError("network state 'net' must be an object")
                hsp = net.get("http_server_properties", {})
                if not isinstance(hsp, dict):
                    raise ValueError("http_server_properties must be an object")
                for field, host_field in (("servers", "server"),
                                          ("broken_alternative_services", "host")):
                    entries = hsp.get(field, [])
                    if not isinstance(entries, list):
                        raise ValueError("{} must be a list".format(field))
                    for row in entries:
                        if not isinstance(row, dict) or not isinstance(
                                row.get(host_field), str):
                            raise ValueError("{} contains an invalid host record"
                                             .format(field))
                origins = []
                for row in hsp.get("servers") or []:
                    if isinstance(row, dict) and row.get("server"):
                        origins.append((_host_of(row["server"]), "connected server"))
                for row in hsp.get("broken_alternative_services") or []:
                    if isinstance(row, dict) and row.get("host"):
                        origins.append((_host_of(row["host"]),
                                        "broken alternative service"))
                r.submetrics["connection_records"] = (
                    r.submetrics.get("connection_records", 0) + len(origins))
                r.checked += len(origins)
                mark_ok(label, "connection-records")
                for host, kind in origins:
                    ind = _host_matches(host, ctx.iocs)
                    if ind is not None:
                        record_hit(
                            nps_path, ind,
                            "{}: the browser has a connection record for {}"
                            .format(kind, host), EV_CONTACTED)
            except (OSError, ValueError, RecursionError, MemoryError) as exc:
                r.skipped += 1
                mark_fail(label, "connection-records",
                          _locked_note(nps_path, exc))

    def scan_firefox_hsts(label, path):
        """Firefox's HSTS store, SiteSecurityServiceState.txt.

        Like Chromium's TransportSecurity, every hostname here is one the browser
        connected to over HTTPS and received an HSTS header from, so a match is
        proof of contact. Unlike Chromium's, Firefox keeps the hostnames in
        PLAINTEXT, so we read the file as text and run the shared matcher over it;
        only our indicators are searched for, so no other host from the file ever
        reaches the output.
        """
        try:
            problem = path_problem(path)
            if problem:
                raise PermissionError(13, problem, path)
            os.stat(path)
        except FileNotFoundError:
            return
        except OSError as exc:
            r.skipped += 1
            mark_fail(label, "hsts", _locked_note(path, exc))
            return
        try:
            with io.open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            r.skipped += 1
            mark_fail(label, "hsts", _locked_note(path, exc))
            return
        entries = text.count(":HSTS")
        r.submetrics["hsts_entries"] = (
            r.submetrics.get("hsts_entries", 0) + entries)
        r.checked += entries
        mark_ok(label, "hsts")
        for ind in ctx.iocs.search(text.lower()):
            record_hit(
                path, ind,
                "Firefox HSTS state recorded for this host - the browser "
                "received an HSTS header from it over HTTPS", EV_CONTACTED)

    # No browser profile location is known for this platform at all: say so as a
    # gap rather than returning an empty, falsely-clean result.
    ff_roots = FIREFOX_ROOTS if FIREFOX_ROOTS is not None else _firefox_roots()
    if not CHROMIUM_ROOTS and not ff_roots:
        r.could_not_run("browser", "no browser profile locations are known for "
                        "{}".format(sys.platform))
        return r

    # --- Chromium family: Chrome, Edge, Brave, Vivaldi, Chromium ---------------------
    for label, root in CHROMIUM_ROOTS:
        problem = path_problem(root)
        if problem:
            r.could_not_run(label + ":profiles", "{}: {}".format(root, problem))
            continue
        if not os.path.isdir(root):
            continue  # browser not installed — absent, so no sub-check for it
        try:
            profs = chromium_profiles(root)
        except OSError as exc:
            # One bad ACL on the user-data root must not abort the whole module.
            r.could_not_run(label + ":profiles", _locked_note(root, exc))
            continue
        names = _chromium_profile_names(root)
        ctx.emit("[*] {} ({} profile(s))".format(root, len(profs)))
        for prof in profs:
            problem = path_problem(prof)
            if problem:
                r.could_not_run(label + ":profile:" + os.path.basename(prof), problem)
                continue
            if not os.path.isdir(prof):
                continue
            folder = os.path.basename(prof)
            display = names.get(folder, "")
            # Name the account in the hit, falling back to the folder when the
            # browser has no display name recorded for it.
            current["name"] = ("{} ({})".format(display, folder) if display
                               else folder)
            ctx.emit("[*]   profile: {}".format(current["name"]))
            scan_history(label, os.path.join(prof, "History"), "chromium")
            scan_cookies(label, os.path.join(prof, "Network", "Cookies"),
                         "chromium")
            scan_cookies(label, os.path.join(prof, "Cookies"), "chromium")
            scan_favicons(label, os.path.join(prof, "Favicons"), "chromium")
            scan_connection_records(label, prof)
            for sub, evidence in (
                    (("Cache", "Cache_Data"), EV_REFERENCED),
                    (("Code Cache", "js"), EV_REFERENCED),
                    (("Local Storage", "leveldb"), EV_CONTACTED),
                    (("Session Storage",), EV_CONTACTED),
                    (("Service Worker", "CacheStorage"), EV_CONTACTED)):
                scan_blobs(label, os.path.join(prof, *sub), evidence)

    # --- Firefox: roaming profiles for the dbs, local cache for the cache ---
    # A stray cross-profile hit must never be stamped with the last Chrome
    # profile, so reset attribution before the Firefox walk and keep it
    # per-profile inside the loop (the cache lives in a sibling tree whose
    # profile folders share the same names - the old code swept it ONCE, outside
    # the loop, stamping every Firefox cache hit with the last Chrome profile).
    current["name"] = ""
    for profiles_dir, cache_dir in ff_roots:
        refused = [(p, path_problem(p)) for p in (profiles_dir, cache_dir)]
        if any(reason for _p, reason in refused):
            for p, reason in refused:
                if reason:
                    r.could_not_run("firefox:profiles:" + p, reason)
            continue
        prof_is_dir = os.path.isdir(profiles_dir)
        cache_is_dir = os.path.isdir(cache_dir)
        if not prof_is_dir and not cache_is_dir:
            continue
        ff_names, ff_known = _firefox_ini(profiles_dir) if prof_is_dir else ({}, set())
        ctx.emit("[*] {}".format(profiles_dir if prof_is_dir else cache_dir))

        folders = set()
        if prof_is_dir:
            try:
                folders.update(os.listdir(profiles_dir))
            except OSError as exc:
                r.could_not_run("firefox:profiles",
                                _locked_note(profiles_dir, exc))
        if cache_is_dir:
            try:
                folders.update(os.listdir(cache_dir))
            except OSError as exc:
                r.could_not_run("firefox:cache-dir", _locked_note(cache_dir, exc))

        for name in sorted(folders):
            prof = os.path.join(profiles_dir, name)
            cprof = os.path.join(cache_dir, name)
            refused = [(p, path_problem(p)) for p in (prof, cprof)]
            if any(reason for _p, reason in refused):
                for p, reason in refused:
                    if reason:
                        r.could_not_run("firefox:profile:" + p, reason)
                continue
            if not os.path.isdir(prof) and not os.path.isdir(cprof):
                continue
            # On Linux the profiles root also holds non-profile folders (Crash
            # Reports, Pending Pings, Profile Groups). Only treat a folder as a
            # profile if profiles.ini lists it or it holds a profile marker file,
            # so those are not scanned and mislabelled as profiles.
            if name not in ff_known:
                try:
                    if not _is_ff_profile_dir(prof):
                        continue
                except OSError as exc:
                    r.could_not_run("firefox:profile:" + name, str(exc))
                    continue
            display = ff_names.get(name, "")
            current["name"] = ("{} ({})".format(display, name) if display
                               else name)
            ctx.emit("[*]   profile: {}".format(current["name"]))
            if os.path.isdir(prof):
                scan_history("firefox", os.path.join(prof, "places.sqlite"),
                             "firefox")
                scan_cookies("firefox", os.path.join(prof, "cookies.sqlite"),
                             "firefox")
                scan_favicons("firefox", os.path.join(prof, "favicons.sqlite"),
                              "firefox")
                scan_firefox_hsts(
                    "firefox",
                    os.path.join(prof, "SiteSecurityServiceState.txt"))
            if os.path.isdir(cprof):
                scan_blobs("firefox", cprof, EV_REFERENCED)

    # Nothing written after this point should inherit a stale profile name.
    current["name"] = ""

    # --- roll each (browser, kind) up into a check the verdict can read -----
    #
    # A kind that at least one profile read is a check that ran (and, with no hit,
    # is clean). A kind that was present but could never be read is a check that
    # could_not_run, which the verdict surfaces as a gap - never folded into a
    # clean result.
    for (label, kind), state in kinds.items():
        check_name = "{}:{}".format(label, kind)
        if state["ok"]:
            r.ran(check_name)
            # A profile that could not be read is still a gap when a DIFFERENT
            # profile of the same browser read fine: the unread profile was
            # never searched, so nothing has been cleared for it. Previously the
            # successful profile set a single flag and these vanished, so a
            # locked second profile came out CLEAN with no gap - the collapse of
            # UNKNOWN into CLEAN that D3 exists to prevent. Each is named with
            # its account so the report can say WHICH one was not covered.
            for profile_name, reason in state["failures"]:
                r.could_not_run(
                    "{} [{}]".format(check_name, profile_name or "profile"),
                    reason)
        else:
            # Nothing anywhere read this kind: the kind itself is the gap.
            r.could_not_run(check_name, state["reason"] or "could not be read")

    # Report the measured window. Without this, "browser: CLEAN" invites the reader
    # to assume it means "clean for as long as I have owned this computer", which is
    # never true — and for a campaign that ran in 2024-2025, the gap between the two
    # readings is the whole answer.
    if seen_mtimes:
        earliest = min(seen_mtimes)
        # The oldest surviving file is survivorship, not coverage: ONE artifact
        # from 2023 does not mean a usable record of 2023. So report the
        # distribution by year as well, and let the report say how much evidence
        # actually falls inside the period being asked about.
        by_year = {}
        for m in seen_mtimes:
            y = datetime.datetime.fromtimestamp(m).year
            by_year[y] = by_year.get(y, 0) + 1
        r.reach["cache"] = {
            "earliest": datetime.datetime.fromtimestamp(earliest).isoformat(
                timespec="seconds"),
            "days": max(0, (datetime.datetime.now()
                            - datetime.datetime.fromtimestamp(earliest)).days),
            "basis": "oldest of {:,} cache/LevelDB/Service-Worker files "
                     "searched".format(len(seen_mtimes)),
            "note": "The HTTP cache is recycled within weeks, but Local Storage, "
                    "LevelDB and Service Worker files can persist for years - "
                    "which is why this date is often much older than the cache "
                    "alone. It is the oldest SURVIVOR, not proof of a continuous "
                    "record since then.",
            "by_year": by_year,
        }
    if cookie_times:
        oldest = min(cookie_times)
        r.reach["cookies"] = {
            "earliest": oldest.isoformat(timespec="seconds"),
            "days": max(0, (datetime.datetime.now() - oldest).days),
            "basis": "oldest surviving cookie across {} cookie store(s)".format(
                cookie_stores[0]),
            "note": "Cookies are the strongest evidence the browser keeps: one "
                    "exists only if the browser actually got a response from that "
                    "site. But this is the oldest SURVIVOR, not a full record back "
                    "to that date. Cookies expire (Chrome caps them at 400 days) "
                    "or get cleared, so most cookies from that time are gone.",
        }
    if history_rows[0]:
        r.reach["history"] = {
            "earliest": None,
            "days": None,
            "basis": "browser history was searched, but records only top-level "
                     "navigations",
            "note": "History reaches back further than the cache but CANNOT record "
                    "an ad: ads load as a sub-resource inside a page, and only the "
                    "page itself is recorded. The long record cannot see ads; the "
                    "record that sees ads is not long.",
        }
    return r
