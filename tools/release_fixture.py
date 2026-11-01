"""Child-process CLI fixtures for release_check.py; not a scanner feature.

Only discovery roots and OS collectors are substituted. The actual CLI,
browser/hash/host/pattern modules, evidence grading, JSON and text rendering run.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
DOMAIN = "release-fixture.invalid"
PAYLOAD = b"Harmless Zero Breach release test bytes; not malware.\n"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def snapshot(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}


def main():
    target, case, directory, scanner = sys.argv[1:]
    root = Path(directory).resolve()
    inputs, outputs, scratch = root / "inputs", root / "outputs", root / "tmp"
    for p in (inputs, outputs, scratch):
        p.mkdir(parents=True)
    # Even an accidentally unpatched discovery point sees a synthetic home.
    for key in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "SystemRoot"):
        os.environ[key] = str(inputs)
    for key in ("TMP", "TEMP", "TMPDIR"):
        os.environ[key] = str(scratch)
    import tempfile
    tempfile.tempdir = str(scratch)
    sys.path[:0] = [str(ROOT / "scan"), str(ROOT / "scan/tests")]
    if target == "bundle":
        spec = importlib.util.spec_from_file_location("release_candidate", scanner)
        cli = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cli
        spec.loader.exec_module(cli)
        browser = hashes = host = patterns = reporting = cli
    else:
        from adint_scan import cli, report as reporting
        from adint_scan.modules import browser, hashscan as hashes, host, patternscan as patterns

    profile = inputs / "Browser" / "Default"
    profile.mkdir(parents=True)
    history = profile / "History"
    with sqlite3.connect(str(history)) as con:
        con.execute("CREATE TABLE urls (url TEXT, title TEXT)")
        con.execute("INSERT INTO urls VALUES (?, ?)", ("https://example.invalid/", "ordinary"))
    if case in ("corrupt", "hit-and-gap"):
        history.write_bytes(b"not a SQLite database")
    if case in ("contact", "hit-and-gap"):
        cookie = profile / "Network" / "Cookies"
        cookie.parent.mkdir()
        with sqlite3.connect(str(cookie)) as con:
            con.execute("CREATE TABLE cookies (host_key TEXT, name TEXT, "
                        "creation_utc INTEGER, encrypted_value BLOB)")
            con.execute("INSERT INTO cookies VALUES (?, 'sid', 13300000000000000, ?)",
                        ("." + DOMAIN, b"PRIVATE_COOKIE_SENTINEL_DO_NOT_REPORT"))
    if case == "reference":
        blob = profile / "Local Storage" / "leveldb" / "000001.log"
        blob.parent.mkdir(parents=True)
        blob.write_text("saved article https://" + DOMAIN + "/research", encoding="utf-8")
    files = inputs / "Files"
    files.mkdir()
    (files / "ordinary.dll").write_bytes(PAYLOAD if case in ("hash", "quick") else b"ordinary")
    feed = inputs / "iocs.txt"
    feed.write_text("# as-of: 2026-10-19\n" + DOMAIN + "\tdelivery\tprimary\tfixture\n"
                    + DIGEST + "\tsample\tprimary\tfixture\n", encoding="utf-8")
    hosts = inputs / "System32" / "drivers" / "etc" / "hosts"
    hosts.parent.mkdir(parents=True)
    # Protective blocklist entries must never create findings.
    hosts.write_text("127.0.0.1 localhost\n0.0.0.0 " + DOMAIN + "\n", encoding="utf-8")
    registered = inputs / "Registered" / "server.dll"
    if case == "patterns-localserver":
        registered = inputs / "Registered" / "folder.exe" / "payload.bat"
    registered.parent.mkdir(parents=True)
    engine = importlib.util.find_spec("yara_x") is not None
    if case in ("patterns", "patterns-localserver") and engine:
        from test_patterns import synthetic_mstic_fixture
        registered.write_bytes(synthetic_mstic_fixture())
    else:
        registered.write_bytes(b"ordinary registered file")
    before = snapshot(inputs)
    denied_activity = []
    original_network_guard = cli.no_network

    @contextlib.contextmanager
    def checked_network_guard():
        # The scanner's socket wrappers reject calls before Python emits an
        # audit event. Observe their recorder too, including caught attempts.
        with original_network_guard() as recorder:
            try:
                yield recorder
            finally:
                denied_activity.extend(recorder.attempts)

    allowed = (root, ROOT, Path(sys.prefix).absolute(), Path(sys.prefix).resolve(),
               Path(sys.base_prefix).absolute(), Path(sys.base_prefix).resolve())

    def within(path):
        # Lexical only; no link resolution before the scanner's locality guard.
        path = os.path.normcase(os.path.abspath(os.fspath(path)))
        return any(path == os.path.normcase(str(base))
                   or path.startswith(os.path.normcase(str(base)) + os.sep) for base in allowed)

    def audit(event, args):
        if event.startswith("socket.") or event in ("subprocess.Popen", "os.system"):
            denied_activity.append(event)
            raise RuntimeError("fixture attempted external activity: " + event)
        if event in ("open", "os.listdir", "os.scandir") and args:
            path = args[0]
            if isinstance(path, (str, bytes, os.PathLike)) and not within(os.fsdecode(path)):
                denied_activity.append(event)
                raise RuntimeError("fixture attempted file access outside test/code/runtime roots")

    events = [{"Time": "2025-06-01T00:00:00", "Message": "ordinary.invalid"}]
    if case == "dns-off-retained-hit":
        events[0]["Message"] = DOMAIN
    if case.startswith("dns-cap-"):
        events = events * 50000
        if case == "dns-cap-hit":
            events[20000] = {"Time": "2025-06-01T00:00:00", "Message": DOMAIN}
        else:
            events = [{"Time": "2026-01-01T00:00:00", "Message": "ordinary.invalid"}] * 50000

    def ps_json(command, timeout=60):
        if "-ListLog " in command:
            return [{"IsEnabled": not case.startswith("dns-off-"),
                     "RecordCount": 0 if case == "dns-off-empty" else len(events) + int(case.startswith("dns-cap-"))}], ""
        if "Get-WinEvent -LogName " in command:
            require("-MaxEvents 50000" in command, "unexpected DNS read cap")
            if case == "dns-off-unreadable":
                return [], "fixture read denied"
            return events, ""
        if "Get-DnsClientCache" in command:
            return [{"Entry": DOMAIN, "Data": "0.0.0.0", "Type": 1}], ""
        if "Win32_OperatingSystem" in command:
            return [{"Boot": "2026-01-01T00:00:00"}], ""
        raise RuntimeError("unexpected OS query in fixture")

    entries = ([{"clsid": "{FIXTURE}",
                 "kind": "LocalServer32" if case == "patterns-localserver" else "InprocServer32",
                 "raw": str(registered) + (" -Embedding" if case == "patterns-localserver" else ""),
                 "view": "native"}] if case in ("patterns", "patterns-localserver") else [])
    report_path = outputs / "report.json"
    argv = ["--iocs", str(feed if case != "bad-feed" else inputs / "missing.txt"),
            "--json", str(report_path)]
    if target == "bundle":
        argv.append("--no-pause")
    if case == "quick":
        argv.append("--quick")
    if case in ("patterns", "patterns-localserver"):
        argv.append("--patterns")
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(cli, "no_network", checked_network_guard))
        for mod, name, value in (
                (browser, "CHROMIUM_ROOTS", [("fixture", str(profile.parent))]),
                (browser, "FIREFOX_ROOTS", []),
                (browser, "SAFARI_LIBRARY", ""),
                (hashes, "_roots", lambda: [str(files)]),
                (patterns, "_pattern_roots", lambda: [str(files)]),
                (host, "winreg", object()),
                (host, "_ps_json", ps_json),
                (host, "_enum_com_registrations", lambda r: (entries, [])),
                (host, "_network_drive_letters", lambda: (set(), True)),
                (host, "_user_writable_dirs", lambda: [str(inputs)]),
                (reporting, "_platform_info", lambda: {"system": "Windows", "release": "fixture"})):
            stack.enter_context(patch.object(mod, name, value))
        stack.enter_context(patch.object(host.platform, "system", return_value="Windows"))
        stdout, stderr = io.StringIO(), io.StringIO()
        # Do not let the CLI reconfigure the capture streams.
        stack.enter_context(patch.object(cli, "_force_utf8_io", lambda: None))
        sys.addaudithook(audit)
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(argv)
    text = stdout.getvalue()
    (outputs / "report.txt").write_text(text, encoding="utf-8")
    require(not denied_activity, "blocked external activity occurred: " + str(denied_activity))
    require(snapshot(inputs) == before, "scanner changed fixture inputs")
    require(not list(scratch.iterdir()), "scanner left temporary snapshot files behind")
    require("PRIVATE_COOKIE_SENTINEL_DO_NOT_REPORT" not in text, "cookie value leaked to text")
    if case == "bad-feed":
        require(code == 1 and not report_path.exists(), "invalid feed must fail setup without a report")
        result = {"exit": code, "setup_error": True}
    else:
        doc = json.loads(report_path.read_text(encoding="utf-8"))
        require("PRIVATE_COOKIE_SENTINEL_DO_NOT_REPORT" not in report_path.read_text(encoding="utf-8"),
                "cookie value leaked to JSON")
        modules, verdict = doc["modules"], doc["verdict"]
        hits = sorted((name, h["indicator"], h["evidence"])
                      for name, mod in modules.items() for h in mod["hits"])
        expected = {"contact": ("browser", DOMAIN, "contacted"),
                    "hit-and-gap": ("browser", DOMAIN, "contacted"),
                    "reference": ("browser", DOMAIN, "referenced"),
                    "hash": ("hash", DIGEST, "on-disk"),
                    "dns-cap-hit": ("host", DOMAIN, "dns-record")}
        expected["dns-off-retained-hit"] = ("host", DOMAIN, "dns-record")
        if case in ("patterns", "patterns-localserver") and engine:
            expected[case] = ("patterns", "yara:MAL_DevilsTongue_HijackDll", "file-pattern")
        require(hits == ([expected[case]] if case in expected else []),
                "wrong evidence/hits: " + str(hits))
        require(code == (2 if hits else 0), "incorrect CLI exit code")
        require(verdict["hits_total"] == len(hits), "incorrect total finding count")
        expected_verdict = ("INDICATORS_FOUND" if hits else
                            "NO_KNOWN_INDICATORS_WITH_GAPS" if case in
                            ("corrupt", "quick", "dns-cap-gap", "patterns", "patterns-localserver", "dns-off-retained-clean",
                             "dns-off-unreadable", "dns-off-empty") else "NO_KNOWN_INDICATORS")
        require(verdict["status"] == expected_verdict, "incorrect overall verdict: " + str(verdict))
        if case.startswith("dns-cap-"):
            require(any("dns-log-older-events" in g for g in verdict["gaps"]), "missing DNS cap gap")
            require(modules["host"]["submetrics"]["dns_log_events_scanned"] == 50000, "wrong DNS count")
            require('this machine holds no' not in text, 'unread history misreported as absent')
            require('reported by this scan' in text, 'reach statement is not scoped to scan')
        if case.startswith("dns-off-"):
            require(modules["host"]["submetrics"]["dns_log_enabled"] == 0, "logging state misreported")
            require(bool(verdict["gaps"]), "disabled logging coverage gap missing")
        if case.startswith("dns-off-retained-"):
            require(modules["host"]["submetrics"]["dns_log_events_scanned"] == 1, "retained event not searched")
            require("HOW TO TURN ON DNS HISTORY" in text, "future-logging instructions missing")
        if case in ("dns-off-empty", "dns-off-unreadable"):
            require(not modules["host"]["submetrics"].get("dns_log_events_scanned"), "unread log falsely searched")
        if case == "quick":
            require(modules["hash"]["status"] == "UNKNOWN", "quick scan falsely cleared file hashes")
        if case in ("corrupt", "hit-and-gap"):
            require(any("history" in g for g in verdict["gaps"]), "corrupt database gap missing")
        if case in ("contact", "hit-and-gap"):
            require(str(cookie) in text, "human report lost the full cookie file path")
        if case in ("patterns", "patterns-localserver"):
            require(modules["patterns"]["status"] == ("HITS" if engine else "UNKNOWN"),
                    "optional engine status is dishonest")
        require("HOW FAR BACK THIS SCAN COULD SEE" in text, "human report did not render")
        result = {"exit": code, "verdict": verdict["status"], "hits": hits,
                  "modules": {n: m["status"] for n, m in modules.items()},
                  "gaps": sorted(g.split(":", 1)[0] for g in verdict["gaps"])}
    (root / "result.json").write_text(json.dumps(result), encoding="utf-8")
    print("PASS {} {}: inputs unchanged, expected report/exit, no external activity".format(target, case))


if __name__ == "__main__":
    main()
