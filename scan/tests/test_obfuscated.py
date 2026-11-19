"""The opt-in --obfuscated check: disguised indicators and hidden code.

Every benign case here is one the rules actually hit on a real machine before
they were tightened; each must stay silent. Hermetic: fixtures live in temp
folders and every root the module would otherwise discover is overridden, so
the tester's own browser and home folder are never read.
"""

from __future__ import annotations

import base64
import contextlib
import datetime
import importlib.util
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adint_scan import cli, iocs as iocmod, report                  # noqa: E402
from adint_scan.context import ScanContext                          # noqa: E402
from adint_scan.modules import browser, hashscan, host, obfuscated  # noqa: E402
from adint_scan.netguard import no_network                          # noqa: E402
from adint_scan.result import (EV_ENCODED, EV_HIDDEN_CODE,          # noqa: E402
                               ModuleResult)

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NOT = bytes(255 - b for b in range(256))

FEED = ("# as-of: 2026-11-19\n"
        "controlium.net\tdelivery\tprimary\ttest\n"
        "52.174.65.77\tcc\tprimary\ttest\n"
        # A palindrome: its reversed spelling IS its forward spelling.
        "abc.cba\tcc\tprimary\ttest\n"
        # Each is the other reversed: a plain mention of one is not the other
        # in disguise.
        "11.22.33.44\tcc\tprimary\ttest\n"
        "44.33.22.11\tcc\tprimary\ttest\n")


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="obf_")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        feed = os.path.join(self.tmp, "iocs.txt")
        with io.open(feed, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(FEED)
        self.iocs = iocmod.load(feed)
        self.ud = os.path.join(self.tmp, "User Data")
        self.prof = os.path.join(self.ud, "Default")
        self.cache = os.path.join(self.prof, "Cache", "Cache_Data")
        self.ext = os.path.join(self.prof, "Extensions", "abcdef", "1.0_0")
        self.home = os.path.join(self.tmp, "Downloads")
        for d in (self.cache, self.ext, self.home):
            os.makedirs(d)
        for name, value in (("OBF_CHROMIUM_ROOTS", [("test", self.ud)]),
                            ("OBF_FIREFOX_ROOTS", []),
                            ("OBF_USER_ROOTS", [self.home])):
            p = patch.object(obfuscated, name, value)
            p.start()
            self.addCleanup(p.stop)

    def put(self, folder, name, data):
        os.makedirs(os.path.join(folder, os.path.dirname(name)) or folder,
                    exist_ok=True)
        path = os.path.join(folder, name)
        with io.open(path, "wb") as fh:
            fh.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        return path

    def run_module(self):
        ctx = ScanContext(iocs=self.iocs, emit=lambda _m: None, obfuscated=True)
        with no_network() as guard:
            r = obfuscated.run(ctx)
        self.assertEqual(guard.attempts, [])
        return r

    def found(self, r, evidence=EV_ENCODED):
        return sorted((h.indicator, h.detail.split(" at byte")[0])
                      for h in r.hits if h.evidence == evidence)


class TestDisguisedIndicators(Fixture):
    def test_every_form_is_found(self):
        cases = {
            "reversed": (b"x=\"ten.muilortnoc\";", "written backwards"),
            "reverse-dns": (b"bundle net.controlium.helper\n", "reverse-DNS"),
            "not": (b"\x00" + b"controlium.net".translate(NOT) + b"\x00",
                    "bit-inverted (bitwise NOT"),
            "reversed-not": (b"\x00" + b"ten.muilortnoc".translate(NOT) + b"\x00",
                             "written backwards and bit-inverted"),
            "reversed-ip": (b"ip 77.56.471.25 here", "written backwards"),
        }
        for label, (data, words) in cases.items():
            with self.subTest(form=label):
                path = self.put(self.cache, "f_" + label, data)
                r = self.run_module()
                os.remove(path)
                hits = [h for h in r.hits if h.evidence == EV_ENCODED]
                self.assertEqual(len(hits), 1, [h.detail for h in hits])
                self.assertIn(words, hits[0].detail)
                self.assertEqual(hits[0].location, path)
                self.assertIn("does not show that this device contacted",
                              hits[0].detail)

    def test_the_documented_yipphb_spelling_is_found_in_a_script(self):
        # YIPPHB kept its URL reversed; the same shape with an indicator host.
        self.put(self.home, "loader.js", 'u="xyz/ten.muilortnoc//:sptth"')
        r = self.run_module()
        self.assertIn(("controlium.net", "this indicator is stored written backwards"),
                      self.found(r))
        self.assertIn("hidden-code:reversed-url", [h.indicator for h in r.hits])

    def test_reversed_subdomain_is_its_parent_indicator(self):
        self.put(self.cache, "f_1", b"ten.muilortnoc.saon")
        self.assertEqual([i for i, _d in self.found(self.run_module())],
                         ["controlium.net"])

    def test_reversed_ip_inside_a_longer_number_does_not_match(self):
        for text in (b"77.56.471.251", b"177.56.471.25", b"9.77.56.471.25",
                     b"77.56.471.25.9"):
            with self.subTest(text=text):
                path = self.put(self.cache, "f_ip", b" " + text + b" ")
                self.assertEqual(self.found(self.run_module()), [])
                os.remove(path)

    def test_longer_hostname_does_not_match(self):
        for text in (b"ten.muilortnocton", b"krowten.muilortnoc",
                     b"ten.muilortnoc-efas", b"_ten.muilortnoc"):
            with self.subTest(text=text):
                path = self.put(self.cache, "f_host", b" " + text + b" ")
                self.assertEqual(self.found(self.run_module()), [])
                os.remove(path)

    def test_forward_spelling_is_left_to_the_ordinary_checks(self):
        self.put(self.cache, "f_fwd", b"https://controlium.net/ 52.174.65.77")
        self.assertEqual(self.found(self.run_module()), [])

    def test_palindromes_and_mutual_reversals_are_not_disguise(self):
        self.put(self.cache, "f_pal", b"abc.cba and 44.33.22.11 and 11.22.33.44")
        self.assertEqual(self.found(self.run_module()), [])
        forms = obfuscated._obf_allowed_forms(self.iocs.indicators)
        self.assertNotIn("reversed", forms["abc.cba"])
        self.assertNotIn("reversed-not", forms["abc.cba"])
        self.assertIn("reverse-dns", forms["abc.cba"])   # cba.abc differs
        self.assertNotIn("reversed", forms["11.22.33.44"])
        self.assertNotIn("reverse-dns", forms["52.174.65.77"])

    def test_one_hit_per_indicator_and_form_per_file(self):
        self.put(self.cache, "f_many", b"ten.muilortnoc " * 50)
        self.assertEqual(len(self.found(self.run_module())), 1)


class TestHiddenCode(Fixture):
    def rules(self, name, text, folder=None):
        self.put(folder or self.ext, name, text)
        return sorted(h.indicator for h in self.run_module().hits
                      if h.evidence == EV_HIDDEN_CODE)

    def test_trojan_source_raw_override_is_found(self):
        # The "commenting-out" example from the Trojan Source paper.
        line = "/*\u202e } if (isAdmin) \u2066 begin admins only */\n"
        self.assertEqual(self.rules("a.js", "var x = 1;\n" + line),
                         ["hidden-code:bidi-control"])

    def test_escaped_override_text_is_not_a_hit(self):
        self.assertEqual(self.rules("a.js", 'var rlo = "\\u202e"; /\\u202E/.test(s)'), [])

    def test_katex_range_is_silent(self):
        # Minified KaTeX: a raw U+202A as the end of a regex range.
        src = ('Oa="("+qa+"+)|\\\\\\\\(\\n|[ \\r\\t]+\\n?)[ \\r\\t]*|'
               '([!-\\\\[\\\\]-\u2027\u202a-\ud7ff\uf900-\uffff]"+Ra+"*|"')
        self.assertEqual(self.rules("katex-BuEtkClJ.js", src), [])

    def test_text_direction_detector_is_silent(self):
        src = ('const n=(t?VY:UY)().exec(e)?.[0];return"\u200e"===n?"ltr":'
               '"\u200f"===n||"\u061c"===n?"rtl":void 0')
        self.assertEqual(self.rules("sidepanel-C79rwKTq.js", src), [])

    def test_arabic_locale_strings_are_silent(self):
        rlo = '{"algorithm": {"message": "\u202e\u0627\u0644\u062e\u0648"}}'
        self.assertEqual(self.rules(os.path.join("_locales", "ar", "messages.json"),
                                    rlo), [])
        wallet = os.path.join(self.home, "Microsoft Edge", "Edge Wallet", "1.0",
                              "json", "i18n-ec", "ar")
        self.assertEqual(self.rules("strings.json",
                                    '{"walletOther": "\u063a\u064a\u0631\u202c"}',
                                    folder=wallet), [])
        self.assertEqual(self.rules(os.path.join("i18n", "en-XB.json"),
                                    '{"value": "\u202e"}'), [])

    def test_same_open_override_outside_a_locale_folder_is_found(self):
        self.assertEqual(self.rules("ui.json", '{"message": "\u202e\u0627\u0644"}'),
                         ["hidden-code:bidi-control"])

    def test_balanced_isolates_in_code_are_silent(self):
        self.assertEqual(self.rules("strings.js",
                                    'm="\u2068\u0644\u062a\u063a\u2069";'), [])

    def test_invisible_runs_are_found(self):
        glassworm = "".join(chr(0xE0100 + i) for i in range(40))
        cases = {"variation-selectors": "eval(d('" + glassworm + "'))",
                 "zero-width": "x\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c=1",
                 "hangul-filler": "var \u3164" + "\u3164" * 8 + "=1",
                 "mid-file-bom": "a" + "\ufeff" * 8,
                 "tags": "s='\U000e0041\U000e0042\U000e0043'"}
        for label, src in cases.items():
            with self.subTest(case=label):
                path = self.put(self.home, "x.js", src)
                hits = [h.indicator for h in self.run_module().hits]
                os.remove(path)
                self.assertEqual(hits, ["hidden-code:invisible-run"])

    def test_emoji_presentation_and_flags_are_silent(self):
        england = "\U0001f3f4\U000e0067\U000e0062\U000e0065\U000e006e\U000e0067\U000e007f"
        src = ("\ufeff" + 'a="\u2764\ufe0f"; b="\U0001f468\u200d\U0001f469";'
               ' c="' + england + '"; d="\u2764\ufe0f\u200d\U0001f525";')
        self.assertEqual(self.rules("emoji.js", src), [])

    def test_reversed_url_is_found(self):
        self.assertEqual(self.rules("a.sh", 'u="moc.elpmaxe//:sptth"'),
                         ["hidden-code:reversed-url"])

    def test_reversed_base64_literal_is_found(self):
        forward = base64.b64encode(b"powershell -enc payload-for-a-test 12").decode()
        self.assertTrue(forward.endswith("="))
        self.assertEqual(self.rules("a.js", "var p = '" + forward[::-1] + "';"),
                         ["hidden-code:reversed-base64"])

    def test_minified_assignments_are_not_reversed_base64(self):
        src = ("r%=0x7fffffffffffffffffffffffffffffffffffffffffff;"
               "l[c]=attributeValueWithoutPrefixAndSomeMoreWordsHere1;"
               'if("undefined"==typeofSomeVeryLongIdentifierNameGoesHere2x+"")')
        self.assertEqual(self.rules("min.js", src), [])

    def test_hidden_code_needs_a_code_file(self):
        self.put(self.ext, "notes.txt", "u='moc.elpmaxe//:sptth'")
        self.put(self.cache, "f_0", b"u='moc.elpmaxe//:sptth'")
        self.assertEqual(self.found(self.run_module(), EV_HIDDEN_CODE), [])


    def test_this_check_and_its_tests_are_plain_ascii(self):
        # The rules name these characters by escape; a raw copy in the source
        # would be the very thing a reviewer cannot see.
        for path in (obfuscated.__file__, os.path.abspath(__file__)):
            with io.open(path, "rb") as fh:
                self.assertTrue(all(b < 0x80 for b in fh.read()), path)


class TestGaps(Fixture):
    def test_oversized_file_is_a_gap_not_clean(self):
        self.put(self.cache, "big", b"x" * 64)
        with patch.object(obfuscated, "_OBF_MAX_BYTES", 16):
            r = self.run_module()
        gaps = [c for c in r.checks if not c.ran]
        self.assertTrue(any("Cache_Data" in c.name for c in gaps), r.checks)
        self.assertEqual(r.skipped, 1)
        self.assertNotEqual(r.status, "CLEAN")

    @unittest.skipIf(sys.platform == "win32" or getattr(os, "geteuid", lambda: 1)() == 0,
                     "needs POSIX permissions and a non-root tester")
    def test_unreadable_file_is_a_gap(self):
        self.put(self.home, "ok.js", "var a = 1;")
        bad = self.put(self.home, "locked.js", "var b = 2;")
        os.chmod(bad, 0)
        self.addCleanup(os.chmod, bad, 0o600)
        r = self.run_module()
        self.assertTrue(any(not c.ran and "(partial)" in c.name
                            and "not searched" in c.reason for c in r.checks),
                        r.checks)
        self.assertEqual(r.status, "PARTIAL")

    def test_absent_browser_is_not_a_gap(self):
        shutil.rmtree(self.ud)
        r = self.run_module()
        self.assertEqual(r.status, "CLEAN")

    def test_no_cookie_or_login_database_is_opened(self):
        for db in ("Cookies", "Login Data", "History", "Web Data"):
            self.put(self.prof, db, b"ten.muilortnoc")
        opened = []
        real = io.open

        def spy(path, *a, **k):
            opened.append(os.path.basename(str(path)))
            return real(path, *a, **k)

        with patch.object(obfuscated.io, "open", spy):
            r = self.run_module()
        self.assertEqual(r.hits, [])
        self.assertFalse(set(opened) & {"Cookies", "Login Data", "History",
                                        "Web Data"})


class TestReport(Fixture):
    def test_report_says_investigate_not_contact(self):
        self.put(self.cache, "f_1", b"ten.muilortnoc")
        self.put(self.ext, "a.js", "u='moc.elpmaxe//:sptth'")
        r = self.run_module()
        doc = report.build_document(self.iocs, [r], datetime.datetime.now())
        text = " ".join(report.render_human(doc).split())
        self.assertIn("AN INDICATOR IS STORED DISGUISED IN A FILE", text)
        self.assertIn("A SCRIPT CONTAINS HIDDEN OR DISGUISED CODE", text)
        self.assertIn("does not show that this device contacted", text)
        self.assertIn("not a trace of this campaign", text)
        self.assertIn("controlium[.]net", text)
        self.assertNotIn("controlium.net", text)
        self.assertNotIn("A KNOWN SPYWARE FILE", text)
        self.assertNotIn("THIS DEVICE CONTACTED", text)
        self.assertEqual(doc["verdict"]["status"], report.V_HITS)


class TestOptIn(unittest.TestCase):
    """Off by default in both entry points; on with --obfuscated."""

    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.mkdtemp(prefix="obf_bundle_")
        out = os.path.join(cls.build, "candidate.py")
        subprocess.run([sys.executable, "-B", os.path.join(ROOT, "build", "bundle.py"),
                        ROOT, out], check=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
        spec = importlib.util.spec_from_file_location("_obf_bundle", out)
        cls.bundle = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.bundle
        spec.loader.exec_module(cls.bundle)

    @classmethod
    def tearDownClass(cls):
        sys.modules.pop("_obf_bundle", None)
        shutil.rmtree(cls.build, True)

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="obf_cli_")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.feed = os.path.join(self.tmp, "iocs.txt")
        with io.open(self.feed, "w", encoding="utf-8") as fh:
            fh.write(FEED)

    def run_cli(self, bundled, extra, obf_run):
        target = self.bundle if bundled else cli
        documents = []

        def empty(name):
            def run(ctx):
                result = target.ModuleResult(name)
                result.ran("fixture")
                return result
            return run

        with contextlib.ExitStack() as stack:
            if bundled:
                for name in ("browser", "hash", "host"):
                    stack.enter_context(patch.object(target, "run_" + name, empty(name)))
                stack.enter_context(patch.object(target, "run_obfuscated", obf_run))
            else:
                for mod in (browser, hashscan, host):
                    stack.enter_context(patch.object(mod, "run", empty(mod.NAME)))
                stack.enter_context(patch.object(obfuscated, "run", obf_run))
            stack.enter_context(patch.object(target, "_force_utf8_io", lambda: None))
            stack.enter_context(patch.object(target, "render_human",
                                             lambda d: documents.append(d) or ""))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            args = ["--iocs", self.feed] + extra + (["--no-pause"] if bundled else [])
            code = target.main(args)
        return code, documents[0]

    def test_default_does_not_run_and_flag_does(self):
        def forbidden(ctx):
            self.fail("--obfuscated check ran without the flag")
        for bundled in (False, True):
            with self.subTest(bundled=bundled):
                code, doc = self.run_cli(bundled, [], forbidden)
                self.assertEqual(code, 0)
                self.assertNotIn("obfuscated", doc["modules"])

                def selected(ctx, _b=bundled):
                    self.assertTrue(ctx.obfuscated)
                    r = (self.bundle if _b else cli).ModuleResult("obfuscated")
                    r.ran("fixture")
                    return r
                code, doc = self.run_cli(bundled, ["--quick", "--obfuscated"], selected)
                self.assertEqual(code, 0)
                self.assertEqual(doc["modules"]["obfuscated"]["status"], "CLEAN")

    def test_single_file_build_runs_the_real_module(self):
        b = self.bundle
        cache = os.path.join(self.tmp, "User Data", "Default", "Cache", "Cache_Data")
        os.makedirs(cache)
        with io.open(os.path.join(cache, "f_1"), "wb") as fh:
            fh.write(b"ten.muilortnoc")
        with patch.object(b, "OBF_CHROMIUM_ROOTS",
                          [("test", os.path.join(self.tmp, "User Data"))]), \
                patch.object(b, "OBF_FIREFOX_ROOTS", []), \
                patch.object(b, "OBF_USER_ROOTS", []):
            code, doc = self.run_cli(True, ["--obfuscated"], b.run_obfuscated)
        self.assertEqual(code, 2)
        hits = doc["modules"]["obfuscated"]["hits"]
        self.assertEqual([(h["indicator"], h["evidence"]) for h in hits],
                         [("controlium.net", "encoded")])


if __name__ == "__main__":
    unittest.main(verbosity=2)
