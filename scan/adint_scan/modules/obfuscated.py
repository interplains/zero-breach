"""Opt-in (--obfuscated): indicators stored in disguise, and code built to hide.

The other checks only match an indicator written forwards. Loaders that want a
C&C address to survive a string search store it in some other form: YIPPHB kept
"bdw6ufv4/moc.lruynit//:sptth" reversed, and the March 2026 plain-crypto-js /
axios npm compromise shipped its payload reversed. Part A searches the same
browser cache, storage and extension folders the browser check reads, plus the
user-writable roots the hash check walks, for every domain and IP in the set
written:

  reversed                   "ten.muilortnoc"
  dot-label reversed         "net.controlium" (reverse-DNS order, as bundle IDs
                             and Android package names carry it)
  bitwise NOT                every byte XOR 0xFF
  reversed and bitwise NOT

A page ABOUT the campaign names an indicator forwards, so a disguised copy is
more than a reference (EV_ENCODED) - but it is still not contact.

Part B looks at script and code files for constructions used to hide code,
whatever it talks to: text-direction controls left open at the end of a line
(Trojan Source, CVE-2021-42574), long runs of invisible characters (GlassWorm
and os-info-checker-es6 in 2025, Unicode-tag "ASCII smuggling", the 2021
Hangul-filler backdoor), reversed URLs, and reversed base64 string literals.
None of those is an indicator, so a hit is EV_HIDDEN_CODE: worth a look, not
contact, not infection.

Precision matters more than coverage here. Every rule below was run over a
real machine; the only hits were honest software, and each of those cases is
pinned as a regression test (tests/test_obfuscated.py).

Contract: NAME and run(ctx) -> ModuleResult. Read-only, stdlib only, no
network (D2); a token is compared against a dict and nothing is resolved.
Cookie, login and other browser databases are never opened: the browser folders
read here are the cache/storage folders and the Extensions folder only.
"""

from __future__ import annotations

import io
import os
import re
import sys

from ..result import Hit, ModuleResult, EV_ENCODED, EV_HIDDEN_CODE
from ..localpaths import path_problem, walk_local
from .browser import (CHROMIUM_BLOB_DIRS, _chromium_roots, _firefox_roots,
                      chromium_profiles)
from .hashscan import (EXTS as _obf_binary_exts, PRUNE_DIRS as _obf_prune_dirs,
                       _roots as _obf_hash_roots)

NAME = "obfuscated"

# Tests point these at temp folders so the suite never reads the tester's own
# browser or home folder. None means "the same places the browser and hash
# checks use on this platform".
OBF_CHROMIUM_ROOTS = None   # [(label, user-data dir)]
OBF_FIREFOX_ROOTS = None    # [(profiles dir, cache dir)]
OBF_USER_ROOTS = None       # [dir]

# Larger files are a gap, never silently clean. Cache entries, extension
# bundles and scripts sit far below this.
_OBF_MAX_BYTES = 32 * 1024 * 1024

# Script and code files: the only ones Part B reads as text. In the user
# roots, Part A also reads the binary types the hash check fingerprints.
_OBF_CODE_EXTS = (".js", ".mjs", ".cjs", ".ts", ".py", ".sh", ".zsh", ".ps1",
                  ".vbs", ".applescript", ".html", ".htm", ".json", ".plist",
                  ".command", ".bat", ".cmd")

# --- Part A: indicators in disguise ------------------------------------------

_OBF_FORM_TEXT = {
    "reversed": "written backwards",
    "reverse-dns": "with its dot-separated labels in reverse order "
                   "(reverse-DNS order)",
    "not": "with every byte bit-inverted (bitwise NOT / XOR 0xFF)",
    "reversed-not": "written backwards and bit-inverted (bitwise NOT)",
}

# A token is a maximal run of hostname characters. Underscore on either side
# ends the run without making a token: the stock matcher refuses a name glued
# to "_" too, and backing off to a shorter run would match inside it.
_OBF_HOST_CHARS = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-"
_OBF_NOT_TABLE = bytes(255 - b for b in range(256))


def _obf_class(chars):
    return b"[" + b"".join(re.escape(bytes([c])) for c in sorted(set(chars))) + b"]"


def _obf_token_re(chars):
    edge = _obf_class(chars + b"_")
    return re.compile(b"(?<!" + edge + b")" + _obf_class(chars) + b"{7,}(?!"
                      + edge + b")")


_OBF_ASCII_TOKEN = _obf_token_re(_OBF_HOST_CHARS)
# The same alphabet after XOR 0xFF, so NOT-encoded names are found in the same
# single pass without transforming the whole file.
_OBF_NOT_TOKEN = _obf_token_re(_OBF_HOST_CHARS.translate(_OBF_NOT_TABLE))


def _obf_dns_reverse(value):
    return ".".join(reversed(value.split(".")))


def _obf_allowed_forms(indicators):
    """{indicator value: set of forms worth reporting for it}.

    A form whose spelling is the forward spelling of any indicator (a
    palindrome, or 1.2.3.4 vs 4.3.2.1) is dropped: the ordinary checks already
    report that text, and calling it disguised would be false. Reverse-DNS is
    skipped for IPs: a reversed address is how a PTR (in-addr.arpa) name is
    written, which is ordinary DNS, not disguise."""
    forward = {i.value for i in indicators}
    out = {}
    for ind in indicators:
        v = ind.value
        spelled = {"reversed": v[::-1]}
        if ind.type == "domain":
            spelled["reverse-dns"] = _obf_dns_reverse(v)
        forms = {f for f, s in spelled.items() if s not in forward}
        forms.add("not")    # bit-inverted bytes can never spell an ASCII name
        if v[::-1] != v:
            forms.add("reversed-not")
        out[v] = forms
    return out


def _obf_candidates(name):
    """Forward-space spellings the stock matcher would accept inside `name`:
    the whole run, then each dot-suffix (a subdomain is still the indicator).
    Trailing dots are the fully-qualified spelling and are ignored."""
    name = name.rstrip(".")
    out = [] if name.startswith(".") else [(name, True)]
    i = name.find(".")
    while i != -1:
        out.append((name[i + 1:], False))
        i = name.find(".", i + 1)
    return out


def _obf_lookup(name, form, by_value, allowed):
    """The most specific indicator `name` reads as under `form`, or None. An
    IP must be the whole run: a dot or digit beside it continues the number."""
    for cand, whole in _obf_candidates(name):
        ind = by_value.get(cand)
        if (ind is not None and form in allowed[cand]
                and (whole or ind.type == "domain")):
            return ind
    return None


def _obf_find_disguised(data, by_value, allowed):
    """[(indicator, form, byte offset)] - first occurrence per pair."""
    seen = {}
    for m in _OBF_ASCII_TOKEN.finditer(data):
        tok = m.group(0)
        if b"." not in tok:
            continue    # every indicator has a dot in every form
        text = tok.decode("ascii").lower()
        for form, name in (("reversed", text[::-1]),
                           ("reverse-dns", _obf_dns_reverse(text))):
            ind = _obf_lookup(name, form, by_value, allowed)
            if ind is not None:
                seen.setdefault((ind.value, form), (ind, form, m.start()))
    for m in _OBF_NOT_TOKEN.finditer(data):
        text = m.group(0).translate(_OBF_NOT_TABLE).decode("ascii").lower()
        if "." not in text:
            continue
        for form, name in (("not", text), ("reversed-not", text[::-1])):
            ind = _obf_lookup(name, form, by_value, allowed)
            if ind is not None:
                seen.setdefault((ind.value, form), (ind, form, m.start()))
    return list(seen.values())


# --- Part B: code built to hide ------------------------------------------------

# Right-to-left translations carry direction controls legitimately.
_OBF_LOCALE_DIR = re.compile(r"^(?:_locales|locales?|l10n|i18n.*|nls)$", re.I)

_OBF_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069\u061c]")
_OBF_EMBEDS = "\u202a\u202b\u202d\u202e"     # LRE RLE LRO RLO, closed by PDF
_OBF_ISOLATES = "\u2066\u2067\u2068"         # LRI RLI FSI, closed by PDI
# Openers that can make following code display right-to-left. A left-to-right
# opener on a left-to-right line moves nothing (KaTeX's minified regex holds a
# raw U+202A as a range end), and a lone mark such as U+061C moves nothing.
_OBF_RTL_OPENERS = "\u202b\u202e\u2067\u2068"

# Invisible characters. FEFF at the very start is a byte-order mark and is
# removed before matching.
_OBF_INVISIBLE = ("\ufe00-\ufe0f\U000e0100-\U000e01ef\U000e0000-\U000e007f"
                  "\u200b-\u200d\u2060\ufeff\u3164\uffa0\u115f\u1160")
_OBF_INVISIBLE_RUN = re.compile("[" + _OBF_INVISIBLE + "]{8,}")
_OBF_TAG_RUN = re.compile("[\U000e0000-\U000e007f]{3,}")
# England, Scotland and Wales are written as a black flag plus tag letters and
# a cancel tag. That is the one honest use of tag characters.
_OBF_FLAG = re.compile("\U0001f3f4[\U000e0020-\U000e007e]{1,8}\U000e007f")

_OBF_REVERSED_URL = re.compile(r"//:s?ptth", re.I)
# Reversed base64 starts with its "=" padding. Only a whole string literal
# counts - same quote on both sides - because minified code is full of "="
# followed by a long identifier (r%=0x7fff..., l[c]=attributeValue...). The
# opening quote must not end a word or another string, and the body must not
# end in "+": that is a comparison then a concatenation,
# "undefined"==someName+"", not one literal.
_OBF_REVERSED_B64 = re.compile(
    r"""(?<![\w$"'`\\])(["'`])={1,2}([A-Za-z0-9+/]{39,}[A-Za-z0-9/])\1""")


def _obf_open_rtl(line):
    """True if a right-to-left override or isolate is still open at the end of
    the line. That is how Trojan Source reorders the code a reviewer sees."""
    stack = []
    for ch in _OBF_BIDI.findall(line):
        if ch in _OBF_EMBEDS or ch in _OBF_ISOLATES:
            stack.append(ch)
        elif ch == "\u202c":                       # PDF
            if stack and stack[-1] in _OBF_EMBEDS:
                stack.pop()
        elif ch == "\u2069":                       # PDI closes through its isolate
            while stack:
                if stack.pop() in _OBF_ISOLATES:
                    break
    return any(ch in _OBF_RTL_OPENERS for ch in stack)


def _obf_b64_like(body):
    # A 40-character identifier is all letters; base64 of real data almost
    # always mixes case and carries a digit or + /.
    return (any(c.isdigit() or c in "+/" for c in body)
            and any(c.islower() for c in body) and any(c.isupper() for c in body))


def _obf_excerpt(text, start, end):
    return text[max(0, start - 30):end + 30][:100].encode(
        "unicode_escape").decode("ascii")


def _obf_decode(data):
    if data.startswith(b"\xff\xfe"):
        text = data[2:].decode("utf-16-le", "replace")
    elif data.startswith(b"\xfe\xff"):
        text = data[2:].decode("utf-16-be", "replace")
    else:
        text = data.decode("utf-8", "replace")
    return text[1:] if text.startswith("\ufeff") else text


def _obf_hidden_code(path, data):
    """[(rule, detail)] for one script/code file, at most one per rule."""
    text = _obf_decode(data)
    out = []

    def line_of(pos):
        return text.count("\n", 0, pos) + 1

    parts = re.split(r"[\\/]", path)[:-1]
    if (_OBF_BIDI.search(text)
            and not any(_OBF_LOCALE_DIR.match(p) for p in parts)):
        bad = [n for n, line in enumerate(text.split("\n"), 1)
               if _OBF_BIDI.search(line) and _obf_open_rtl(line)]
        if bad:
            out.append(("bidi-control",
                        "a right-to-left text-direction control is left open on "
                        "line {} ({} line(s) in all), so the code shown to a "
                        "reader is not the order it runs in (Trojan Source, "
                        "CVE-2021-42574)".format(bad[0], len(bad))))

    flagless = _OBF_FLAG.sub("\U0001f3f4", text)
    m = _OBF_INVISIBLE_RUN.search(flagless)
    if m:
        out.append(("invisible-run",
                    "{} invisible characters in a row at line {} - a way to "
                    "hide code or data in plain sight (as GlassWorm did in "
                    "2025)".format(len(m.group(0)), line_of(m.start()))))
    else:
        m = _OBF_TAG_RUN.search(flagless)
        if m:
            out.append(("invisible-run",
                        "{} invisible Unicode tag characters at line {}, not "
                        "part of a flag emoji - they can carry hidden text"
                        .format(len(m.group(0)), line_of(m.start()))))

    m = _OBF_REVERSED_URL.search(text)
    if m:
        out.append(("reversed-url",
                    "a web address written backwards at line {}: {}".format(
                        line_of(m.start()),
                        _obf_excerpt(text, m.start(), m.end()))))

    for m in _OBF_REVERSED_B64.finditer(text):
        if _obf_b64_like(m.group(2)):
            out.append(("reversed-base64",
                        "a string of base64 written backwards (padding first) "
                        "at line {}".format(line_of(m.start()))))
            break
    return out


# --- walking -------------------------------------------------------------------

def _obf_targets():
    """(check name, folder, kind). kind 'browser': every file, indicators only;
    'extensions': every file, plus hidden-code on code files; 'user': code and
    binary file types only, both parts."""
    chromium = OBF_CHROMIUM_ROOTS if OBF_CHROMIUM_ROOTS is not None else _chromium_roots()
    firefox = OBF_FIREFOX_ROOTS if OBF_FIREFOX_ROOTS is not None else _firefox_roots()
    users = OBF_USER_ROOTS if OBF_USER_ROOTS is not None else [
        # A Windows root on another OS names nothing that exists here; it is not
        # a gap. (The hash check lists the same roots on every platform.)
        r for r in _obf_hash_roots()
        if sys.platform == "win32" or os.path.isabs(r)]
    out, problems = [], []
    for label, root in chromium:
        problem = path_problem(root)
        if problem:
            problems.append((label + ":profiles", "{}: {}".format(root, problem)))
            continue
        if not os.path.isdir(root):
            continue        # browser not installed
        try:
            profiles = chromium_profiles(root)
        except OSError as exc:
            problems.append((label + ":profiles", "{}: {}".format(root, exc)))
            continue
        for prof in sorted(profiles):
            folder = os.path.basename(prof)
            for sub, _evidence in CHROMIUM_BLOB_DIRS:
                out.append(("{}:{}:{}".format(label, folder, "/".join(sub)),
                            os.path.join(prof, *sub), "browser"))
            out.append(("{}:{}:Extensions".format(label, folder),
                        os.path.join(prof, "Extensions"), "extensions"))
    for _profiles, cache in firefox:
        out.append(("firefox:cache", cache, "browser"))
    for root in users:
        out.append(("root:" + root, root, "user"))
    return out, problems


def run(ctx) -> ModuleResult:
    r = ModuleResult(NAME)
    ctx.partial = r
    r.submetrics["files_obfuscation_searched"] = 0
    r.submetrics["code_files_checked"] = 0
    r.note("Opt-in check. Looks for published indicators stored reversed, in "
           "reverse-DNS order or bit-inverted, and for script files built to "
           "hide code. A disguised indicator is not proof of contact; hidden "
           "code is not a trace of this campaign. UTF-16 text and compressed "
           "files (such as Firefox .xpi add-ons) are not decoded.")

    net = [i for i in ctx.iocs.indicators if i.type in ("domain", "ip")]
    by_value = {i.value: i for i in net}
    allowed = _obf_allowed_forms(net)
    if not net:
        r.could_not_run("disguised-indicators",
                        "no domains or IP addresses in the indicator set")

    targets, problems = _obf_targets()
    for name, reason in problems:
        r.could_not_run(name, reason)

    # A file reachable from two roots (on Windows, %LOCALAPPDATA% holds the
    # browser folders) is searched once.
    done = set()

    for name, root, kind in targets:
        problem = path_problem(root)
        if problem:
            r.could_not_run(name, problem)
            continue
        if not os.path.isdir(root):
            continue        # absent: nothing to search, not a gap
        ctx.emit("[obfuscated] searching {} ...".format(root))
        tally = {"read": 0, "unreadable": 0, "examples": []}

        def _walk_err(exc, _t=tally):
            _t["unreadable"] += 1
            r.skipped += 1
            if len(_t["examples"]) < 3:
                _t["examples"].append("{}: {}".format(
                    getattr(exc, "filename", None) or root,
                    getattr(exc, "strerror", None) or exc))

        for dirpath, dirs, files in walk_local(root, onerror=_walk_err):
            if kind == "user":
                dirs[:] = [d for d in dirs if d.lower() not in _obf_prune_dirs]
            for fn in files:
                low = fn.lower()
                is_code = low.endswith(_OBF_CODE_EXTS)
                if kind == "user" and not (is_code or low.endswith(_obf_binary_exts)):
                    continue
                full = os.path.join(dirpath, fn)
                key = os.path.normcase(full)
                if key in done:
                    continue
                done.add(key)
                try:
                    problem = path_problem(full)
                    if problem:
                        raise PermissionError(13, problem, full)
                    if os.path.getsize(full) > _OBF_MAX_BYTES:
                        raise OSError(27, "larger than the 32 MB search limit", full)
                    with io.open(full, "rb") as fh:
                        data = fh.read(_OBF_MAX_BYTES + 1)
                    if len(data) > _OBF_MAX_BYTES:
                        raise OSError(27, "grew past the 32 MB search limit", full)
                except (OSError, MemoryError) as exc:
                    _walk_err(exc)
                    continue
                tally["read"] += 1
                r.checked += 1
                r.submetrics["files_obfuscation_searched"] += 1

                for ind, form, offset in _obf_find_disguised(data, by_value, allowed):
                    r.add_hit(Hit(
                        indicator=ind.value, location=full,
                        detail="this indicator is stored {} at byte {}. That is "
                               "deliberate encoding, stronger than a saved "
                               "reference, but it does not show that this "
                               "device contacted it".format(
                                   _OBF_FORM_TEXT[form], offset),
                        tier=ind.tier, confidence=ind.confidence,
                        source=ind.source, evidence=EV_ENCODED))
                    ctx.emit("[obfuscated] !! {} ({}) in {}".format(
                        ind.value, form, full))

                if is_code and kind in ("extensions", "user"):
                    r.submetrics["code_files_checked"] += 1
                    for rule, detail in _obf_hidden_code(full, data):
                        r.add_hit(Hit(
                            indicator="hidden-code:" + rule, location=full,
                            detail=detail, tier="hidden-code",
                            confidence="heuristic", evidence=EV_HIDDEN_CODE))
                        ctx.emit("[obfuscated] !! {} in {}".format(rule, full))

        if tally["read"] or not tally["unreadable"]:
            r.ran(name)
        if tally["unreadable"]:
            r.could_not_run(
                name + (" (partial)" if tally["read"] else ""),
                "{} item(s) were not searched - unreadable, over the 32 MB "
                "limit, or a link that is not followed (e.g. {})".format(
                    tally["unreadable"], "; ".join(tally["examples"])))
    return r
