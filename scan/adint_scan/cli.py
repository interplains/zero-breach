"""Command-line entry point and orchestration.

  adint-scan [--deep] [--quick] [--obfuscated] [--json <path>] [--iocs <path>]

Default behaviour (no flags): read-only tier-1 IOC match across the browser, hash
and host modules, under the no-network guard. Requires no administrator (D7).

There is no system-writing mode. An earlier tier-5 feature (--arm / --undo) was
removed: a review found its --undo path could, from a journal file any program can
write, delete every scheduled task on the machine and still report success, and
could shrink the DNS log and destroy the history it had collected. None of that is
acceptable in a tool at-risk people run, and the one thing it was for - turning on
DNS history - is a single manual command the report already prints. The code is
gone rather than merely unwired, so a reviewer reading this read-only tool finds
no write path at all.

Exit codes: 0 = no indicators found (CLEAN or with gaps); 2 = indicators matched;
1 = the scan could not be set up (bad IOC file, etc.).
"""

from __future__ import annotations

import argparse
import datetime
import os
import sys
import time
from typing import List

from . import __version__
from .context import ScanContext
from .iocs import IocError, load
from .localpaths import path_problem
from .netguard import no_network
from .report import V_HITS, build_document, render_human, write_json
from .result import ModuleResult


def _force_utf8_io() -> None:
    """Make stdout/stderr encode UTF-8 regardless of the console code page.

    On a stock Windows Python the streams default to the legacy code page (cp1252
    in much of the world). Printing a non-Latin browser-profile name or username -
    Arabic, Hebrew, Persian, Cyrillic, CJK, i.e. exactly this tool's users - then
    raises UnicodeEncodeError and the whole scan dies with a traceback instead of
    a report, and worst of all when writing the report file AFTER the work is
    done. Reconfiguring here fixes it without depending on the caller remembering
    `-X utf8`. errors='backslashreplace' guarantees output can never crash."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError):
            pass  # very old Python, or a stream that is not reconfigurable


def _default_ioc_path() -> str:
    # scan/adint_scan/cli.py -> repo root is two levels up; IOCs live in iocs/.
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(os.path.dirname(here))
    return os.path.join(repo, "iocs", "adfection_iocs.txt")


def _parse(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="adint-scan",
        description="Local, read-only check for AdFection / Candiru indicators. "
                    "A clean result is NOT a clean bill of health.")
    p.add_argument("--quick", action="store_true",
                   help="skip fingerprinting every file (roughly halves the "
                        "runtime). The skipped check is reported as a gap, not "
                        "as clean.")
    p.add_argument("--deep", action="store_true",
                   help="tier 2: full persistence sweep (noisy; most hits are "
                        "legitimate). Opens with a warning.")
    p.add_argument("--patterns", action="store_true",
                   help="experimental local Candiru file-pattern check; needs "
                        "the separately installed, pinned YARA-X dependency. "
                        "Does not inspect running memory.")
    p.add_argument("--pattern-path", action="append", default=[], metavar="PATH",
                   help="file or folder for --patterns (repeatable). Limits only "
                        "the pattern check; browser, hash and host checks keep "
                        "their usual scope.")
    p.add_argument("--obfuscated", action="store_true",
                   help="also look for indicators stored reversed or "
                        "bit-inverted, and for script files built to hide "
                        "code. Slower; a hit means investigate.")
    p.add_argument("--json", metavar="PATH",
                   help="also write the machine-readable report to PATH.")
    p.add_argument("--iocs", metavar="PATH", default=_default_ioc_path(),
                   help="indicator file (default: bundled adfection_iocs.txt).")
    p.add_argument("--version", action="version",
                   version="Zero Breach {}".format(__version__))
    args = p.parse_args(argv)
    if args.pattern_path and not args.patterns:
        p.error("--pattern-path requires --patterns")
    return args


def _run_modules(ctx: ScanContext) -> List[ModuleResult]:
    # Imported lazily so a platform-specific import error degrades to UNKNOWN
    # rather than killing the whole run.
    from .modules import browser, hashscan, host

    results: List[ModuleResult] = []
    # The entire scan runs inside the no-network guard (D2).
    with no_network():
        modules = [browser, hashscan, host]
        if ctx.patterns:
            from .modules import patternscan
            modules.append(patternscan)
        if ctx.obfuscated:
            from .modules import obfuscated
            modules.append(obfuscated)
        for mod in modules:
            # --quick drops the file-fingerprint check. It costs ~45% of the
            # whole scan (345s of 774s measured) to look for ONE published file
            # hash, and Candiru compiles a fresh build per target, so another
            # victim's file would not match it anyway. Skipping is reported as a
            # GAP, never as clean (D3) - a check that did not run has not
            # cleared anything.
            if mod is hashscan and ctx.quick:
                r = ModuleResult(hashscan.NAME)
                r.could_not_run(
                    "file-fingerprints",
                    "skipped by --quick. No file on this machine was "
                    "fingerprinted, so a known sample sitting on disk would "
                    "not have been found. Re-run without --quick to include it")
                results.append(r)
                ctx.emit("[*] skipping file fingerprints (--quick)")
                continue
            ctx.emit("[*] running check: {}".format(mod.NAME))
            started = time.time()
            ctx.partial = None
            try:
                result = mod.run(ctx)
            except Exception as exc:  # a module must never crash the whole tool
                # Keep what the module had already found. Replacing it with a
                # fresh empty result discarded real hits: one malformed artifact
                # late in the browser walk wiped out a matching cookie that had
                # already been read, and the scan reported only a gap. The error
                # is still recorded as a gap, so the reader sees both the
                # finding and the fact that the check did not finish.
                partial = ctx.partial
                if isinstance(partial, ModuleResult) and partial.name == mod.NAME:
                    result = partial
                else:
                    result = ModuleResult(mod.NAME)
                result.could_not_run(mod.NAME, "module error: {}".format(exc))
            finally:
                ctx.partial = None
            result.duration_s = time.time() - started
            ctx.emit("[*]   {} finished in {:.0f}s".format(
                mod.NAME, result.duration_s))
            results.append(result)
        if ctx.deep:
            # Tier 2 is the last item in the build order and is not written yet.
            # An advertised flag must not crash, and it must not quietly report
            # a clean sweep it never performed: the honest result is UNKNOWN.
            try:
                from .modules import deep as deepmod
            except ImportError:
                r = ModuleResult("deep")
                r.could_not_run(
                    "persistence-sweep",
                    "tier 2 (--deep) is not implemented yet — no full "
                    "persistence sweep was performed. A full persistence review "
                    "requires a separate forensic examination")
                results.append(r)
            else:
                ctx.emit("[*] running module: {}".format(deepmod.NAME))
                try:
                    results.append(deepmod.run(ctx))
                except Exception as exc:
                    r = ModuleResult(deepmod.NAME)
                    r.could_not_run(deepmod.NAME, "module error: {}".format(exc))
                    results.append(r)
    return results


def _refuse_remote(label: str, value: str) -> bool:
    """Refuse a user-typed path that is not on a local disk.

    --iocs and --json are paths people type, often copied from an instruction
    somebody else wrote ("run it against our updated list at ..."). Opening or
    creating a UNC path or a mapped network drive makes Windows itself open an
    SMB session to that host - sending this account's network credentials and,
    for --json, the complete report. The socket guard cannot see that. Every
    other path the scanner opens is already checked this way; these two were
    the gap. abspath first: path_problem refuses relative paths outright, and
    "--json report.json" is the documented usage."""
    problem = path_problem(os.path.abspath(value))
    if problem:
        print("error: {} {}: {} - use a path on a local disk".format(
            label, value, problem), file=sys.stderr)
        return True
    return False


def main(argv: List[str] = None) -> int:
    _force_utf8_io()
    args = _parse(sys.argv[1:] if argv is None else argv)

    # Checked before anything is opened, and before a 15-minute scan rather than
    # after it. The bundled default is never attacker-chosen, so only a path the
    # user supplied is checked.
    if args.iocs != _default_ioc_path() and _refuse_remote("--iocs", args.iocs):
        return 1
    if args.json and _refuse_remote("--json", args.json):
        return 1

    try:
        iocs = load(args.iocs)
    except IocError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 1

    if args.deep:
        print("WARNING (--deep): a full persistence sweep lists many legitimate\n"
              "entries. Most findings are NOT malicious. Read each one; do not\n"
              "panic at an unsigned binary in a user-writable path.\n",
              file=sys.stderr)

    ctx = ScanContext(iocs=iocs, deep=args.deep, quick=args.quick,
                      patterns=args.patterns, pattern_paths=tuple(args.pattern_path),
                      obfuscated=args.obfuscated)
    started = datetime.datetime.now()
    results = _run_modules(ctx)

    document = build_document(iocs, results, started)
    print(render_human(document))

    if args.json:
        try:
            write_json(document, args.json)
            print("\n[wrote JSON report to {}]".format(args.json), file=sys.stderr)
        except OSError as exc:
            # The human report already printed; a failed JSON write must not bury
            # it under a traceback. Report the failure and keep the verdict code.
            print("\n[could not write JSON report to {}: {}]".format(
                args.json, exc), file=sys.stderr)

    return 2 if document["verdict"]["status"] == V_HITS else 0


if __name__ == "__main__":
    raise SystemExit(main())
