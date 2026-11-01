"""Human-readable + machine-readable reporting, and the overall verdict.

Doctrine enforced here:
  D1  Every run that finds nothing prints, verbatim, the mandatory closing line.
  D3  A module that could not run is UNKNOWN, never CLEAN; gaps are stated out
      loud in the interface, not buried.
  The verdict for a hit is "investigate", never "you are compromised" — an ad
  impression is not proof of infection (README / the IOC file header).
"""

from __future__ import annotations

import datetime
import copy
import json
import platform as _platform
import re
from typing import Any, Dict, List

from . import __version__
from .iocs import IocSet
from .result import (CLEAN, HITS, PARTIAL, UNKNOWN, ModuleResult, is_serious,
                     EV_ON_DISK, EV_FILE_PATTERN, EV_PERSISTENCE, EV_CONTACTED, EV_ATTEMPTED,
                     EV_CONFIGURED, EV_REFERENCED, EV_DNS)

# The exact text required by D1. Do not reword.
D1_LINE = ("No known indicators were found in the places that can be checked. "
           "This is not a clean bill of health.")

V_HITS = "INDICATORS_FOUND"
V_NONE_WITH_GAPS = "NO_KNOWN_INDICATORS_WITH_GAPS"
V_NONE = "NO_KNOWN_INDICATORS"


def _windows_release(release: str, version: str) -> str:
    """Correct Python's release string on Windows 11.

    platform.release() reports "10" on Windows 11, because the underlying
    GetVersionEx still reports major version 10 for compatibility. Windows 11 is
    build 22000 and up, so the build number in platform.version() is what
    actually distinguishes them. This matters because the JSON report is meant to
    be evidence: a report that names the wrong OS is a report someone has to
    double-check by hand.
    """
    if release != "10":
        return release
    try:
        build = int(version.split(".")[2])
    except (IndexError, ValueError):
        return release
    return "11" if build >= 22000 else release


def _platform_info() -> Dict[str, str]:
    system = _platform.system()
    release = _platform.release()
    version = _platform.version()
    if system == "Windows":
        release = _windows_release(release, version)
    return {
        "system": system,
        "release": release,
        "version": version,
        "machine": _platform.machine(),
        "python": _platform.python_version(),
    }


def build_document(iocs: IocSet, modules: List[ModuleResult],
                   started: datetime.datetime) -> Dict[str, Any]:
    hits_total = sum(len(m.hits) for m in modules)
    gaps: List[str] = []
    for m in modules:
        for c in m.checks:
            if not c.ran:
                gaps.append("{}/{}: {}".format(m.name, c.name, c.reason))
        # A module that produced NO checks at all is UNKNOWN - it observed
        # nothing - but has no failed Check to turn into a gap, so without this it
        # is invisible to the verdict and a "nothing found" reads as clean. The
        # common cause is a browser module on a machine where no supported browser
        # is installed, or on macOS/Linux before the platform paths existed.
        if m.status == UNKNOWN and not m.checks:
            gaps.append("{}: nothing in this check could run, so it cleared "
                        "nothing".format(m.name))

    if hits_total > 0:
        status = V_HITS
    elif gaps:
        status = V_NONE_WITH_GAPS
    else:
        status = V_NONE

    age = iocs.age_days()
    return {
        "tool": {"name": "adint-scan", "version": __version__},
        "timestamp": started.replace(microsecond=0).isoformat(),
        "platform": _platform_info(),
        "ioc_set": {
            "path": iocs.source_path,
            "count": len(iocs),
            "age_days": age,
            "stale": iocs.is_stale(),
        },
        "modules": {m.name: m.to_dict() for m in modules},
        "verdict": {
            "status": status,
            "hits_total": hits_total,
            "gaps": gaps,
        },
        # D1 line is present whenever nothing was found (CLEAN or with gaps).
        "doctrine_line": None if hits_total > 0 else D1_LINE,
        # Whether a "HOW TO TURN ON DNS HISTORY" block will actually be rendered,
        # so the summary's pointer to it does not dangle on a host where no reach
        # entry carried how_to_enable (e.g. a non-Windows machine).
        "_dns_howto": any(
            info.get("how_to_enable")
            for m in modules for info in (m.reach or {}).values()),
        "_indicators": iocs.network_strings,
    }


def write_json(document: Dict[str, Any], path: str) -> None:
    # The internal rendering flag is not part of the evidence record.
    doc = {k: v for k, v in document.items() if not k.startswith("_")}
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


# --- human-readable rendering ----------------------------------------------

_RULE = "=" * 72


def _fmt_count(n: int) -> str:
    return "{:,}".format(n)


# Raw metric keys are developer shorthand. Say what each number is, in words,
# because "com_registrations=37" tells a reader nothing about whether 37 is bad.
_METRIC_LABELS = {
    "sqlite": "browser databases read",
    "blob": "cache / stored-data files searched",
    "hsts_entries": "HSTS security records checked (proof of past connections)",
    "connection_records": "saved connection records checked",
    "files_hashed": "files fingerprinted",
    "files_pattern_scanned": "files checked against Candiru patterns",
    "bytes_pattern_scanned": "bytes checked against Candiru patterns",
    "com_registrations": "auto-start COM registrations reviewed",
    "com_user_writable": "   of those, in a folder you can write to",
    "dns_cache_entries": "names in the DNS cache since last reboot",
    "dns_log_records": "DNS history records available",
    "dns_log_events_scanned": "DNS history events searched",
    "hosts_entries": "entries in the hosts file",
    "hosts_blocked_indicators": "   of those, indicators you are BLOCKING (good)",
    "launch_items": "macOS auto-start items read",
    "download_records": "macOS download records checked",
    "known_paths_checked": "known malware file-paths checked",
    "known_paths_present": "   of those, a file is present at (see notes)",
}


def _describe_metrics(metrics: Dict[str, int]) -> List[str]:
    out = []
    for key, value in metrics.items():
        if key == "bytes_hashed":
            out.append("{:,.1f} GB of files read".format(value / 1e9))
            continue
        if key == "dns_log_enabled":
            out.append("Windows DNS history logging: {}".format(
                "ON" if value else "OFF (the Windows default)"))
            continue
        label = _METRIC_LABELS.get(key)
        if label is None:
            out.append("{}: {}".format(key, _fmt_count(value)))
        else:
            out.append("{}: {}".format(label, _fmt_count(value)))
    return out


def render_human(document: Dict[str, Any]) -> str:
    document = _human_document(document)
    out: List[str] = []
    w = out.append

    w(_RULE)
    w("  Zero Breach {}  —  AdFection / Candiru indicator check".format(
        document["tool"]["version"]))
    # The name must not be read as a promise. The tagline carries the tool's one
    # non-negotiable caveat right next to it, so a screenshot of the top of the
    # report cannot imply "you are safe".
    w("  Checks for TRACES of ad-delivered spyware. A clean result is NOT a")
    w("  clean bill of health - see what could not be checked, below.")
    w("  {}   {} {}".format(document["timestamp"],
                            document["platform"]["system"],
                            document["platform"]["release"]))
    w(_RULE)
    w("")

    # The answer first. Everything after it is the supporting evidence.
    out.extend(render_summary(document).split("\n"))

    ioc = document["ioc_set"]
    age = ioc["age_days"]
    age_txt = "unknown age" if age is None else "{} day(s) old".format(age)
    w("Indicator set : {} indicators, {}".format(ioc["count"], age_txt))
    if ioc["stale"]:
        w("  ** WARNING: this indicator set is more than 30 days old. Update it "
          "before trusting a clean result. **")
    w("")

    # Put the full indicator evidence after the coverage/DNS-history instructions.
    # The concise result and urgent next steps remain visible in the summary.
    _render_reach(w, document)

    w("DETAIL  —  what was examined, and the evidence behind the summary")
    w("")
    for name, m in document["modules"].items():
        took = (" in {:.0f}s".format(m["duration_s"])
                if m.get("duration_s") else "")
        w("--- {} check  [{}]{} ---".format(name, m["status"], took))
        w("    examined: {}    could not read: {}".format(
            _fmt_count(m["checked"]), _fmt_count(m["skipped"])))
        if m["submetrics"]:
            for line in _describe_metrics(m["submetrics"]):
                w("    {}".format(line))
        for note in m["notes"]:
            w("    note   : {}".format(note))
        if m["hits"]:
            # Strongest evidence first: someone reading this should see a sample
            # on disk or a proven contact before a string that merely appeared in
            # cached page text.
            order = {EV_ON_DISK: 0, EV_FILE_PATTERN: 0.5, EV_PERSISTENCE: 1, EV_CONTACTED: 2,
                     EV_DNS: 3, EV_ATTEMPTED: 4, EV_CONFIGURED: 5,
                     EV_REFERENCED: 6, "": 0}
            for h in sorted(m["hits"], key=lambda x: order.get(x.get("evidence", ""), 0)):
                prov = "{}/{}".format(h["tier"], h["confidence"]) if h["tier"] else "?"
                ev = h.get("evidence") or "unclassified"
                w("    !! HIT  {}  [{}]  evidence: {}".format(
                    _defang(h["indicator"]), prov, ev.upper()))
                gloss = _evidence_gloss(h)
                if gloss:
                    w("            meaning: {}".format(gloss))
                if h.get("profile"):
                    w("            account: {}".format(h["profile"]))
                w("            at     : {}".format(
                    _defang_text(h["location"], h["indicator"])))
                w("            detail : {}".format(
                    _defang_text(h["detail"], h["indicator"])))
                if h.get("observed"):
                    w("            when   : {}".format(
                        _defang_text(h["observed"], h["indicator"])))
                if h.get("source"):
                    w("            source : {}".format(h["source"]))
        w("")

    v = document["verdict"]
    w(_RULE)
    if v["status"] == V_HITS:
        w("VERDICT: {} indicator(s) matched.".format(v["hits_total"]))
        w("")
        counts = {}
        for m in document["modules"].values():
            for h in m["hits"]:
                key = h.get("evidence") or "unclassified"
                counts[key] = counts.get(key, 0) + 1
        w("  By evidence strength: " + ", ".join(
            "{} {}".format(n, k) for k, n in sorted(counts.items())))
        w("")
        w("  Follow the next steps in the summary. The indicator's role and the")
        w("  evidence type determine those steps; the number of matches does not.")
        w("  A match means INVESTIGATE, not 'you are compromised'.")
        w("  A match does not by itself establish that spyware ran on this device.")
    else:
        if v["gaps"]:
            w("VERDICT: no known indicators found IN WHAT COULD BE CHECKED.")
            w("")
            w("Checks that could NOT run (a gap is not a clean result):")
            for g in v["gaps"]:
                w("  - {}".format(g))
            w("")
        else:
            w("VERDICT: no known indicators found in any check that ran.")
            w("")
        # D1: the mandatory closing line, verbatim.
        w(document["doctrine_line"])
        w("")
    w("")
    _support_options(w)
    w(_RULE)
    return _defang_report("\n".join(out), document)


# The window the AdFection campaign was actually active, from the Citizen Lab
# report: at least 45 targeted devices at Al Jazeera during 2024-2025. If the
# evidence on this machine does not reach back that far, the honest thing is to say
# the check could not have covered it, rather than let a clean result imply it did.
CAMPAIGN_FROM = datetime.date(2024, 1, 1)
CAMPAIGN_TO = datetime.date(2025, 12, 31)
CAMPAIGN_LABEL = "2024-2025 (the documented campaign period)"


def overlap_statement(earliest: datetime.date, source: str) -> List[str]:
    """Compare the dates reported by this scan with the campaign window.

    Unread or out-of-scope records may be older; an oldest date does not prove
    that records cover every day since then or that missing evidence is gone.
    """
    if earliest > CAMPAIGN_TO:
        return [
            "** The oldest dated evidence reported by this scan is {} ({}).".format(
                source,
                earliest.isoformat()),
            "   The campaign this tool searches for was active in {}.".format(
                CAMPAIGN_LABEL),
            "   Those dates DO NOT OVERLAP. The dates reported here do not reach",
            "   the campaign period. Older or unread records may still exist;",
            "   this scan cannot rule out past contact during that period. **",
        ]
    if earliest > CAMPAIGN_FROM:
        return [
            "** The oldest dated evidence reported by this scan is {} ({}).".format(
                source, earliest.isoformat()),
            "   That reaches PART of the campaign period ({}),".format(CAMPAIGN_LABEL),
            "   from {} onwards, and only through that one kind of record.".format(
                earliest.isoformat()),
            "   This does not establish continuous coverage from that date.",
            "   Older or unread records may still exist. A clean result cannot",
            "   rule out past contact during the campaign period. **",
        ]
    return [
        "** The oldest dated evidence reported by this scan is {} ({}), which predates".format(
            source, earliest.isoformat()),
        "   the campaign period. This does not establish continuous coverage",
        "   through that period. Surviving records are never everything, and a",
        "   clean result cannot rule out past contact during that period. **",
    ]


def _render_reach(w, document: Dict[str, Any]) -> None:
    """Say how far back the evidence reaches. A clean result over 11 weeks and a
    clean result over 3 years are different findings, and the reader cannot tell
    them apart unless the tool says which one it just produced."""
    entries = []
    for mod_name, m in document["modules"].items():
        for label, info in (m.get("reach") or {}).items():
            entries.append((mod_name, label, info))
    if not entries:
        return

    w(_RULE)
    w("HOW FAR BACK THIS SCAN COULD SEE")
    w("")
    w("  These dates come from the records examined by this scan. They do not")
    w("  establish a complete history; older or unread records may still exist:")
    w("")

    earliest_overall = None
    earliest_source = ""
    for mod_name, label, info in entries:
        earliest = info.get("earliest")
        days = info.get("days")
        when = "unknown (no date established)" if not earliest else earliest[:10]
        age = ""
        if isinstance(days, int) and earliest:
            age = "  ({} days ago)".format(days)
        w("  {}/{}".format(mod_name, label))
        w("      reaches back to : {}{}".format(when, age))
        w("      basis           : {}".format(info.get("basis", "")))
        if info.get("note"):
            w("      {}".format(info["note"]))
        w("")
        if earliest:
            try:
                d = datetime.date.fromisoformat(earliest[:10])
                if earliest_overall is None or d < earliest_overall:
                    earliest_overall = d
                    earliest_source = "{}/{}".format(mod_name, label)
            except ValueError:
                pass

    # How many artifacts actually date from inside the campaign window. This is
    # the number that answers "could this scan have seen it?", where the oldest
    # surviving file only answers "how far back does anything reach?".
    in_window = 0
    total_dated = 0
    for _mod_name, _label, info in entries:
        by_year = info.get("by_year") or {}
        for year, count in by_year.items():
            year = int(year)
            total_dated += count
            if CAMPAIGN_FROM.year <= year <= CAMPAIGN_TO.year:
                in_window += count

    if earliest_overall is not None:
        for line in overlap_statement(earliest_overall, earliest_source):
            w("  " + line)
        w("")

    # Does ANY reach record - cookie ages, DNS, not just the cache files that
    # carry by_year - reach into the campaign window? This decides whether the
    # absolute "nothing dates from the campaign period" sentence is even true.
    something_in_window = False
    for _mod_name, _label, info in entries:
        earliest = info.get("earliest")
        if earliest:
            try:
                d = datetime.date.fromisoformat(earliest[:10])
                if d <= CAMPAIGN_TO:
                    something_in_window = True
            except ValueError:
                pass

    if total_dated:
        merged = {}
        for _mod_name, _label, info in entries:
            for year, count in (info.get("by_year") or {}).items():
                year = int(year)
                merged[year] = merged.get(year, 0) + count

        w("  Age of the browser cache files searched, by year (cache files only,")
        w("  not cookies or DNS - those are summarised above):")
        w("      " + "   ".join("{}: {:,}".format(y, merged[y])
                                for y in sorted(merged)))
        w("")
        pct = 100.0 * in_window / total_dated
        w("  Of those cache files, dating from the campaign period ({}-{}): "
          "{:,} of {:,} ({:.1f}%).".format(
              CAMPAIGN_FROM.year, CAMPAIGN_TO.year, in_window, total_dated, pct))

        # A per-year floor matters more than the total: the campaign ran across
        # several years, and a year with almost nothing left is a year this scan
        # cannot speak about, however healthy the overall percentage looks.
        sparse = [y for y in range(CAMPAIGN_FROM.year, CAMPAIGN_TO.year + 1)
                  if merged.get(y, 0) < 100]
        if in_window == 0 and not something_in_window:
            w("  No dated evidence summarised here reaches the campaign period.")
            w("  Older or unread records may still exist. A clean result cannot")
            w("  rule out past contact during that period.")
        elif in_window == 0 and something_in_window:
            w("  No browser CACHE file examined dates from the campaign period, though some")
            w("  older evidence (shown above) does. Cache is the thinnest record;")
            w("  the window above is the one to read.")
        elif sparse:
            w("  BUT cache coverage is uneven. These campaign years have almost no")
            w("  surviving cache, so a clean result says little about them:")
            for y in sparse:
                w("      {}: {:,} cache file(s)".format(y, merged.get(y, 0)))
        w("")

    # The actionable part, rendered as its own ruled-off section so the one thing
    # a reader can act on does not get lost at the tail of the reach block.
    howto = []
    for _mod_name, _label, info in entries:
        howto.extend(info.get("how_to_enable") or [])
    if howto:
        w("")
        w(_RULE)
        for line in howto:
            w(line)
        w(_RULE)
    w("")


# What a hit in each tier actually MEANS, in plain language. The tier is the
# whole point of curating the indicator set: contact with an ad tracker and
# contact with a command-and-control server are different events, and a report
# that renders them identically has failed the person reading it.
TIER_MEANING = {
    "delivery": ("Advertising/tracking infrastructure belonging to this network. "
                 "The evidence grade says what was observed; a DNS record or "
                 "saved reference does not prove an ad reached this device. "
                 "An ad impression is NOT evidence of infection."),
    "cc": ("A Candiru command-and-control server. This is the most serious "
           "class of indicator - it is the address an active implant talks to."),
    "validator": ("A Candiru validator server. These profiled a device and "
                  "decided, per device, whether to deliver an exploit. Contact "
                  "suggests this device was being assessed as a target."),
    "candiru": ("A server attributed to Candiru by Recorded Future. Its exact "
                "role is not published, so treat it as serious but unspecified."),
    "candiru-ip": ("An IP address attributed to Candiru infrastructure in 2025. "
                   "Weak on its own: cloud IP addresses are reassigned to "
                   "unrelated, innocent customers within months."),
    "historical": ("Infrastructure from separate, older Candiru campaigns. "
                   "Interpret dated evidence in the cited report's context; "
                   "current ownership and activity are not established."),
    "sample": ("The file fingerprint of a published Candiru sample. A match "
               "here is conclusive, not circumstantial."),
    "candiru-pattern": ("A published Candiru detection rule matched patterns "
                        "inside a file. This needs expert verification; it is "
                        "not an exact sample identification or proof that "
                        "spyware ran."),
    "vuln-driver": ("A LEGITIMATE, signed third-party driver that this actor "
                    "abuses to disable protections (bring-your-own-vulnerable-"
                    "driver). The file itself is not spyware and is present on "
                    "clean machines that genuinely use that hardware or "
                    "software. This is a lead worth checking - who installed "
                    "it, and when - NOT evidence that spyware is on this "
                    "machine."),
}

# Tiers whose file hashes identify legitimate software this actor abuses, rather
# than the spyware itself. A match must never be reported as proof of infection:
# the same file sits on clean machines for honest reasons (see `vuln-driver`).
NOT_MALWARE_TIERS = {"vuln-driver"}

EVIDENCE_MEANING = {
    EV_FILE_PATTERN: ("patterns inside a file matched a published detection "
                      "rule. This is a lead for investigation, not a confirmed "
                      "infection or an exact known-file match"),
    EV_ON_DISK: ("a file on this machine has the fingerprint of a published "
                 "spyware sample - this is conclusive, not circumstantial"),
    # Same grade, different claim: see _on_disk_gloss(). A legitimate-but-abused
    # driver sits on disk too, and saying "conclusive" about it would be false.
    EV_PERSISTENCE: ("the name is registered to run automatically on this "
                     "machine - a hallmark of installed spyware"),
    EV_CONTACTED: "this device demonstrably communicated with it",
    EV_DNS: ("the name or address appears in local DNS data; this does not "
             "establish communication with the indicated server, and a logged "
             "lookup may have failed"),
    EV_ATTEMPTED: ("something on this device looked the name up, but a filter "
                   "blocked the connection"),
    EV_CONFIGURED: ("the name is in local configuration pointing at a real "
                    "address (a protective block entry is not reported at all)"),
    EV_REFERENCED: ("the name appeared in saved page content - most often a page "
                    "ABOUT this campaign, not contact with it"),
}

# A short imperative headline per grade, used in the summary. The ones that are
# not EV_REFERENCED are serious and each gets its own, so a sample on disk and a
# persistence entry can never be rendered as "probably nothing".
EVIDENCE_HEADLINE = {
    EV_FILE_PATTERN: "A FILE MATCHED A CANDIRU DETECTION RULE - NEEDS REVIEW",
    EV_ON_DISK: "A KNOWN SPYWARE FILE IS ON THIS MACHINE",
    EV_PERSISTENCE: "SOMETHING IS SET TO RUN AUTOMATICALLY FROM THIS INFRASTRUCTURE",
    EV_CONTACTED: "THIS DEVICE CONTACTED THIS INFRASTRUCTURE",
    EV_DNS: "THIS INDICATOR APPEARS IN LOCAL DNS RECORDS",
    EV_ATTEMPTED: "THIS DEVICE TRIED TO REACH THIS INFRASTRUCTURE (a filter blocked it)",
    EV_CONFIGURED: "THIS INFRASTRUCTURE IS CONFIGURED ON THIS MACHINE",
}


# A file-on-disk hit means two very different things depending on what the file
# IS. The grade (EV_ON_DISK) is the same either way, so the claim has to be
# chosen from the tier, not from the grade alone.
ON_DISK_NOT_MALWARE_HEADLINE = (
    "A LEGITIMATE FILE THIS ATTACKER IS KNOWN TO ABUSE IS ON THIS MACHINE")
ON_DISK_NOT_MALWARE_GLOSS = (
    "this file is NOT spyware - it is signed, legitimate software that this "
    "actor loads to disable protections. It is also installed for honest "
    "reasons. Worth establishing how it got here; not proof of anything")


def _headline_for(hit) -> str:
    """The summary headline for one serious hit, chosen by grade AND tier."""
    if hit.get("tier") in NOT_MALWARE_TIERS and hit.get("evidence") == EV_ON_DISK:
        return ON_DISK_NOT_MALWARE_HEADLINE
    if hit.get("evidence") == EV_ON_DISK and hit.get("tier") != "sample":
        return "A FILE FINGERPRINT MATCHED; ITS CLASSIFICATION NEEDS REVIEW"
    if hit.get("tier") == "candiru-ip" and hit.get("evidence") == EV_CONTACTED:
        return "THIS DEVICE CONTACTED A HISTORICALLY ATTRIBUTED IP ADDRESS"
    return EVIDENCE_HEADLINE.get(hit.get("evidence"), "A SERIOUS INDICATOR MATCHED")


def _evidence_gloss(hit) -> str:
    """What this grade establishes for this hit (tier-aware, same reason)."""
    if hit.get("tier") in NOT_MALWARE_TIERS and hit.get("evidence") == EV_ON_DISK:
        return ON_DISK_NOT_MALWARE_GLOSS
    if hit.get("evidence") == EV_ON_DISK and hit.get("tier") != "sample":
        return ("a file fingerprint matched an indicator, but its classification "
                "does not identify it as a known spyware sample; expert review "
                "is needed")
    if hit.get("tier") == "candiru-ip" and hit.get("evidence") == EV_CONTACTED:
        return ("a connection record names this IP address; who controlled it "
                "at the time is not established by this match")
    return EVIDENCE_MEANING.get(hit.get("evidence") or "", "")


def _defang(indicator: str) -> str:
    """Make an indicator safe to paste into an email or chat without a client,
    gateway or link scanner auto-fetching it. The report is designed to be
    forwarded to Access Now / Amnesty, and the tool's own rule is never to
    contact an indicator - so it must not ship them in a fetchable form. The JSON
    report keeps the raw value; only the human text is defanged."""
    out = indicator.replace("http://", "hxxp://").replace("https://", "hxxps://")
    # Neuter the last dot (domains) or wrap every dot (IPs) so nothing resolves.
    if any(c.isalpha() for c in indicator) and "." in out:
        head, _, tail = out.rpartition(".")
        return "{}[.]{}".format(head, tail)
    return out.replace(".", "[.]")


# A URL scheme is all a mail gateway, link preview or security scanner needs in
# order to fetch the thing. ftp:// is covered too, because a detail line quotes
# whatever was in the saved page.
_SCHEMES = {"https://": "hxxps://", "http://": "hxxp://", "ftp://": "fxp://"}
_SCHEME_RE = re.compile("|".join(_SCHEMES), re.IGNORECASE)


def _defang_text(text: str, indicator: str) -> str:
    """Defang the indicator traces inside a free-text field - a detail line, a
    path - and change nothing else about it.

    Two passes, and only two. Schemes are neutered wherever they appear, because
    a detail line quotes saved page content and a live https:// in there is
    fetchable straight out of the report. Then the indicator's own value is
    swapped for whatever _defang() renders it as, so the two places a reader
    sees the same name agree. That match is case-insensitive: the browser module
    lowercases the text it quotes, while the indicator need not be lowercase.

    Deliberately NOT a general "wrap every dot" pass. A location is usually a
    Windows path - "C:\\Users\\x\\AppData\\...\\Network\\Cookies" - and blanket
    dot-wrapping would mangle real file and folder names into something the
    person acting on this report can no longer find on their own disk.
    """
    out = _SCHEME_RE.sub(lambda m: _SCHEMES[m.group(0).lower()], str(text))
    defanged = _defang(indicator) if indicator else indicator
    if indicator and defanged != indicator:
        out = re.sub(re.escape(indicator), lambda _m: defanged, out,
                     flags=re.IGNORECASE)
    return out


# Artifact-derived text is attacker-influenced: a browser profile's display name,
# a registry value, a page title. Rendered raw, a newline or a terminal escape
# inside one can forge whole report lines - a fake "VERDICT: no known indicators
# found" printed under a real hit, which survives being pasted into an email to a
# helpline. Control characters, Unicode line separators and bidirectional
# overrides (which can visually reverse a line without any newline) are
# replaced, and newlines collapse to spaces so a field can never begin a line of
# its own. The JSON report keeps the raw evidence.
_UNSAFE_CHARS = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def _safe_text(value, limit=2000):
    text = str(value).replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    text = _UNSAFE_CHARS.sub("�", text)
    return text if len(text) <= limit else text[:limit] + "…"


# Tighter limits for the single-line fields an attacker can fill most freely.
_HIT_FIELD_LIMITS = {"profile": 120, "observed": 64, "location": 500,
                     "detail": 500}


def _human_document(document):
    """Sanitize artifact-derived fields without changing the JSON evidence.

    Notes and gaps can quote remote paths just as hits can. Published source
    citations and the fixed help links remain usable.
    """
    doc = copy.deepcopy(document)

    def scrub(value, limit=2000):
        if isinstance(value, str):
            return _defang_text(_safe_text(value, limit), "")
        if isinstance(value, list):
            return [scrub(item, limit) for item in value]
        if isinstance(value, dict):
            return {key: scrub(item, limit) for key, item in value.items()}
        return value

    for module in doc["modules"].values():
        for key in ("notes", "checks", "reach"):
            if key in module:
                module[key] = scrub(module[key])
        for hit in module["hits"]:
            for key in ("location", "detail", "observed", "profile"):
                if key in hit:
                    hit[key] = scrub(hit[key], _HIT_FIELD_LIMITS[key])
    doc["verdict"]["gaps"] = scrub(doc["verdict"].get("gaps", []))
    return doc


def _defang_report(text, document):
    """Cover every occurrence, including notes and another hit's details."""
    indicators = set(document.get("_indicators", []))
    indicators.update(hit["indicator"] for module in document["modules"].values()
                      for hit in module["hits"])
    for indicator in sorted(indicators, key=len, reverse=True):
        if indicator and _defang(indicator) != indicator:
            text = re.sub(re.escape(indicator), lambda m: _defang(m.group(0)),
                          text, flags=re.IGNORECASE)
    return text


def _recommended_action(hit) -> int:
    """Human next steps, separate from evidence grades and the JSON verdict.

    0: saved context; 1: self-review; 2: qualified interpretation;
    3: prompt expert help. Unknown metadata never becomes reassurance.
    """
    evidence, tier = hit.get("evidence"), hit.get("tier")
    if evidence == EV_REFERENCED:
        return 0
    if evidence == EV_ON_DISK and tier == "vuln-driver":
        return 1
    if evidence in (EV_ON_DISK, EV_PERSISTENCE):
        return 3
    if (tier in ("delivery", "candiru-ip") and
            evidence in (EV_CONTACTED, EV_DNS, EV_ATTEMPTED, EV_CONFIGURED)):
        return 1
    return 2


def _advice_paragraph(w, text):
    for line in _wrap(text, 66):
        w("    " + line)


def _next_steps(w, hits):
    action = max(_recommended_action(h) for h in hits)
    w("  WHAT TO DO")
    if any(h.get("evidence") == EV_FILE_PATTERN for h in hits):
        _advice_paragraph(w, "A file matched a Candiru pattern rule. Ask a "
                         "qualified incident responder to verify the named file "
                         "and rule. Preserve the file and this report; do not "
                         "open, run or delete the file. A pattern match alone "
                         "does not prove infection or that the file executed.")
        w("")
        if all(h.get("evidence") in (EV_FILE_PATTERN, EV_REFERENCED) for h in hits):
            return
    if action == 3:
        _advice_paragraph(w, "Seek expert help promptly. Preserve this report and "
                         "the named files or registrations. Do NOT delete, move, "
                         "run or try to clean them. A file match establishes "
                         "presence; a registration establishes configuration. "
                         "Neither alone establishes that spyware executed.")
        w("")
        _advice_paragraph(w, "Contact a qualified incident responder or your "
                         "organisation's security team. You do not need to "
                         "finish investigating first. Support options are at "
                         "the end of this report.")
    elif action == 2:
        _advice_paragraph(w, "Qualified interpretation is recommended. Review "
                         "the evidence type, saved date and location below. "
                         "A DNS record may be a failed lookup; it does not "
                         "establish a connection. Missing or unrecognised "
                         "evidence labels also need review, not reassurance.")
        w("")
        _advice_paragraph(w, "A connection record for command-and-control, "
                         "validator or other attributed spyware infrastructure "
                         "warrants specialist review. For a DNS-only or "
                         "configuration finding, seek qualified help if the "
                         "local context does not explain it, or if you have "
                         "a credible reason to believe you are being targeted. "
                         "These records do not by themselves establish infection.")
        w("")
        _advice_paragraph(w, "Keep the report and original records. Do NOT delete "
                         "or clean them while arranging review. Your organisation's "
                         "security team or a qualified incident responder can help.")
    else:
        _advice_paragraph(w, "Start with the saved evidence below. Check the "
                         "indicator's role, evidence type, browser/profile, "
                         "date (if available), and file or record that matched. "
                         "Use the report and existing records; do not visit "
                         "the indicator to investigate it.")
        if any(h.get("tier") == "delivery" and h.get("evidence") in
               (EV_CONTACTED, EV_DNS, EV_ATTEMPTED) for h in hits):
            w("")
            _advice_paragraph(w, "Advertising-network records alone do not show "
                             "that you were selected for an exploit or infected. "
                             "A connection can result from an ordinary ad; a "
                             "DNS record does not even establish that connection. "
                             "This finding alone does not call for a spyware "
                             "helpline referral.")
        if any(h.get("tier") == "vuln-driver" and
               h.get("evidence") == EV_ON_DISK for h in hits):
            w("")
            _advice_paragraph(w, "For the legitimate driver, check whether its "
                             "location and installation history match hardware "
                             "or software you use. Your IT support or the "
                             "software vendor can help identify it. Do not "
                             "delete it solely because of this match.")
        if any(h.get("tier") == "candiru-ip" for h in hits):
            w("")
            _advice_paragraph(w, "For a historical IP address, ownership can change. "
                             "The tool has not established who controlled it "
                             "at the time of this record. Check the saved date "
                             "against the cited research; an absent date leaves "
                             "that question unresolved.")
        if any(h.get("evidence") == EV_CONFIGURED for h in hits):
            w("")
            _advice_paragraph(w, "For a configuration entry, check who or what "
                             "created it and why. An ordinary ad impression "
                             "does not explain a local hosts-file entry. "
                             "Do not edit it merely to make this finding disappear.")
        w("")
        _advice_paragraph(w, "Keep the report. If you cannot explain a finding, "
                         "ask trusted IT support for help interpreting it. "
                         "Stronger findings or a credible targeting concern "
                         "warrant qualified security help directly; you do not "
                         "have to complete these steps first.")
    w("")
    _advice_paragraph(w, "Do NOT open, visit or look up indicator addresses. Keep "
                     "the [.] spelling when sharing them.")


def _support_options(w):
    w("WHEN TO SEEK SUPPORT")
    w("A credible targeting concern or a genuine security notification warrants")
    w("qualified help regardless of this scan's result. You do not need to")
    w("complete self-checks first. Contact your organisation's security team")
    w("or a qualified incident responder.")
    w("")
    w("For journalists, activists, human-rights defenders and other civil")
    w("society members, Access Now offers a Digital Security Helpline:")
    w("  https://www.accessnow.org/help/")
    w("  Eligibility and support: https://www.accessnow.org/help/helpline-faq/")
    w("Check its intake instructions before sending private evidence.")
    w("")
    w("Research and further guidance:")
    w("  Amnesty International Security Lab  https://securitylab.amnesty.org/")
    w("  The Citizen Lab                     https://citizenlab.ca/")
    w("")
    w("A saved reference or advertising-network trace alone is not a reason")
    w("to assume spyware infection. No result from this tool rules it out.")


def render_summary(document: Dict[str, Any]) -> str:
    """The part a person actually reads. Answers, in order: what was found, what
    it means, what to do, and what this scan could not check.

    Everything below this in the report is the evidence for these few lines."""
    document = _human_document(document)
    out: List[str] = []
    w = out.append
    v = document["verdict"]

    all_hits = [h for _m, m in document["modules"].items() for h in m["hits"]]
    serious = [h for h in all_hits if is_serious(h.get("evidence", ""))]
    benign = [h for h in all_hits if not is_serious(h.get("evidence", ""))]

    w(_RULE)
    w("  SUMMARY  —  read this part")
    w(_RULE)

    if not all_hits:
        w("  RESULT: no known indicator was found in anything that could be")
        w("          checked.")
        w("")
        w("  This is NOT a clean bill of health. See the two sections below for")
        w("  what was searched and, more importantly, what could not be.")
    elif serious:
        n = len(serious)
        action = max(_recommended_action(h) for h in serious)
        if action == 3:
            w("  RESULT: SERIOUS FINDING - seek expert help promptly.")
        elif action == 2:
            w("  RESULT: potentially SERIOUS finding - qualified review recommended.")
        else:
            w("  RESULT: {} finding{} to review; start with the saved context.".format(
                n, "" if n == 1 else "s"))
        if benign:
            nb = len(benign)
            w("          ({} further match{} {} only {} in saved page "
              "content.)".format(
                  nb, "" if nb == 1 else "es", "is" if nb == 1 else "are",
                  "a reference" if nb == 1 else "references"))
        w("")
        w("  WHAT WAS FOUND")
        # Strongest grade first; collapse repeats of the same indicator+grade so
        # one domain in three cache files is not three lines.
        for h in sorted(_dedup_serious(serious),
                        key=_recommended_action, reverse=True):
            headline = _headline_for(h)
            w("    >> {}".format(headline))
            w("       {}  [{}]".format(_defang(h["indicator"]), h["tier"]))
            meaning = TIER_MEANING.get(h["tier"])
            if meaning:
                for line in _wrap(meaning, 64):
                    w("          " + line)
            if h.get("profile"):
                w("          Account: {}".format(h["profile"]))
            if h.get("observed"):
                w("          When: {}".format(h["observed"][:19].replace("T", " ")))
            w("          Where: {}".format(
                _defang_text(h["location"], h["indicator"])))
            w("")
        _next_steps(w, serious)
        if benign:
            n_b = len(benign)
            w("")
            w("    The {} reference-only match{} {} listed in DETAIL. Saved text".format(
                  n_b, "" if n_b == 1 else "es", "is" if n_b == 1 else "are"))
            w("    can mention an indicator without a connection to it.")
    else:
        n = len(benign)
        w("  RESULT: {} match{} found, all of them reference-only.".format(
            n, "" if n == 1 else "es"))
        w("")
        w("  WHAT THIS PROBABLY IS")
        for line in _wrap(
                "These matches are names found in saved content, such as page "
                "text, an unvisited bookmark or browser storage. A reference "
                "does not establish a connection, execution or infection. "
                "Check the saved title, location and date in DETAIL without "
                "opening the indicator address. A reference alone is probably "
                "not a sign of compromise; it does not clear the device either.", 68):
            w("    " + line)
        w("")
        _advice_paragraph(w, "A reference alone does not call for a helpline "
                         "referral. If you have a credible targeting concern "
                         "or a genuine security notification, seek qualified "
                         "help directly regardless of this result.")

    gaps = v.get("gaps") or []
    if gaps:
        w("")
        w("  WHAT COULD NOT BE CHECKED  ({} gap{})".format(
            len(gaps), "" if len(gaps) == 1 else "s"))
        shown = gaps[:4]
        for g in shown:
            for i, line in enumerate(_wrap(g, 66)):
                w("    " + ("- " if i == 0 else "  ") + line)
        if len(gaps) > len(shown):
            w("    ... and {} more, listed in full at the end of this report."
              .format(len(gaps) - len(shown)))
        # The DNS gap is the one a reader can actually close - but only point at
        # the instructions if they were actually rendered (they are not on a
        # non-Windows host), or the pointer dangles.
        if document.get("_dns_howto") and any("dns" in g.lower() for g in gaps):
            w("")
            w("    -> You can fix the DNS gap for next time, in one command.")
            w("       See \"HOW TO TURN ON DNS HISTORY\" further down. It tells you")
            w("       nothing about the past, but it means a future check can")
            w("       actually answer the question.")
    # Every report, not only one with findings. A clean or reference-only result
    # is the one people are most relaxed about posting publicly to say "I'm
    # fine" - and it carries the same usernames, profile names and paths.
    w("")
    for line in _wrap(_PRIVACY_NOTE, 68):
        w("  " + line)
    w(_RULE)
    w("")
    return _defang_report("\n".join(out), document)


_PRIVACY_NOTE = ("Before you share this report: it can contain your Windows "
                 "username, browser profile names, file paths and browsing "
                 "details. Ask a responder how to share evidence securely; "
                 "do not post the full report publicly.")


def _dedup_serious(hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse repeats of the same indicator at the same grade, strongest grade
    first, so one domain found in three cache files is one line, not three."""
    order = {g: i for i, g in enumerate(
        [EV_ON_DISK, EV_PERSISTENCE, EV_CONTACTED, EV_DNS, EV_ATTEMPTED, EV_CONFIGURED])}
    seen = {}
    for h in hits:
        key = (h["indicator"], h.get("evidence", ""))
        if key not in seen:
            seen[key] = h
    return sorted(seen.values(),
                  key=lambda h: order.get(h.get("evidence", ""), 99))


def _wrap(text: str, width: int) -> List[str]:
    words, lines, cur = text.split(), [], ""
    for word in words:
        if cur and len(cur) + 1 + len(word) > width:
            lines.append(cur)
            cur = word
        else:
            cur = (cur + " " + word).strip()
    if cur:
        lines.append(cur)
    return lines


def _referrals(w) -> None:
    w("  - Access Now Digital Security Helpline  https://www.accessnow.org/help/")
    w("  - Amnesty International Security Lab     https://securitylab.amnesty.org/")
    w("  - The Citizen Lab                        https://citizenlab.ca/")
