# adint-scan

> Release v0.1.6 fixes extension-like folder names in COM command paths and
> avoids treating unread history as absent. It never executes registered commands.
> Optional Candiru pattern dependencies and limits are documented in
> [DETECTION-UPGRADE.md](../DETECTION-UPGRADE.md).

A local, read-only check for the published AdFection / Candiru indicators,
with explicit reporting of missing evidence and checks that could not run.

## What it tells you, and what it cannot

It answers two questions honestly:

1. Are the published indicators present in the places this machine can actually
   be checked?
2. What evidence survives, and what could not be checked? Manual DNS-history
   setup is documented below. The `--arm` commands are disabled in this release.

**A clean result means "no known indicators were found in the places that can be
checked." It does not mean the device is clean.** Spyware of this grade is
purpose-built to defeat exactly this class of check. The tool says so on every
run, and it reports a check that *could not run* as `UNKNOWN`, never as clean —
a gap and a clean result are different answers and are never merged.

If you have a concrete reason to suspect this machine, the answer is expert
forensics, not this tool:

- [Access Now Digital Security Helpline](https://www.accessnow.org/help/)
- [Amnesty International Security Lab](https://securitylab.amnesty.org/)
- [The Citizen Lab](https://citizenlab.ca/)

## Running it

No dependencies beyond Python 3.8+. No installation.

```
cd scan
python -X utf8 adint-scan.py
```

```
adint-scan [--deep] [--quick] [--obfuscated] [--json PATH] [--iocs PATH] [--patterns] [--pattern-path ABSOLUTE_PATH]
```

| flag | effect |
|---|---|
| *(none)* | tier 1: browser, hash and host IOC match. Read-only, no admin. |
| `--quick` | skip file fingerprinting (~halves the runtime). The skip is reported as a gap, not as clean. |
| `--json PATH` | also write the machine-readable report |
| `--iocs PATH` | use a different indicator file (default `../iocs/adfection_iocs.txt`) |
| `--deep` | tier 2: full persistence sweep. Not implemented — the flag reports an honest `UNKNOWN` gap rather than faking a sweep |
| `--patterns` | opt-in, bounded check against two published Candiru file rules; requires Python 3.9+ and the pinned optional YARA-X wheel |
| `--pattern-path ABSOLUTE_PATH` | file or folder for the optional pattern check; repeatable and requires `--patterns` |
| `--obfuscated` | opt-in: also look for indicators stored in disguise and for script files built to hide code (see below). Standard library only |

Exit codes: `0` nothing found, `2` an indicator matched, `1` the scan could not
be set up. This release changes no system settings and needs no administrator.
Locked SQLite databases may be copied to temporary snapshots, which are removed
after use. `--json PATH` writes the report you request.

### Modules

| module | what it reads |
|---|---|
| `browser` | history, cookies, favicons, HTTP cache, LevelDB and Service Worker caches across Chrome / Edge / Brave / Vivaldi / Chromium (every profile) and Firefox. Locked databases are copied before being opened. |
| `hash` | SHA-256 of candidate files under AppData, ProgramData, both Temps, Downloads, Desktop, Documents and Public, against the sample hashes in the IOC set. |
| `host` | per-user COM registrations (this chain's documented persistence), the DNS resolver cache, up to 50,000 recent retained DNS-history events on Windows, and the hosts file. Older retained events are an explicit gap. |
| `obfuscated` (optional) | the browser cache, storage and Extensions folders, plus the hash check's user-writable folders, for disguised indicators; script files there for hidden code. Cookie, login and history databases are not opened. |
| `patterns` (optional) | file bytes checked against two published Candiru research rules; without an explicit pattern path, safely checks up to 128 local user-writable COM server files first. A match needs investigation and cannot confirm infection. |

Why the browser module looks at the cache and not just history: history records
only top-level navigations, and an ad is a subresource inside an iframe. A real
impression would never appear in history. The cache, cookie stores and LevelDB
files do record subresource origins — and they are short-lived, which is part of
the honest answer about how far back any of this can see.

### Disguised indicators and hidden code (`--obfuscated`)

The other checks match an indicator only as it is normally written. Malware
that wants an address to survive a text search stores it some other way: the
YIPPHB loader kept its URL backwards (`.../moc.lruynit//:sptth`), and the March
2026 axios / plain-crypto-js npm compromise shipped its payload reversed. This
check looks for every domain and IP in the set written backwards, in reverse-DNS
order (`net.example`, as app bundle IDs carry names), bit-inverted (XOR 0xFF), or
backwards and bit-inverted. The usual boundary rules apply, so a reversed IP
inside a longer number does not match.

A page about the campaign writes an indicator forwards, so a disguised copy
is graded `encoded`: more than a saved reference, but **not** evidence that
the device contacted it.

In script and code files it also looks for constructions used to hide code,
whoever wrote them: a right-to-left direction control left open at the end of a
line (Trojan Source, CVE-2021-42574), runs of eight or more invisible characters
(GlassWorm and os-info-checker-es6, 2025; Unicode tag "ASCII smuggling"; the
2021 Hangul-filler backdoor), backwards URLs, and backwards base64 string
literals. These are graded `hidden-code`. They have nothing to do with this
campaign's indicators and are not a sign of infection; some honest software
trips them. Check which extension or download the file belongs to.

It is opt-in because it reads many more files than the default scan and
because its code rules are heuristics, which the default scan does not use.
Right-to-left translation folders (`_locales`, `i18n*` and similar), flag emoji
and single emoji modifiers are deliberately ignored. UTF-16 text and compressed
add-ons (Firefox `.xpi`) are not decoded, and folders the hash check prunes
(`node_modules`, `.git`, caches) are not walked in the user folders.

## Turning on DNS history (the one thing worth doing for next time)

The single biggest finding from the reference machine was that
`Microsoft-Windows-DNS-Client/Operational` **is disabled by default on Windows**.
On a normal machine there is therefore no DNS history at all, which is why the
2024–2025 window in which the Al Jazeera devices were hit cannot be checked
retrospectively. That cannot be fixed backwards. It can be fixed forwards, in one
command, and the report prints it for you when it finds the log disabled:

```
# in an Administrator PowerShell
wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true /ms:67108864
```

`/e:true` turns the log on; `/ms` sizes it to 64 MB so it holds months rather
than hours. Turn it back off with the same line and `/e:false`. This protects
nothing and tells you nothing about the past — it just means a future scan has a
record to search instead of an empty attic.

> **A system-writing "arm" helper** (automated DNS-log enabling, a persistence
> baseline/diff) exists in `arm.py` but is **deliberately not wired to the CLI in
> this release**. A pre-release review found its undo path could, from its own
> journal file, delete scheduled tasks and could discard collected DNS history,
> and in a tool at-risk people run that is not acceptable. It returns once the
> undo path has been rebuilt with a write-ahead journal and per-step safety. The
> one manual command above does the one thing that mattered.

## Rules the code is held to

- **Never contact an indicator.** No DNS resolution, ping, HTTP or WHOIS of any
  indicator, ever — resolving a C&C domain announces a possible victim to the
  people running it. A runtime guard blocks Python network calls. Local-path
  guards reject redirected paths and Windows remote drives; POSIX network mounts
  can appear local and may be read. Certificate verification that could
  retrieve data is disabled. The guard is not an OS network sandbox. Tests use
  synthetic fixtures and reject network-capable imports; `urllib.parse` is
  permitted solely for lexical URL parsing.
- **No telemetry.** None, of any kind.
- **Measured, never inferred.** If a check could not run, it is `UNKNOWN`.
- **Precision over coverage.** An unsigned binary in a user-writable path is not
  a finding; plenty of honest software looks like that. Fourteen scary findings
  that mean nothing teach people to ignore the tool.
- **Read-only by default**, and nothing writes without an explicit flag.
- **No administrator** required for the default scan.

## Tests

```
cd scan
python -X utf8 -m unittest discover -s tests -v
```

## Emitters

`../build/emit_stix.py` and `../build/emit_misp.py` turn the same curated IOC
file into a STIX 2.1 bundle and a MISP event, written to `../dist/`. STIX because
Amnesty's **MVT** already does mobile forensics well and consumes it — the right
move is to hand MVT users the indicators, not to rebuild MVT. MISP because
institutions deploy by policy: one newsroom admin importing one event protects
everyone behind the gateway.

Delivery-tier ad infrastructure is deliberately *not* marked `to_ids` in the MISP
event. An ad impression is not proof of infection, and shipping it as a detection
signature would bury an analyst in false positives.

## Attribution

The indicators come from The Citizen Lab's *Exposing AdFection* (2026-10-15) and
Confiant's companion *ADINT* report. **Neither is affiliated with this tool and
neither endorses it.** Their report is the source; the tool is not theirs.
