# Zero Breach

> Release v0.1.8 corrects the version the download reports (v0.1.7 shipped
> reporting itself as 0.1.6) and refuses network paths given to `--iocs`/`--json`
> in the single-file build. Optional Candiru patterns still need the pinned YARA-X engine;
> see [pattern validation](DETECTION-UPGRADE.md). Default checks remain standard-library-only.

[![tests](https://github.com/interplains/zero-breach/actions/workflows/tests.yml/badge.svg)](https://github.com/interplains/zero-breach/actions/workflows/tests.yml)

A local, read-only scanner that checks a computer for traces of the **AdFection /
Candiru** spyware campaign — the operation in which an ad-tech company used
real-time ad bidding to deliver zero-click spyware to targeted people. Tested on
Windows, macOS and Linux (Python 3.8–3.12) in CI.

It searches the machine's own leftover records — browser history, cookies, caches
and connection records, file fingerprints, auto-start registrations, known
malware file-paths and the DNS resolver cache — for published indicators, and
reports what it found, how strong the evidence is, and just as importantly
**what it could not check**.

> **A clean result is not a clean bill of health.** Spyware of this grade is built
> to defeat exactly this kind of check, most of the evidence it leaves expires
> within weeks, and Windows does not record DNS history unless someone turned it
> on. This tool narrows uncertainty; it does not remove it. If you have real
> reason to believe you are a target, the right step is expert help — the
> [Access Now Digital Security Helpline](https://www.accessnow.org/help/) or the
> [Amnesty International Security Lab](https://securitylab.amnesty.org/) — not a
> self-service script.

## Background

In October 2026 The Citizen Lab documented how the ad-tech firm Discover-Tech used
its **Controlium** platform to fingerprint and infect devices the moment an
advertisement was rendered, delivering Candiru spyware with no click required.
At least 45 devices at Al Jazeera were targeted across 2024–2025. The indicator
set here is drawn from that reporting and from Recorded Future's independent
tracking of the same infrastructure.

The delivery vector abuses real-time ad bidding. Keep operating systems and
browsers updated, reduce exposure with ad filtering, and investigate surviving
traces where appropriate. This tool checks those traces; it does not replace
updates or establish that a device is safe.

- The Citizen Lab, *Exposing AdFection* (2026-10-15)
- Recorded Future / Insikt Group, *Tracking Candiru's DevilsTongue Spyware* (CTA-2025-0805)

## What it checks

| area | what it reads |
|---|---|
| **Browser** | history, cookies (host names and timestamps only), favicons, HTTP cache, Local/Session Storage, Service Worker caches, and HSTS/connection records — across Chrome, Edge, Brave, Vivaldi, Chromium and Firefox, plus Safari's history, cookies and caches on macOS, for discovered profiles in supported locations |
| **Files** | SHA-256 of candidate files under the user-writable locations spyware drops into, against known sample hashes — and, kept deliberately separate, the hash of a legitimate signed driver this actor abuses, which is reported as a lead rather than as proof |
| **Host** (Windows) | per-user COM registrations (this campaign's documented persistence), the DNS resolver cache, whether DNS history logging is even enabled, the hosts file, and known fixed-path driver drops (e.g. the `HW.sys` vulnerable driver) |
| **Host** (macOS) | launchd auto-start items in `~/Library/LaunchAgents`, `/Library/LaunchAgents` and `/Library/LaunchDaemons`, the hosts file, and the system's record of where downloaded files came from. Windows-only checks stay reported as gaps; macOS keeps no searchable DNS history by default |

Every match is **evidence-graded**, because the artifact decides the meaning.
Cookie metadata and stored connection records can support a contact finding,
but do not establish infection or explain how the record arrived. A domain
merely appearing in a cached web page may be a saved reference, such as an
article about the campaign. The tool distinguishes saved references from
connection evidence so that each finding can be interpreted in context.

### Supported browsers

| family | browsers | profile locations checked |
| ------ | -------- | ------------------------- |
| Chromium | Chrome, Edge, Brave, **Vivaldi**, Chromium | Windows `%LOCALAPPDATA%\\<vendor>\\User Data`; macOS `~/Library/Application Support/<vendor>`; Linux `~/.config/<vendor>` plus snap and Flatpak locations |
| Firefox | Firefox | standard profile and cache directories |
| WebKit | Safari (macOS) | `~/Library/Safari`, `~/Library/Caches/com.apple.Safari` and the Safari sandbox under `~/Library/Containers/com.apple.Safari` |

Vivaldi paths: `%LOCALAPPDATA%\\Vivaldi\\User Data` (Windows),
`~/Library/Application Support/Vivaldi` (macOS), `~/.config/vivaldi`,
`~/.config/vivaldi-snapshot` and the Flatpak `com.vivaldi.Vivaldi` config
(Linux). Other Chromium-based browsers (Opera, Arc and similar) are not scanned
yet. Unsupported browsers and custom profile locations are not checked and may
not appear in the report; a no-match result does not cover them. Close the
browser before scanning so its databases are not locked.

Safari's cookie file is read in place, so no copy of it reaches disk, and its
parser takes host names, cookie names and dates but never the cookie value. Its
favicon and HSTS records are not read yet. macOS privacy protection can refuse
access to Safari or another browser's folder for the app running the scan. That
is reported as a gap, and the report says how to allow it.

> **Release note:** Vivaldi support is included in v0.1.2. Earlier downloads
> do not include it. Verify each version against its own signature and checksum.

## Install and run

Default checks require Python 3.8 or newer, no administrator and no added packages.

**Single file (simplest):** [download zero-breach.py](https://github.com/interplains/zero-breach/releases/latest/download/zero-breach.py),
verify it using the [release checksums](https://github.com/interplains/zero-breach/releases/latest),
then open a terminal in the download folder. On Windows use `python`; on macOS
or Linux use `python3` in place of `python` in the commands below.

```
python -X utf8 zero-breach.py            # full scan
python -X utf8 zero-breach.py --quick    # faster; skips file fingerprinting
python -X utf8 zero-breach.py --json report.json
```

**Optional Candiru file patterns:** Download `requirements-patterns.txt` from
the same release as the scanner. This mode needs Python 3.9 or newer. From the
folder containing both downloads, make a separate Python environment and install
the hash-pinned YARA-X wheel:

```text
# Windows PowerShell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-patterns.txt
.venv\Scripts\python.exe -X utf8 zero-breach.py --patterns

# macOS / Linux
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-patterns.txt
.venv/bin/python -X utf8 zero-breach.py --patterns
```

`--pattern-path ABSOLUTE_PATH` limits this extra file check to a chosen local
file or folder; it can be repeated. The normal browser, hash and host checks keep
their usual scope. Pattern matches are leads for investigation, not proof of an
active infection. A no-match result cannot rule out Candiru or other spyware.
Without `--pattern-path`, the optional check first examines up to 128 safe local
files named by per-user Windows COM registrations, then its usual file roots.
A COM registration by itself is not a spyware finding. The two published rules
only apply to files smaller than about 1 MB, so larger files remain outside
their detection scope.

On Windows, the DNS-history check reads up to the newest 50,000 retained
events. If older retained records remain, the report marks that history as
partial rather than complete. This does not turn on logging or recover events
that were never recorded.

**From source:**

```
python -X utf8 scan/adint-scan.py
```

The scan changes no system settings and needs no administrator. It makes no
intentional network requests or indicator lookups. Redirected paths and Windows
remote drives are skipped, and online certificate verification is disabled.
On POSIX, network mounts can still be read through ordinary filesystem calls.
Locked database
snapshots are temporary; cleanup is attempted after use, and any cleanup failure
is reported with the retained location. `--json` writes the requested report.

Exit codes: `0` nothing found, `2` an indicator matched, `1` the scan could not be
set up (e.g. a bad indicator file).

## Verifying what you downloaded

Use the official repository above and check the downloaded file before running it.

**1. Verify the publisher's signature.** Release v0.1.8 includes detached GPG
signatures for the scanner and its checksum manifest, using ArchiveGenocide's
established release key. Follow [SIGNING.md](SIGNING.md), and compare the full
key fingerprint with [ArchiveGenocide's verification page](https://archivegenocide.com/verify.html).
The [ArchiveGenocide download panel](https://archivegenocide.com/scan/#verify-download)
also publishes the version-specific checksum separately from GitHub.

**2. Match the published hash.** Every release lists the SHA-256 of `zero-breach.py`.
Confirm your download matches it:

```
# Windows PowerShell
Get-FileHash zero-breach.py -Algorithm SHA256
# macOS / Linux
shasum -a 256 zero-breach.py
```

**3. Rebuild it yourself and compare.** The single file is generated from this
repository, deterministically — the matching release tag rebuilds a byte-identical file. So
you do not have to trust the download at all; you can reproduce it:

```
git clone https://github.com/interplains/zero-breach.git
cd zero-breach
git checkout v0.1.8
python build/build.py          # writes dist/zero-breach.py and prints its SHA-256
```

These commands reproduce v0.1.8; substitute the matching tag for another release.
On macOS or Linux use `python3` for the build command.
Compare the hash with that release's published hash. The development branch may
contain later changes and is not expected to reproduce an earlier release.

**Antivirus note.** `zero-breach.py` is plain-text Python — you can read every line
in a text editor. Some antivirus products flag *any* script that reads browser
databases, because that behaviour resembles an infostealer. Zero Breach reads
cookie **host names and timestamps** through its SQL queries, never cookie values,
and does not decrypt credentials. A locked database snapshot necessarily copies
the database bytes before querying that metadata. If your antivirus
objects, read the source, check the hash, and decide for yourself.

## Reading the result

The report opens with a plain-language summary: what was found, how serious it is,
what to do, and **what could not be checked**. Findings are ranked strongest-first:

- **on-disk** — a file matches a published fingerprint. A spyware-sample match
  identifies that sample; a `vuln-driver` match identifies legitimate software
  known to be abused and is not proof of infection.
- **persistence** — a name is registered to run automatically (serious)
- **contacted** — a connection record; its significance depends on the
  indicator's role, such as advertising delivery versus command-and-control
- **dns-record** — a name or address appears in local resolver data; a lookup
  may have failed, and resolution alone does not prove contact with the server
- **configured** — a name is mapped to a real address in local configuration
- **referenced** — the name appeared in saved content, such as page text,
  an unvisited bookmark or browser storage; this does not establish contact

Next steps depend on both the evidence and the indicator's role. Advertising
traces and legitimate-driver matches start with checking the saved context;
they do not automatically trigger a spyware-helpline referral. More concerning
infrastructure warrants qualified interpretation. Known spyware-file matches
and persistence findings call for prompt expert review and preservation of the
evidence. A credible targeting concern warrants direct help regardless of the
scan result. Multiple weak matches do not automatically become strong evidence.

Evidence locations are printed in full so they can be copied. Detailed findings
follow the coverage information and, where applicable, DNS-history instructions.

Domain and IP matches are printed defanged (`example[.]com`) so that forwarding a
report to a help organisation cannot cause a mail gateway to contact the
indicator on the reader's behalf.

DNS cache entries pointing at a blocking/sink address are described as protective
configuration, not attempted contact: the hosts file can preload them without
any lookup. For a more consistent SQLite snapshot, close browsers before scanning.
Local-path checks are not an OS sandbox: POSIX network mounts and concurrent
filesystem changes require an external isolation boundary for strict offline use.

### Example: a "nothing found" result

The most common outcome, and the one where reading carefully matters most — note
that it leads with the caveat and lists what it could *not* check:

```
========================================================================
  Zero Breach 0.1.8  —  AdFection / Candiru indicator check
  Checks for TRACES of ad-delivered spyware. A clean result is NOT a
  clean bill of health - see what could not be checked, below.
  2026-10-18T14:30:00   Windows 11
========================================================================
  SUMMARY  —  read this part
========================================================================
  RESULT: no known indicator was found in anything that could be
          checked.

  This is NOT a clean bill of health. See the two sections below for
  what was searched and, more importantly, what could not be.

  WHAT COULD NOT BE CHECKED  (2 gaps)
    - hash/file-fingerprints: skipped by --quick. Re-run without --quick
      to include it
    - host/dns-log: DNS-Client/Operational log is disabled (the Windows
      default) - there is no queryable DNS history, so past activity
      cannot be checked retrospectively from this host
========================================================================
```

A real match is shown under a `>> ` heading stating plainly what it is (a file on
disk, an auto-start entry, a proven connection), with the account and date, and a
numbered "what to do" that starts with *do not delete the evidence*.

## Indicator data and interoperability

The current source dataset has **405 indicators: 292 domains, 111 IP addresses,
one spyware hash and one legitimate vulnerable-driver hash**, in
[`iocs/adfection_iocs.txt`](iocs/adfection_iocs.txt), one per line with its tier,
confidence and source. The current release **embeds all 405 indicators**, including
67 additional domains/hostnames compared with v0.1.1. Earlier signed release
assets remain unchanged; later source/feed updates do not replace them.

Coverage combines Citizen Lab's AdFection (2026), Hooking Candiru (2021) and
CatalanGate (2022) reports, Confiant ADINT (2026), Recorded Future (2025),
Microsoft DevilsTongue (2021), ESET (2021), Avast (2022), Google TAG (2021) and
Amnesty Security Lab's Indonesia research (2024). Only their Candiru-related
indicators are included. Each export retains the indicator's actual citation.
They are exported to [`dist/`](dist/) in several formats:

- **STIX 2.1** and **MISP** — for MISP, a SIEM, or Amnesty International's Mobile
  Verification Toolkit: `mvt-ios check-backup --iocs dist/adfection.stix.json <backup>`
- **DNS/ad blocklists** — `hosts`, Adblock/uBlock/AdGuard, dnsmasq, and a plain
  domain list, for a phone's or router's DNS filter, Pi-hole or AdGuard Home.
  The current lists contain **291 reviewed domains/hostnames**. Shared cloud IPs
  and hosting parents are excluded. Bare `adtimizer.co` remains scanner evidence
  but is excluded from blocking; its specifically documented operational hosts
  are included. Historical attribution does not establish current ownership or
  activity. Regenerate with `--no-historical` to omit the historical tier; this
  still includes Recorded Future's separately attributed 2025 infrastructure.
  Hosts files block exact names; Adblock and dnsmasq rules also cover subdomains.

Regenerate the exports with `python build/emit_stix.py`, `build/emit_misp.py` and
`build/emit_denylist.py`.

**Correction for existing STIX users:** the legitimate driver hash
`6a4875ae86131a594019dec4abd46ac6ba47e57a88287b814d07d929858fe3e5`
is excluded from active STIX indicators. If you imported an earlier feed, process
`dist/adfection.withdrawals.stix.json` in a consumer that supports STIX revocation,
or explicitly remove the old driver rule and its relationship:
`indicator--80275ed1-64f2-58c7-97dc-9cdacac0ff5d` and
`relationship--66b188af-2489-5b41-a84f-b90c34f5fc73`.
The withdrawal file is for removing earlier objects, **not a detection/MVT feed**.
Continue using `dist/adfection.stix.json` for scanning. The scanner and MISP retain
the driver as a clearly labelled investigation lead; its presence is not proof
of spyware.

### Updating the indicators

The list goes stale — new infrastructure appears and old domains lapse. Refresh
it from this repository with a separate, explicitly-run script (the scanner itself
makes no intentional network requests):

```
python scan/update-iocs.py            # fetch, verify, show what changed (dry run)
python scan/update-iocs.py --apply    # also replace the local list
```

It downloads over HTTPS, checks the file against a published SHA-256, confirms it
parses before replacing anything, and shows a diff first. The trust model and the
updater limitations are documented at the top of the script. It does not verify
GPG signatures automatically. The signed release manifest authenticates the IOC
file shipped with the signed release, not later development-branch updates; see [SIGNING.md](SIGNING.md).

## Design principles

- **Never contact an indicator.** A Python socket guard blocks direct DNS and
  network calls. Local-path checks reject redirected paths and Windows remote
  drives, while POSIX network mounts may appear as local filesystem paths;
  Authenticode checks that could retrieve certificates are disabled. The socket
  guard is not an operating-system network sandbox; use OS isolation when a
  strict offline execution boundary is required.
- **Measured, never inferred.** A check that could not run is reported as a gap,
  never as clean. This is enforced structurally, not by convention.
- **Precision over coverage.** An unsigned binary in a user-writable path is not a
  finding; plenty of honest software looks like that. Alarms that mean nothing
  teach people to ignore the tool.
- **Queries only required metadata.** Cookie queries select host names and
  timestamps, not values. Temporary snapshots copy entire locked database files;
  the scanner does not decrypt browser credentials.
- **Read-only, no administrator, no telemetry, no dependencies.**

## Tests

Maintainers: run `python tools/release_check.py --require-patterns` before
publishing. It builds the download and exercises source/download fixture scans,
reports, optional patterns and the webpage when supplied. Setup and the short
release checklist are in [TESTING.md](TESTING.md).

```
cd scan && python -m unittest discover -s tests
```

The suite covers the network guard, the evidence grading, the boundary matching
(so a longer name or number that merely contains an indicator does not match), the
loader's failure modes, and behavioural checks that cookie queries exclude values
and that the scanner does not read the browser's master key. Snapshot copies still
contain the database bytes, as described above.

## Contact

Questions or feedback: the project's **Telegram** — https://t.me/+t9gq13mSKcE4NGI0.
To report a security problem, please see [SECURITY.md](SECURITY.md).

## Licence

The software is licensed under the **Apache License 2.0** (`LICENSE`). The
indicator data in `iocs/` and `dist/` is released into the public domain under
**CC0 1.0** (`iocs/LICENSE.md`), so it can be copied into blocklists, MISP, STIX
and other tools without restriction.

This project is **not affiliated with, and not endorsed by**, The Citizen Lab,
Confiant, Recorded Future, Amnesty International or Access Now. Their work is cited
as the source of the indicators and as the place to turn for expert help. See
`NOTICE` for details.
