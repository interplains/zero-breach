"""ScanContext — what every module receives. Keeps modules decoupled from the CLI."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Callable

from .iocs import IocSet


@dataclass
class ScanContext:
    iocs: IocSet
    deep: bool = False
    # Skip the file-fingerprinting check, which is the slowest part of the scan
    # by far and the weakest signal in it. See cli.py for why.
    quick: bool = False
    verbose: bool = True
    # progress sink; defaults to stderr so stdout stays the clean human report
    emit: Callable[[str], None] = field(
        default=lambda msg: print(msg, file=sys.stderr))
    # The result the running module is filling in, published here as soon as it
    # exists. A module that dies half way through has usually already found
    # something - a matching cookie read before a later, malformed artifact
    # raised - and that evidence must survive the crash. Without this the CLI
    # could only build a fresh empty result and the hits were thrown away.
    # Modules set it; nothing else should read it except the CLI's recovery path.
    partial: object = None
    # Optional research feature. Never installs a dependency or fetches rules.
    patterns: bool = False
    pattern_paths: tuple = ()
    # Local, per-user COM server files discovered by the host check. Only the
    # optional pattern module consumes these; explicit --pattern-path wins.
    pattern_candidate_paths: tuple = ()
    pattern_candidate_omitted: int = 0
    # Opt-in search for disguised indicators and hidden code (--obfuscated).
    obfuscated: bool = False
