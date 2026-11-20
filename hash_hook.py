"""
©AngelaMos | 2026
hash_hook.py

pre-commit hook that refuses commits containing likely password hashes
"""

from __future__ import annotations

import re
import sys
from collections.abc import Sequence
from pathlib import Path

from hash_identifier import HashCandidate, identify

# Put this marker in a comment on any line that is a deliberate fixture
ALLOW_MARKER = "pragma: allow-hash"

# Real password hashes are long (bcrypt is 60 chars, MD5-crypt is 34).
# Shorter pieces like `$2b$...` in a docstring or `$S$` in math are not hashes
MIN_HASH_LENGTH = 20

# Docs and examples abbreviate hashes with `...`. A real hash never contains it
PLACEHOLDER = "..."

# A line is split into "words" on whitespace, quotes, brackets, commas, '='
_WORD_SPLIT = re.compile(r"""[\s'"`,;=()\[\]{}<>]+""")


def _pieces(line: str) -> list[str]:
    """
    Everything on one line worth feeding to identify()

    The whole line (for files that are just one hash per line), each word
    (for `password = "$2b$..."`), and each colon part of a word
    (for `user:hash`). Duplicates removed, order kept
    """
    stripped = line.strip()
    words = _WORD_SPLIT.split(stripped)
    colon_parts = [part for word in words for part in word.split(":")]
    out: list[str] = []
    for piece in [stripped, *words, *colon_parts]:
        if piece and piece not in out:
            out.append(piece)
    return out


def _is_blocking(candidate: HashCandidate) -> bool:
    """High confidence, and not one of the 'might not be a hash' guesses"""
    if candidate.confidence != "high":
        return False
    name = candidate.algorithm.lower()
    return "(not a" not in name and "phc" not in name


def scan_file(path: Path) -> list[tuple[int, str, str]]:
    """
    Return (line_number, algorithm, shortened_text) for each offending line

    Unreadable or binary files are skipped, not treated as errors
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []

    findings: list[tuple[int, str, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if ALLOW_MARKER in line:
            continue
        for piece in _pieces(line):
            if len(piece) < MIN_HASH_LENGTH or PLACEHOLDER in piece:
                continue
            candidates = identify(piece)
            if candidates and _is_blocking(candidates[0]):
                # Only show the start, so the hash isn't copied into CI logs
                findings.append((number, candidates[0].algorithm, piece[:12] + "..."))
                break  # one finding per line is enough
    return findings


def main(argv: Sequence[str] | None = None) -> int:
    """pre-commit passes the changed filenames as arguments. 1 blocks, 0 allows"""
    paths = [Path(arg) for arg in (sys.argv[1:] if argv is None else argv)]

    found_any = False
    for path in paths:
        for number, algorithm, snippet in scan_file(path):
            print(f"{path}:{number}: looks like a {algorithm} hash ({snippet})")
            found_any = True

    if found_any:
        print(f"\nCommit blocked. If it's a deliberate fixture, add `{ALLOW_MARKER}` "
              "in a comment on that line.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())