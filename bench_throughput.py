"""
bench_throughput.py

Measure how fast hash_identifier processes a file of hashes, stage by
stage, so we can see WHERE the time goes

Usage:
    uv run python bench_throughput.py hibp-1000.txt
"""

import io
import json
import sys
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path

from rich.console import Console

from hash_identifier import identify

# Each stage runs over the whole file this many times. One pass over
# 1000 hashes takes milliseconds, which is too short to time reliably
REPEATS = 20
TOP = 5


def _load(path: str) -> list[str]:
    """Return the non-blank, stripped lines of the file"""
    text = Path(path).read_text(encoding = "utf-8")
    return [line.strip() for line in text.splitlines() if line.strip()]


def _stage_identify(hashes: list[str]) -> None:
    """Stage 1: the identifier and nothing else"""
    for h in hashes:
        identify(h)


def _stage_json(hashes: list[str]) -> None:
    """Stage 2: identify, then serialise one JSON object per line"""
    out = io.StringIO()
    for h in hashes:
        record = {
            "input": h,
            "candidates": [asdict(c) for c in identify(h)[:TOP]],
        }
        out.write(json.dumps(record) + "\n")


def _stage_plain(hashes: list[str]) -> None:
    """Stage 3: identify, then write one plain text line per hash"""
    out = io.StringIO()
    for h in hashes:
        candidates = identify(h)
        if candidates:
            top = candidates[0]
            out.write(f"{h} -> {top.algorithm} ({top.confidence})\n")


def _stage_rich(hashes: list[str]) -> None:
    """Stage 4: identify, then print through rich, like batch mode"""
    console = Console(file = io.StringIO(), width = 120)
    for h in hashes:
        candidates = identify(h)
        if candidates:
            top = candidates[0]
            console.print(
                f"[green]{h}[/green] -> {top.algorithm} "
                f"({top.confidence} confidence)"
            )


def _time(label: str, work: Callable[[list[str]], None], hashes: list[str]) -> float:
    """Run `work` REPEATS times, print the rate, return seconds per hash"""
    start = time.perf_counter()
    for _ in range(REPEATS):
        work(hashes)
    elapsed = time.perf_counter() - start
    total = len(hashes) * REPEATS
    per_hash = elapsed / total
    print(f"{label:<30} {total / elapsed:>10,.0f} hashes/s {per_hash * 1e6:>9.1f} us/hash")
    return per_hash


def main() -> int:
    """Verify the classification, then time each stage"""
    if len(sys.argv) != 2:
        print("usage: python bench_throughput.py <file-of-hashes>")
        return 2

    hashes = _load(sys.argv[1])
    print(f"{len(hashes)} hashes loaded\n")

    # ----- Part 1: what did identify() say about every line? -----
    verdicts: Counter[str] = Counter()
    for h in hashes:
        candidates = identify(h)
        if candidates:
            top = candidates[0]
            verdicts[f"{top.algorithm} ({top.confidence})"] += 1
        else:
            verdicts["NOT IDENTIFIED"] += 1
    print("Top candidate per hash:")
    for verdict, count in verdicts.most_common():
        print(f"  {count:>6}  {verdict}")

    # ----- Part 2: how fast is each stage? -----
    print(f"\nThroughput ({REPEATS} passes over the file per stage):")
    results = {
        "identify": _time("1. identify only", _stage_identify, hashes),
        "json": _time("2. identify + JSON", _stage_json, hashes),
        "plain": _time("3. identify + plain write", _stage_plain, hashes),
        "rich": _time("4. identify + rich print", _stage_rich, hashes),
    }

    # ----- Part 3: what share of the rich pipeline is the brain? -----
    share = results["identify"] / results["rich"] * 100
    print(f"\nidentify() is {share:.0f}% of the time in the rich pipeline")
    return 0


if __name__ == "__main__":
    sys.exit(main()) 