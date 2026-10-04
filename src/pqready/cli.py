"""pqready: grade how ready a TLS endpoint is for post-quantum cryptography."""

from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import __version__
from .grade import LETTERS, grade
from .report import render_json, render_markdown, render_terminal
from .scan import Target, scan


def _targets(args) -> list[Target]:
    specs = list(args.targets)
    if args.file:
        for line in Path(args.file).read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                specs.append(line)
    return [Target.parse(s, args.connect) for s in specs]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pqready", description=__doc__)
    ap.add_argument("targets", nargs="*", help="host or host:port")
    ap.add_argument("-f", "--file", help="file with one target per line")
    ap.add_argument("--connect", help="dial this IP instead of resolving the host (scan an origin behind a CDN)")
    ap.add_argument("--cafile", help="extra CA bundle to trust (for lab or internal certificates)")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("-w", "--workers", type=int, default=8, help="targets scanned in parallel")
    ap.add_argument("--json", metavar="PATH", help="write a JSON report")
    ap.add_argument("--md", metavar="PATH", help="write a Markdown report")
    ap.add_argument("--fail-under", choices=LETTERS, help="exit 1 if any target grades below this (for CI)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true", help="only print the summary")
    ap.add_argument("--version", action="version", version=f"pqready {__version__}")
    args = ap.parse_args(argv)

    targets = _targets(args)
    if not targets:
        ap.error("give at least one target or --file")

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        scans = list(pool.map(lambda t: scan(t, args.cafile, args.timeout), targets))
    results = [(r, grade(r)) for r in scans]

    color = sys.stdout.isatty() and not args.no_color
    if args.quiet:
        from .report import summary_line
        print(summary_line(results))
    else:
        print(render_terminal(results, color), end="")
    if args.json:
        Path(args.json).write_text(render_json(results))
    if args.md:
        Path(args.md).write_text(render_markdown(results))

    if args.fail_under:
        limit = LETTERS.index(args.fail_under)
        failing = [r.target.label for r, g in results if g.letter == "ERR" or LETTERS.index(g.letter) > limit]
        if failing:
            print(f"below {args.fail_under}: {', '.join(failing)}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
