from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"


def _setup_logging(log_dir: Path, verbose: bool) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    handlers: list[logging.Handler] = [
        logging.StreamHandler(sys.stderr),
        logging.FileHandler(log_dir / "iocbot.log", encoding="utf-8"),
    ]
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format=LOG_FORMAT,
        handlers=handlers,
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="iocbot",
        description=(
            "IOC intelligence collector: gathers C2 / malware-distribution / "
            "cracked-software IOCs from public sources, deduplicates and scores "
            "them, and writes CSV exports for manual analyst review."
        ),
    )
    parser.add_argument(
        "--root",
        default=Path(__file__).resolve().parent.parent,
        help="project root (default: package parent directory)",
    )
    parser.add_argument("--config-dir", default=None, help="config directory (default: <root>/config)")
    parser.add_argument("--data-dir", default=None, help="data directory (default: <root>/data)")
    parser.add_argument("--output-dir", default=None, help="output directory (default: <root>/output)")
    parser.add_argument(
        "--sources",
        default=None,
        help="substring filter: only run sources whose name contains this string",
    )
    parser.add_argument(
        "--max-articles",
        type=int,
        default=None,
        help="per-feed cap on articles fetched this cycle",
    )
    parser.add_argument("--skip-reports", action="store_true", help="skip RSS/article sources")
    parser.add_argument("--skip-blocklists", action="store_true", help="skip Tier-C blocklists")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    parser.add_argument(
        "--json",
        action="store_true",
        help="print cycle stats as JSON to stdout instead of the summary",
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    config_dir = Path(args.config_dir) if args.config_dir else root / "config"
    data_dir = Path(args.data_dir) if args.data_dir else root / "data"
    output_dir = Path(args.output_dir) if args.output_dir else root / "output"

    for required in ("sources.yaml", "validation.yaml", "crowdstrike.yaml"):
        if not (config_dir / required).is_file():
            print(f"error: missing config file: {config_dir / required}", file=sys.stderr)
            return 2

    _setup_logging(data_dir / "logs", args.verbose)

    from .pipeline import Pipeline

    pipe = Pipeline(root, config_dir, data_dir, output_dir)
    stats = pipe.run(
        sources_filter=args.sources,
        max_articles=args.max_articles,
        skip_reports=args.skip_reports,
        skip_blocklists=args.skip_blocklists,
    )
    if args.json:
        print(json.dumps(stats, indent=2, default=str))
    else:
        summaries = sorted((output_dir / "daily").glob("*/IOC_SUMMARY.txt"))
        if summaries:
            print(summaries[-1].read_text(encoding="utf-8"))
        else:
            print(json.dumps(stats.get("export_counts", {}), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
