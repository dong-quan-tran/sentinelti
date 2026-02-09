from __future__ import annotations

import json
import argparse

from sentinelti.scoring import enrich_score

#from urllib.parse import urlparse
#import tldextract
#from .scoring import enrich_score

from .db import init_db
from .feeds.urlhaus import upsert_indicators_from_urlhaus
from sentinelti.ml.service import score_url, score_urls


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SentinelTI - Threat Intelligence Aggregator"
    )

    subparsers = parser.add_subparsers(dest="command")

    # init command
    subparsers.add_parser("init", help="Initialize the SQLite database")

    # ingest command
    ingest_parser = subparsers.add_parser(
        "ingest", help="Ingest data from a threat intel feed"
    )
    ingest_parser.add_argument(
        "feed",
        choices=["urlhaus"],
        help="Feed name to ingest (currently only 'urlhaus')",
    )

    # score-url command
    score_parser = subparsers.add_parser(
        "score-url", help="Score a single URL with the ML classifier"
    )
    score_parser.add_argument(
        "url",
        help="URL to score",
    )
    score_parser.add_argument(
        "--json",
        action="store_true",
        help="Output result as JSON instead of a Python dict.",
    )
    score_parser.add_argument(
        "--json-pretty",
        action="store_true",
        help="Pretty-print JSON output (implies --json).",
    )
    # score-urls command (optional batch mode)
    score_batch_parser = subparsers.add_parser(
        "score-urls", help="Score multiple URLs (space-separated) with the ML classifier"
    )
    score_batch_parser.add_argument(
        "urls",
        nargs="+",
        help="One or more URLs to score",
    )
    score_batch_parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON list instead of line-by-line dicts.",
    )
    score_batch_parser.add_argument(
        "--json-pretty",
        action="store_true",
        help="Pretty-print JSON output (implies --json).",
    )
    args = parser.parse_args()

    if args.command == "init":
        init_db()
        print("Database initialized.")

    elif args.command == "ingest":
        if args.feed == "urlhaus":
            print("Ingesting URLhaus feed...")
            upsert_indicators_from_urlhaus()
            print("Done.")

    elif args.command == "score-url":
        result = enrich_score(args.url)
        
        if args.json or args.json_pretty:
            indent = 2 if args.json_pretty else None               
            print(json.dumps(result, indent=indent))
        else:
            print(result)

    elif args.command == "score-urls":
        results = [enrich_score(url) for url in args.urls]

        if args.json or args.json_pretty:
            indent = 2 if args.json_pretty else None
            print(json.dumps(results, indent=indent))
        else:
            for result in results:
                print(result)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

