from __future__ import annotations

import argparse

from urllib.parse import urlparse
import tldextract

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

    # score-urls command (optional batch mode)
    score_batch_parser = subparsers.add_parser(
        "score-urls", help="Score multiple URLs (space-separated) with the ML classifier"
    )
    score_batch_parser.add_argument(
        "urls",
        nargs="+",
        help="One or more URLs to score",
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
        raw = score_url(args.url)
        result = enrich_score(args.url, raw)
        print(result)

    elif args.command == "score-urls":
        raws = score_urls(args.urls)
        for url, raw in zip(args.urls, raws):
            result = enrich_score(url, raw)
            print(result)

    else:
        parser.print_help()

def enrich_score(url: str, score_result: dict) -> dict:
    """
    Take the raw score_url() result and add heuristic-based fields:
    - final_label: 'benign', 'suspicious', or 'malicious'
    - risk: 'low', 'medium', 'high'
    - reasons: list of strings explaining why
    """
    prob = score_result.get("prob_malicious", 0.0)
    model_label = score_result.get("label", 0)

    parsed = urlparse(url)
    host = parsed.netloc or ""
    reasons: list[str] = []

    # Heuristic 1: @ in authority part
    if "@" in host:
        reasons.append("URL contains '@' in the authority part (possible obfuscation)")

    # Heuristic 2: raw IP address host
    # (simple check: all digits and dots, no letters)
    if host and all(c.isdigit() or c == "." for c in host):
        reasons.append("Host is a raw IP address")

    # Heuristic 3: suspicious tokens in host/path
    suspicious_tokens = [
        "login",
        "verify",
        "verification",
        "secure",
        "update",
        "account",
        "bank",
        "paypal",
        "appleid",
    ]
    lower_url = url.lower()
    if any(tok in lower_url for tok in suspicious_tokens):
        reasons.append("Contains suspicious tokens commonly used in phishing URLs")

    # Heuristic 4: unusual TLDs (very simple list; tune as needed)
    ext = tldextract.extract(url)
    tld = ext.suffix.lower()
    unusual_tlds = {"xyz", "top", "club", "click", "link"}
    if tld in unusual_tlds:
        reasons.append(f"Uses an uncommon TLD: .{tld}")

    # Decide final_label / risk
    if prob >= 0.8:
        final_label = "malicious"
        risk = "high"
    elif prob >= 0.5 or reasons:
        # medium if model is unsure but heuristics fire
        final_label = "suspicious"
        risk = "medium"
    else:
        final_label = "benign"
        risk = "low"

    enriched = dict(score_result)
    enriched.update(
        {
            "final_label": final_label,
            "risk": risk,
            "reasons": reasons,
        }
    )
    return enriched

if __name__ == "__main__":
    main()
