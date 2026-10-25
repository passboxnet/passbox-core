#!/usr/bin/env python3
"""Refreshes the bundled snapshot of the Have I Been Pwned breach catalogue.

Clients match their saved logins against the catalogue on the device (the
`breached_site` finding of the security analysis). Normally they get the
catalogue from their Passbox server (`GET /api/v1/breaches/catalog`), which
refreshes it from Have I Been Pwned every few hours. This snapshot is the
fallback for servers that turn the catalogue off (`PASSBOX_BREACH_CATALOG=off`,
air-gapped installations) and for clients that have not fetched it yet.

The breach data is licensed under CC BY 4.0 by Have I Been Pwned
(https://haveibeenpwned.com/); the apps name the source wherever they show
it, see THIRD_PARTY_NOTICES.md. Run it from the repository root:

    python3 scripts/update-breach-catalog.py              # download
    python3 scripts/update-breach-catalog.py --from FILE  # use a saved /breaches response

The filter matches the server's (crates/server/src/api/breach_catalog.rs):
entries without a domain, fabricated entries, spam lists and retired
breaches are left out. Afterwards update the date in THIRD_PARTY_NOTICES.md,
run `cargo test -p passbox-core analysis` and commit the file.
"""

import argparse
import datetime
import json
import os
import sys
import urllib.request

URL = "https://haveibeenpwned.com/api/v3/breaches"
OUT = os.path.join("crates", "core", "data", "site-breaches.tsv")


def fetch():
    request = urllib.request.Request(URL, headers={"User-Agent": "Passbox-breach-catalog-snapshot"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def clean(text):
    return " ".join(str(text or "").replace("\t", " ").split())


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--from", dest="source", help="a saved /api/v3/breaches response")
    args = parser.parse_args()
    if args.source:
        with open(args.source, encoding="utf-8") as f:
            breaches = json.load(f)
    else:
        breaches = fetch()
    rows = []
    for b in breaches:
        domain = clean(b.get("Domain")).lower()
        if not domain or b.get("IsFabricated") or b.get("IsSpamList") or b.get("IsRetired"):
            continue
        flags = ("v" if b.get("IsVerified") else "") + ("s" if b.get("IsSensitive") else "")
        classes = ";".join(clean(c) for c in b.get("DataClasses") or [])
        rows.append(
            "\t".join(
                [
                    clean(b["Name"]),
                    clean(b.get("Title")) or clean(b["Name"]),
                    domain,
                    clean(b.get("BreachDate")),
                    clean(b.get("AddedDate")),
                    clean(b.get("ModifiedDate")),
                    str(int(b.get("PwnCount") or 0)),
                    flags,
                    classes,
                ]
            )
        )
    rows.sort(key=lambda r: r.split("\t", 1)[0].lower())
    today = datetime.date.today().isoformat()
    header = [
        f"# Have I Been Pwned breach catalogue, snapshot of {today}",
        "# Source: https://haveibeenpwned.com/api/v3/breaches (CC BY 4.0, https://haveibeenpwned.com/)",
        "# name\ttitle\tdomain\tbreach date\tadded\tmodified\taccounts\tflags (v verified, s sensitive)\tdata classes",
    ]
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(header + rows) + "\n")
    print(f"wrote {len(rows)} breaches to {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
