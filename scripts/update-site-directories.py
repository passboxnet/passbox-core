#!/usr/bin/env python3
"""Refreshes the bundled 2FA and passkey site lists used by the security analysis.

Downloads the public datasets of 2fa.directory (MIT) and the Passkeys
Directory (passkeys.2fa.directory, CC BY 4.0) and writes compact lists to
crates/core/data/. Clients never query these services per item; they only
ship the snapshot written here. Run it from the repository root:

    python3 scripts/update-site-directories.py            # download
    python3 scripts/update-site-directories.py --from DIR # use tfa.json/passkeys.json in DIR

Afterwards check the date in THIRD_PARTY_NOTICES.md, run the Rust tests
(`cargo test -p passbox-core analysis`) and commit the lists.
"""

import argparse
import datetime
import json
import os
import sys
import urllib.request

TFA_URL = "https://api.2fa.directory/v4/all.json"
PASSKEYS_URL = "https://passkeys-api.2fa.directory/v1/all.json"
OUT_DIR = os.path.join("crates", "core", "data")

# 2fa.directory method -> one-letter code in the bundled list.
METHODS = {
    "totp": "t",
    "u2f": "u",
    "sms": "s",
    "email": "e",
    "call": "c",
    "custom-software": "a",
    "custom-hardware": "h",
}


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "passbox-site-directories"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def clean_domain(domain):
    domain = domain.strip().lower().rstrip(".")
    if not domain or any(c in domain for c in " \t/:@") or "." not in domain:
        return None
    try:
        domain.encode("ascii")
    except UnicodeEncodeError:
        domain = domain.encode("idna").decode("ascii")
    return domain


def clean_url(url):
    url = (url or "").strip()
    if not url.startswith("https://") or any(c in url for c in "\t\r\n"):
        return ""
    return url


def write(path, header, rows):
    with open(path, "w", encoding="utf-8", newline="\n") as out:
        for line in header:
            out.write(f"# {line}\n")
        for row in sorted(rows):
            out.write("\t".join(row) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--from", dest="source", help="directory with tfa.json and passkeys.json")
    args = parser.parse_args()
    if args.source:
        with open(os.path.join(args.source, "tfa.json"), encoding="utf-8") as f:
            tfa = json.load(f)
        with open(os.path.join(args.source, "passkeys.json"), encoding="utf-8") as f:
            passkeys = json.load(f)
    else:
        tfa = fetch(TFA_URL)
        passkeys = fetch(PASSKEYS_URL)
    today = datetime.date.today().isoformat()

    tfa_rows = {}
    for domain, entry in tfa.items():
        methods = entry.get("methods") or []
        codes = "".join(sorted({METHODS[m] for m in methods if m in METHODS}))
        name = clean_domain(domain)
        if not codes or not name:
            continue
        tfa_rows[name] = (name, codes, clean_url(entry.get("documentation")))
    write(
        os.path.join(OUT_DIR, "twofactor-sites.tsv"),
        [
            f"2fa.directory snapshot of {today}, {TFA_URL}",
            "License: MIT, 2fa.directory contributors (see THIRD_PARTY_NOTICES.md)",
            "domain<TAB>methods<TAB>documentation; methods: t=TOTP u=security key s=SMS e=email"
            " c=call a=vendor app h=vendor hardware",
        ],
        tfa_rows.values(),
    )

    pk_rows = {}
    for domain, entry in passkeys.items():
        flags = ("p" if entry.get("passwordless") else "") + ("m" if entry.get("mfa") else "")
        name = clean_domain(domain)
        if not flags or not name:
            continue
        pk_rows[name] = (name, flags, clean_url(entry.get("documentation")))
    write(
        os.path.join(OUT_DIR, "passkey-sites.tsv"),
        [
            f"Passkeys Directory (passkeys.2fa.directory) snapshot of {today}, {PASSKEYS_URL}",
            "License: CC BY 4.0, Passkeys Directory contributors (see THIRD_PARTY_NOTICES.md)",
            "domain<TAB>flags<TAB>documentation; flags: p=passkey sign-in without password"
            " m=passkey as second factor",
        ],
        pk_rows.values(),
    )
    print(f"{len(tfa_rows)} sites with 2FA, {len(pk_rows)} sites with passkeys", file=sys.stderr)


if __name__ == "__main__":
    main()
