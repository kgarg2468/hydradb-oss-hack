#!/usr/bin/env python3
"""Build poc/incident-chalk-debug.json.

The package/version list comes from the public write-ups (Aikido, Semgrep, Wiz,
Sonatype). Every publish timestamp is then verified against the npm registry's
own `time` map, which is the authoritative record and survives unpublish.
"""

import json
import os
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))

# package -> (malicious version, remediated/clean version if one was published same day)
WAVE1 = [
    ("ansi-styles", "6.2.2", "6.2.3"),
    ("debug", "4.4.2", None),
    ("chalk", "5.6.1", "5.6.2"),
    ("supports-color", "10.2.1", "10.2.2"),
    ("strip-ansi", "7.1.1", "7.1.2"),
    ("ansi-regex", "6.2.1", "6.2.2"),
    ("wrap-ansi", "9.0.1", "9.0.2"),
    ("color-convert", "3.1.1", None),
    ("color-name", "2.0.1", None),
    ("is-arrayish", "0.3.3", None),
    ("slice-ansi", "7.1.1", "7.1.2"),
    ("error-ex", "1.3.3", None),
    ("color-string", "2.1.1", None),
    ("color", "5.0.1", None),
    ("simple-swizzle", "0.2.3", None),
    ("supports-hyperlinks", "4.1.1", "4.1.2"),
    ("has-ansi", "6.0.1", "6.0.2"),
    ("chalk-template", "1.1.1", "1.1.2"),
    ("backslash", "0.2.1", None),
]

# Second account compromise by the same actor, tracked separately.
WAVE2 = [
    ("proto-tinker-wc", "0.1.87", None),
    ("duckdb", "1.3.3", None),
    ("@duckdb/node-api", "1.3.3", None),
    ("@duckdb/node-bindings", "1.3.3", None),
    ("@duckdb/duckdb-wasm", "1.29.2", None),
]


def registry(pkg):
    url = "https://registry.npmjs.org/" + urllib.request.quote(pkg, safe="@")
    with urllib.request.urlopen(url, timeout=40) as fh:
        return json.load(fh)


def collect(rows, wave):
    out = []
    for pkg, bad, fixed in rows:
        try:
            doc = registry(pkg)
        except Exception as exc:
            print(f"  registry lookup failed for {pkg}: {exc}")
            out.append({"package": pkg, "malicious_version": bad, "wave": wave})
            continue
        times = doc.get("time", {})
        versions = doc.get("versions", {})
        rec = {
            "package": pkg,
            "malicious_version": bad,
            "wave": wave,
            "published_at": times.get(bad),
            "still_present_in_registry": bad in versions,
            "remediated_version": fixed,
            "remediated_published_at": times.get(fixed) if fixed else None,
        }
        out.append(rec)
        print(f"  {pkg}@{bad} published={rec['published_at']} still_listed={rec['still_present_in_registry']}")
    return out


def main():
    print("wave 1 (Qix account takeover):")
    w1 = collect(WAVE1, 1)
    print("wave 2 (follow-on account compromise):")
    w2 = collect(WAVE2, 2)

    published = [r["published_at"] for r in w1 if r.get("published_at")]
    doc = {
        "incident": "npm supply-chain compromise of chalk/debug and 17 related packages",
        "date": "2025-09-08",
        "root_cause": (
            "Maintainer 'Qix' was phished via a fake npm 2FA-reset email from the "
            "look-alike domain npmjs.help (registered 2025-09-05). The attacker "
            "captured username, password and a live TOTP code and took over the account."
        ),
        "payload": (
            "Browser-side crypto-clipper. Hooked fetch/XMLHttpRequest and wallet APIs "
            "(window.ethereum, Solana) and rewrote payment destinations to attacker "
            "addresses before signing. No OS/filesystem persistence."
        ),
        "window": {
            "first_malicious_publish_utc": min(published) if published else None,
            "last_wave1_malicious_publish_utc": max(published) if published else None,
            "community_detection_utc": "2025-09-08T15:20:00Z",
            "first_remediated_publish_utc": "2025-09-08T14:47:54.486Z",
            "last_wave1_remediated_publish_utc": "2025-09-08T15:14:43.242Z",
            "practical_exposure_window_utc": [
                "2025-09-08T13:12:10Z",
                "2025-09-08T15:30:00Z",
            ],
            "note": (
                "Exposure required resolving a floating range to a malicious version "
                "during the window. A committed lockfile pinning a pre-incident version "
                "was NOT exposed - this is exactly what the as-of query has to prove."
            ),
        },
        "sources": [
            "https://registry.npmjs.org/<package> (time field) - authoritative publish timestamps, queried by build_incident.py",
            "https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised",
            "https://semgrep.dev/blog/2025/chalk-debug-and-color-on-npm-compromised-in-new-supply-chain-attack/",
            "https://www.wiz.io/blog/widespread-npm-supply-chain-attack-breaking-down-impact-scope-across-debug-chalk",
            "https://www.sonatype.com/blog/npm-chalk-and-debug-packages-hit-in-software-supply-chain-attack",
            "https://vercel.com/blog/critical-npm-supply-chain-attack-response-september-8-2025",
        ],
        "packages": w1 + w2,
    }

    path = os.path.join(HERE, "incident-chalk-debug.json")
    with open(path, "w") as fh:
        json.dump(doc, fh, indent=2)
    print(f"\nwrote {path} with {len(doc['packages'])} packages")


if __name__ == "__main__":
    main()
