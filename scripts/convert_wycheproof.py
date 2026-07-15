#!/usr/bin/env python3
"""Offline maintainer tool: convert Wycheproof JSON test vectors into the
.rsp-style key=value format consumed by dev.chainguard.fipstest.util.VectorFile.

Never runs at test time. Regenerate committed vectors with something like:

  python3 scripts/convert_wycheproof.py /path/to/aes_gcm_test.json \
      vectors/aead/aes-gcm-wycheproof.rsp --source-ref <wycheproof commit>

Curation policy (matching the test plan): keep ALL records whose result is
not "valid" (the negative cases are the point), plus up to --valid-per-group
valid records per test group for positive coverage.

Only Python 3 stdlib is used.
"""

import argparse
import datetime
import json
import sys


def scalar(value):
    if isinstance(value, str):
        return "\n" not in value  # multi-line values (PEM blocks) break the format
    return isinstance(value, (int, float, bool))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="Wycheproof JSON file")
    parser.add_argument("output", help=".rsp output path")
    parser.add_argument("--source-ref", default="unknown",
                        help="wycheproof git commit/tag for the provenance header")
    parser.add_argument("--valid-per-group", type=int, default=3,
                        help="max 'valid' records kept per group (default 3)")
    parser.add_argument("--tcids", default="",
                        help="comma-separated tcIds to keep (overrides curation policy)")
    parser.add_argument("--flags", default="",
                        help="comma-separated flags; if set, also keep any record with one")
    args = parser.parse_args()

    with open(args.input) as f:
        data = json.load(f)

    keep_tcids = {int(t) for t in args.tcids.split(",") if t.strip()}
    keep_flags = {t for t in args.flags.split(",") if t.strip()}

    lines = []
    lines.append("# source: wycheproof %s (%s)" % (args.input.split("/")[-1], args.source_ref))
    lines.append("# algorithm: %s, schema: %s" % (
        data.get("algorithm", "?"), data.get("schema", data.get("generatorVersion", "?"))))
    lines.append("# converted: %s by scripts/convert_wycheproof.py - do not edit by hand"
                 % datetime.date.today().isoformat())
    lines.append("# curation: all non-valid records + up to %d valid per group"
                 % args.valid_per_group)
    lines.append("")

    total = kept = 0
    for group in data["testGroups"]:
        header_emitted = False
        valid_kept = 0
        for test in group["tests"]:
            total += 1
            result = test.get("result", "valid")
            if keep_tcids:
                selected = test["tcId"] in keep_tcids
            else:
                selected = result != "valid"
                if not selected and valid_kept < args.valid_per_group:
                    selected = True
                    valid_kept += 1
                if not selected and keep_flags and keep_flags & set(test.get("flags", [])):
                    selected = True
            if not selected:
                continue
            kept += 1
            if not header_emitted:
                for key, value in group.items():
                    if key not in ("tests",) and scalar(value):
                        lines.append("[%s = %s]" % (key, value))
                lines.append("")
                header_emitted = True
            for key, value in test.items():
                if key == "flags":
                    value = ",".join(value)
                if scalar(value) or key == "flags":
                    lines.append("%s = %s" % (key, value))
            lines.append("")

    with open(args.output, "w") as f:
        f.write("\n".join(lines).rstrip("\n") + "\n")

    print("%s: kept %d of %d records" % (args.output, kept, total))
    if kept == 0:
        print("ERROR: no records selected", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
