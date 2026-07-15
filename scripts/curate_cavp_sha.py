#!/usr/bin/env python3
"""Offline maintainer tool: curate NIST CAVP SHA/SHA-3 .rsp files into the
vectors/ directory. The CAVP format is already key=value based; this script
samples ShortMsg/LongMsg records (they are thousands strong upstream), copies
Monte files whole (the MCT checkpoints chain, so all are needed), and stamps
an [algorithm = ...] group header plus a provenance header.

Usage:
  python3 scripts/curate_cavp_sha.py <cavp-dir> <cavp-dir2> ... --out vectors/digest

Source zips (fetch manually, they are not committed):
  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip
"""

import argparse
import datetime
import os
import re
import sys

# CAVP file stem -> JCA algorithm name (BCFIPS)
ALGORITHMS = {
    "SHA1": "SHA-1",
    "SHA224": "SHA-224",
    "SHA256": "SHA-256",
    "SHA384": "SHA-384",
    "SHA512": "SHA-512",
    "SHA512_224": "SHA-512(224)",
    "SHA512_256": "SHA-512(256)",
    "SHA3_224": "SHA3-224",
    "SHA3_256": "SHA3-256",
    "SHA3_384": "SHA3-384",
    "SHA3_512": "SHA3-512",
}

SHORT_KEEP = 12  # records sampled from each ShortMsg file
LONG_KEEP = 2    # records sampled from each LongMsg file


def parse_records(path):
    """Return (header_params, records) where records are lists of (k, v)."""
    params = []
    records = []
    current = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                if current:
                    records.append(current)
                    current = []
                continue
            if line.startswith("#"):
                continue
            m = re.match(r"\[(.+?)\s*=\s*(.+?)\]", line)
            if m:
                params.append((m.group(1), m.group(2)))
                continue
            k, _, v = line.partition("=")
            current.append((k.strip(), v.strip()))
    if current:
        records.append(current)
    return params, records


def sample(records, keep):
    if len(records) <= keep:
        return records
    step = max(1, len(records) // (keep - 1))
    picked = records[::step][: keep - 1]
    if records[-1] not in picked:
        picked.append(records[-1])
    return picked


def emit(out_path, algorithm, kind, source_file, params, records):
    lines = [
        "# source: NIST CAVP %s (%s)" % (source_file, kind),
        "# converted: %s by scripts/curate_cavp_sha.py - do not edit by hand"
        % datetime.date.today().isoformat(),
        "",
        "[algorithm = %s]" % algorithm,
    ]
    for k, v in params:
        lines.append("[%s = %s]" % (k, v))
    lines.append("")
    for rec in records:
        for k, v in rec:
            lines.append("%s = %s" % (k, v))
        lines.append("")
    with open(out_path, "w") as f:
        f.write("\n".join(lines).rstrip("\n") + "\n")
    print("%s: %d records" % (out_path, len(records)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dirs", nargs="+", help="unzipped CAVP directories")
    parser.add_argument("--out", required=True, help="output directory (vectors/digest)")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)
    converted = 0
    for d in args.dirs:
        for name in sorted(os.listdir(d)):
            m = re.match(r"(SHA[0-9_]*)(ShortMsg|LongMsg|Monte)\.rsp$", name)
            if not m or m.group(1) not in ALGORITHMS:
                continue
            algorithm = ALGORITHMS[m.group(1)]
            kind = m.group(2)
            params, records = parse_records(os.path.join(d, name))
            if kind == "ShortMsg":
                records = sample(records, SHORT_KEEP)
                suffix = "short-kat"
            elif kind == "LongMsg":
                records = sample(records, LONG_KEEP)
                suffix = "long-kat"
            else:
                suffix = "mct"  # Monte: keep everything, checkpoints chain
            out_name = "%s-%s.rsp" % (
                algorithm.lower().replace("(", "-").replace(")", ""), suffix)
            emit(os.path.join(args.out, out_name), algorithm, kind, name,
                 params, records)
            converted += 1
    if converted == 0:
        print("ERROR: no CAVP files recognized", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
