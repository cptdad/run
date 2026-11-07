#!/usr/bin/env python3
"""Compare two APKs entry by entry, ignoring only the signature.

    scripts/reproducible/compare-apks.py <a.apk> <b.apk>

Exit 0 when every ZIP entry (name, size, CRC-32, and the bytes themselves) matches and the
entry order is the same; 1 otherwise, listing what differs. The APK Signing Block (v2/v3) and
the v1 signature files under META-INF (MANIFEST.MF, *.SF, *.RSA/*.DSA/*.EC) are skipped, so a
signed APK can be compared with an unsigned rebuild of the same sources — which is exactly what
F-Droid does before it publishes the developer-signed APK (its tool is apksigcopier; this
script is the quick local check). Nothing else is ignored: a differing timestamp, a
re-ordered entry or a one-byte change in a .dex fails the comparison.
"""
import hashlib
import sys
import zipfile

SIG_PREFIX = "META-INF/"
SIG_SUFFIXES = (".SF", ".RSA", ".DSA", ".EC", "/MANIFEST.MF")


def is_signature_entry(name: str) -> bool:
    return name.startswith(SIG_PREFIX) and (name.endswith(SIG_SUFFIXES) or name == "META-INF/MANIFEST.MF")


def entries(path: str):
    with zipfile.ZipFile(path) as z:
        out = []
        for info in z.infolist():
            if is_signature_entry(info.filename):
                continue
            digest = hashlib.sha256(z.read(info.filename)).hexdigest()
            out.append((info.filename, info.file_size, info.CRC, info.compress_type, info.date_time, digest))
        return out


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    a, b = sys.argv[1], sys.argv[2]
    ea, eb = entries(a), entries(b)
    names_a = [e[0] for e in ea]
    names_b = [e[0] for e in eb]
    bad = 0
    only_a = sorted(set(names_a) - set(names_b))
    only_b = sorted(set(names_b) - set(names_a))
    for n in only_a:
        print(f"only in A: {n}")
        bad += 1
    for n in only_b:
        print(f"only in B: {n}")
        bad += 1
    if [n for n in names_a if n not in only_a] != [n for n in names_b if n not in only_b]:
        print("entry ORDER differs")
        bad += 1
    by_b = {e[0]: e for e in eb}
    for e in ea:
        o = by_b.get(e[0])
        if o is None:
            continue
        if e != o:
            what = []
            if e[1] != o[1]:
                what.append(f"size {e[1]} vs {o[1]}")
            if e[2] != o[2] or e[5] != o[5]:
                what.append("content")
            if e[3] != o[3]:
                what.append(f"compression {e[3]} vs {o[3]}")
            if e[4] != o[4]:
                what.append(f"timestamp {e[4]} vs {o[4]}")
            print(f"differs: {e[0]}: {', '.join(what)}")
            bad += 1
    compared = len(ea) - len(only_a)
    if bad:
        print(f"\n{bad} difference(s) over {compared} compared entries (signature entries skipped)")
        return 1
    print(f"identical: {compared} entries match byte for byte (signature entries skipped)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
