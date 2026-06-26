#!/usr/bin/env python3
import argparse
import csv
import gzip
import io
import json
import sys
import urllib.request

EPSS_CSV = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _read(src):
    if src.startswith(("http://", "https://")):
        return urllib.request.urlopen(src, timeout=30).read()
    with open(src, "rb") as f:
        return f.read()


def _maybe_gunzip(raw):
    return gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw


def load_epss(src):
    text = _maybe_gunzip(_read(src)).decode("utf-8")
    scores = {}
    for row in csv.reader(io.StringIO(text)):
        if not row or row[0].startswith("#") or row[0] == "cve":
            continue
        scores[row[0]] = (float(row[1]), float(row[2]))
    return scores


def load_kev(src):
    data = json.loads(_read(src))
    return {v["cveID"]: (v.get("dueDate") or "")
            for v in data.get("vulnerabilities", [])}


def epss_class(score):
    if score is None:
        return ""
    if score >= 0.5:
        return "epss-high"
    if score >= 0.1:
        return "epss-med"
    return "epss-low"


def build_custom(cve, epss, kev):
    score, pct = epss.get(cve, (None, None))
    return {
        "EPSS": f"{score * 100:.1f}%" if score is not None else "-",
        "EPSSScore": score,
        "Percentile": f"{pct * 100:.0f}" if pct is not None else "-",
        "EPSSClass": epss_class(score),
        "KEV": cve in kev,
        "KEVDueDate": kev.get(cve, ""),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report", help="rapport Trivy JSON (trivy --format json)")
    ap.add_argument("-o", "--out", required=True, help="JSON enrichi de sortie")
    ap.add_argument("--epss-file", default=EPSS_CSV,
                    help="CSV EPSS local (.csv/.csv.gz) ou URL (defaut: FIRST)")
    ap.add_argument("--kev-file", default=KEV_JSON,
                    help="JSON KEV CISA local ou URL (defaut: CISA)")
    ap.add_argument("--no-sort", action="store_true",
                    help="ne pas reordonner les vulns par exploitabilite")
    args = ap.parse_args()

    with open(args.report) as f:
        report = json.load(f)

    epss = load_epss(args.epss_file)
    kev = load_kev(args.kev_file)

    for result in report.get("Results", []) or []:
        vulns = result.get("Vulnerabilities") or []
        for v in vulns:
            v["Custom"] = build_custom(v.get("VulnerabilityID", ""), epss, kev)
        if not args.no_sort:
            vulns.sort(key=lambda v: (not v["Custom"]["KEV"],
                                      -(v["Custom"]["EPSSScore"] or 0)))

    with open(args.out, "w") as f:
        json.dump(report, f)

    total = sum(len(r.get("Vulnerabilities") or [])
                for r in report.get("Results", []) or [])
    kevn = sum(1 for r in report.get("Results", []) or []
               for v in (r.get("Vulnerabilities") or []) if v["Custom"]["KEV"])
    print(f"enrichi: {total} vulns, dont {kevn} dans KEV", file=sys.stderr)


if __name__ == "__main__":
    main()
