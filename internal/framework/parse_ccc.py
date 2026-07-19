"""Parse the CCC catalogue from raw reading order.

The first catalogue came from `pdftotext -layout`, which preserves visual
columns and interleaves margin headings into body text. That cost real clauses:
2-1-P-1-1 and 2-4-T-1-1 exist in the document but were absent from the
catalogue, which only surfaced when a mapping link pointed at a clause the
catalogue could not resolve.

Raw reading order has no columns to confuse, so clauses appear in sequence.
Text between one clause code and the next belongs to the first.
"""

import json
import re
import sys
from pathlib import Path

SRC = Path(sys.argv[1] if len(sys.argv) > 1 else "ccc_raw.txt")
OUT = Path(sys.argv[2] if len(sys.argv) > 2 else "ccc_catalog.json")

DOMAINS = {
    "1": "Cybersecurity Governance",
    "2": "Cybersecurity Defence",
    "3": "Cybersecurity Resilience",
    "4": "Third-Party and Cloud Computing Cybersecurity",
}

CODE = re.compile(r"(?<![\d-])(\d)-(\d{1,2})-([PT])-(\d{1,2})(?:-(\d{1,2}))?(?![\d-])")
NOISE = re.compile(
    r"Document classification: Public|TLP: White|Cloud Cybersecurity Controls|"
    r"Sharing Indicator", re.I)


def main():
    text = SRC.read_text(encoding="utf-8", errors="replace")
    text = NOISE.sub(" ", text)
    text = re.sub(r"\s+", " ", text)

    matches = list(CODE.finditer(text))
    if not matches:
        print("no clause codes found")
        return

    controls, seen = [], set()
    for i, m in enumerate(matches):
        code = m.group(0)
        if code in seen:
            continue
        seen.add(code)

        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[m.end():end].strip()
        # Trim at the next section heading, which follows a full stop.
        body = re.sub(r"\s{2,}", " ", body)[:400].strip()

        entry = {
            "code": code,
            "subdomain": f"{m.group(1)}-{m.group(2)}",
            "parent": (f"{m.group(1)}-{m.group(2)}-{m.group(3)}-{m.group(4)}"
                       if m.group(5) else None),
            "kind": "subcontrol" if m.group(5) else "control",
            "audience": "csp" if m.group(3) == "P" else "cst",
            "text": body,
        }
        if len(body) < 20:
            entry["needs_review"] = True
        controls.append(entry)

    controls.sort(key=lambda c: tuple(
        int(x) if x.isdigit() else {"P": 0, "T": 1}[x] for x in c["code"].split("-")))

    subdomains = {}
    for c in controls:
        d = c["subdomain"].split("-")[0]
        subdomains.setdefault(c["subdomain"], {
            "code": c["subdomain"], "domain": d,
            "domain_name": DOMAINS.get(d, ""), "title": "",
        })

    OUT.write_text(json.dumps({
        "framework": "NCA CCC-2:2024",
        "source": "https://nca.gov.sa/en/regulatory-documents/controls-list/ccc/",
        "domains": [{"code": k, "name": v} for k, v in DOMAINS.items()],
        "subdomains": [subdomains[k] for k in sorted(
            subdomains, key=lambda x: tuple(int(i) for i in x.split("-")))],
        "controls": controls,
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    csp = [c for c in controls if c["audience"] == "csp"]
    cst = [c for c in controls if c["audience"] == "cst"]
    print(f"subdomains        : {len(subdomains)} / 24")
    print(f"CSP main controls : {len([c for c in csp if c['kind']=='control'])} / 37")
    print(f"CSP subcontrols   : {len([c for c in csp if c['kind']=='subcontrol'])} / 94")
    print(f"CST main controls : {len([c for c in cst if c['kind']=='control'])} / 18")
    print(f"CST subcontrols   : {len([c for c in cst if c['kind']=='subcontrol'])} / 26")
    print(f"needs_review      : {len([c for c in controls if c.get('needs_review')])}")


if __name__ == "__main__":
    main()
