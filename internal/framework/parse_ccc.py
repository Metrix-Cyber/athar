"""Parse NCA CCC-2:2024 into a catalogue plus an ECC cross-mapping.

Two things distinguish this from the ECC parser.

First, the CCC splits every domain into CSP (provider) and CST (tenant)
control sets, encoded in the clause as 2-2-P-1 and 2-2-T-1. They are not
alternatives: a tenant is assessed against the T controls and has no
obligation under the P controls. Merging them would tell a customer they are
non-compliant with requirements that are their provider's responsibility.

Second, the document states its own ECC cross-references — "In addition to
Subcontrols in the ECC control 2-2-3, the CST shall cover...". Those mappings
are the NCA's, not a judgement made here, which makes them defensible in a way
an inferred mapping would not be. They are extracted rather than invented.
"""

import json
import re
import sys
from pathlib import Path

SRC = Path(sys.argv[1] if len(sys.argv) > 1 else "ccc.txt")
OUT = Path(sys.argv[2] if len(sys.argv) > 2 else "ccc_catalog.json")
MAP = Path(sys.argv[3] if len(sys.argv) > 3 else "ccc_mapping.json")

DOMAINS = {
    "1": "Cybersecurity Governance",
    "2": "Cybersecurity Defence",
    "3": "Cybersecurity Resilience",
    "4": "Third-Party and Cloud Computing Cybersecurity",
}

AUDIENCE = {"P": "csp", "T": "cst"}

NOISE = re.compile(
    r"^\s*(Document classification|TLP:|Cloud Cybersecurity Controls|FIGURE|"
    r"Objective\b|Controls\s*$|[-\s]*$|\d+\s*$)", re.I)

# 2-2-P-1 / 2-2-T-1  (main control)
MAIN = re.compile(r"(?<![\d-])(\d)-(\d{1,2})-([PT])-(\d{1,2})(?![\d-])")
# 2-2-P-1-1 (subcontrol)
SUB = re.compile(r"(?<![\d-])(\d)-(\d{1,2})-([PT])-(\d{1,2})-(\d{1,2})(?![\d-])")
# "In addition to Subcontrols in the ECC control 2-2-3" / "ECC controls 1-9-3 and 1-9-4"
ECCREF = re.compile(
    r"ECC controls?\s+((?:\d+-\d+(?:-\d+)*)(?:\s+and\s+\d+-\d+(?:-\d+)*)*)", re.I)
ECCCODE = re.compile(r"\d+-\d+(?:-\d+)*")


def clean(lines):
    out = []
    for ln in lines:
        if NOISE.match(ln):
            continue
        ascii_ratio = sum(c.isascii() for c in ln) / max(len(ln), 1)
        if ln.strip() and ascii_ratio < 0.6:
            continue
        if ln.strip():
            out.append(ln.rstrip())
    return out


def parse(lines):
    controls = {}
    order = []
    links = []          # (ecc_code, ccc_code, audience)
    pending_ecc = []     # ECC codes seen since the last clause
    pending_sub = None   # CCC subdomain those codes were introduced under
    cur = None

    for ln in lines:
        # Capture ECC cross-references; they precede the clauses they apply to.
        m = ECCREF.search(ln)
        if m:
            pending_ecc = ECCCODE.findall(m.group(1))
            pending_sub = None  # bound to the first clause that follows

        # Subcontrols first: a line may hold both forms, and the subcontrol is
        # the more specific match.
        sm = SUB.search(ln)
        if sm:
            code = sm.group(0)
            if code not in controls:
                controls[code] = {
                    "kind": "subcontrol",
                    "audience": AUDIENCE[sm.group(3)],
                    "subdomain": f"{sm.group(1)}-{sm.group(2)}",
                    "parent": f"{sm.group(1)}-{sm.group(2)}-{sm.group(3)}-{sm.group(4)}",
                    "text": [],
                }
                order.append(code)
                sub = f"{sm.group(1)}-{sm.group(2)}"
                # A cross-reference applies to the clauses of the section that
                # introduced it. Without this guard the reference leaks past
                # the section boundary and the next subdomain's first control
                # inherits it — observed putting ECC 2-2-3 onto CCC 2-3-P-1,
                # which would file a finding under a control it does not
                # evidence.
                if pending_sub is None:
                    pending_sub = sub
                if pending_sub == sub:
                    for ecc in pending_ecc:
                        links.append((ecc, code, AUDIENCE[sm.group(3)]))
            rest = ln[sm.end():].strip()
            if rest:
                controls[code]["text"].append(rest)
            cur = code
            continue

        mm = MAIN.search(ln)
        if mm and mm.start() <= 12:
            code = mm.group(0)
            if code not in controls:
                controls[code] = {
                    "kind": "control",
                    "audience": AUDIENCE[mm.group(3)],
                    "subdomain": f"{mm.group(1)}-{mm.group(2)}",
                    "parent": None,
                    "text": [],
                }
                order.append(code)
                sub = f"{mm.group(1)}-{mm.group(2)}"
                if pending_sub is None:
                    pending_sub = sub
                if pending_sub == sub:
                    for ecc in pending_ecc:
                        links.append((ecc, code, AUDIENCE[mm.group(3)]))
            rest = ln[mm.end():].strip()
            if rest:
                controls[code]["text"].append(rest)
            cur = code
            continue

        if cur and ln.strip():
            controls[cur]["text"].append(ln.strip())

    return controls, order, links


def main():
    lines = clean(SRC.read_text(encoding="utf-8", errors="replace").splitlines())
    controls, order, links = parse(lines)

    out_controls = []
    for code in order:
        c = controls[code]
        text = re.sub(r"\s{2,}", " ", " ".join(c["text"])).strip()
        entry = {
            "code": code,
            "subdomain": c["subdomain"],
            "parent": c["parent"],
            "kind": c["kind"],
            "audience": c["audience"],
            "text": text,
        }
        if len(text) < 20:
            entry["needs_review"] = True
        out_controls.append(entry)

    subdomains = {}
    for c in out_controls:
        d = c["subdomain"].split("-")[0]
        subdomains.setdefault(c["subdomain"], {
            "code": c["subdomain"], "domain": d,
            "domain_name": DOMAINS.get(d, ""), "title": "",
        })

    catalog = {
        "framework": "NCA CCC-2:2024",
        "source": "https://nca.gov.sa/en/regulatory-documents/controls-list/ccc/",
        "domains": [{"code": k, "name": v} for k, v in DOMAINS.items()],
        "subdomains": [subdomains[k] for k in sorted(
            subdomains, key=lambda x: tuple(int(i) for i in x.split("-")))],
        "controls": out_controls,
    }
    OUT.write_text(json.dumps(catalog, indent=2, ensure_ascii=False), encoding="utf-8")

    # Deduplicate mapping links.
    seen, mapping = set(), []
    for ecc, ccc, aud in links:
        key = (ecc, ccc)
        if key in seen:
            continue
        seen.add(key)
        mapping.append({"from": ecc, "to": ccc, "audience": aud})
    MAP.write_text(json.dumps({
        "from_framework": "NCA ECC-2:2024",
        "to_framework": "NCA CCC-2:2024",
        "note": "Extracted from explicit cross-references in the CCC document "
                "(\"In addition to Subcontrols in the ECC control ...\"). These "
                "are the NCA's own correspondences, not inferred.",
        "links": mapping,
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    csp = [c for c in out_controls if c["audience"] == "csp"]
    cst = [c for c in out_controls if c["audience"] == "cst"]
    print(f"subdomains        : {len(subdomains)} / 24")
    print(f"CSP main controls : {len([c for c in csp if c['kind']=='control'])} / 37")
    print(f"CSP subcontrols   : {len([c for c in csp if c['kind']=='subcontrol'])} / 94")
    print(f"CST main controls : {len([c for c in cst if c['kind']=='control'])} / 18")
    print(f"CST subcontrols   : {len([c for c in cst if c['kind']=='subcontrol'])} / 26")
    print(f"ECC->CCC links    : {len(mapping)}")
    nr = [c['code'] for c in out_controls if c.get('needs_review')]
    print(f"needs_review      : {len(nr)}")


if __name__ == "__main__":
    main()
