"""Parse NCA ECC-2:2024 extracted text into a structured control catalogue.

The source is pdftotext -layout output, whose line order is imperfect: control
codes sometimes appear after their own text, sometimes inline mid-line, and
subdomain headers use '-' in some places and '.' in others.

This parser is deliberately conservative. It extracts what it can prove and
reports counts against the document's stated totals (4 domains, 28 subdomains,
108 main controls, 92 subcontrols) so any shortfall is visible rather than
silently shipped as authoritative regulatory content.
"""

import json
import re
import sys
from pathlib import Path

SRC = Path(sys.argv[1] if len(sys.argv) > 1 else "ecc.txt")
OUT = Path(sys.argv[2] if len(sys.argv) > 2 else "ecc_catalog.json")

DOMAINS = {
    "1": "Cybersecurity Governance",
    "2": "Cybersecurity Defense",
    "3": "Cybersecurity Resilience",
    "4": "Third-Party and Cloud Computing Cybersecurity",
}

NOISE = re.compile(
    r"^\s*(Document classification|TLP:|Essential Cybersecurity Controls|"
    r"FIGURE|TABLE|Objective\b|Controls\s*$|[-\s]*$|\d+\s*$)",
    re.I,
)

# "2-2 Identity and Access Management" or "1.7 Compliance with ..."
SUBDOMAIN = re.compile(r"^\s*(\d)[-.](\d{1,2})\s+([A-Z][A-Za-z].*)$")
# "2-2-3" or inline; captured anywhere on the line
MAIN_CTRL = re.compile(r"(?<![\d.-])(\d)-(\d{1,2})-(\d{1,2})(?![\d-])")
# "2.2.3.1" — subcontrols always use dots in this document
SUBCTRL = re.compile(r"(?<![\d.-])(\d)\.(\d{1,2})\.(\d{1,2})\.(\d{1,2})(?![\d.])")


def clean(lines):
    out = []
    for ln in lines:
        if NOISE.match(ln):
            continue
        ln = ln.replace("﻿", "").rstrip()
        # Drop lines that are mostly non-ASCII (Arabic page furniture).
        ascii_ratio = sum(c.isascii() for c in ln) / max(len(ln), 1)
        if ln and ascii_ratio < 0.6:
            continue
        if ln.strip():
            out.append(ln)
    return out


def norm(code):
    return code.replace(".", "-")


def parse(lines):
    subdomains = {}
    controls = {}          # code -> {"text": [...], "subdomain": ...}
    order = []
    cur_sub = None
    cur_code = None

    for ln in lines:
        m = SUBDOMAIN.match(ln)
        if m and not MAIN_CTRL.search(ln):
            d, s, title = m.group(1), m.group(2), m.group(3).strip()
            cur_sub = f"{d}-{s}"
            subdomains[cur_sub] = {
                "code": cur_sub,
                "domain": d,
                "domain_name": DOMAINS.get(d, ""),
                "title": re.sub(r"\s{2,}", " ", title),
            }
            cur_code = None
            continue

        # A line may carry both a parent code and a subcontrol code, e.g.
        # "1-6-3 1.6.3.3 Conducting compliance test...". The text belongs to the
        # subcontrol, but the parent must still be registered — dropping it was
        # why the first pass lost exactly the 10 controls that have children.
        sm = SUBCTRL.search(ln)
        if sm:
            head = ln[:sm.start()]
            hm = MAIN_CTRL.search(head)
            if hm and hm.group(0) not in controls:
                controls[hm.group(0)] = {
                    "text": [], "subdomain": cur_sub, "kind": "control"}
                order.append(hm.group(0))

            code = norm(sm.group(0))
            text = ln[sm.end():].strip()
            if code not in controls:
                controls[code] = {"text": [], "subdomain": cur_sub, "kind": "subcontrol"}
                order.append(code)
            if text:
                controls[code]["text"].append(text)
            cur_code = code
            continue

        mm = MAIN_CTRL.search(ln)
        if mm and mm.start() <= 6:
            code = mm.group(0)
            text = ln[mm.end():].strip()
            if code not in controls:
                controls[code] = {"text": [], "subdomain": cur_sub, "kind": "control"}
                order.append(code)
            if text:
                controls[code]["text"].append(text)
            cur_code = code
            continue

        # Continuation of the current control's wrapped text.
        if cur_code and ln.strip():
            controls[cur_code]["text"].append(ln.strip())

    return subdomains, controls, order


PREAMBLE = re.compile(
    r"(Cybersecurity requirements[^.]*?(?:shall )?include the following as a minimum)",
    re.I)


def recover_parents(controls, order, lines):
    """Register any parent control implied by an existing subcontrol.

    These parents are 'X shall include the following as a minimum:' statements
    whose text is laid out before the code in the PDF, so it is recovered by
    searching the source rather than by position.
    """
    preambles = [m.group(1) for ln in lines for m in [PREAMBLE.search(ln)] if m]
    for code in list(controls):
        if controls[code]["kind"] != "subcontrol":
            continue
        parent = "-".join(code.split("-")[:3])
        if parent in controls:
            continue
        controls[parent] = {
            "text": [], "subdomain": "-".join(code.split("-")[:2]),
            "kind": "control", "recovered": True,
        }
        order.append(parent)
    return preambles


SPLIT = re.compile(
    r"((?:The\s+)?[Cc]ybersecurity requirements[^.]*?include the following as a minimum:?)\s*$")

# Page furniture that survives inside a wrapped line rather than on its own.
INLINE_JUNK = re.compile(
    r"\s*-?\s*Essential Cybersecurity Controls\s*-?\s*|"
    r"\s*Document classification: Public\s*\d*\s*|\s*TLP:\s*White\s*")


def split_preambles(out_controls):
    """Move a trailing 'shall include the following as a minimum:' sentence
    from a control onto its successor.

    In the source layout these preambles sit before their own control code, so
    pdftotext attaches them to the preceding control. The successor is exactly
    the parent control whose text was otherwise empty.
    """
    by_code = {c["code"]: c for c in out_controls}
    for c in out_controls:
        c["text"] = INLINE_JUNK.sub(" ", c["text"]).strip()
        c["text"] = re.sub(r"\s{2,}", " ", c["text"])

    for c in out_controls:
        if c["kind"] != "control":
            continue
        m = SPLIT.search(c["text"])
        if not m:
            continue
        d, s, n = (int(x) for x in c["code"].split("-"))
        succ = by_code.get(f"{d}-{s}-{n + 1}")
        if succ is None or succ["text"]:
            continue
        succ["text"] = m.group(1).strip()
        succ.pop("needs_review", None)
        c["text"] = c["text"][:m.start()].strip()


def main():
    lines = clean(SRC.read_text(encoding="utf-8", errors="replace").splitlines())
    subdomains, controls, order = parse(lines)
    recover_parents(controls, order, lines)

    out_controls = []
    for code in order:
        c = controls[code]
        text = re.sub(r"\s{2,}", " ", " ".join(c["text"])).strip()
        parts = code.split("-")
        entry = {
            "code": code,
            "subdomain": "-".join(parts[:2]),
            "parent": "-".join(parts[:3]) if len(parts) == 4 else None,
            "kind": c["kind"],
            "text": text,
        }
        # Flag anything a human must verify against the source document before
        # this catalogue is treated as authoritative regulatory content.
        if c.get("recovered") or len(text) < 25:
            entry["needs_review"] = True
        out_controls.append(entry)

    split_preambles(out_controls)

    mains = [c for c in sorted(out_controls, key=lambda x: tuple(int(i) for i in x["code"].split("-"))) if c["kind"] == "control"]
    subs = [c for c in out_controls if c["kind"] == "subcontrol"]

    catalog = {
        "framework": "NCA ECC-2:2024",
        "source": "https://nca.gov.sa/en/regulatory-documents/controls-list/ecc/",
        "domains": [{"code": k, "name": v} for k, v in DOMAINS.items()],
        "subdomains": [subdomains[k] for k in sorted(
            subdomains, key=lambda x: tuple(int(i) for i in x.split("-")))],
        "controls": out_controls,
    }
    OUT.write_text(json.dumps(catalog, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"subdomains : {len(subdomains):>4} / 28")
    print(f"controls   : {len(mains):>4} / 108")
    print(f"subcontrols: {len(subs):>4} / 92")
    missing = [f"{d}-{s}" for d in "1234" for s in range(1, 16)
               if f"{d}-{s}" not in subdomains]
    empty = [c["code"] for c in out_controls if len(c["text"]) < 25]
    if empty:
        print(f"\nSuspiciously short text ({len(empty)}): {', '.join(empty[:15])}")
    print(f"\nSubdomains found: {', '.join(sorted(subdomains, key=lambda x: tuple(int(i) for i in x.split('-'))))}")


if __name__ == "__main__":
    main()
