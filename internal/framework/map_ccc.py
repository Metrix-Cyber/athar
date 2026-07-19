"""Extract ECC -> CCC clause mappings from the CCC document.

The first attempt used `pdftotext -layout`, which preserves visual columns and
therefore interleaves the next section's margin headings into the current
section's body. That produced links attributing ECC 2-2-3 to CCC 2-3-P-1, and
the artifacts could not be separated from the real correspondences.

Raw reading order has no such problem: the document reads as a sequence of
"In addition to ... the ECC control X, the {CSP|CST} shall cover ..." markers,
each followed by exactly its own clauses until the next marker. Segmenting on
those markers makes the mapping a direct reading of the document rather than an
inference from proximity.

Every link here is stated by the NCA. Nothing is inferred.
"""

import json
import re
import sys
from pathlib import Path

SRC = Path(sys.argv[1] if len(sys.argv) > 1 else "ccc_raw.txt")
OUT = Path(sys.argv[2] if len(sys.argv) > 2 else "ccc_mapping.json")

# "In addition to Subcontrols in the ECC control 2-2-3, the CST shall cover"
# "In addition to the ECC controls 1-9-3 and 1-9-4, the CSP shall"
MARKER = re.compile(
    r"In addition to[^.]*?ECC controls?\s+"
    r"((?:\d+-\d+(?:-\d+)*)(?:\s+and\s+\d+-\d+(?:-\d+)*)*)"
    r"[^.]*?the\s+(CSP|CST)\b",
    re.I | re.S,
)
ECCCODE = re.compile(r"\d+-\d+(?:-\d+)*")
# CCC clause: 2-2-T-1-1 or 2-2-P-1
CCCCODE = re.compile(r"(?<![\d-])\d-\d{1,2}-([PT])-\d{1,2}(?:-\d{1,2})?(?![\d-])")


def main():
    text = SRC.read_text(encoding="utf-8", errors="replace")
    text = re.sub(r"\s+", " ", text)

    marks = list(MARKER.finditer(text))
    if not marks:
        print("no markers found; the document wording may have changed")
        return

    links, skipped = [], 0
    for i, m in enumerate(marks):
        ecc_codes = ECCCODE.findall(m.group(1))
        audience = m.group(2).lower()
        # The segment runs to the next marker, or to the end of the document.
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        segment = text[m.end():end]

        # One marker introduces the clauses of one CCC subdomain. A code from a
        # different subdomain is the next section bleeding in — the residue of
        # the same layout problem, in a smaller form. Anchor on the first code
        # seen and reject the rest.
        anchor_sub = None

        for cm in CCCCODE.finditer(segment):
            code = cm.group(0)
            letter = cm.group(1)
            sub = "-".join(code.split("-")[:2])
            # A CSP clause appearing inside a CST section (or vice versa) is a
            # stray cross-reference, not part of this segment's obligations.
            # Dropping it keeps provider and tenant duties from bleeding into
            # one another, which is the distinction that matters most in this
            # framework.
            if letter.lower() != audience[2].lower():  # csp->p, cst->t
                skipped += 1
                continue
            if anchor_sub is None:
                anchor_sub = sub
            if sub != anchor_sub:
                skipped += 1
                continue
            for ecc in ecc_codes:
                links.append({"from": ecc, "to": code, "audience": "csp" if letter == "P" else "cst"})

    # Deduplicate.
    seen, out = set(), []
    for l in links:
        key = (l["from"], l["to"])
        if key not in seen:
            seen.add(key)
            out.append(l)

    OUT.write_text(json.dumps({
        "from_framework": "NCA ECC-2:2024",
        "to_framework": "NCA CCC-2:2024",
        "note": "Extracted from explicit cross-references in the CCC document. "
                "Each link is stated by the NCA (\"In addition to Subcontrols in "
                "the ECC control X, the CSP/CST shall cover...\"), not inferred.",
        "links": out,
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    cst = [l for l in out if l["audience"] == "cst"]
    csp = [l for l in out if l["audience"] == "csp"]
    print(f"markers found     : {len(marks)}")
    print(f"links             : {len(out)}  ({len(cst)} tenant, {len(csp)} provider)")
    print(f"cross-audience skipped: {skipped}")
    print(f"distinct ECC clauses  : {len({l['from'] for l in out})}")


if __name__ == "__main__":
    main()
