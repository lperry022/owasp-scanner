# A06:2021 – Vulnerable and Outdated Components
# Placeholder rule: looks for requirements with outdated versions.

import re

PIN_RE = re.compile(r'^\s*([A-Za-z0-9][A-Za-z0-9_\-]*)\s*==\s*([A-Za-z0-9\.\-\+]+)\s*$')

SUSPECT_PACKAGES = {"flask", "django"}  

def check(code_lines, add_vulnerability):
    for i, line in enumerate(code_lines):
        stripped = line.strip()

        if stripped.startswith("#"):
            continue

        m = PIN_RE.match(stripped)
        if not m:
            continue

        pkg = m.group(1).lower()
        ver = m.group(2)

        if pkg in SUSPECT_PACKAGES:
            add_vulnerability(
                "A06: Vulnerable and Outdated Components",
                f"Dependency pin detected (manual review required): {pkg}=={ver}",
                i + 1,
                "MEDIUM",
                "LOW",
            )