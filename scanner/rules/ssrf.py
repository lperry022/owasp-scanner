# A10:2021 – Server-Side Request Forgery (SSRF)
# Heuristic data-flow: user input -> variable -> requests.*(var)

import re

REQUEST_CALL_RE = re.compile(r'\brequests\.(get|post|put|patch|delete|head)\s*\(')

def check(code_lines, add_vulnerability):
    input_vars = set()

    for i, line in enumerate(code_lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        m = re.match(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*input\s*\(', stripped)
        if m:
            input_vars.add(m.group(1))

    for i, line in enumerate(code_lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        if REQUEST_CALL_RE.search(stripped):
            for var in input_vars:
                if re.search(rf'\b{var}\b', stripped):
                    add_vulnerability(
                        "A10: Server-Side Request Forgery",
                        f"Potential SSRF: unvalidated user-controlled URL passed to requests.*(): {stripped}",
                        i + 1,
                        "HIGH",
                        "HIGH",
                    )
                    break
