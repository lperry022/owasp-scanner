# A03:2021 – Injection*

import re

def check(code_lines, add_vulnerability):
    assigned_queries = {}

    for i, line in enumerate(code_lines):
        if re.search(r"=\s*['\"]\s*(SELECT|INSERT|UPDATE|DELETE)", line, re.IGNORECASE) and '+' in line:
            var_match = re.match(r"\s*(\w+)\s*=", line)
            if var_match:
                var_name = var_match.group(1)
                assigned_queries[var_name] = i + 1  

                add_vulnerability(
                    "A01: Injection",
                    f"SQL query created via string concatenation: {line.strip()}",
                    i + 1,
                    "HIGH",
                    "MEDIUM"
                )

        for var_name in assigned_queries:
            if f"execute({var_name})" in line:
                add_vulnerability(
                    "A01: Injection",
                    f"Suspicious query passed to execute(): {line.strip()}",
                    i + 1,
                    "HIGH",
                    "HIGH"
                )