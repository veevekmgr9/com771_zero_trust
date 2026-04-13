import re


def inspect_input(user_input):
    if user_input is None:
        return True, "Safe"

    value = str(user_input).strip()

    sql_patterns = [
        r"(\bor\b|\band\b)\s+\d+\s*=\s*\d+",
        r"(--)",
        r"(\bUNION\b)",
        r"(\bSELECT\b)",
        r"(\bDROP\b)",
        r"(\bINSERT\b)",
        r"(\bDELETE\b)",
        r"(\bUPDATE\b)",
        r"(\bALTER\b)",
        r"(\bEXEC\b)",
        r"(\bXP_\b)",
        r"('|\").*(\bor\b|\band\b).*(=)"
    ]

    xss_patterns = [
        r"<script.*?>.*?</script>",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"<img.*?>",
        r"<svg.*?>",
        r"<iframe.*?>"
    ]

    for pattern in sql_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            return False, "SQL Injection"

    for pattern in xss_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            return False, "XSS"

    return True, "Safe"