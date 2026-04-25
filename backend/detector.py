import re

# ── LAYER 1: STRUCTURAL REGEX PATTERNS ──
patterns = {

    # Indian Government IDs
    "Aadhaar": (
        r'\b[2-9][0-9]{3}\s[0-9]{4}\s[0-9]{4}\b'
        r'|\b[2-9][0-9]{11}\b'
        r'|\b[2-9][0-9]{3}-[0-9]{4}-[0-9]{4}\b'
    ),
    "PAN": r'\b[A-Z]{5}[0-9]{4}[A-Z]\b',
    "VoterID": r'\b[A-Z]{3}[0-9]{7}\b',
    "Passport": r'\b[A-PR-WY][1-9][0-9]{7}\b',
    "DL": (
        r'\b[A-Z]{2}[0-9]{2}\s[0-9]{4}\s[0-9]{7}\b'
        r'|\b[A-Z]{2}[0-9]{2}\s[0-9]{11}\b'
        r'|\b[A-Z]{2}-[0-9]{2}-[0-9]{4}-[0-9]{7}\b'
        r'|\b[A-Z]{2}[0-9]{13}\b'
    ),

    # Phone — tightened to avoid matching inside longer digit strings
    "Phone": (
        r'(?<!\d)(?:\+91[\s\-]?)?[6-9][0-9]{9}(?!\d)'
        r'|(?<!\d)[6-9][0-9]{4}\s[0-9]{5}(?!\d)'
        r'|(?<!\d)0[6-9][0-9]{9}(?!\d)'
    ),

    # Financial
    "CreditCard": (
        r'\b4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b'
        r'|\b5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b'
        r'|\b3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}\b'
        r'|\b6(?:011|5[0-9]{2})[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b'
        r'|\b(?:6304|6759|6761|6763)[0-9]{8,15}\b'
    ),
    "DebitCard": (
        r'\b(?:508[5-9]|6069|607[0-9]|608[0-9])[0-9]{12}\b'
        r'|\b4[0-9]{15}\b'
        r'|\b5[1-5][0-9]{14}\b'
    ),
    "BankAccount": (
        r'\b[0-9]{9,18}\b(?=.*(?i)account|a/c|acc)'
    ),
    "IFSC": r'\b[A-Z]{4}0[A-Z0-9]{6}\b',
    "UPI":  r'\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b',
    "CVV":  r'(?i)(?:cvv|cvc|cvv2)\s*[:\-]?\s*\b[0-9]{3,4}\b',

    # Other
    "Email": r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b',
    "PIN":   r'(?i)(?:pin\s*code|pincode|postal)\s*[:\-]?\s*\b[1-9][0-9]{5}\b',
    # DOB via regex — dd/mm/yyyy or dd-mm-yyyy or dd.mm.yyyy
    "DOB_regex": r'\b(?:0?[1-9]|[12][0-9]|3[01])[-/.](?:0?[1-9]|1[0-2])[-/.](?:19|20)[0-9]{2}\b',
    "Enrollment": r'\b[0-9]{4}/[0-9]{5}/[0-9]{5}\b',
}

# ── LAYER 2: CONTEXT-AWARE PATTERNS ──
# Gender is intentionally excluded — never detected, never masked.
CONTEXT_PATTERNS = [

    # Names — full name captured; only LAST WORD will be masked (surname only)
    (r'(?i)(?:full\s*)?name\s*[:\-]?\s*([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){1,4})', "Name"),
    (r"(?i)father'?s?\s*name\s*[:\-]?\s*([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){1,3})", "Name"),
    (r"(?i)mother'?s?\s*name\s*[:\-]?\s*([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){1,3})", "Name"),
    (r'(?i)(?:s/o|d/o|w/o|c/o)\s*[:\-]?\s*([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){1,3})', "Name"),
    (r'(?i)(?:applicant|nominee|holder|subscriber)\s*[:\-]?\s*([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){1,3})', "Name"),

    # Phone — context-triggered
    (r'(?i)(?:mobile|phone|cell|contact|tel|ph)\s*(?:no\.?|number|num)?\s*[:\-]?\s*(\+?91[\s\-]?[6-9][0-9]{9}|[6-9][0-9]{9})', "Phone"),

    # DOB — context-labeled fields (e.g. "DOB : 13-06-2006")
    (r'(?i)(?:date\s*of\s*birth|d\.?o\.?b\.?|dob|born\s*on)\s*[:\-/]?\s*(\d{1,2}[-/. ]\d{1,2}[-/. ]\d{2,4}|\d{4}[-/. ]\d{1,2}[-/. ]\d{1,2})', "DOB"),

    # Address
    (r'(?i)(?:address|addr|residence|residing\s*at)\s*[:\-]?\s*(.{10,120}?)(?=\n[A-Z]|\Z|pin|state|dist)', "Address"),
    (r'(?i)(?:house\s*no|flat\s*no|door\s*no|plot\s*no)\s*[:\-]?\s*([A-Z0-9/\-]{1,10})', "Address"),

    # Financial context
    (r'(?i)(?:account\s*(?:no|number|num)|a/?c\s*(?:no)?)\s*[:\-]?\s*([0-9]{9,18})', "BankAccount"),
    (r'(?i)(?:card\s*(?:no|number)|debit|credit)\s*[:\-]?\s*([0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4})', "CardNumber"),
    (r'(?i)(?:ifsc|ifsc\s*code)\s*[:\-]?\s*([A-Z]{4}0[A-Z0-9]{6})', "IFSC"),
    (r'(?i)(?:upi\s*id|upi)\s*[:\-]?\s*([a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64})', "UPI"),
    (r'(?i)(?:cvv|cvc)\s*[:\-]?\s*([0-9]{3,4})', "CVV"),

    # Email
    (r'(?i)(?:email|e-mail|mail)\s*[:\-]?\s*([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})', "Email"),

    # Aadhaar
    (r'(?i)(?:aadhaar|aadhar|uid)\s*(?:no\.?|number|num)?\s*[:\-]?\s*([2-9][0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4})', "Aadhaar"),

    # PAN
    (r'(?i)(?:pan|pan\s*no|permanent\s*account)\s*[:\-]?\s*([A-Z]{5}[0-9]{4}[A-Z])', "PAN"),

    # Passport
    (r'(?i)(?:passport\s*(?:no|number))\s*[:\-]?\s*([A-PR-WY][1-9][0-9]{7})', "Passport"),

    # DL
    (r'(?i)(?:dl\s*no|driving\s*licen[cs]e\s*(?:no|number))\s*[:\-]?\s*([A-Z]{2}[0-9]{2}[\s\-]?[0-9]{4,11})', "DL"),

    # Voter ID
    (r'(?i)(?:voter\s*id|epic\s*(?:no|number)|election)\s*[:\-]?\s*([A-Z]{3}[0-9]{7})', "VoterID"),

    # Blood group (minor PII — detected but NOT masked)
    (r'(?i)(?:blood\s*group|b\.?g\.?)\s*[:\-]?\s*([ABO]{1,2}[+-])', "BloodGroup"),

    # Gender — deliberately absent. We never detect or mask gender.
]

# Risk levels per type
RISK_MAP = {
    "Aadhaar": "HIGH", "PAN": "HIGH", "Passport": "HIGH",
    "DL": "HIGH", "VoterID": "HIGH", "CreditCard": "HIGH",
    "DebitCard": "HIGH", "BankAccount": "HIGH", "CVV": "HIGH",
    "Phone": "HIGH", "CardNumber": "HIGH",
    "IFSC": "MEDIUM", "UPI": "MEDIUM", "Email": "MEDIUM",
    "Name": "MEDIUM", "DOB": "MEDIUM", "DOB_regex": "MEDIUM",
    "Address": "MEDIUM", "Enrollment": "MEDIUM",
    "PIN": "LOW", "BloodGroup": "LOW",
}

# These types are reported in scan results but their content is NOT redacted
NO_MASK_TYPES = {"BloodGroup"}


def get_mask_target(finding_type, match_text):
    """
    Returns the token to actually redact from the document.
    - Name with multiple words → only the last word (surname)
    - Everything else → full matched string
    """
    if finding_type == "Name":
        parts = match_text.strip().split()
        if len(parts) > 1:
            return parts[-1]   # surname only
        return match_text      # single-token name → mask fully
    return match_text


def luhn_check(card_number):
    digits = [int(d) for d in re.sub(r'\D', '', card_number)]
    if len(digits) < 13:
        return False
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits)
    for d in even_digits:
        total += sum(divmod(d * 2, 10))
    return total % 10 == 0


def detect(text):
    findings = []
    for label, pattern in patterns.items():
        try:
            matches = re.findall(pattern, text)
        except re.error:
            continue

        valid_matches = []
        for match in matches:
            match = match.strip() if isinstance(match, str) else match
            if label in ("CreditCard", "DebitCard", "CardNumber"):
                if luhn_check(match):
                    valid_matches.append(match)
            elif label == "BankAccount":
                pass  # context-only
            else:
                valid_matches.append(match)

        if valid_matches:
            findings.append({
                "type": label,
                "matches": valid_matches,
                "risk": RISK_MAP.get(label, "MEDIUM"),
                "mask_targets": [get_mask_target(label, m) for m in valid_matches],
                "should_mask": label not in NO_MASK_TYPES,
            })
    return findings


def detect_context(text):
    findings = []
    for pattern, label in CONTEXT_PATTERNS:
        try:
            matches = re.findall(pattern, text)
        except re.error:
            continue

        for match in matches:
            if isinstance(match, tuple):
                match = match[0] if match else ""
            match = match.strip()

            if not match or len(match) < 2:
                continue
            if label == "Name" and len(match) < 4:
                continue
            if label == "Address" and len(match) < 8:
                continue

            findings.append({
                "type": label,
                "matches": [match],
                "risk": RISK_MAP.get(label, "MEDIUM"),
                "mask_targets": [get_mask_target(label, match)],
                "should_mask": label not in NO_MASK_TYPES,
            })
    return findings


def detect_with_nlp(text):
    layer1 = detect(text)
    layer2 = detect_context(text)

    seen = set()
    result = []

    all_findings = layer1 + layer2
    priority = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    all_findings.sort(key=lambda f: priority.get(f["risk"], 3))

    for f in all_findings:
        for i, m in enumerate(f["matches"]):
            m_clean = m.strip()
            mask_targets = f.get("mask_targets", [])
            mask_target = mask_targets[i] if i < len(mask_targets) else m_clean

            if m_clean and m_clean not in seen:
                seen.add(m_clean)
                result.append({
                    "type": f["type"],
                    "matches": [m_clean],
                    "mask_targets": [mask_target],
                    "risk": f["risk"],
                    "should_mask": f.get("should_mask", True),
                })
    return result