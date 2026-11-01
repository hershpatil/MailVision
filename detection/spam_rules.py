import re
from urllib.parse import urlparse

# Rule definitions with matching patterns and human-readable explanations
SPAM_KEYWORDS = [
    r'\bfree\b', r'\bwinner\b', r'\bwon\b', r'\bprize\b', r'\bclaim\b', r'\bguaranteed\b',
    r'\binstant cash\b', r'\bbonus\b', r'\bjackpot\b', r'\breward\b', r'\bcongratulations\b',
    r'\b100%\b', r'\bgift card\b', r'\bno cost\b', r'\bexclusive deal\b', r'\blottery\b'
]

URGENCY_KEYWORDS = [
    r'\burgent\b', r'\bact now\b', r'\bclaim now\b', r'\bclick now\b', r'\blimited time\b',
    r'\bexpires\b', r'\blast chance\b', r'\bimmediate action\b', r'\bdon\'?t delay\b',
    r'\bvalid for 24 hours\b', r'\bfinal notice\b'
]

FINANCIAL_SENSITIVE_KEYWORDS = [
    r'\bverify your account\b', r'\bbank account\b', r'\bcredit card\b', r'\bpassword\b',
    r'\bssn\b', r'\bsocial security\b', r'\bwire transfer\b', r'\bpin number\b',
    r'\bupdate your billing\b', r'\botp\b', r'\bsecurity alert\b'
]

SHORTENER_DOMAINS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc'
]

class SpamRuleEngine:
    """
    Rule-based engine for analyzing spam heuristics and generating structured indicators.
    Does NOT override ML prediction, but provides human-understandable signals.
    """

    def analyze_rules(self, text: str) -> dict:
        if not text:
            return {
                "indicators": [],
                "rule_stats": {
                    "has_promotional_keywords": False,
                    "has_urgency": False,
                    "has_sensitive_requests": False,
                    "has_suspicious_urls": False,
                    "has_phone_patterns": False,
                    "excessive_caps": False,
                    "excessive_punctuation": False,
                    "matched_keywords_count": 0
                }
            }

        indicators = []
        matched_keywords = set()

        # 1. Check Promotional / Spam Keywords
        for pattern in SPAM_KEYWORDS:
            matches = re.findall(pattern, text, flags=re.IGNORECASE)
            if matches:
                matched_keywords.update(m.lower() for m in matches)

        has_promotional = len(matched_keywords) > 0
        if has_promotional:
            indicators.append({
                "type": "PROMOTIONAL_LANGUAGE",
                "label": "Promotional / Prize Language Detected",
                "description": f"Contains spam-indicative words: {', '.join(sorted(list(matched_keywords))[:5])}",
                "severity": "medium"
            })

        # 2. Check Urgency Language
        urgency_matches = []
        for pattern in URGENCY_KEYWORDS:
            if re.search(pattern, text, flags=re.IGNORECASE):
                urgency_matches.append(pattern.replace(r'\b', '').replace(r'\'?', ''))

        has_urgency = len(urgency_matches) > 0
        if has_urgency:
            indicators.append({
                "type": "URGENCY_LANGUAGE",
                "label": "Urgency & High-Pressure Phrasing",
                "description": f"Uses high-pressure time-sensitive phrasing: {', '.join(urgency_matches[:3])}",
                "severity": "high"
            })

        # 3. Check Financial / Sensitive Requests
        sensitive_matches = []
        for pattern in FINANCIAL_SENSITIVE_KEYWORDS:
            if re.search(pattern, text, flags=re.IGNORECASE):
                sensitive_matches.append(pattern.replace(r'\b', ''))

        has_sensitive = len(sensitive_matches) > 0
        if has_sensitive:
            indicators.append({
                "type": "SENSITIVE_REQUEST",
                "label": "Account / Financial Data Request",
                "description": f"Requests sensitive credential or banking details: {', '.join(sensitive_matches[:3])}",
                "severity": "high"
            })

        # 4. Check Suspicious URLs
        # Use the same pattern as the preprocessor so URL counts are consistent.
        urls = re.findall(r'http[s]?://\S+|www\.\S+', text)
        has_ip_url = any(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url) for url in urls)

        # Extract the hostname precisely before comparing to shortener domains,
        # so that 't.co' does not substring-match inside 'gpt.com' or 'copilot.com'.
        def _hostname(url: str) -> str:
            try:
                # Ensure the URL has a scheme so urlparse works correctly.
                if not url.startswith(('http://', 'https://')):
                    url = 'http://' + url
                return urlparse(url).hostname or ''
            except Exception:
                return ''

        has_shortener = any(
            _hostname(url) in SHORTENER_DOMAINS
            for url in urls
        )

        # NOTE: Multiple URLs alone is NOT a spam signal — a legitimate message
        # (e.g. sharing several help resources) may contain several links.
        # Only flag when there is a genuinely suspicious characteristic.
        has_suspicious_urls = has_ip_url or has_shortener or (len(urls) > 0 and has_promotional)

        if has_suspicious_urls:
            url_reasons = []
            if has_ip_url:
                url_reasons.append("Raw IP address URL")
            if has_shortener:
                url_reasons.append("URL shortener service")
            if len(urls) > 0 and has_promotional:
                url_reasons.append("Link embedded alongside promotional offer")

            indicators.append({
                "type": "SUSPICIOUS_URL",
                "label": "Suspicious / Shortened Link",
                "description": f"Contains suspicious web links: {'; '.join(url_reasons)}",
                "severity": "high"
            })

        # 5. Check Phone Number Call-to-Actions
        phone_matches = re.findall(r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b|\b0800\d+|\b1-800-\d+|\bcall\s+\d+', text, flags=re.IGNORECASE)
        has_phone = len(phone_matches) > 0
        if has_phone:
            indicators.append({
                "type": "CALL_TO_ACTION_PHONE",
                "label": "Unsolicited Phone Contact Pattern",
                "description": f"Direct phone call-to-action detected: {', '.join(phone_matches[:2])}",
                "severity": "medium"
            })

        # 6. Check Excessive Capitalization
        words = text.split()
        caps_words = [w for w in words if w.isupper() and len(w) > 1]
        caps_ratio = len([c for c in text if c.isupper()]) / max(len(text), 1)

        excessive_caps = (len(caps_words) >= 3 and caps_ratio > 0.25) or (caps_ratio > 0.40 and len(text) > 20)
        if excessive_caps:
            indicators.append({
                "type": "EXCESSIVE_CAPS",
                "label": "Excessive Capitalization (SHOUTING)",
                "description": f"Contains abnormally high uppercase letters ({caps_ratio:.0%} uppercase characters)",
                "severity": "low"
            })

        # 7. Check Excessive Punctuation (!!!, $$$, ???)
        repeated_punc = re.findall(r'!{2,}|\?{2,}|\${2,}', text)
        excessive_punc = len(repeated_punc) > 0
        if excessive_punc:
            indicators.append({
                "type": "EXCESSIVE_PUNCTUATION",
                "label": "Aggressive Punctuation / Symbols",
                "description": f"Uses repeated exclamation, question, or currency symbols ({', '.join(list(set(repeated_punc))[:3])})",
                "severity": "low"
            })

        # 8. Strong lottery / prize-scam detector
        # Requires ALL THREE conditions simultaneously:
        #   a) prize-or-lottery language (won / prize / lottery / jackpot)
        #   b) urgency OR a click/link call-to-action
        #   c) at least one URL present
        # This combination is highly indicative of a scam and very unlikely in
        # legitimate messages (a real lottery would not cold-message you with a
        # link and tell you to hurry).
        _LOTTERY_PRIZE_PATTERN = re.compile(
            r'\b(won|winner|lottery|prize|jackpot|reward)\b', re.IGNORECASE
        )
        _CLICK_CTA_PATTERN = re.compile(
            r'\b(click|clicking|link|collect|claim|visit|go\s+to)\b', re.IGNORECASE
        )
        _URGENCY_STRONG_PATTERN = re.compile(
            r'\b(as\s+soon\s+as\s+possible|asap|hurry|urgent|immediately|act\s+now|claim\s+now|don\'?t\s+delay)\b',
            re.IGNORECASE
        )

        has_lottery_prize_lang = bool(_LOTTERY_PRIZE_PATTERN.search(text))
        has_click_cta = bool(_CLICK_CTA_PATTERN.search(text))
        has_urgency_strong = bool(_URGENCY_STRONG_PATTERN.search(text))
        has_any_url = len(urls) > 0

        # The scam pattern fires only when prize/lottery + (urgency OR click CTA) + URL
        is_strong_lottery_scam = (
            has_lottery_prize_lang
            and (has_urgency_strong or has_click_cta)
            and has_any_url
        )

        if is_strong_lottery_scam:
            indicators.append({
                "type": "STRONG_LOTTERY_SCAM_PATTERN",
                "label": "Strong Lottery / Prize Scam Pattern",
                "description": "Combines prize/lottery language with a call-to-action and a URL - a hallmark pattern of prize-scam messages.",
                "severity": "high"
            })

        # 9. Contextual Employment / Fake Job Scam Detector
        # Scams typically promise guaranteed selection, direct placement without interviews,
        # high salary, and crucially require an upfront fee (registration, processing, security deposit)
        # to secure the position.
        _EMPLOYMENT_CONTEXT_PATTERN = re.compile(
            r'\b(job|jobs|internship|internships|position|positions|vacancy|vacancies|'
            r'opening|openings|role|roles|employment|recruitment|hiring|placement|placements|'
            r'candidate|candidates|candidature|fresher|freshers|career|careers|'
            r'software\s+engine(?:er|ering))\b',
            re.IGNORECASE
        )
        _SELECTION_OFFER_PATTERN = re.compile(
            r'\b(selected\s+(?:for|as)|selection\s+(?:is\s+)?confirmed|job\s+offer|'
            r'offer\s+letter|hired\s+for|secure\s+your\s+(?:position|job|seat|role|placement)|'
            r'confirm\s+your\s+(?:position|seat|candidature|placement)|'
            r'guaranteed\s+(?:job|placement|selection|position))\b',
            re.IGNORECASE
        )
        _NO_INTERVIEW_PATTERN = re.compile(
            r'\b(no\s+interview|without\s+(?:any\s+)?interview|no\s+(?:technical\s+)?assessment|'
            r'no\s+(?:written\s+)?test|no\s+exam|without\s+(?:any\s+)?assessment|'
            r'direct\s+(?:joining|selection|appointment|hiring))\b',
            re.IGNORECASE
        )
        _UPFRONT_FEE_PATTERN = re.compile(
            r'\b((?:refundable\s+)?(?:registration|processing|security|training|onboarding|verification|documentation|document|application)\s+(?:fee|fees|deposit|deposits|charge|charges|amount|cost)|'
            r'pay\s+(?:a\s+)?(?:refundable\s+)?(?:registration|processing|security|training|onboarding)?\s*fee|'
            r'fee\s+of\s+(?:[₹$€£]|rs\.?|inr)?\s*[\d,]+|'
            r'deposit\s+(?:of\s+)?(?:[₹$€£]|rs\.?|inr)\s*[\d,]+)\b',
            re.IGNORECASE
        )
        _PAY_TO_SECURE_PATTERN = re.compile(
            r'\b(?:pay|deposit|transfer|send)\b.*?\b(?:to\s+secure|to\s+confirm|to\s+claim|to\s+book|to\s+reserve|to\s+lock)\s+(?:your\s+)?(?:position|job|seat|offer|placement|role)\b',
            re.IGNORECASE
        )
        _SALARY_PROMISE_PATTERN = re.compile(
            r'\b(high-paying|high\s+paying|lucrative\s+(?:salary|package)|salary\s+of|'
            r'package\s+of|stipend\s+of|(?:[₹$€£]|rs\.?|inr)\s*[\d,.]+\s*(?:lpa|per\s+annum|per\s+month|p\.a\.|p\.m\.)|'
            r'\b[\d,.]+\s*lpa\b)\b',
            re.IGNORECASE
        )
        _URGENCY_VACANCIES_PATTERN = re.compile(
            r'\b(limited\s+(?:vacancies|seats|openings|slots)|apply\s+immediately|'
            r'immediate\s+joining|hurry|act\s+fast|apply\s+now|today\s+only|last\s+chance)\b',
            re.IGNORECASE
        )

        has_employment_context = bool(_EMPLOYMENT_CONTEXT_PATTERN.search(text))
        has_selection_or_offer = bool(_SELECTION_OFFER_PATTERN.search(text))
        has_no_interview = bool(_NO_INTERVIEW_PATTERN.search(text))
        has_upfront_fee = bool(_UPFRONT_FEE_PATTERN.search(text))
        has_pay_to_secure = bool(_PAY_TO_SECURE_PATTERN.search(text))
        has_salary_promise = bool(_SALARY_PROMISE_PATTERN.search(text))
        has_urgency_vacancies = bool(_URGENCY_VACANCIES_PATTERN.search(text))

        # Evaluate combined evidence:
        # 1. Employment context + explicit pay-to-secure requirement (strongest indicator)
        # 2. Employment context + upfront fee requirement + (guaranteed selection OR no interview OR high salary OR urgency)
        # 3. Employment context + guaranteed selection/offer + no interview/assessment required
        is_employment_scam = (
            (has_employment_context and has_pay_to_secure) or
            (has_employment_context and has_upfront_fee and (has_selection_or_offer or has_no_interview or has_salary_promise or has_urgency_vacancies)) or
            (has_employment_context and has_no_interview and has_selection_or_offer)
        )

        if is_employment_scam:
            reasons = []
            if has_pay_to_secure or has_upfront_fee:
                reasons.append("Upfront payment or registration fee demanded for employment")
            if has_no_interview:
                reasons.append("Guaranteed selection without interview or technical assessment")
            if has_salary_promise and (has_upfront_fee or has_pay_to_secure):
                reasons.append("High salary promise paired with payment demand")
            if has_urgency_vacancies:
                reasons.append("Urgency phrasing with limited vacancies")

            desc = f"Suspicious recruitment pattern: {'; '.join(reasons)}." if reasons else "Combines unverified job selection signals with high-risk payment or evaluation bypass heuristics."

            indicators.append({
                "type": "EMPLOYMENT_SCAM_PATTERN",
                "label": "Fake Job / Employment Scam Pattern",
                "description": desc,
                "severity": "high"
            })

        return {
            "indicators": indicators,
            "rule_stats": {
                "has_promotional_keywords": has_promotional,
                "has_urgency": has_urgency,
                "has_sensitive_requests": has_sensitive,
                "has_suspicious_urls": has_suspicious_urls,
                "has_phone_patterns": has_phone,
                "excessive_caps": excessive_caps,
                "excessive_punctuation": excessive_punc,
                "matched_keywords_count": len(matched_keywords),
                "is_strong_lottery_scam": is_strong_lottery_scam,
                "is_employment_scam": is_employment_scam
            }
        }

    def evaluate_risk(self, indicators: list, rule_stats: dict, ml_prediction: str = None, text: str = None) -> dict:
        """
        Evaluate security threat risk level (Low, Medium, High) separately from ML confidence.

        Risk assessment guidelines:
        - High Risk: Phishing / credential theft, upfront fee scams, lottery scams,
          raw numeric IP URLs, or multiple high-severity threat indicators.
        - Medium Risk: Promotional patterns, URL shorteners, unsolicited phone calls,
          isolated urgency, or bulk spam patterns without active malicious threat.
        - Low Risk: No significant suspicious indicators. Standard safe correspondence.
        """
        reasons = []
        is_high = False
        is_medium = False

        indicator_types = {ind.get("type") for ind in indicators}
        high_severity_count = sum(1 for ind in indicators if ind.get("severity") == "high")

        # Check for Raw IP Address in SUSPICIOUS_URL
        has_raw_ip = any(
            "raw ip" in ind.get("description", "").lower()
            for ind in indicators
            if ind.get("type") == "SUSPICIOUS_URL"
        )

        # Check for URL Shorteners
        has_shortener = any(
            "shortener" in ind.get("description", "").lower()
            for ind in indicators
            if ind.get("type") == "SUSPICIOUS_URL"
        )

        # --- 1. High-Risk Evaluation ---
        if "SENSITIVE_REQUEST" in indicator_types:
            is_high = True
            reasons.append("Direct request for sensitive credentials, passwords, or banking information (phishing attempt).")

        if rule_stats.get("is_employment_scam") or "EMPLOYMENT_SCAM_PATTERN" in indicator_types:
            is_high = True
            reasons.append("Identified employment scam pattern requiring upfront payment or bypass of legitimate hiring procedures.")

        if rule_stats.get("is_strong_lottery_scam") or "STRONG_LOTTERY_SCAM_PATTERN" in indicator_types:
            is_high = True
            reasons.append("Deceptive lottery or prize claim combined with a call-to-action and web link.")

        if has_raw_ip:
            is_high = True
            reasons.append("Contains raw numeric IP address link attempting to bypass domain security filters.")

        if high_severity_count >= 2:
            is_high = True
            reasons.append("Multiple high-severity threat indicators detected in message content.")

        if is_high:
            seen = set()
            unique_reasons = [r for r in reasons if not (r in seen or seen.add(r))]
            return {
                "risk_level": "High",
                "reasons": unique_reasons
            }

        # --- 2. Medium-Risk Evaluation ---
        if has_shortener:
            is_medium = True
            reasons.append("Contains shortened URL service (e.g. bit.ly, tinyurl) concealing the destination domain.")

        if "PROMOTIONAL_LANGUAGE" in indicator_types:
            is_medium = True
            reasons.append("Contains promotional marketing terminology or prize-oriented phrasing.")

        if "CALL_TO_ACTION_PHONE" in indicator_types:
            is_medium = True
            reasons.append("Unsolicited direct phone call-to-action detected.")

        if "URGENCY_LANGUAGE" in indicator_types:
            is_medium = True
            reasons.append("Contains high-pressure urgency phrasing urging immediate action.")

        if ml_prediction == "SPAM" and not is_medium:
            is_medium = True
            reasons.append("Message characteristics align with unsolicited bulk advertising.")

        if is_medium:
            seen = set()
            unique_reasons = [r for r in reasons if not (r in seen or seen.add(r))]
            return {
                "risk_level": "Medium",
                "reasons": unique_reasons
            }

        # --- 3. Low-Risk Default ---
        return {
            "risk_level": "Low",
            "reasons": [
                "No significant suspicious indicators detected.",
                "Content characteristics align with standard correspondence."
            ]
        }
