import os
import re
import joblib
import numpy as np

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from preprocessing.text_preprocessor import TextPreprocessor
from detection.spam_rules import SpamRuleEngine

class MessageAnalyzer:
    """
    Combined Analysis Engine combining TF-IDF + Multinomial Naive Bayes ML prediction
    with rule-based heuristics and text statistics.
    """
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.preprocessor = TextPreprocessor()
        self.rule_engine = SpamRuleEngine()
        self._load_artifacts()

    def _load_artifacts(self):
        if not os.path.exists(config.MODEL_PATH) or not os.path.exists(config.VECTORIZER_PATH):
            raise FileNotFoundError(
                f"Model or Vectorizer file missing. Expected {config.MODEL_PATH} and {config.VECTORIZER_PATH}. "
                "Please run model/train_model.py first."
            )
        self.model = joblib.load(config.MODEL_PATH)
        self.vectorizer = joblib.load(config.VECTORIZER_PATH)

    def calculate_statistics(self, text: str) -> dict:
        """Calculate detailed text statistics."""
        urls = re.findall(r'http[s]?://\S+|www\.\S+', text)
        digits = re.findall(r'\d', text)
        specials = re.findall(r'[^a-zA-Z0-9\s]', text)
        uppercases = re.findall(r'[A-Z]', text)
        words = text.split()

        rule_res = self.rule_engine.analyze_rules(text)
        keyword_count = rule_res['rule_stats']['matched_keywords_count']

        char_len = len(text)
        caps_ratio = (len(uppercases) / char_len) if char_len > 0 else 0.0

        return {
            "character_count": char_len,
            "word_count": len(words),
            "url_count": len(urls),
            "digit_count": len(digits),
            "special_char_count": len(specials),
            "uppercase_count": len(uppercases),
            "keyword_count": keyword_count,
            "caps_ratio": round(caps_ratio, 4)
        }

    def analyze_message(self, text: str) -> dict:
        """
        Analyze user message text and return structured analysis result.
        """
        if not text or not isinstance(text, str) or not text.strip():
            return {
                "status": "error",
                "message": "Input message cannot be empty."
            }

        if len(text) > config.MAX_INPUT_LENGTH:
            return {
                "status": "error",
                "message": f"Input message exceeds maximum allowed length of {config.MAX_INPUT_LENGTH} characters."
            }

        # 1. Calculate text statistics
        stats = self.calculate_statistics(text)

        # 2. Text Preprocessing
        cleaned_text = self.preprocessor.clean_text(text)

        # 3. Feature Extraction
        vectorized_text = self.vectorizer.transform([cleaned_text])

        # 4. ML Prediction & Probability Estimation
        probabilities = self.model.predict_proba(vectorized_text)[0]
        # Class mapping: 0 = HAM, 1 = SPAM
        ham_prob = float(probabilities[0])
        spam_prob = float(probabilities[1])

        # Primary prediction decision comes strictly from ML Model
        predicted_class = int(np.argmax(probabilities))
        prediction_label = "SPAM" if predicted_class == 1 else "HAM"
        confidence_prob = spam_prob if predicted_class == 1 else ham_prob

        # 5. Rule Engine Analysis
        rule_output = self.rule_engine.analyze_rules(text)

        # 6. Strong rule override: if the rule engine detects a high-confidence
        #    scam pattern (lottery scam or employment scam), escalate
        #    to SPAM even when the ML model leans HAM.
        #    We do NOT fabricate probabilities — spam_prob / ham_prob reflect the
        #    real ML scores. Only the label and reported confidence change.
        if (rule_output["rule_stats"].get("is_strong_lottery_scam") or
            rule_output["rule_stats"].get("is_employment_scam")) and predicted_class == 0:
            prediction_label = "SPAM"
            confidence_prob = spam_prob   # use ML spam score as displayed confidence

        # 7. Independent Security Risk Assessment
        risk_res = self.rule_engine.evaluate_risk(
            indicators=rule_output["indicators"],
            rule_stats=rule_output["rule_stats"],
            ml_prediction=prediction_label,
            text=text
        )

        return {
            "status": "success",
            "prediction": prediction_label,
            "confidence": round(confidence_prob * 100, 2),
            "spam_probability": round(spam_prob * 100, 2),
            "ham_probability": round(ham_prob * 100, 2),
            "risk_level": risk_res["risk_level"],
            "risk_reasons": risk_res["reasons"],
            "indicators": rule_output["indicators"],
            "statistics": stats
        }

# Singleton instance for quick usage
_analyzer_instance = None

def get_analyzer():
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = MessageAnalyzer()
    return _analyzer_instance
