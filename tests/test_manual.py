import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detection.analyzer import get_analyzer

a = get_analyzer()

samples = [
    ('Spam', 'Congratulations! You have won a free prize. Claim now!'),
    ('Ham', 'Hey, are we still meeting for lunch today?'),
    ('Phishing', 'Your account has been suspended. Verify your password immediately.'),
    ('Unusual Symbols & URLs', 'URGENT!!! Click http://192.168.1.1/login $$$ to claim 100% FREE cash!')
]

for name, text in samples:
    res = a.analyze_message(text)
    pred = res['prediction']
    conf = res['confidence']
    sp = res['spam_probability']
    hp = res['ham_probability']
    print(f"=== {name} ===")
    print(f"Prediction: {pred} | Confidence: {conf}% | SpamProb: {sp}% | HamProb: {hp}%")
    print(f"Indicators Count: {len(res['indicators'])}")
    for ind in res['indicators']:
        lbl = ind['label']
        desc = ind['description']
        sev = ind['severity']
        print(f"  - [{sev.upper()}] {lbl}: {desc}")
    print()
