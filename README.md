# MailVision

**MailVision** is an intelligent, machine-learning-powered spam detection web application that analyzes message content to identify potentially unwanted or suspicious messages. Powered by Python, Flask, Scikit-learn, NLTK, SQLite, and a cybersecurity-themed responsive web UI.

---

## Features

- **Hybrid Detection Engine**: Combines **Multinomial Naive Bayes** machine learning classification with an extended **rule-based heuristic engine**.
- **Real Model Confidence & Probabilities**: Displays exact ML prediction confidence, spam probability %, and ham probability %.
- **Actionable Risk Indicators**: Identifies specific threat signals including promotional phrasing, high-pressure urgency keywords, sensitive account credential requests, suspicious/shortened URLs, toll-free phone patterns, shouting caps, and aggressive punctuation.
- **Detailed Message Statistics**: Measures character count, word count, URL count, digit count, special character count, uppercase count, and suspicious keyword occurrences.
- **Offline Model Evaluation**: Comprehensive model training and evaluation script (`model/train_model.py`) that calculates Accuracy, Precision, Recall, F1 Score, and Confusion Matrices saved in `model/metrics.json`.
- **Prediction History Log**: SQLite-backed history tracking past user checks with timestamp, prediction status, confidence scores, and message statistics. (Raw message text is **never** logged to preserve user privacy).
- **Sample Presets**: Quick-load preset test messages for Spam, Phishing, and Ham.
- **Responsive Cybersecurity UI**: Modern dark slate/navy theme with status banners, progress gauges, glowing badges, and smooth AJAX analysis without full-page reloads.

---

## Technology Stack

- **Frontend**: HTML5, CSS3, JavaScript (ES6+), Bootstrap 5, FontAwesome.
- **Backend**: Python 3, Flask.
- **Machine Learning & NLP**: Scikit-Learn, NLTK (Tokenizer, Stopwords, WordNetLemmatizer), Pandas, NumPy, TF-IDF Vectorizer, Joblib.
- **Database**: SQLite3.
- **Testing**: Python `unittest` framework.

---

## Machine Learning Pipeline

```text
Dataset (SMS Spam Collection)
            ↓
Data Cleaning & Standardizing
            ↓
Text Preprocessing (Lowercasing, Tokenization, Stopwords, Lemmatization)
            ↓
Train/Test Stratified Split (80% / 20%)
            ↓
TF-IDF Feature Extraction (N-grams 1-2, Sublinear TF, 5,000 Features)
            ↓
Model Training & Evaluation (Naive Bayes, Logistic Regression, Linear SVM)
            ↓
Model Persistence (spam_model.pkl, tfidf_vectorizer.pkl, metrics.json)
            ↓
MailVision Inference + Rule Engine + SQLite Logging
```

---

## Model Evaluation Results

During model training, the classifiers were evaluated on an independent test set ($N = 1,114$ samples) from the SMS Spam Collection dataset. The complete metrics are stored in `model/metrics.json`.

| Model | Accuracy | Precision (Spam) | Recall (Spam) | F1-Score |
| :--- | :---: | :---: | :---: | :---: |
| **Multinomial Naive Bayes** *(Selected)* | **98.38%** | **99.25%** | **88.59%** | **0.9362** |
| **Linear SVM (Calibrated)** | **99.19%** | **99.30%** | **94.63%** | **0.9691** |
| **Logistic Regression** | **98.03%** | **99.22%** | **85.91%** | **0.9209** |

> **Rationale for Selecting Multinomial Naive Bayes for Deployment:**
> Multinomial Naive Bayes is natively suited for text classification with sparse TF-IDF feature matrices, executes with near-instant inference speed, and provides smooth, well-calibrated class probability estimates for user confidence scoring.

---

## Project Structure

```text
MailVision/
├── app.py                      # Flask Application Server
├── config.py                   # Global configuration & path definitions
├── requirements.txt            # Python package dependencies
├── README.md                   # Project documentation
├── .gitignore                  # Git ignore rules
│
├── data/                       # Dataset directory
│   └── SMSSpamCollection       # UCI SMS Spam Collection dataset
│
├── model/                      # ML pipeline scripts & saved artifacts
│   ├── train_model.py          # Standalone training & evaluation script
│   ├── spam_model.pkl          # Trained Multinomial Naive Bayes classifier
│   ├── tfidf_vectorizer.pkl    # Fitted TF-IDF vectorizer
│   └── metrics.json            # Measured evaluation metrics & dataset info
│
├── preprocessing/              # Reusable NLP preprocessing module
│   └── text_preprocessor.py    # Text cleaning, tokenization, lemmatization
│
├── detection/                  # Analysis and heuristic rule engine
│   ├── spam_rules.py           # Spam indicators & rule matchers
│   └── analyzer.py             # Combined ML + Rule analysis engine
│
├── database/                   # Database persistence layer
│   ├── db.py                   # SQLite helper methods
│   └── predictions.db          # SQLite prediction history database
│
├── templates/                  # Jinja HTML templates
│   ├── base.html               # Shared layout header & footer
│   ├── index.html              # Main Spam Analyzer interface
│   ├── history.html            # Prediction history table page
│   ├── about.html              # System architecture & dataset info
│   ├── 404.html                # 404 Not Found error template
│   └── 500.html                # 500 Internal Server Error template
│
├── static/                     # Web assets
│   ├── css/
│   │   └── style.css           # Cybersecurity-themed CSS styles
│   └── js/
│       └── script.js           # AJAX analysis, presets, counters
│
└── tests/                      # Automated unit test suite
    ├── test_detector.py        # Master test discovery suite
    ├── test_rules.py           # Heuristic rule engine unit tests
    ├── test_analyzer.py        # Analysis engine integration tests
    ├── test_db.py              # SQLite database unit tests
    └── test_routes.py          # Flask API endpoints unit tests
```

---

## Installation & Setup Instructions

### 1. Open Directory
```bash
cd c:\E\Email_spam_detector
```

### 2. (Optional) Create Virtual Environment
```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Train the ML Model
Run the standalone model training script to download the dataset, train all classifiers, evaluate metrics, and save model artifacts:
```bash
python model/train_model.py
```

### 5. Run Automated Tests
```bash
python -m unittest discover tests
```

### 6. Start MailVision Web Application
```bash
python app.py
```
Open your browser and navigate to:
```text
http://127.0.0.1:5000
```

---

## System Limitations & Disclaimer

> [!IMPORTANT]
> - **SMS vs Email Dataset**: The initial model is trained on the SMS Spam Collection dataset ($N = 5,574$). While MailVision accurately analyzes text message bodies and email copy, real-world email security gateways also analyze email headers (SPF, DKIM, DMARC), sender IP reputation, attachment malware hashes, and domain age.
> - **Text Length**: Recommended text length for analysis is up to 10,000 characters.

---

## Future Improvements

1. Integration with real email header parsing (.eml file upload, SPF/DKIM/DMARC checks).
2. Deep learning / Transformer models (DistilBERT / RoBERTa) for fine-grained contextual embeddings.
3. Real-time URL threat intelligence scanning (Google Safe Browsing API integration).
4. Email attachment hash lookups via VirusTotal API.
