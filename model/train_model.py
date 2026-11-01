import os
import json
import zipfile
import io
import urllib.request
import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from preprocessing.text_preprocessor import TextPreprocessor

def download_dataset_if_needed():
    """Download and extract SMS Spam Collection dataset if missing."""
    os.makedirs(config.DATA_DIR, exist_ok=True)
    if not os.path.exists(config.DATASET_PATH):
        print(f"Dataset not found at {config.DATASET_PATH}. Downloading from UCI repository...")
        try:
            req = urllib.request.urlopen(config.DATASET_URL)
            z = zipfile.ZipFile(io.BytesIO(req.read()))
            z.extractall(config.DATA_DIR)
            print("Dataset downloaded and extracted successfully.")
        except Exception as e:
            raise RuntimeError(f"Failed to download dataset: {e}")

def load_dataset():
    """Load dataset into Pandas DataFrame."""
    download_dataset_if_needed()
    # SMSSpamCollection is tab-separated text: <label>\t<message>
    df = pd.read_csv(config.DATASET_PATH, sep='\t', names=['label', 'message'], encoding='utf-8')
    # Convert labels: ham -> 0, spam -> 1
    df['target'] = df['label'].map({'ham': 0, 'spam': 1})
    return df

def train_and_evaluate():
    print("=" * 60)
    print("Starting Machine Learning Training Pipeline")
    print("=" * 60)

    # 1. Load data
    df = load_dataset()
    total_messages = len(df)
    spam_count = int((df['target'] == 1).sum())
    ham_count = int((df['target'] == 0).sum())

    print(f"Dataset Stats: Total={total_messages}, Spam={spam_count} ({spam_count/total_messages:.1%}), Ham={ham_count} ({ham_count/total_messages:.1%})")

    # 2. Preprocess text
    print("Preprocessing text dataset...")
    preprocessor = TextPreprocessor()
    df['cleaned_message'] = df['message'].apply(preprocessor.clean_text)

    # Filter out any completely empty strings if preprocessed to nothing
    df = df[df['cleaned_message'].str.strip() != ''].reset_index(drop=True)

    X = df['cleaned_message']
    y = df['target']

    # 3. Train / Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"Split data: Train={len(X_train)}, Test={len(X_test)}")

    # 4. TF-IDF Feature Extraction
    print("Extracting TF-IDF features...")
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=5000,
        sublinear_tf=True,
        min_df=2,
        max_df=0.95
    )
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)

    # 5. Model Definitions
    models = {
        "Multinomial Naive Bayes": MultinomialNB(alpha=0.2),
        "Logistic Regression": LogisticRegression(C=1.0, max_iter=1000, random_state=42),
        "Linear SVM": CalibratedClassifierCV(LinearSVC(C=1.0, random_state=42, dual='auto'))
    }

    results = {}

    print("\nTraining and Evaluating Models:")
    print("-" * 60)

    for name, model in models.items():
        model.fit(X_train_tfidf, y_train)
        y_pred = model.predict(X_test_tfidf)

        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))
        cm = confusion_matrix(y_test, y_pred).tolist()

        results[name] = {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": cm
        }

        print(f"{name:25s} | Acc: {acc:.4f} | Prec: {prec:.4f} | Rec: {rec:.4f} | F1: {f1:.4f}")

    # 6. Save Artifacts
    os.makedirs(config.MODEL_DIR, exist_ok=True)

    # Selected model for deployment: Multinomial Naive Bayes
    primary_model = models["Multinomial Naive Bayes"]

    joblib.dump(primary_model, config.MODEL_PATH)
    joblib.dump(vectorizer, config.VECTORIZER_PATH)
    print(f"\nPrimary model saved to: {config.MODEL_PATH}")
    print(f"TF-IDF vectorizer saved to: {config.VECTORIZER_PATH}")

    metrics_payload = {
        "dataset_info": {
            "total_messages": total_messages,
            "spam_messages": spam_count,
            "ham_messages": ham_count,
            "train_samples": len(X_train),
            "test_samples": len(X_test)
        },
        "models": results,
        "selected_model": "Multinomial Naive Bayes",
        "rationale": "Multinomial Naive Bayes provides exceptional text classification performance, handles sparse TF-IDF feature matrices natively, and yields reliable probability estimation for spam risk confidence scoring."
    }

    with open(config.METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=4)

    print(f"Metrics report saved to: {config.METRICS_PATH}")
    print("=" * 60)
    print("ML Pipeline Execution Completed Successfully!")
    print("=" * 60)

if __name__ == "__main__":
    train_and_evaluate()
