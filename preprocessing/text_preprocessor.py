import re
import string
import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer

# Ensure required NLTK resources are available
def _init_nltk():
    resources = ['stopwords', 'wordnet', 'punkt']
    for res in resources:
        try:
            nltk.data.find(f'corpora/{res}' if res in ['stopwords', 'wordnet'] else f'tokenizers/{res}')
        except LookupError:
            nltk.download(res, quiet=True)

_init_nltk()

class TextPreprocessor:
    """
    Text preprocessor for email and SMS text message spam classification.
    Performs lowercasing, HTML stripping, URL normalization, tokenization,
    stopword removal, and lemmatization.
    """
    def __init__(self, remove_stopwords=True, lemmatize=True):
        self.remove_stopwords = remove_stopwords
        self.lemmatize = lemmatize
        self.stop_words = set(stopwords.words('english'))
        # Retain certain negation/spam-indicative words if needed
        # e.g., 'not', 'no', 'free', 'win', 'claim'
        self.lemmatizer = WordNetLemmatizer()

    def clean_text(self, text: str) -> str:
        """
        Preprocess text for ML model training and inference.
        """
        if not text or not isinstance(text, str):
            return ""

        # 1. Lowercase text
        text = text.lower()

        # 2. Strip HTML tags
        text = re.sub(r'<[^>]+>', ' ', text)

        # 3. Remove URLs entirely from the ML feature text.
        #    Previously URLs were replaced with 'urltoken', which the Naive Bayes
        #    model learned as a strong spam signal (+4.49 log-prob), causing false
        #    positives on legitimate messages that contain links.
        #    URL presence and risk are already handled by the rule engine
        #    (detection/spam_rules.py) independently of the ML features.
        text = re.sub(r'http[s]?://\S+|www\.\S+', ' ', text)

        # 4. Normalize email addresses
        text = re.sub(r'\b[\w\.-]+@[\w\.-]+\.\w+\b', ' emailtoken ', text)

        # 5. Normalize currency symbols ($ -> moneytoken, £ -> moneytoken)
        text = re.sub(r'[\$£€₹]', ' moneytoken ', text)

        # 6. Normalize standalone phone numbers
        text = re.sub(r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b', ' phonetoken ', text)

        # 7. Remove punctuation except preserved space
        text = text.translate(str.maketrans('', '', string.punctuation))

        # 8. Tokenize by whitespace
        tokens = text.split()

        # 9. Optional stopword removal & lemmatization
        processed_tokens = []
        for token in tokens:
            if self.remove_stopwords and token in self.stop_words:
                continue
            if self.lemmatize:
                token = self.lemmatizer.lemmatize(token)
            processed_tokens.append(token)

        return " ".join(processed_tokens)


def get_preprocessor():
    return TextPreprocessor()
