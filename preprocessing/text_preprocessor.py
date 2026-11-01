import os
import re
import string
import logging
import nltk

logger = logging.getLogger(__name__)

# Standard 198 English stopwords as fail-safe fallback for serverless environments
DEFAULT_STOPWORDS = {
    'i', 'me', 'my', 'myself', 'we', 'our', 'ours', 'ourselves', 'you', "you're", "you've",
    "you'll", "you'd", 'your', 'yours', 'yourself', 'yourselves', 'he', 'him', 'his',
    'himself', 'she', "she's", 'her', 'hers', 'herself', 'it', "it's", 'its', 'itself',
    'they', 'them', 'their', 'theirs', 'themselves', 'what', 'which', 'who', 'whom',
    'this', 'that', "that'll", 'these', 'those', 'am', 'is', 'are', 'was', 'were',
    'be', 'been', 'being', 'have', 'has', 'had', 'having', 'do', 'does', 'did',
    'doing', 'a', 'an', 'the', 'and', 'but', 'if', 'or', 'because', 'as', 'until',
    'while', 'of', 'at', 'by', 'for', 'with', 'about', 'against', 'between', 'into',
    'through', 'during', 'before', 'after', 'above', 'below', 'to', 'from', 'up',
    'down', 'in', 'out', 'on', 'off', 'over', 'under', 'again', 'further', 'then',
    'once', 'here', 'there', 'when', 'where', 'why', 'how', 'all', 'any', 'both',
    'each', 'few', 'more', 'most', 'other', 'some', 'such', 'no', 'nor', 'not',
    'only', 'own', 'same', 'so', 'than', 'too', 'very', 's', 't', 'can', 'will',
    'just', 'don', "don't", 'should', "should've", 'now', 'd', 'll', 'm', 'o',
    're', 've', 'y', 'ain', 'aren', "aren't", 'couldn', "couldn't", 'didn', "didn't",
    'doesn', "doesn't", 'hadn', "hadn't", 'hasn', "hasn't", 'haven', "haven't",
    'isn', "isn't", 'ma', 'mightn', "mightn't", 'mustn', "mustn't", 'needn', "needn't",
    'shan', "shan't", 'shouldn', "shouldn't", 'wasn', "wasn't", 'weren', "weren't",
    'won', "won't", 'wouldn', "wouldn't"
}

# Ensure search paths include local and serverless writable directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_NLTK_DATA = os.path.join(BASE_DIR, "nltk_data")
TMP_NLTK_DATA = os.path.join("/tmp", "nltk_data") if os.name != 'nt' else os.path.join(os.environ.get("TEMP", "C:\\temp"), "nltk_data")

for candidate in [PROJECT_NLTK_DATA, TMP_NLTK_DATA]:
    if candidate not in nltk.data.path:
        nltk.data.path.insert(0, candidate)

def _init_nltk():
    """Ensure required NLTK resources are available without unnecessary downloads."""
    # Only check for stopwords and wordnet; punkt is not needed as tokenization uses whitespace split
    resources = ['stopwords', 'wordnet']
    download_dir = TMP_NLTK_DATA
    try:
        os.makedirs(download_dir, exist_ok=True)
    except Exception:
        download_dir = None

    for res in resources:
        try:
            nltk.data.find(f'corpora/{res}')
        except LookupError:
            try:
                if download_dir:
                    nltk.download(res, download_dir=download_dir, quiet=True)
                else:
                    nltk.download(res, quiet=True)
            except Exception as e:
                logger.warning(f"Could not download NLTK resource '{res}': {e}. Using fallback tokenizer/stopwords.")

_init_nltk()

# Import NLTK modules safely after initializing paths
try:
    from nltk.corpus import stopwords
except Exception:
    stopwords = None

try:
    from nltk.stem import WordNetLemmatizer
except Exception:
    WordNetLemmatizer = None

class TextPreprocessor:
    """
    Text preprocessor for email and SMS text message spam classification.
    Performs lowercasing, HTML stripping, URL normalization, tokenization,
    stopword removal, and lemmatization with fail-safe fallbacks.
    """
    def __init__(self, remove_stopwords=True, lemmatize=True):
        self.remove_stopwords = remove_stopwords
        self.lemmatize = lemmatize

        # Load stopwords safely with static fallback
        if stopwords:
            try:
                self.stop_words = set(stopwords.words('english'))
            except Exception:
                self.stop_words = set(DEFAULT_STOPWORDS)
        else:
            self.stop_words = set(DEFAULT_STOPWORDS)

        # Initialize lemmatizer safely with fallback
        self.lemmatizer = None
        self._has_lemmatizer = False
        if WordNetLemmatizer:
            try:
                lem = WordNetLemmatizer()
                lem.lemmatize('test')
                self.lemmatizer = lem
                self._has_lemmatizer = True
            except Exception:
                self.lemmatizer = None
                self._has_lemmatizer = False

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

        # 3. Remove URLs entirely from the ML feature text
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

        # 9. Stopword removal & lemmatization
        processed_tokens = []
        for token in tokens:
            if self.remove_stopwords and token in self.stop_words:
                continue
            if self.lemmatize and self._has_lemmatizer:
                try:
                    token = self.lemmatizer.lemmatize(token)
                except Exception:
                    pass
            processed_tokens.append(token)

        return " ".join(processed_tokens)


def get_preprocessor():
    return TextPreprocessor()
