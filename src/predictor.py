import os
import joblib


# Project root folder
BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

# Model paths
MODEL_PATH = os.path.join(
    BASE_DIR,
    "model",
    "phishing_model.pkl"
)

VECTORIZER_PATH = os.path.join(
    BASE_DIR,
    "model",
    "tfidf_vectorizer.pkl"
)


# Check files exist
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        f"Model file not found: {MODEL_PATH}"
    )

if not os.path.exists(VECTORIZER_PATH):
    raise FileNotFoundError(
        f"Vectorizer file not found: {VECTORIZER_PATH}"
    )


# Load trained model
model = joblib.load(MODEL_PATH)

# Load TF-IDF vectorizer
vectorizer = joblib.load(VECTORIZER_PATH)


def predict_email(text):

    if not text:
        text = ""

    # Convert email text into TF-IDF features
    text_vector = vectorizer.transform([text])

    # Predict
    prediction = model.predict(text_vector)[0]

    # Confidence
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(text_vector)[0]
        confidence = max(probabilities) * 100
    else:
        confidence = 0.0

    return prediction, confidence