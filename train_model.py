import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


# Paths
DATASET_PATH = "dataset/phishing_email.csv"
MODEL_DIR = "model"

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "phishing_model.pkl"
)

VECTORIZER_PATH = os.path.join(
    MODEL_DIR,
    "tfidf_vectorizer.pkl"
)


print("\n======================================")
print("   PHISHGUARD AI - MODEL TRAINING")
print("======================================\n")


# Create model folder
os.makedirs(MODEL_DIR, exist_ok=True)


# Load dataset
print("Loading dataset...")

df = pd.read_csv(DATASET_PATH)

print("Original dataset:", df.shape)


# Select columns
df = df[["text_combined", "label"]].copy()


# Clean text
df["text_combined"] = (
    df["text_combined"]
    .fillna("")
    .astype(str)
)

# Clean labels
df["label"] = pd.to_numeric(
    df["label"],
    errors="coerce"
)

df = df.dropna(
    subset=["label"]
)

df["label"] = df["label"].astype(int)

# Remove empty emails
df = df[
    df["text_combined"].str.strip() != ""
]

# Remove duplicate emails
df = df.drop_duplicates(
    subset=["text_combined"]
)


print("Cleaned dataset:", df.shape)

print("\nLabel distribution:")
print(df["label"].value_counts())


# Input and output
X = df["text_combined"]
y = df["label"]


# Train/test split
print("\nSplitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# TF-IDF
print("\nCreating TF-IDF features...")

vectorizer = TfidfVectorizer(
    lowercase=True,
    stop_words="english",
    ngram_range=(1, 2),
    max_features=100000,
    sublinear_tf=True
)

X_train_tfidf = vectorizer.fit_transform(
    X_train
)

X_test_tfidf = vectorizer.transform(
    X_test
)

print(
    "TF-IDF features:",
    X_train_tfidf.shape
)


# Model
print("\nTraining Logistic Regression...")

model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced"
)

model.fit(
    X_train_tfidf,
    y_train
)


# Prediction
print("\nEvaluating model...")

y_pred = model.predict(
    X_test_tfidf
)


# Accuracy
accuracy = accuracy_score(
    y_test,
    y_pred
)

print(
    "\nAccuracy:",
    round(accuracy * 100, 2),
    "%"
)


# Report
print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred
    )
)


# Confusion matrix
print("\nConfusion Matrix:")
print(
    confusion_matrix(
        y_test,
        y_pred
    )
)


# Save model
print("\nSaving model files...")

joblib.dump(
    model,
    MODEL_PATH
)

joblib.dump(
    vectorizer,
    VECTORIZER_PATH
)


print("\n======================================")
print("       MODEL TRAINING COMPLETED")
print("======================================")

print("\nModel:")
print(MODEL_PATH)

print("\nVectorizer:")
print(VECTORIZER_PATH)

print("\n🛡️ PhishGuard AI model is ready!")