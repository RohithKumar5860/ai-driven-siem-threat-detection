"""
ML Training Script — Isolation Forest for SIEM Anomaly Detection
Run from the project root:
    python ml/train_model.py
"""
import os
import sys
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

# Ensure project root is on the path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

MODEL_OUTPUT = os.path.join(ROOT_DIR, "ml", "model.pkl")

np.random.seed(42)


def generate_synthetic_data(n_normal: int = 4000, n_anomaly: int = 400) -> pd.DataFrame:
    """
    Generate a labelled synthetic dataset with two features:
        - port         : destination port number
        - payload_size : bytes in the payload

    Normal traffic uses common ports and moderate payload sizes.
    Anomalous traffic uses unusual ports or very large payloads.
    """
    # Normal traffic
    normal_ports = np.random.choice(
        [80, 443, 22, 21, 25, 53, 110, 143, 3306, 5432, 8080, 8443],
        size=n_normal,
    )
    normal_payloads = np.random.randint(100, 8000, size=n_normal)

    # Anomalous traffic — suspicious ports or huge payloads
    anomaly_ports = np.random.choice(
        [4444, 31337, 1337, 9001, 6666, 54321, 12345],
        size=n_anomaly // 2,
    )
    anomaly_ports = np.concatenate(
        [anomaly_ports, np.random.randint(1, 65535, size=n_anomaly - len(anomaly_ports))]
    )
    anomaly_payloads = np.concatenate([
        np.random.randint(12000, 65535, size=n_anomaly // 2),
        np.random.randint(100, 65535, size=n_anomaly - n_anomaly // 2),
    ])

    ports = np.concatenate([normal_ports, anomaly_ports])
    payloads = np.concatenate([normal_payloads, anomaly_payloads])
    labels = np.concatenate([
        np.ones(n_normal),    # 1 = normal
        -np.ones(n_anomaly),  # -1 = anomaly
    ])

    df = pd.DataFrame({"port": ports, "payload_size": payloads, "label": labels})
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # shuffle
    return df


def train(df: pd.DataFrame) -> Pipeline:
    """Train an Isolation Forest pipeline (scaler + model)."""
    X = df[["port", "payload_size"]].values

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("iso_forest", IsolationForest(
            n_estimators=200,
            max_samples="auto",
            contamination=0.09,   # ~9 % anomalies in our synthetic data
            random_state=42,
            n_jobs=-1,
        )),
    ])
    pipeline.fit(X)
    return pipeline


def evaluate(pipeline: Pipeline, df: pd.DataFrame) -> None:
    """Print a basic accuracy report against the synthetic labels."""
    X = df[["port", "payload_size"]].values
    y_true = df["label"].values
    y_pred = pipeline.predict(X)

    correct = int(np.sum(y_pred == y_true))
    total = len(y_true)
    accuracy = correct / total * 100

    tp = int(np.sum((y_pred == -1) & (y_true == -1)))
    fp = int(np.sum((y_pred == -1) & (y_true == 1)))
    fn = int(np.sum((y_pred == 1) & (y_true == -1)))
    tn = int(np.sum((y_pred == 1) & (y_true == 1)))

    print(f"\n{'='*50}")
    print("  Isolation Forest — Training Evaluation")
    print(f"{'='*50}")
    print(f"  Total samples : {total:,}")
    print(f"  Accuracy      : {accuracy:.2f}%")
    print(f"  True  Positives (anomaly correctly flagged) : {tp}")
    print(f"  False Positives (normal wrongly flagged)    : {fp}")
    print(f"  False Negatives (anomaly missed)            : {fn}")
    print(f"  True  Negatives (normal correctly passed)   : {tn}")
    print(f"{'='*50}\n")


def save_model(pipeline: Pipeline, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        pickle.dump(pipeline, f, protocol=pickle.HIGHEST_PROTOCOL)
    print(f"  Model saved -> {path}")


if __name__ == "__main__":
    print("\n[train_model] Generating synthetic dataset ...")
    df = generate_synthetic_data()
    print(f"[train_model] Dataset: {len(df):,} rows  |  "
          f"normal={int((df.label == 1).sum()):,}  anomaly={int((df.label == -1).sum()):,}")

    print("[train_model] Training Isolation Forest ...")
    pipeline = train(df)

    evaluate(pipeline, df)

    print("[train_model] Saving model ...")
    save_model(pipeline, MODEL_OUTPUT)

    print("[train_model] Training complete.\n")
