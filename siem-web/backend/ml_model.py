import os
import pickle
import numpy as np
from backend.utils import get_logger

logger = get_logger(__name__)

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(_BASE_DIR, "ml", "model.pkl")

# Score contribution when the ML model flags an anomaly
SCORE_ML_ANOMALY = 25

# Cached model reference (load once)
_model = None


def _load_model():
    """Load the Isolation Forest model from disk (cached)."""
    global _model
    if _model is not None:
        return _model
    if not os.path.exists(MODEL_PATH):
        logger.warning(
            f"[MLModel] model.pkl not found at {MODEL_PATH}. "
            "Run `python ml/train_model.py` to generate it. ML scoring disabled."
        )
        return None
    try:
        with open(MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
        logger.info(f"[MLModel] Isolation Forest loaded from {MODEL_PATH}")
        return _model
    except Exception as e:
        logger.error(f"[MLModel] Failed to load model: {e}")
        return None


def predict(port: int, payload_size: int) -> tuple[bool, int]:
    """
    Run the Isolation Forest on the given features.

    Returns:
        (is_anomaly: bool, ml_score: int)
    """
    model = _load_model()
    if model is None:
        # Model unavailable — degrade gracefully
        return False, 0

    try:
        features = np.array([[port, payload_size]], dtype=float)
        prediction = model.predict(features)  # -1 = anomaly, 1 = normal
        is_anomaly = bool(prediction[0] == -1)
        ml_score = SCORE_ML_ANOMALY if is_anomaly else 0
        logger.info(
            f"[MLModel] port={port} payload={payload_size} -> "
            f"anomaly={is_anomaly} score=+{ml_score}"
        )
        return is_anomaly, ml_score
    except Exception as e:
        logger.error(f"[MLModel] Prediction error: {e}")
        return False, 0


def reload_model() -> bool:
    """Force reload the model from disk (e.g., after retraining)."""
    global _model
    _model = None
    m = _load_model()
    return m is not None
