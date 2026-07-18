"""
model.py — загрузка модели и предсказание для одного файла.
Работает с любой сохранённой моделью — RandomForest или XGBoost.
"""

import os
import pickle
from typing import Optional

import numpy as np

from ai.features import extract_features, FEATURE_NAMES

AI_DIR      = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH  = os.path.join(AI_DIR, "model.pkl")
SCALER_PATH = os.path.join(AI_DIR, "scaler.pkl")
META_PATH   = os.path.join(AI_DIR, "model_meta.pkl")

_model  = None
_scaler = None
_meta   = None


def is_model_ready():
    return os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH)


def get_model_info():
    """Возвращает информацию об активной модели для отображения в GUI."""
    global _meta
    if _meta is None and os.path.exists(META_PATH):
        with open(META_PATH, "rb") as f:
            _meta = pickle.load(f)
    if _meta:
        name = _meta.get("model_name", "Unknown")
        f1   = _meta.get("winner_f1", 0)
        return f"{name} · F1={f1:.3f} · {len(FEATURE_NAMES)} признаков"
    return f"RandomForest · {len(FEATURE_NAMES)} признаков"


def _load_model():
    global _model, _scaler, _meta
    if _model is not None:
        return
    if not is_model_ready():
        raise FileNotFoundError("Модель не найдена. Запусти: python -m ai.trainer")
    with open(MODEL_PATH,  "rb") as f: _model  = pickle.load(f)
    with open(SCALER_PATH, "rb") as f: _scaler = pickle.load(f)
    if os.path.exists(META_PATH):
        with open(META_PATH, "rb") as f: _meta = pickle.load(f)


def predict_file(file_path: str) -> Optional[dict]:
    try:
        _load_model()
    except FileNotFoundError:
        return None

    features = extract_features(file_path)
    if features is None:
        return None

    X        = np.array([features], dtype=np.float64)
    X_scaled = _scaler.transform(X)

    label_id      = int(_model.predict(X_scaled)[0])
    probabilities = _model.predict_proba(X_scaled)[0]

    label      = "MALWARE" if label_id == 1 else "SAFE"
    confidence = float(probabilities[label_id])

    if label == "MALWARE":
        risk = "HIGH" if confidence >= 0.80 else "MEDIUM"
    else:
        risk = "LOW"  if confidence >= 0.80 else "MEDIUM"

    return {
        "label":      label,
        "confidence": confidence,
        "risk":       risk,
        "features":   dict(zip(FEATURE_NAMES, features)),
    }


def predict_batch(file_paths):
    return [predict_file(p) for p in file_paths]
