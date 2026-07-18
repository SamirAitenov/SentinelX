"""
trainer.py — обучает RandomForest и XGBoost, сравнивает, сохраняет лучшую.

Запуск:
    python -m ai.trainer
"""

import os
import sys
import pickle

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_curve, auc, f1_score, accuracy_score
)
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from ai.features import extract_features, FEATURE_NAMES
from ai.dataset_generator import generate_dataset

# ---------------------------------------------------------------------------
# Пути
# ---------------------------------------------------------------------------
AI_DIR      = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(AI_DIR, "dataset")
MODEL_PATH  = os.path.join(AI_DIR, "model.pkl")
SCALER_PATH = os.path.join(AI_DIR, "scaler.pkl")
META_PATH   = os.path.join(AI_DIR, "model_meta.pkl")
PLOTS_DIR   = os.path.join(AI_DIR, "plots")

MALWARE = 1
SAFE    = 0


# ---------------------------------------------------------------------------
# Загрузка данных
# ---------------------------------------------------------------------------

def load_samples(directory, label):
    X, y = [], []
    for filename in os.listdir(directory):
        path = os.path.join(directory, filename)
        if not os.path.isfile(path):
            continue
        features = extract_features(path)
        if features is not None:
            X.append(features)
            y.append(label)
    return X, y


def build_dataset(n_malware=400, n_safe=400):
    print(f"Генерирую датасет ({n_malware} malware + {n_safe} safe)...")
    malware_dir, safe_dir = generate_dataset(
        DATASET_DIR, n_malware=n_malware, n_safe=n_safe
    )

    X_mal, y_mal   = load_samples(malware_dir, MALWARE)
    X_safe, y_safe = load_samples(safe_dir,    SAFE)

    print(f"  Malware: {len(X_mal)} векторов")
    print(f"  Safe:    {len(X_safe)} векторов")

    X = np.array(X_mal + X_safe, dtype=np.float64)
    y = np.array(y_mal + y_safe, dtype=np.int32)
    return X, y


# ---------------------------------------------------------------------------
# Графики
# ---------------------------------------------------------------------------

def _plot_confusion_matrix(cm, model_name, ax):
    im = ax.imshow(cm, interpolation="nearest", cmap="Blues")
    ax.figure.colorbar(im, ax=ax)
    classes = ["SAFE", "MALWARE"]
    ax.set(
        xticks=[0, 1], yticks=[0, 1],
        xticklabels=classes, yticklabels=classes,
        xlabel="Предсказано", ylabel="Факт",
        title=f"Confusion Matrix\n{model_name}"
    )
    total = cm.sum()
    for i in range(2):
        for j in range(2):
            pct = cm[i, j] / total * 100
            ax.text(j, i, f"{cm[i,j]}\n({pct:.1f}%)",
                    ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black",
                    fontsize=11, fontweight="bold")


def save_plots(rf_model, xgb_model, scaler, X_test, y_test):
    os.makedirs(PLOTS_DIR, exist_ok=True)

    rf_pred  = rf_model.predict(X_test)
    xgb_pred = xgb_model.predict(X_test)

    rf_prob  = rf_model.predict_proba(X_test)[:, 1]
    xgb_prob = xgb_model.predict_proba(X_test)[:, 1]

    # ── 1. Confusion matrices ───────────────────────────────────────────────
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    fig.patch.set_facecolor("#0A0F1C")
    for ax in axes:
        ax.set_facecolor("#111827")
        ax.tick_params(colors="white")
        ax.xaxis.label.set_color("white")
        ax.yaxis.label.set_color("white")
        ax.title.set_color("#00F5FF")

    _plot_confusion_matrix(confusion_matrix(y_test, rf_pred),  "RandomForest", axes[0])
    _plot_confusion_matrix(confusion_matrix(y_test, xgb_pred), "XGBoost",      axes[1])
    fig.suptitle("Confusion Matrix — RandomForest vs XGBoost",
                 color="#00F5FF", fontsize=14, fontweight="bold")
    plt.tight_layout()
    path = os.path.join(PLOTS_DIR, "confusion_matrix.png")
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"  Сохранён: {path}")

    # ── 2. ROC кривые ──────────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 6))
    fig.patch.set_facecolor("#0A0F1C")
    ax.set_facecolor("#111827")

    for prob, name, color in [
        (rf_prob,  "RandomForest", "#00F5FF"),
        (xgb_prob, "XGBoost",     "#00FF99"),
    ]:
        fpr, tpr, _ = roc_curve(y_test, prob)
        roc_auc     = auc(fpr, tpr)
        ax.plot(fpr, tpr, color=color, lw=2,
                label=f"{name} (AUC = {roc_auc:.3f})")

    ax.plot([0, 1], [0, 1], color="#555", lw=1, linestyle="--")
    ax.set_xlim([0, 1]); ax.set_ylim([0, 1.02])
    ax.set_xlabel("False Positive Rate", color="white")
    ax.set_ylabel("True Positive Rate",  color="white")
    ax.set_title("ROC Curve — RandomForest vs XGBoost",
                 color="#00F5FF", fontweight="bold")
    ax.tick_params(colors="white")
    ax.legend(facecolor="#111827", labelcolor="white")
    ax.grid(True, color="#1F2A3D", alpha=0.5)

    path = os.path.join(PLOTS_DIR, "roc_curve.png")
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"  Сохранён: {path}")

    # ── 3. Feature importance (RandomForest) ───────────────────────────────
    importances = rf_model.feature_importances_
    idx = importances.argsort()[::-1]

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor("#0A0F1C")
    ax.set_facecolor("#111827")

    colors = ["#00F5FF" if i == idx[0] else "#1F2A3D" for i in range(len(FEATURE_NAMES))]
    bars = ax.barh(
        [FEATURE_NAMES[i] for i in idx],
        [importances[i] for i in idx],
        color=["#00F5FF" if j == 0 else "#0B8C94" for j in range(len(idx))]
    )
    ax.set_xlabel("Важность признака", color="white")
    ax.set_title("Feature Importance — RandomForest",
                 color="#00F5FF", fontweight="bold")
    ax.tick_params(colors="white")
    ax.invert_yaxis()
    ax.grid(True, axis="x", color="#1F2A3D", alpha=0.5)

    for bar, imp in zip(bars, [importances[i] for i in idx]):
        ax.text(imp + 0.002, bar.get_y() + bar.get_height() / 2,
                f"{imp:.3f}", va="center", color="white", fontsize=9)

    path = os.path.join(PLOTS_DIR, "feature_importance.png")
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"  Сохранён: {path}")

    # ── 4. Сравнение метрик ────────────────────────────────────────────────
    metrics = {
        "Accuracy": [
            accuracy_score(y_test, rf_pred),
            accuracy_score(y_test, xgb_pred),
        ],
        "F1 Score": [
            f1_score(y_test, rf_pred),
            f1_score(y_test, xgb_pred),
        ],
        "AUC": [
            auc(*roc_curve(y_test, rf_prob)[:2]),
            auc(*roc_curve(y_test, xgb_prob)[:2]),
        ],
    }

    x      = np.arange(len(metrics))
    width  = 0.35
    fig, ax = plt.subplots(figsize=(9, 5))
    fig.patch.set_facecolor("#0A0F1C")
    ax.set_facecolor("#111827")

    bars1 = ax.bar(x - width/2, [v[0] for v in metrics.values()],
                   width, label="RandomForest", color="#00F5FF", alpha=0.9)
    bars2 = ax.bar(x + width/2, [v[1] for v in metrics.values()],
                   width, label="XGBoost",      color="#00FF99", alpha=0.9)

    ax.set_ylim(0, 1.12)
    ax.set_xticks(x)
    ax.set_xticklabels(metrics.keys(), color="white")
    ax.set_ylabel("Значение", color="white")
    ax.set_title("RandomForest vs XGBoost — сравнение метрик",
                 color="#00F5FF", fontweight="bold")
    ax.tick_params(colors="white")
    ax.legend(facecolor="#111827", labelcolor="white")
    ax.grid(True, axis="y", color="#1F2A3D", alpha=0.5)

    for bar in list(bars1) + list(bars2):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                f"{bar.get_height():.3f}", ha="center", va="bottom",
                color="white", fontsize=9, fontweight="bold")

    path = os.path.join(PLOTS_DIR, "model_comparison.png")
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"  Сохранён: {path}")


# ---------------------------------------------------------------------------
# Обучение
# ---------------------------------------------------------------------------

def train(n_malware=400, n_safe=400):
    X, y = build_dataset(n_malware, n_safe)

    print(f"\nДатасет: {len(X)} образцов, {X.shape[1]} признаков")

    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )

    # ── RandomForest ────────────────────────────────────────────────────────
    print("\n[1/2] Обучаю RandomForest...")
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_split=4,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    rf_pred = rf.predict(X_test)
    rf_f1   = f1_score(y_test, rf_pred)
    rf_acc  = accuracy_score(y_test, rf_pred)
    print(f"   Accuracy: {rf_acc:.1%}  |  F1: {rf_f1:.4f}")

    # ── XGBoost ─────────────────────────────────────────────────────────────
    print("\n[2/2] Обучаю XGBoost...")
    xgb = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
        verbosity=0,
    )
    xgb.fit(X_train, y_train)
    xgb_pred = xgb.predict(X_test)
    xgb_f1   = f1_score(y_test, xgb_pred)
    xgb_acc  = accuracy_score(y_test, xgb_pred)
    print(f"   Accuracy: {xgb_acc:.1%}  |  F1: {xgb_f1:.4f}")

    # ── Сравнение ───────────────────────────────────────────────────────────
    print(f"\n{'='*50}")
    print(f"  СРАВНЕНИЕ МОДЕЛЕЙ")
    print(f"{'='*50}")
    print(f"  {'Модель':<20} {'Accuracy':>10} {'F1':>10}")
    print(f"  {'-'*42}")
    print(f"  {'RandomForest':<20} {rf_acc:>10.1%} {rf_f1:>10.4f}")
    print(f"  {'XGBoost':<20} {xgb_acc:>10.1%} {xgb_f1:>10.4f}")
    print(f"{'='*50}")

    # выбираем лучшую по F1
    if xgb_f1 >= rf_f1:
        best_model = xgb
        best_name  = "XGBoost"
    else:
        best_model = rf
        best_name  = "RandomForest"

    print(f"\n  Победитель: {best_name} (F1 = {max(rf_f1, xgb_f1):.4f})")

    # кросс-валидация для победителя
    print(f"\nКросс-валидация {best_name} (5-fold):")
    cv = cross_val_score(best_model, X_scaled, y, cv=5, scoring="f1")
    print(f"  F1: {[f'{s:.3f}' for s in cv]}")
    print(f"  Среднее: {cv.mean():.3f} ± {cv.std():.3f}")

    # ── Графики ─────────────────────────────────────────────────────────────
    print("\nСохраняю графики...")
    save_plots(rf, xgb, scaler, X_test, y_test)

    # ── Сохранение ──────────────────────────────────────────────────────────
    with open(MODEL_PATH,  "wb") as f: pickle.dump(best_model, f)
    with open(SCALER_PATH, "wb") as f: pickle.dump(scaler, f)
    with open(META_PATH,   "wb") as f:
        pickle.dump({
            "model_name":  best_name,
            "rf_accuracy": rf_acc,  "rf_f1":  rf_f1,
            "xgb_accuracy": xgb_acc, "xgb_f1": xgb_f1,
            "winner_f1":   max(rf_f1, xgb_f1),
            "n_features":  len(FEATURE_NAMES),
            "feature_names": FEATURE_NAMES,
        }, f)

    print(f"\nМодель сохранена → {MODEL_PATH}  ({best_name})")
    print(f"Графики          → {PLOTS_DIR}/")
    print("\nГотово.")


if __name__ == "__main__":
    train()
