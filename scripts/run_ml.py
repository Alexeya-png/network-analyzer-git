#!/usr/bin/env python3
import sys
import json
import os
import numpy as np
import joblib
from sklearn.metrics import accuracy_score

def load_payload():
    """Читает JSON из stdin, либо из файла по первому аргументу."""
    if sys.stdin.isatty() and len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        with open(sys.argv[1], 'r') as f:
            return json.load(f)
    return json.load(sys.stdin)

def main():
    # 1) Загружаем входные данные
    payload = load_payload()
    features    = np.array(payload.get("features", []))
    true_labels = np.array(payload.get("true_labels", []))

    if features.size == 0:
        print(json.dumps({"error": "No features provided"}))
        sys.exit(1)

    # 2) Загружаем модель
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(script_dir, "random_forest_model.joblib")
    model = joblib.load(model_path)

    # 3) Предсказания и вероятности
    raw_preds = model.predict(features)             # [0,1,...]
    proba     = model.predict_proba(features)       # shape=(n_samples,n_classes)

    # 4) Явно берём метку 1 как «вредоносную»
    if 1 not in model.classes_:
        print(json.dumps({"error": f"Model classes are {model.classes_}, expected 1"}))
        sys.exit(1)
    idx_mal = list(model.classes_).index(1)

    # 5) Применяем порог 0.5 для вероятности вредоносности
    preds = (proba[:, idx_mal] > 0.5).astype(int)

    # 6) Метрика accuracy (если есть «правда»)
    acc = None
    if true_labels.size == len(preds):
        acc = round(accuracy_score(true_labels, preds) * 100, 1)

    # 7) Собираем summary
    total_count     = len(preds)
    malicious_count = int((preds == 1).sum())
    benign_count    = total_count - malicious_count

    summary = {
        "total":     total_count,
        "malicious": malicious_count,
        "benign":    benign_count,
        **({"accuracy": acc} if acc is not None else {})
    }

    # 8) Формируем и выводим JSON
    out = {
        "predictions": preds.tolist(),
        "confidence":  proba[:, idx_mal].tolist(),
        "summary":     summary
    }
    print(json.dumps(out))

if __name__ == "__main__":
    main()
