"""
fp_check.py - измеряет ложные срабатывания на ТВОИХ обычных файлах.

ТОЛЬКО ЧТЕНИЕ: файлы не перемещаются и не удаляются (scan_file() здесь
не используется, потому что он отправляет угрозы в карантин).

Запуск из папки проекта:
    python fp_check.py "C:\\путь\\к\\папке\\с\\твоими\\проектами"
"""

import os
import sys

os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.getcwd())

from core.hash_checker import is_malicious_hash
from core.heuristic_engine import heuristic_analysis
from ai.model import predict_file, is_model_ready

try:
    from core.app import analyze as behavior_analyze   # поведенческий анализ
except Exception:
    behavior_analyze = None

SKIP_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv",
             "quarantine", "dist", "build"}
MAX_SIZE = 2 * 1024 * 1024        # пропускаем файлы больше 2 МБ
LIMIT = 3000                      # не больше 3000 файлов

if len(sys.argv) < 2:
    print('Укажи папку: python fp_check.py "C:\\путь\\к\\папке"')
    sys.exit(1)

root = sys.argv[1]
if not os.path.isdir(root):
    print(f"Папка не найдена: {root}")
    sys.exit(1)

ai_ready = is_model_ready()
if not ai_ready:
    print("Модель ИИ не найдена (python -m ai.trainer). Считаю без ИИ.")

total = 0
flagged = {"hash": [], "heuristic_high": [], "heuristic_medium": [],
           "ai_malware": [], "behavior_malicious": []}

for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    for name in filenames:
        path = os.path.join(dirpath, name)
        try:
            if os.path.getsize(path) > MAX_SIZE:
                continue
        except OSError:
            continue

        total += 1
        if total > LIMIT:
            break

        if is_malicious_hash(path):
            flagged["hash"].append(path)

        risk = heuristic_analysis(path)
        if risk == "HIGH":
            flagged["heuristic_high"].append(path)
        elif risk == "MEDIUM":
            flagged["heuristic_medium"].append(path)

        if ai_ready:
            r = predict_file(path)
            if r and r["label"] == "MALWARE":
                flagged["ai_malware"].append(path)

        if behavior_analyze:
            try:
                b = behavior_analyze(path)
                if b.get("verdict") == "MALICIOUS":
                    flagged["behavior_malicious"].append(path)
            except Exception:
                pass
    if total > LIMIT:
        break

print(f"\nПроверено файлов: {min(total, LIMIT)}  (папка: {root})")
print("Все эти файлы твои обычные, поэтому каждое срабатывание это ЛОЖНОЕ срабатывание.\n")

labels = [
    ("hash", "Хеш-проверка"),
    ("heuristic_high", "Эвристика HIGH (уходит в карантин)"),
    ("heuristic_medium", "Эвристика MEDIUM"),
    ("ai_malware", "ИИ: MALWARE"),
    ("behavior_malicious", "Поведенческий: MALICIOUS"),
]
n = max(min(total, LIMIT), 1)
for key, label in labels:
    cnt = len(flagged[key])
    print(f"  {label:38} {cnt:5}  ({cnt / n:.1%})")

print("\nПримеры (до 5 на категорию):")
for key, label in labels:
    for p in flagged[key][:5]:
        print(f"  [{label}] {p}")
