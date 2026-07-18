"""
test_ai_manual.py — интерактивное тестирование AI модуля

Запуск:
    python test_ai_manual.py
"""

import os
import sys

os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.getcwd())

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

from ai.model import predict_file, is_model_ready
from ai.features import extract_features, FEATURE_NAMES

if not is_model_ready():
    print(f"{RED}Модель не найдена. Сначала запусти: python -m ai.trainer{RESET}")
    sys.exit(1)

print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════╗{RESET}")
print(f"{BOLD}{CYAN}║       SentinelX — AI модуль тест         ║{RESET}")
print(f"{BOLD}{CYAN}╚══════════════════════════════════════════╝{RESET}")
print(f"  Напиши путь к файлу или 'q' для выхода\n")

while True:
    try:
        path = input(f"{CYAN}Файл:{RESET} ").strip().strip('"')
    except (EOFError, KeyboardInterrupt):
        print("\nВыход.")
        break

    if path.lower() == "q":
        break

    if not path:
        continue

    if not os.path.exists(path):
        print(f"  {RED}Файл не найден: {path}{RESET}\n")
        continue

    print(f"\n  Анализирую: {os.path.basename(path)}")
    print(f"  {'─'*42}")

    result = predict_file(path)

    if result is None:
        print(f"  {RED}Не удалось прочитать файл{RESET}\n")
        continue

    label = result["label"]
    conf  = result["confidence"]
    risk  = result["risk"]

    # цвет вердикта
    if label == "MALWARE":
        label_color = RED
        icon = "⚠"
    else:
        label_color = GREEN
        icon = "✓"

    risk_color = {
        "HIGH":   RED,
        "MEDIUM": YELLOW,
        "LOW":    GREEN,
    }.get(risk, RESET)

    print(f"\n  {icon} Вердикт:     {BOLD}{label_color}{label}{RESET}")
    print(f"  📊 Уверенность: {BOLD}{conf:.0%}{RESET}")
    print(f"  🎯 Риск:        {BOLD}{risk_color}{risk}{RESET}")

    # топ сигналы
    feats = result["features"]
    signals = []
    if feats.get("keyword_count", 0) >= 1:
        signals.append(f"подозрительных команд: {int(feats['keyword_count'])}")
    if feats.get("base64_score", 0) >= 0.2:
        signals.append(f"base64 score: {feats['base64_score']:.2f}")
    if feats.get("url_count", 0) >= 1:
        signals.append(f"URL в файле: {int(feats['url_count'])}")
    if feats.get("ip_count", 0) >= 1:
        signals.append(f"IP адресов: {int(feats['ip_count'])}")
    if feats.get("entropy", 0) >= 6.0:
        signals.append(f"высокая энтропия: {feats['entropy']:.2f}")
    if feats.get("suspicious_ext", 0) == 1.0:
        signals.append("подозрительное расширение")

    if signals:
        print(f"\n  🔍 Почему так решила модель:")
        for s in signals:
            print(f"     • {s}")

    # все 15 признаков
    print(f"\n  📋 Все признаки ({len(FEATURE_NAMES)}):")
    print(f"  {'─'*42}")
    for name, val in zip(FEATURE_NAMES, extract_features(path)):
        bar_len = int(min(val, 1.0) * 20) if val <= 1.0 else min(int(val / 10), 20)
        bar = "█" * bar_len

        # подсвечиваем важные признаки
        color = RESET
        if name in ("keyword_count", "unique_keywords") and val >= 2:
            color = RED
        elif name == "entropy" and val >= 6.0:
            color = YELLOW
        elif name == "base64_score" and val >= 0.2:
            color = YELLOW
        elif name in ("url_count", "ip_count") and val >= 1:
            color = YELLOW
        elif name == "suspicious_ext" and val == 1.0:
            color = YELLOW

        print(f"  {name:<25} {color}{val:>8.3f}{RESET}  {CYAN}{bar}{RESET}")

    print()
