"""
launch.py — запускает SentinelX и Red Team одновременно

Запуск:
    python launch.py
"""

import subprocess
import sys
import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))

python = sys.executable

# запускаем оба приложения как отдельные процессы
sentinelx = subprocess.Popen([python, "main.py"])
red_team  = subprocess.Popen([python, "red_team_gui.py"])

# ждём пока оба закроются
sentinelx.wait()
red_team.wait()
