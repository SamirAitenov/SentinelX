# gui/translations.py
# Все тексты интерфейса в двух языках.
# Добавить новый язык = добавить новый словарь.

TRANSLATIONS = {
    "EN": {
        # Сайдбар
        "app_subtitle":        "AI ANTIVIRUS",
        "sidebar_protected":   "● PROTECTED",
        "sidebar_monitor_off": "● MONITOR OFF",
        "lang_button":         "RU",

        # Навигация
        "nav_dashboard":  "Dashboard",
        "nav_scan":       "Scan",
        "nav_ai_scan":    "AI Scan",
        "nav_behavior":   "Behavior",
        "nav_threats":    "Threats",
        "nav_quarantine": "Quarantine",
        "nav_logs":       "Logs",
        "nav_settings":   "Settings",

        # Dashboard
        "dash_title":          "Dashboard",
        "dash_subtitle":       "Live overview of your system's protection status.",
        "dash_protected":      "●  SYSTEM PROTECTED",
        "dash_rt_off":         "●  REALTIME PROTECTION OFF",
        "cpu_usage":           "CPU Usage",
        "ram_usage":           "RAM Usage",
        "threats_blocked":     "Threats Blocked",
        "in_quarantine":       "In Quarantine",
        "resource_monitor":    "RESOURCE MONITOR",
        "top_processes":       "TOP PROCESSES",

        # Scan
        "scan_title":          "Scan",
        "scan_subtitle":       "Choose a folder to check every file for suspicious hashes and behaviour.",
        "scan_folder_btn":     "📁  SCAN A FOLDER",
        "scan_clear_btn":      "Clear output",
        "scan_placeholder":    "Scan results will appear here…",
        "scan_select_folder":  "Select Folder",
        "scanning":            "SCANNING…",
        "scanning_label":      "Scanning: ",
        "no_threats":          "✔ No threats found.",
        "threat_detected":     "⚠ THREAT DETECTED",
        "scan_file_label":     "File: ",
        "scan_reason_label":   "Reason: ",
        "last_scan":           "Last scan: ",
        "threats_found":       "threat(s) found",

        # Threats
        "threats_title":       "Threats",
        "threats_subtitle":    "Every threat detected during a scan or by realtime protection.",
        "filter_by_risk":      "Filter by risk:",
        "col_id":              "ID",
        "col_file":            "File",
        "col_risk":            "Risk",
        "col_date":            "Date",
        "records":             "record(s)",
        "no_threats_recorded": "No threats recorded",
        "no_threats_hint":     "Run a scan or enable realtime protection to start tracking threats here.",
        "no_risk_threats":     "No {} risk threats",
        "no_risk_hint":        "Nothing currently classified as {}. Try a different filter.",

        # Quarantine
        "quar_title":          "Quarantine",
        "quar_subtitle":       "Files isolated here can no longer run. Restore them or delete them for good.",
        "refresh_btn":         "⟳  Refresh",
        "col_size":            "Size",
        "col_quarantined":     "Quarantined",
        "col_actions":         "Actions",
        "restore_btn":         "Restore",
        "delete_btn":          "Delete",
        "quar_empty_title":    "Quarantine is empty",
        "quar_empty_hint":     "Dangerous files found during a scan or by realtime protection will show up here.",
        "restore_confirm_title": "Restore file",
        "restore_confirm_msg": "Restore \"{}\" to its original location?\n\nOnly do this if you're sure it isn't actually malicious.",
        "restored_title":      "Restored",
        "restored_msg":        "\"{}\" has been restored.",
        "restore_fail_title":  "Restore failed",
        "restore_fail_msg":    "Could not restore \"{}\".",
        "delete_confirm_title": "Delete permanently",
        "delete_confirm_msg":  "Permanently delete \"{}\"? This cannot be undone.",
        "delete_fail_title":   "Delete failed",
        "delete_fail_msg":     "Could not delete \"{}\".",

        # Logs
        "logs_title":          "Logs",
        "logs_subtitle":       "A timestamped record of everything SentinelX has done.",
        "clear_log_btn":       "Clear log",
        "search_logs":         "Search logs…",
        "no_logs_title":       "No activity yet",
        "no_logs_hint":        "Scan a folder or enable realtime protection to start generating logs.",
        "no_match_title":      "No matching logs",
        "no_match_hint":       "Nothing in the log matches \"{}\". Try a different search term.",
        "clear_logs_confirm_title": "Clear logs",
        "clear_logs_confirm_msg":   "Clear the entire activity log? This cannot be undone.",

        # Settings
        "settings_title":      "Settings",
        "settings_subtitle":   "Configure how SentinelX watches and protects your system.",
        "realtime_title":      "Realtime Protection",
        "realtime_desc":       "Watches a folder continuously and scans every new file the instant it appears.",
        "watching":            "Watching: ",
        "change_folder_btn":   "Change folder",
        "select_monitor_folder": "Select folder to monitor",
        "about_title":         "About SentinelX",
        "about_text":          "SentinelX combines hash matching and heuristic analysis to flag suspicious files, moves anything dangerous into quarantine, and keeps a full activity log of what it did and when.",
        "version_label":       "Version 1.0  ·  Engine: Hash + Heuristic + Behavior + AI",
        "rt_error_title":      "Could not start protection",

        # AI Scan
        "ai_title":            "AI Scan",
        "ai_subtitle":         "RandomForest model analyses 15 numeric features of each file — size, entropy, keyword density, base64 content and more — to classify it independently of keyword matching.",
        "model_ready":         "Model ready",
        "model_not_trained":   "Model not trained yet",
        "model_not_trained_desc": "Click 'Train model now' to generate a synthetic dataset and train the RandomForest classifier. Takes about 10–20 seconds.",
        "retrain_btn":         "Retrain model",
        "train_btn":           "Train model now",
        "training_btn":        "Training…",
        "training_desc":       "Generating dataset and training — please wait…",
        "scan_file_btn":       "🔬  SCAN A FILE",
        "scan_folder_btn_ai":  "📁  SCAN A FOLDER",
        "clear_btn":           "Clear",
        "col_ai_label":        "AI Label",
        "col_confidence":      "Confidence",
        "col_top_signal":      "Top signal",
        "select_file_scan":    "Select file to scan",
        "select_folder_scan":  "Select folder",
        "scan_fail_title":     "Scan failed",
        "scan_fail_msg":       "Could not read file:\n{}",
        "last_scan_ai":        "Last scan: {}  ·  AI verdict: {} ({})",
        "scanned_summary":     "Scanned {} files · {} malware detected · {} safe",
        "scanning_progress":   "Scanning… {}/{}",
        "top_signal_keywords": "keywords ×{}",
        "top_signal_base64":   "base64 payload",
        "top_signal_urls":     "URLs ×{}",
        "top_signal_entropy":  "entropy {}",
        "top_signal_ip":       "IP addresses ×{}",
        "top_signal_ext":      "suspicious extension",
        "top_signal_nonascii": "high non-ASCII ratio",
        "top_signal_lines":    "low unique-line ratio",
        "top_signal_general":  "general pattern",

        # Behavior
        "beh_title":           "Behavior Analysis",
        "beh_subtitle":        "Static behavioral analysis — detects what a file intends to do across 6 threat categories: Persistence, Network, Evasion, Destruction, Privilege Escalation and Lateral Movement.",
        "analyse_file_btn":    "🧬  ANALYSE A FILE",
        "analysing_btn":       "Analysing…",
        "col_category":        "Category",
        "col_indicators":      "Indicators",
        "col_top_finding":     "Top Finding",
        "beh_placeholder":     "Select a file to see detailed behavioral analysis…",
        "verdict_label":       "VERDICT",
        "score_label":         "BEHAVIOR SCORE",
        "indicators_label":    "INDICATORS",
        "select_file_analyse": "Select file to analyse",
        "file_label":          "File: ",
    },

    "RU": {
        # Сайдбар
        "app_subtitle":        "ИИ АНТИВИРУС",
        "sidebar_protected":   "● ЗАЩИЩЕНО",
        "sidebar_monitor_off": "● МОНИТОР ВЫКЛ",
        "lang_button":         "EN",

        # Навигация
        "nav_dashboard":  "Главная",
        "nav_scan":       "Сканирование",
        "nav_ai_scan":    "ИИ Сканирование",
        "nav_behavior":   "Поведение",
        "nav_threats":    "Угрозы",
        "nav_quarantine": "Карантин",
        "nav_logs":       "Журнал",
        "nav_settings":   "Настройки",

        # Dashboard
        "dash_title":          "Главная",
        "dash_subtitle":       "Обзор состояния защиты системы в реальном времени.",
        "dash_protected":      "●  СИСТЕМА ЗАЩИЩЕНА",
        "dash_rt_off":         "●  ЗАЩИТА В РЕАЛЬНОМ ВРЕМЕНИ ВЫКЛ",
        "cpu_usage":           "Загрузка ЦП",
        "ram_usage":           "Загрузка ОЗУ",
        "threats_blocked":     "Угроз обнаружено",
        "in_quarantine":       "В карантине",
        "resource_monitor":    "МОНИТОР РЕСУРСОВ",
        "top_processes":       "ТОП ПРОЦЕССЫ",

        # Scan
        "scan_title":          "Сканирование",
        "scan_subtitle":       "Выберите папку для проверки каждого файла на подозрительные хеши и поведение.",
        "scan_folder_btn":     "📁  СКАНИРОВАТЬ ПАПКУ",
        "scan_clear_btn":      "Очистить",
        "scan_placeholder":    "Результаты сканирования появятся здесь…",
        "scan_select_folder":  "Выберите папку",
        "scanning":            "СКАНИРОВАНИЕ…",
        "scanning_label":      "Сканирование: ",
        "no_threats":          "✔ Угроз не обнаружено.",
        "threat_detected":     "⚠ УГРОЗА ОБНАРУЖЕНА",
        "scan_file_label":     "Файл: ",
        "scan_reason_label":   "Причина: ",
        "last_scan":           "Последнее сканирование: ",
        "threats_found":       "угроз найдено",

        # Threats
        "threats_title":       "Угрозы",
        "threats_subtitle":    "Все угрозы, обнаруженные при сканировании или защитой в реальном времени.",
        "filter_by_risk":      "Фильтр по риску:",
        "col_id":              "№",
        "col_file":            "Файл",
        "col_risk":            "Риск",
        "col_date":            "Дата",
        "records":             "запис(ей)",
        "no_threats_recorded": "Угроз не зафиксировано",
        "no_threats_hint":     "Выполните сканирование или включите защиту в реальном времени.",
        "no_risk_threats":     "Угроз с риском {} не найдено",
        "no_risk_hint":        "Ничего с уровнем {}. Попробуйте другой фильтр.",

        # Quarantine
        "quar_title":          "Карантин",
        "quar_subtitle":       "Файлы здесь изолированы и не могут запуститься. Восстановите или удалите навсегда.",
        "refresh_btn":         "⟳  Обновить",
        "col_size":            "Размер",
        "col_quarantined":     "Дата изоляции",
        "col_actions":         "Действия",
        "restore_btn":         "Восстановить",
        "delete_btn":          "Удалить",
        "quar_empty_title":    "Карантин пуст",
        "quar_empty_hint":     "Опасные файлы, обнаруженные при сканировании или защитой, появятся здесь.",
        "restore_confirm_title": "Восстановить файл",
        "restore_confirm_msg": "Восстановить \"{}\" в исходное расположение?\n\nДелайте это только если уверены, что файл не вредоносный.",
        "restored_title":      "Восстановлено",
        "restored_msg":        "\"{}\" был восстановлен.",
        "restore_fail_title":  "Ошибка восстановления",
        "restore_fail_msg":    "Не удалось восстановить \"{}\".",
        "delete_confirm_title": "Удалить навсегда",
        "delete_confirm_msg":  "Удалить \"{}\" навсегда? Это действие нельзя отменить.",
        "delete_fail_title":   "Ошибка удаления",
        "delete_fail_msg":     "Не удалось удалить \"{}\".",

        # Logs
        "logs_title":          "Журнал событий",
        "logs_subtitle":       "Хронологическая запись всех действий SentinelX.",
        "clear_log_btn":       "Очистить",
        "search_logs":         "Поиск в журнале…",
        "no_logs_title":       "Активности нет",
        "no_logs_hint":        "Выполните сканирование или включите защиту в реальном времени.",
        "no_match_title":      "Ничего не найдено",
        "no_match_hint":       "В журнале нет записей совпадающих с \"{}\". Попробуйте другой запрос.",
        "clear_logs_confirm_title": "Очистить журнал",
        "clear_logs_confirm_msg":   "Очистить весь журнал событий? Это действие нельзя отменить.",

        # Settings
        "settings_title":      "Настройки",
        "settings_subtitle":   "Настройте параметры наблюдения и защиты SentinelX.",
        "realtime_title":      "Защита в реальном времени",
        "realtime_desc":       "Непрерывно следит за папкой и сканирует каждый новый файл в момент появления.",
        "watching":            "Наблюдение: ",
        "change_folder_btn":   "Изменить папку",
        "select_monitor_folder": "Выберите папку для наблюдения",
        "about_title":         "О программе SentinelX",
        "about_text":          "SentinelX использует хеш-анализ, эвристику, поведенческий анализ и ИИ для выявления подозрительных файлов, перемещает опасные файлы в карантин и ведёт полный журнал событий.",
        "version_label":       "Версия 1.0  ·  Движок: Хеш + Эвристика + Поведение + ИИ",
        "rt_error_title":      "Не удалось запустить защиту",

        # AI Scan
        "ai_title":            "ИИ Сканирование",
        "ai_subtitle":         "Модель XGBoost анализирует 15 числовых признаков каждого файла — размер, энтропию, плотность ключевых слов, base64 и другие — для классификации независимо от ключевых слов.",
        "model_ready":         "Модель готова",
        "model_not_trained":   "Модель не обучена",
        "model_not_trained_desc": "Нажмите «Обучить модель» чтобы создать датасет и обучить классификатор. Займёт 10–20 секунд.",
        "retrain_btn":         "Переобучить модель",
        "train_btn":           "Обучить модель",
        "training_btn":        "Обучение…",
        "training_desc":       "Генерация датасета и обучение — пожалуйста, подождите…",
        "scan_file_btn":       "🔬  СКАНИРОВАТЬ ФАЙЛ",
        "scan_folder_btn_ai":  "📁  СКАНИРОВАТЬ ПАПКУ",
        "clear_btn":           "Очистить",
        "col_ai_label":        "Вердикт ИИ",
        "col_confidence":      "Уверенность",
        "col_top_signal":      "Главный сигнал",
        "select_file_scan":    "Выберите файл для сканирования",
        "select_folder_scan":  "Выберите папку",
        "scan_fail_title":     "Ошибка сканирования",
        "scan_fail_msg":       "Не удалось прочитать файл:\n{}",
        "last_scan_ai":        "Последнее: {}  ·  ИИ вердикт: {} ({})",
        "scanned_summary":     "Проверено {} файлов · {} вредоносных · {} безопасных",
        "scanning_progress":   "Сканирование… {}/{}",
        "top_signal_keywords": "ключевых слов ×{}",
        "top_signal_base64":   "base64 payload",
        "top_signal_urls":     "URL ×{}",
        "top_signal_entropy":  "энтропия {}",
        "top_signal_ip":       "IP адресов ×{}",
        "top_signal_ext":      "подозрительное расширение",
        "top_signal_nonascii": "высокая доля не-ASCII",
        "top_signal_lines":    "низкая уникальность строк",
        "top_signal_general":  "общий паттерн",

        # Behavior
        "beh_title":           "Анализ поведения",
        "beh_subtitle":        "Статический поведенческий анализ — определяет намерения файла по 6 категориям угроз: Закрепление, Сеть, Уклонение, Уничтожение данных, Повышение привилегий, Боковое перемещение.",
        "analyse_file_btn":    "🧬  АНАЛИЗИРОВАТЬ ФАЙЛ",
        "analysing_btn":       "Анализ…",
        "col_category":        "Категория",
        "col_indicators":      "Индикаторы",
        "col_top_finding":     "Главная находка",
        "beh_placeholder":     "Выберите файл для поведенческого анализа…",
        "verdict_label":       "ВЕРДИКТ",
        "score_label":         "БАЛЛ УГРОЗЫ",
        "indicators_label":    "ИНДИКАТОРЫ",
        "select_file_analyse": "Выберите файл для анализа",
        "file_label":          "Файл: ",
    }
}

# Текущий язык — стартует с EN
_current_lang = "EN"


def get(key: str) -> str:
    """Возвращает перевод для текущего языка."""
    return TRANSLATIONS[_current_lang].get(key, key)


def set_lang(lang: str):
    global _current_lang
    if lang in TRANSLATIONS:
        _current_lang = lang


def current_lang() -> str:
    return _current_lang


def toggle_lang() -> str:
    """Переключает язык EN↔RU и возвращает новый язык."""
    global _current_lang
    _current_lang = "RU" if _current_lang == "EN" else "EN"
    return _current_lang
