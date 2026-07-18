from gui.app import run_gui
from core.database import initialize_database

initialize_database()

run_gui()