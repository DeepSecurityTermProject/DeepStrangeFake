from flask import send_file
from pathlib import Path
def deliver(name):
    return send_file(Path("exports") / Path(name).name)
def export(user_name):
    return deliver(user_name)
