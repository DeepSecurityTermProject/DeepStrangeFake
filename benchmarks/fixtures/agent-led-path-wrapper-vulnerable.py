from pathlib import Path
BASE = Path("uploads")
def read_user_file(name):
    return open(BASE / name, "rb").read()
def download(user_name):
    return read_user_file(user_name)
