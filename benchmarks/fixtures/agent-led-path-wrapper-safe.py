from pathlib import Path
BASE = Path("uploads").resolve()
def read_user_file(name):
    candidate = (BASE / name).resolve()
    return open(candidate, "rb").read() if candidate.is_relative_to(BASE) else b""
def download(user_name):
    return read_user_file(user_name)
