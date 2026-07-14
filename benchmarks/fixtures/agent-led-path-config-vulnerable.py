from pathlib import Path
PATH_CONFIG = {"asset_root": "assets"}
def load_asset(name):
    target = Path(PATH_CONFIG["asset_root"]) / name
    return open(target, "rb").read()
def serve(user_name):
    return load_asset(user_name)
