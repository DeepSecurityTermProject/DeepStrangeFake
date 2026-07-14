from pathlib import Path
PATH_CONFIG = {"asset_root": "assets"}
def load_asset(name):
    root = Path(PATH_CONFIG["asset_root"]).resolve()
    target = (root / name).resolve()
    return open(target, "rb").read() if target.is_relative_to(root) else b""
def serve(user_name):
    return load_asset(user_name)
