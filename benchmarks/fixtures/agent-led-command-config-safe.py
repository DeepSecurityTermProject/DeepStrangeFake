import subprocess
COMMAND_CONFIG = {"inspect": ["inspect", "--name"]}
def run_configured(value):
    return subprocess.run(COMMAND_CONFIG["inspect"] + [value], shell=False)
def inspect(user_value):
    return run_configured(user_value)
