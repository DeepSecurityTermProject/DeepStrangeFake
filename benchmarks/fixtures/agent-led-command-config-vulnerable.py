import os
COMMAND_CONFIG = {"inspect": "inspect --name {value}"}
def run_configured(value):
    return os.system(COMMAND_CONFIG["inspect"].format(value=value))
def inspect(user_value):
    return run_configured(user_value)
