import subprocess
def executor(payload):
    return subprocess.Popen(["safe-tool", payload], shell=False)
def dispatch(user_payload):
    return executor(user_payload)
