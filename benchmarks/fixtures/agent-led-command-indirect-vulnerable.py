import subprocess
def executor(payload):
    return subprocess.Popen(payload, shell=True)
def dispatch(user_payload):
    return executor(user_payload)
