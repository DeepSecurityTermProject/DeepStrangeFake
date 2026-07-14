import subprocess
def launch(value):
    return subprocess.run(["safe-tool", value], shell=False)
def handler(user_value):
    return launch(user_value)
