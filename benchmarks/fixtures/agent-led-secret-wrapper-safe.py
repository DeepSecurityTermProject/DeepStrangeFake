import os
CREDENTIAL = os.environ["COURSE_CREDENTIAL"]
def authenticate(client):
    return client.login(CREDENTIAL)
def handler(client):
    return authenticate(client)
