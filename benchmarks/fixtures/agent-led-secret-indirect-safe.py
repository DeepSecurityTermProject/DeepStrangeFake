import os
AUTH_VALUE = os.getenv("AUTH_VALUE")
def connect(client):
    return client.connect(AUTH_VALUE)
def startup(client):
    return connect(client)
