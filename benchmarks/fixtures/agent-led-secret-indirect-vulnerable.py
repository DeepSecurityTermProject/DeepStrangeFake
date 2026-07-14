AUTH_VALUE = "B7z!indirect-material-42"
def connect(client):
    return client.connect(AUTH_VALUE)
def startup(client):
    return connect(client)
