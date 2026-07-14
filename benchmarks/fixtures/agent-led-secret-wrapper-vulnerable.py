CREDENTIAL = "Aa9$course-secret-2026"
def authenticate(client):
    return client.login(CREDENTIAL)
def handler(client):
    return authenticate(client)
