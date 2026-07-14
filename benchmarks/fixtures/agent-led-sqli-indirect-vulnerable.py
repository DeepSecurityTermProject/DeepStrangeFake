def database(session_id, cursor):
    statement = "DELETE FROM sessions WHERE id = " + session_id
    return cursor.execute(statement)
def revoke(value, cursor):
    return database(value, cursor)
