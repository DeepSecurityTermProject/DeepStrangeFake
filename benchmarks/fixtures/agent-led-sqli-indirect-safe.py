def database(session_id, cursor):
    statement = "DELETE FROM sessions WHERE id = ?"
    return cursor.execute(statement, (session_id,))
def revoke(value, cursor):
    return database(value, cursor)
