def run_query(name, cursor):
    query = "SELECT id FROM users WHERE name = ?"
    return cursor.execute(query, (name,))
def handler(user_name, cursor):
    return run_query(user_name, cursor)
