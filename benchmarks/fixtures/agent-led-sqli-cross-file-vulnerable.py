def run_query(name, cursor):
    query = "SELECT id FROM users WHERE name = '" + name + "'"
    return cursor.execute(query)
def handler(user_name, cursor):
    return run_query(user_name, cursor)
