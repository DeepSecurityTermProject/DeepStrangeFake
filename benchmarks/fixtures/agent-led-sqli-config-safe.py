QUERY_CONFIG = {"item": "SELECT name FROM items WHERE id = ?"}
def execute_template(value, cursor):
    statement = QUERY_CONFIG["item"]
    return cursor.execute(statement, (value,))
def lookup(value, cursor):
    return execute_template(value, cursor)
