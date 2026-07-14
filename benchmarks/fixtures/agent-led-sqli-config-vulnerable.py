QUERY_CONFIG = {"item": "SELECT name FROM items WHERE id = {value}"}
def execute_template(value, cursor):
    statement = QUERY_CONFIG["item"].replace("{value}", value)
    return cursor.execute(statement)
def lookup(value, cursor):
    return execute_template(value, cursor)
