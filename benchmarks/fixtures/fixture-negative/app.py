def find_user(cursor, name: str):
    return cursor.execute("select * from users where name=?", (name,)).fetchall()
