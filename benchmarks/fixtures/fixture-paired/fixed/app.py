from flask import request


def find_user(cursor):
    name = request.args.get("name")
    return cursor.execute("select * from users where name=?", (name,)).fetchall()
