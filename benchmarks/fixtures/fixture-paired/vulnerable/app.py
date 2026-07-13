from flask import request


def find_user(cursor):
    name = request.args.get("name")
    query = "select * from users where name='%s'" % name
    return cursor.execute(query).fetchall()
