import os
import sqlite3

from flask import Flask, request


app = Flask(__name__)


@app.get("/search")
def search():
    term = request.args.get("q", "")
    conn = sqlite3.connect(":memory:")
    conn.execute("create table users(name text)")
    rows = conn.execute("select * from users where name = '%s'" % term).fetchall()
    return {"rows": rows}


@app.get("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return os.popen("ping -n 1 " + host).read()
