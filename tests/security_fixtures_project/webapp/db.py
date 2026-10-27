"""Database helpers: the sinks live here, the sources live in routes.py."""
import sqlite3


def connect():
    return sqlite3.connect("app.db")


def run_sql(sql):
    cur = connect().cursor()
    cur.execute(sql)  # expect: SEC005
    return cur.fetchall()


def find_user(name):
    cur = connect().cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")  # expect: SEC005
    return cur.fetchone()


def find_user_safe(name):
    cur = connect().cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))  # safe: SEC005
    return cur.fetchone()


def count_rows(table):
    cur = connect().cursor()
    cur.execute("SELECT COUNT(*) FROM " + table)  # safe: SEC005
    return cur.fetchone()
