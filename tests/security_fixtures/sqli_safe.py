"""SQL injection (SEC005) — secure cases using the same APIs."""
import re
import sqlite3

from flask import request

ALLOWED_TABLES = {"users", "orders"}


def get_db():
    return sqlite3.connect("app.db")


def parameterised_positional():
    name = request.args.get("name")
    cur = get_db().cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))  # safe: SEC005


def parameterised_named():
    email = request.form["email"]
    conn = get_db()
    conn.execute("SELECT * FROM users WHERE email = :e", {"e": email})  # safe: SEC005


def integer_conversion():
    uid = int(request.args["id"])
    cur = get_db().cursor()
    cur.execute("SELECT * FROM users WHERE id = %d" % uid)  # safe: SEC005


def allowlisted_identifier():
    table = request.args["table"]
    if table not in ALLOWED_TABLES:
        raise ValueError("unknown table")
    cur = get_db().cursor()
    cur.execute(f"SELECT * FROM {table}")  # safe: SEC005


def digit_validation():
    page = request.args["page"]
    if page.isdigit():
        cur = get_db().cursor()
        cur.execute("SELECT * FROM posts LIMIT 10 OFFSET " + page)  # safe: SEC005


def anchored_regex_validation():
    col = request.args["sort"]
    if re.fullmatch(r"[a-z_]+", col):
        cur = get_db().cursor()
        cur.execute("SELECT * FROM t ORDER BY " + col)  # safe: SEC005


def constant_query():
    cur = get_db().cursor()
    cur.execute("SELECT COUNT(*) FROM users")  # safe: SEC005


def run_query(sql):
    cur = get_db().cursor()
    cur.execute(sql)  # safe: SEC005
    return cur.fetchall()


def only_constant_callers():
    run_query("SELECT * FROM users")
    run_query("SELECT * FROM orders WHERE total > 100")


def taint_overwritten():
    q = "SELECT * FROM t WHERE name = '" + request.args["n"] + "'"
    q = "SELECT * FROM t"
    cur = get_db().cursor()
    cur.execute(q)  # safe: SEC005


class Report:
    def __init__(self, where):
        self.where = where

    def run(self):
        cur = get_db().cursor()
        cur.execute("SELECT * FROM reports WHERE " + self.where)  # safe: SEC005


def nightly_report():
    Report("archived = 0").run()


def sanitising_helper(value):
    return int(value)


def through_sanitising_helper():
    uid = sanitising_helper(request.args["id"])
    cur = get_db().cursor()
    cur.execute("SELECT * FROM users WHERE id = " + str(uid))  # safe: SEC005
