"""SQL injection (SEC005) — vulnerable cases."""
import re
import sqlite3
import html

from flask import request
from django.db import connection
from reporting_lib import build_filter


def get_db():
    return sqlite3.connect("app.db")


def direct_concat():
    name = request.args.get("name")
    cur = get_db().cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")  # expect: SEC005


def through_assignments():
    raw = request.form["id"]
    user_id = raw
    query = "DELETE FROM users WHERE id = " + user_id
    final = query
    conn = sqlite3.connect("app.db")
    conn.execute(final)  # expect: SEC005


def fstring_and_percent():
    term = request.args["q"]
    cur = get_db().cursor()
    cur.execute(f"SELECT * FROM items WHERE title LIKE '%{term}%'")  # expect: SEC005
    cur.execute("SELECT * FROM items WHERE id = %s" % term)  # expect: SEC005
    cur.execute("SELECT * FROM items WHERE owner = '{}'".format(term))  # expect: SEC005


def run_query(sql):
    cur = get_db().cursor()
    cur.execute(sql)  # expect: SEC005
    return cur.fetchall()


def interprocedural_caller():
    country = request.args.get("country")
    return run_query("SELECT * FROM cities WHERE country = '" + country + "'")


def constant_caller():
    return run_query("SELECT COUNT(*) FROM cities")


def branch_merge(flag):
    if flag:
        where = "name = '" + request.args["n"] + "'"
    else:
        where = "1 = 1"
    cur = get_db().cursor()
    cur.execute("SELECT * FROM t WHERE " + where)  # expect: SEC005


def loop_accumulation():
    clauses = "1 = 1"
    for value in request.args.getlist("tag"):
        clauses += " OR tag = '" + value + "'"
    cur = get_db().cursor()
    cur.execute("SELECT * FROM posts WHERE " + clauses)  # expect: SEC005


def early_return_does_not_sanitize():
    name = request.args.get("name")
    if not name:
        return []
    cur = get_db().cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)  # expect: SEC005
    return cur.fetchall()


def wrong_sanitizer():
    name = html.escape(request.args["name"])
    cur = get_db().cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")  # expect: SEC005


def unanchored_regex_check():
    col = request.args["sort"]
    if re.match(r"[a-z_]+", col):
        cur = get_db().cursor()
        cur.execute("SELECT * FROM t ORDER BY " + col)  # expect: SEC005


def unknown_library_call():
    clause = build_filter(request.args["filter"])
    cur = get_db().cursor()
    cur.execute("SELECT * FROM reports WHERE " + clause)  # expect: SEC005


def django_view(request):
    order = request.GET["order"]
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM books ORDER BY " + order)  # expect: SEC005


def two_sinks_one_function():
    a = request.args["a"]
    b = request.args["b"]
    cur = get_db().cursor()
    cur.execute("SELECT * FROM t WHERE a = '" + a + "'")  # expect: SEC005
    cur.execute("SELECT * FROM t WHERE b = '" + b + "'")  # expect: SEC005


def closure_capture():
    name = request.args["name"]

    def inner():
        cur = get_db().cursor()
        cur.execute("SELECT * FROM users WHERE name = '" + name + "'")  # expect: SEC005

    inner()


class Repository:
    def __init__(self):
        self.conn = sqlite3.connect("app.db")
        self.filter = request.args.get("filter")

    def search(self):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM t WHERE " + self.filter)  # expect: SEC005


def recursive_query(sql, depth):
    if depth > 0:
        return recursive_query(sql + " AND 1 = 1", depth - 1)
    cur = get_db().cursor()
    cur.execute(sql)  # expect: SEC005


def recursive_entry():
    recursive_query("SELECT * FROM t WHERE x = '" + request.args["x"] + "'", 3)


class Report:
    def __init__(self, where):
        self.where = where

    def run(self):
        cur = get_db().cursor()
        cur.execute("SELECT * FROM reports WHERE " + self.where)  # expect: SEC005


def report_endpoint():
    Report(request.args["where"]).run()


def bound_method_alias():
    q = request.args["q"]
    run = get_db().cursor().execute
    run("SELECT * FROM t WHERE q = '" + q + "'")  # expect: SEC005
