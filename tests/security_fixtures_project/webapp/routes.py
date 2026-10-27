"""HTTP entry points: every untrusted source of the fixture project is here."""
from flask import request

from webapp import db, service
from webapp.service import Exporter


def user_lookup():
    # 1. request source here, SQL sink in db.find_user
    return db.find_user(request.args["name"])


def user_lookup_safe():
    # 4. patched variant of the same flow: parameterised query in db.find_user_safe
    return db.find_user_safe(request.args["name"])


def items():
    # 2. routes -> service.search -> util.normalize/build_where -> db.run_sql
    return service.search(request.args["q"])


def reports():
    # 3. sanitiser (util.to_int) applied in service before the sink in db
    return service.report(request.args["id"])


def backup():
    service.archive(request.form["name"])
    service.archive_unsafe(request.form["name"])


def export():
    Exporter(request.args["fmt"]).run("/tmp/out")


def stats():
    return db.count_rows("users")
