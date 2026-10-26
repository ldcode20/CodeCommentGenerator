"""Path traversal (SEC013) — vulnerable cases."""
import os
import shutil
from pathlib import Path

from flask import abort, request, send_file

BASE_DIR = "/srv/app/uploads"


def join_and_open():
    name = request.args["file"]
    with open(os.path.join(BASE_DIR, name)) as fh:  # expect: SEC013
        return fh.read()


def send_user_path():
    return send_file(request.args["path"])  # expect: SEC013


def pathlib_division():
    name = request.args["doc"]
    target = Path(BASE_DIR) / name
    return target.read_text()  # expect: SEC013


def prefix_check_without_canonicalisation():
    p = os.path.join(BASE_DIR, request.args["f"])
    if not p.startswith(BASE_DIR):
        abort(403)
    return open(p).read()  # expect: SEC013


def delete_user_file():
    os.remove(request.form["victim"])  # expect: SEC013


def read_file(path):
    with open(path, "rb") as fh:  # expect: SEC013
        return fh.read()


def download():
    return read_file(BASE_DIR + "/" + request.args["name"])


def copy_upload():
    src = request.args["src"]
    shutil.copy(src, "/tmp/backup")  # expect: SEC013
