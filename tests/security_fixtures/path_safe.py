"""Path traversal (SEC013) — secure cases using the same APIs."""
import os
from pathlib import Path

from flask import abort, request, send_from_directory
from werkzeug.utils import secure_filename

BASE_DIR = "/srv/app/uploads"


def basename_only():
    name = os.path.basename(request.args["file"])
    with open(os.path.join(BASE_DIR, name)) as fh:  # safe: SEC013
        return fh.read()


def werkzeug_secure_filename():
    name = secure_filename(request.args["file"])
    return open(os.path.join(BASE_DIR, name)).read()  # safe: SEC013


def realpath_commonpath_boundary():
    full = os.path.realpath(os.path.join(BASE_DIR, request.args["f"]))
    if os.path.commonpath([full, BASE_DIR]) != BASE_DIR:
        abort(403)
    return open(full).read()  # safe: SEC013


def realpath_prefix_boundary():
    full = os.path.realpath(os.path.join(BASE_DIR, request.args["f"]))
    if not full.startswith(BASE_DIR + os.sep):
        abort(403)
    return open(full).read()  # safe: SEC013


def pathlib_resolve_boundary():
    base = Path(BASE_DIR).resolve()
    target = (base / request.args["doc"]).resolve()
    if not target.is_relative_to(base):
        abort(403)
    return target.read_text()  # safe: SEC013


def framework_safe_api():
    return send_from_directory(BASE_DIR, request.args["file"])


def constant_path():
    with open("/etc/app/config.json") as fh:  # safe: SEC013
        return fh.read()
