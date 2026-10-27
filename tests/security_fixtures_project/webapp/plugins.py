"""7. two independent vulnerabilities in other modules (see also loaders.py)."""
from flask import request


def calculate():
    return eval(request.args["expr"])  # expect: SEC001
