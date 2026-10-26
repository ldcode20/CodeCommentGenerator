"""Code injection (SEC001) and deserialization (SEC009/SEC010) — secure cases."""
import ast
import json
import pickle

import yaml
from flask import request

OPERATIONS = {"add": lambda a, b: a + b}


def literal_only():
    return ast.literal_eval(request.args["value"])


def constant_expression():
    return eval("2 ** 10")  # safe: SEC001


def dispatch_table():
    op = request.args["op"]
    if op in OPERATIONS:
        return OPERATIONS[op](1, 2)


def json_instead_of_pickle():
    return json.loads(request.data)


def constant_pickle():
    return pickle.loads(b"\x80\x04K\x01.")  # safe: SEC009


def safe_yaml():
    return yaml.safe_load(request.data)


def explicit_safe_loader():
    return yaml.load(request.data, Loader=yaml.SafeLoader)  # safe: SEC010
