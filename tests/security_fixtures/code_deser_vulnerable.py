"""Code injection (SEC001) and unsafe deserialization (SEC009/SEC010) — vulnerable cases."""
import marshal
import pickle

import yaml
from flask import request


def calculator():
    return eval(request.args["expr"])  # expect: SEC001


def run_snippet():
    code = input(">>> ")
    exec(code)  # expect: SEC001


def compile_user_code():
    src = request.form["src"]
    exec(compile(src, "<user>", "exec"))  # expect: SEC001


def evaluate(expression):
    return eval(expression)  # expect: SEC001


def load_session():
    return pickle.loads(request.data)  # expect: SEC009


def load_cache(path):
    with open(path, "rb") as fh:
        return pickle.load(fh)  # expect: SEC009


def load_code_object():
    return marshal.loads(request.get_data())  # expect: SEC009


def parse_config():
    return yaml.load(request.data, Loader=yaml.Loader)  # expect: SEC010


def parse_manifest(path):
    with open(path) as fh:
        return yaml.load(fh)  # expect: SEC010


def parse_unsafe():
    return yaml.unsafe_load(request.get_data())  # expect: SEC010
