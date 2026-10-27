import pickle

from flask import request


def restore_session():
    return pickle.loads(request.data)  # expect: SEC009
