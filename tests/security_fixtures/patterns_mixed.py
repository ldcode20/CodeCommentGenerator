"""AST pattern rules (SEC004, SEC006, SEC007, SEC008, SEC011, SEC012) and suppression."""
import hashlib
import os
import random
import secrets
import sqlite3

from flask import request


def password_digest(pw):
    return hashlib.md5(pw.encode()).hexdigest()  # expect: SEC004


def cache_key(data):
    return hashlib.sha1(data, usedforsecurity=False).hexdigest()  # safe: SEC004


def strong_digest(data):
    return hashlib.sha256(data).hexdigest()  # safe: SEC004


def swallow_errors():
    try:
        os.remove("/tmp/x")
    except:  # expect: SEC006
        pass


def cleanup_and_reraise():
    try:
        os.remove("/tmp/x")
    except:  # safe: SEC006
        print("cleanup")
        raise


def append_item(item, bucket=[]):  # expect: SEC007
    bucket.append(item)
    return bucket


def append_item_ok(item, bucket=None):  # safe: SEC007
    bucket = [] if bucket is None else bucket
    bucket.append(item)
    return bucket


def require_admin(user):
    assert user.is_admin  # expect: SEC008
    return True


def generate_reset_token():
    return "".join(random.choice("abcdef0123456789") for _ in range(32))  # expect: SEC011


def shuffle_cards(deck):
    random.shuffle(deck)  # safe: SEC011
    return deck


def generate_session_token():
    return secrets.token_hex(16)  # safe: SEC011


def connect_upstream():
    return ("10.0.12.7", 8443)  # expect: SEC012


def bind_local():
    return ("127.0.0.1", 8080)  # safe: SEC012


def reviewed_query():
    name = request.args["name"]
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM t WHERE n = '" + name + "'")  # nosec SEC005: reviewed, legacy read-only replica  # expect-suppressed: SEC005


def unjustified_suppression():
    name = request.args["name"]
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM t WHERE n = '" + name + "'")  # nosec  # expect: SEC005
