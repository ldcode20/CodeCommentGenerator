"""5. cycle_a imports cycle_b and cycle_b imports cycle_a; ping/pong recurse across them."""
from flask import request

from webapp import cycle_b


def ping(n, cmd):
    if n <= 0:
        return cmd
    return cycle_b.pong(n - 1, cmd)


def start():
    return cycle_b.pong(3, request.args["cmd"])
