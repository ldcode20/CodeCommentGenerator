"""6. an unresolved external dependency sits on the path."""
import os

from flask import request
from thirdparty.text import transform


def convert():
    os.system("convert " + transform(request.args["file"]))  # expect: SEC002
