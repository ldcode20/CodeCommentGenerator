"""Middle layer: relative imports, several hops between modules."""
import os

from . import db
from .util import build_where, normalize, quote_for_shell, to_int


def search(term):
    clean = normalize(term)
    return db.run_sql("SELECT * FROM items WHERE " + build_where("title", clean))


def report(table_id):
    return db.run_sql("SELECT * FROM reports WHERE id = " + str(to_int(table_id)))


def archive(name):
    os.system("tar czf /backups/" + quote_for_shell(name) + ".tgz /data")  # safe: SEC002


def archive_unsafe(name):
    os.system("tar czf /backups/" + normalize(name) + ".tgz /data")  # expect: SEC002


class Exporter:
    def __init__(self, fmt):
        self.fmt = fmt

    def run(self, path):
        os.system("export --format " + self.fmt + " " + path)  # expect: SEC002
